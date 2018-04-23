/*-
 * Copyright (c) 2005-2010 Pawel Jakub Dawidek <pjd@FreeBSD.org>
 * Copyright (c) 2018 Sean Eric Fagan <sef@ixsystems.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Portions of this file are derived from sys/geom/eli/g_eli_hmac.c
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/types.h>
#include <sys/errno.h>

#ifdef _KERNEL
# include <sys/libkern.h>
# include <sys/malloc.h>
# include <opencrypto/cryptodev.h>
# include <opencrypto/xform.h>
#else
# include <strings.h>
#endif

#include <sys/zio_crypt.h>
#include <sys/fs/zfs.h>
#include <sys/zio.h>

#include <sys/freebsd_crypto.h>

#define SHA512_HMAC_BLOCK_SIZE	128

#undef FCRYPTO_DEBUG

void
crypto_mac_init(struct hmac_ctx *ctx, const crypto_key_t *c_key)
{
	u_char k_ipad[SHA512_HMAC_BLOCK_SIZE],
		k_opad[SHA512_HMAC_BLOCK_SIZE],
		key[SHA512_HMAC_BLOCK_SIZE];
	SHA512_CTX lctx;
	u_int i;
	size_t cl_bytes = CRYPTO_BITS2BYTES(c_key->ck_length);

	/*
	 * This code is based on the similar code in geom/eli/g_eli_hmac.c
	 */
	explicit_bzero(key, sizeof(key));
	if (c_key->ck_length  == 0)
		; /* do nothing */
	else if (cl_bytes <= SHA512_HMAC_BLOCK_SIZE)
		bcopy(c_key->ck_data, key, cl_bytes);
	else {
		/* If key is longer than 128 bytes reset it to key = SHA512(key). */
		SHA512_Init(&lctx);
		SHA512_Update(&lctx, c_key->ck_data, cl_bytes);
		SHA512_Final(key, &lctx);
	}

	/* XOR key with ipad and opad values. */
	for (i = 0; i < sizeof(key); i++) {
		k_ipad[i] = key[i] ^ 0x36;
		k_opad[i] = key[i] ^ 0x5c;
	}
	explicit_bzero(key, sizeof(key));

	/* Start inner SHA512. */
	SHA512_Init(&ctx->innerctx);
	SHA512_Update(&ctx->innerctx, k_ipad, sizeof(k_ipad));
	explicit_bzero(k_ipad, sizeof(k_ipad));
	/* Start outer SHA512. */
	SHA512_Init(&ctx->outerctx);
	SHA512_Update(&ctx->outerctx, k_opad, sizeof(k_opad));
	explicit_bzero(k_opad, sizeof(k_opad));
}

void
crypto_mac_update(struct hmac_ctx *ctx, const void *data, size_t datasize)
{
	SHA512_Update(&ctx->innerctx, data, datasize);
}

void
crypto_mac_final(struct hmac_ctx *ctx, void *md, size_t mdsize)
{
	u_char digest[SHA512_DIGEST_LENGTH];

	/* Complete inner hash */
	SHA512_Final(digest, &ctx->innerctx);
	
	/* Complete outer hash */
	SHA512_Update(&ctx->outerctx, digest, sizeof(digest));
	SHA512_Final(digest, &ctx->outerctx);
	
	explicit_bzero(ctx, sizeof(*ctx));
	/* mdsize == 0 means "Give me the whole hash!" */
	if (mdsize == 0)
		mdsize = SHA512_DIGEST_LENGTH;
	bcopy(digest, md, mdsize);
	explicit_bzero(digest, sizeof(digest));
}

void
crypto_mac(const crypto_key_t *key, const void *in_data, size_t in_data_size,
    void *out_data, size_t out_data_size)
{
	struct hmac_ctx ctx;

	crypto_mac_init(&ctx, key);
	crypto_mac_update(&ctx, in_data, in_data_size);
	crypto_mac_final(&ctx, out_data, out_data_size);
}

#ifdef _KERNEL
static int
freebsd_zfs_crypt_done(struct cryptop *crp)
{
	crp->crp_opaque = (void*)crp;
	wakeup(crp);
	return (0);
}
#endif

/*
 * The meat of encryption/decryption.
 */
int
freebsd_crypt_uio(boolean_t encrypt,
    struct zio_crypt_info *c_info,
    uio_t *data_uio,
    crypto_key_t *key,
    uint8_t *ivbuf,
    size_t datalen,
    size_t auth_len)
{
#ifdef _KERNEL
	struct cryptoini cria, crie, *crip;
	struct cryptop *crp;
	struct cryptodesc *crd, *enc_desc, *auth_desc;
	struct enc_xform *xform = &enc_xform_aes_nist_gcm;
	struct auth_hash *xauth;
	iovec_t *last_iovec;
	uint64_t sid;
	int error;
	uint8_t *p = NULL;
	size_t total = 0;

#ifdef FCRYPTO_DEBUG
	printf("%s(%s, { %s, %d, %d, %s }, %p, { %d, %p, %u }, %p, %u, %u)\n",
	       __FUNCTION__, encrypt ? "encrypt" : "decrypt",
	       c_info->ci_algname, c_info->ci_crypt_type, (unsigned int)c_info->ci_keylen, c_info->ci_name,
	       data_uio,
	       key->ck_format, key->ck_data, (unsigned int)key->ck_length,
	       ivbuf, (unsigned int)datalen, (unsigned int)auth_len);
	printf("\tkey = { ");
	for (int i = 0; i < key->ck_length / 8; i++) {
		uint8_t *b = (uint8_t*)key->ck_data;
		printf("%02x ", b[i]);
	}
	printf("}\n");
	for (int i = 0; i < data_uio->uio_iovcnt; i++) {
		printf("\tiovec #%d: <%p, %u>\n", i, data_uio->uio_iov[i].iov_base, (unsigned int)data_uio->uio_iov[i].iov_len);
		total += data_uio->uio_iov[i].iov_len;
	}
	data_uio->uio_resid = total;
#endif

	/* Only GCM is supported for the moment */
	if (c_info->ci_crypt_type != ZC_TYPE_GCM) {
		error = ENOTSUP;
		goto bad;
	}

	/* This is only valid for GCM */
	switch (ZIO_DATA_MAC_LEN) {
	case AES_128_GMAC_KEY_LEN:
#ifdef FCRYPTO_DEBUG
		printf("%s(%d): Using 128 GMAC\n", __FUNCTION__, __LINE__);
#endif
		xauth = &auth_hash_nist_gmac_aes_128;
		break;
	case AES_192_GMAC_KEY_LEN:
#ifdef FCRYPTO_DEBUG
		printf("%s(%d): Using 192 GMAC\n", __FUNCTION__, __LINE__);
#endif
		xauth = &auth_hash_nist_gmac_aes_192;
		break;
	case AES_256_GMAC_KEY_LEN:
#ifdef FCRYPTO_DEBUG
		printf("%s(%d): Using 256 GMAC\n", __FUNCTION__, __LINE__);
#endif
		xauth = &auth_hash_nist_gmac_aes_256;
		break;
	default:
		error = EINVAL;
		goto bad;
	}

	bzero(&crie, sizeof(crie));
	bzero(&cria, sizeof(cria));

	crie.cri_alg = xform->type;
	crie.cri_key = key->ck_data;
	crie.cri_klen = key->ck_length;
	bcopy(ivbuf, crie.cri_iv, ZIO_DATA_IV_LEN);

	cria.cri_alg = xauth->type;
#if 0
	cria.cri_klen = key->ck_length;
	cria.cri_key = key->ck_data;
	bcopy(ivbuf, cria.cri_iv, ZIO_DATA_IV_LEN);
	cria.cri_next = &crie;
#else
# if 0
	uint8_t stupid_empty_auth_key[ZIO_DATA_MAC_LEN] = { 0 };
	cria.cri_klen = ZIO_DATA_MAC_LEN * 8;
	cria.cri_key = stupid_empty_auth_key;
# else
	// The tag is always last in the uio
	last_iovec = data_uio->uio_iov + (data_uio->uio_iovcnt - 1);
	cria.cri_klen = last_iovec->iov_len * 8;
	cria.cri_key = last_iovec->iov_base;
# endif

#endif
	if (encrypt) {
		crie.cri_next = &cria;
		cria.cri_next = NULL;
		crip = &crie;
	} else {
		cria.cri_next = &crie;
		crie.cri_next = NULL;
		crip = &cria;
	}
	// Everything else is bzero'd
	
	error = crypto_newsession(&sid, crip, CRYPTOCAP_F_HARDWARE | CRYPTOCAP_F_SOFTWARE);
	if (error != 0) {
		printf("%s(%d):  crypto_newsession failed with %d\n", __FUNCTION__, __LINE__, error);
		goto bad;
	}
	crp = crypto_getreq(2);
	if (crp == NULL) {
		error = ENOMEM;
		crypto_freesession(sid);
		goto bad;
	}

	auth_desc = crp->crp_desc;
	enc_desc = auth_desc->crd_next;

	crp->crp_sid = sid;
	crp->crp_ilen = auth_len + datalen;
	crp->crp_buf = (void*)data_uio;
	crp->crp_flags = CRYPTO_F_IOV | CRYPTO_F_CBIFSYNC;
	
	auth_desc->crd_skip = 0;
	auth_desc->crd_len = auth_len;
	auth_desc->crd_inject = auth_len + datalen;
	auth_desc->crd_alg = xauth->type;
//	auth_desc->crd_key = crie.cri_key;
//	auth_desc->crd_klen = crie.cri_klen;
	auth_desc->crd_key = cria.cri_key;
	auth_desc->crd_klen = cria.cri_klen;
	
#ifdef FCRYPTO_DEBUG
	printf("%s: auth: skip = %u, len = %u, inject = %u\n", __FUNCTION__, auth_desc->crd_skip, auth_desc->crd_len, auth_desc->crd_inject);
#endif

	enc_desc->crd_skip = auth_len;
	enc_desc->crd_len = datalen;
	enc_desc->crd_inject = auth_len;
	enc_desc->crd_alg = xform->type;
	enc_desc->crd_flags = CRD_F_IV_EXPLICIT | CRD_F_IV_PRESENT;
	bcopy(ivbuf, enc_desc->crd_iv, ZIO_DATA_IV_LEN);
	enc_desc->crd_key = crie.cri_key;
	enc_desc->crd_klen = crie.cri_klen;
	enc_desc->crd_next = NULL;
	
#ifdef FCRYPTO_DEBUG
	printf("%s: enc: skip = %u, len = %u, inject = %u\n", __FUNCTION__, enc_desc->crd_skip, enc_desc->crd_len, enc_desc->crd_inject);
#endif

	if (encrypt)
		enc_desc->crd_flags |= CRD_F_ENCRYPT;
	
	crp->crp_callback = freebsd_zfs_crypt_done;
	crp->crp_opaque = NULL;
	error = crypto_dispatch(crp);
	if (error == 0) {
		while (crp->crp_opaque == NULL)
			tsleep(crp, PRIBIO, "zfs_crypto", hz/5);
		error = crp->crp_etype;
	}
	crypto_freereq(crp);
	crypto_freesession(sid);
bad:
#ifdef FCRYPTO_DEBUG
	if (error)
		printf("%s: returning error %d\n", __FUNCTION__, error);
#endif
	return (error);
#endif
	return (-1);
}
