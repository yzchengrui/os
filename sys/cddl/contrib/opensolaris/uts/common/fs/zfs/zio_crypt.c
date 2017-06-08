/*
 * CDDL HEADER START
 *
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 *
 * CDDL HEADER END
 */

/*
 * Copyright (c) 2017, Datto, Inc. All rights reserved.
 */

#include <sys/zio_crypt.h>
#include <sys/dmu.h>
#include <sys/dmu_objset.h>
#include <sys/dnode.h>
#include <sys/fs/zfs.h>
#include <sys/zio.h>
#include <sys/zil.h>
#ifdef _KERNEL
#include <sys/crypto/sha2/sha512.h>
#else
#include <sha512.h>
#endif

/*
 * This file is responsible for handling all of the details of generating
 * encryption parameters and performing encryption.
 *
 * BLOCK ENCRYPTION PARAMETERS:
 * Encryption Algorithm (crypt):
 * The encryption algorithm and mode we are going to use. We currently support
 * AES-GCM and AES-CCM in 128, 192, and 256 bits.
 *
 * Plaintext:
 * The unencrypted data that we want to encrypt
 *
 * Initialization Vector (IV):
 * An initialization vector for the encryption algorithms. This is
 * used to "tweak" the encryption algorithms so that equivalent blocks of
 * data are encrypted into different ciphertext outputs. Different modes
 * of encryption have different requirements for the IV. AES-GCM and AES-CCM
 * require that an IV is never reused with the same encryption key. This
 * value is stored unencrypted and must simply be provided to the decryption
 * function. We use a 96 bit IV (as recommended by NIST). For non-dedup blocks
 * we derive the IV randomly. The first 64 bits of the IV are stored in the
 * second word of DVA[2] and the remaining 32 bits are stored in the upper 32
 * bits of blk_fill. For most object types this is safe because we only encrypt
 * level 0 blocks which means that the fill count will be 1. For DMU_OT_DNODE
 * blocks the fill count is instead used to indicate the number of allocated
 * dnodes beneath the bp. The on-disk format supports at most 2^15 slots per
 * L0 dnode block, because the maximum block size is 16MB (2^24). In either
 * case, for level 0 blocks this number will still be smaller than UINT32_MAX
 * so it is safe to store the IV in the top 32 bits of blk_fill, while leaving
 * the bottom 32 bits of the fill count for the dnode code.
 *
 * Master key:
 * This is the most important secret data of an encrypted dataset. It is used
 * along with the salt to generate that actual encryption keys via HKDF. We
 * do not use the master key to encrypt any data because there are theoretical
 * limits on how much data can actually be safely encrypted with any encryption
 * mode. The master key is stored encrypted on disk with the user's key. It's
 * length is determined by the encryption algorithm. For details on how this is
 * stored see the block comment in dsl_crypt.c
 *
 * Salt:
 * Used as an input to the HKDF function, along with the master key. We use a
 * 64 bit salt, stored unencrypted in the first word of DVA[2]. Any given salt
 * can be used for encrypting many blocks, so we cache the current salt and the
 * associated derived key in zio_crypt_t so we do not need to derive it again
 * needlessly.
 *
 * Encryption Key:
 * A secret binary key, generated from an HKDF function used to encrypt and
 * decrypt data.
 *
 * Message Authenication Code (MAC)
 * The MAC is an output of authenticated encryption modes such as AES-GCM and
 * AES-CCM. Its purpose is to ensure that an attacker cannot modify encrypted
 * data on disk and return garbage to the application. Effectively, it is a
 * checksum that can not be reproduced by an attacker. We store the MAC in the
 * second 128 bits of blk_cksum, leaving the first 128 bits for a truncated
 * regular checksum of the ciphertext which can be used for scrubbing.
 *
 * ZIL ENCRYPTION:
 * ZIL blocks have their bp written to disk ahead of the associated data, so we
 * cannot store encryption paramaters there as we normally do. For these blocks
 * the MAC is stored in the embedded checksum within the zil_chain_t header. The
 * salt and IV are generated for the block on bp allocation instead of at
 * encryption time. In addition, ZIL blocks have some pieces that must be left
 * in plaintext for claiming while all of the sensitive user data still needs to
 * be encrypted. The function zio_crypt_init_uios_zil() handles parsing which
 * which pieces of the block need to be encrypted.
 *
 * DNODE ENCRYPTION:
 * Similarly to ZIL blocks, the core part of each dnode_phys_t needs to be left
 * in plaintext for scrubbing and claiming, but the bonus buffers might contain
 * sensitive user data. The function zio_crypt_init_uios_dnode() handles parsing
 * which which pieces of the block need to be encrypted.
 *
 * CONSIDERATIONS FOR DEDUP:
 * In order for dedup to work, blocks that we want to dedup with one another
 * need to use the same IV and encryption key, so that they will have the same
 * cyphertext. Normally, one should never reuse an IV with the same encryption
 * key or else AES-GCM and AES-CCM can both actually leak the plaintext of both
 * blocks. In this case, however, since we are using the same plaindata as
 * well all that we end up with is a duplicate of the original data we already
 * had. As a result, an attacker with read access to the raw disk will be able
 * to tell which blocks are the same but this information is already given away
 * by dedup anyway. In order to get the same IVs and encryption keys for
 * equivalent blocks of data we use a HMAC of the plaindata. We use an HMAC
 * here so there is never a reproducible checksum of the plaindata available
 * to the attacker. The HMAC key is kept alongside the master key, encrypted
 * on disk. The first 64 bits of the HMAC are used in place of the random salt,
 * and the next 96 bits are used as the IV.
 */

zio_crypt_info_t zio_crypt_table[ZIO_CRYPT_FUNCTIONS] = {
	{"",			ZC_TYPE_NONE,	0,	"inherit"},
	{"",			ZC_TYPE_NONE,	0,	"on"},
	{"",			ZC_TYPE_NONE,	0,	"off"},
	{SUN_CKM_AES_CCM,	ZC_TYPE_CCM,	16,	"aes-128-ccm"},
	{SUN_CKM_AES_CCM,	ZC_TYPE_CCM,	24,	"aes-192-ccm"},
	{SUN_CKM_AES_CCM,	ZC_TYPE_CCM,	32,	"aes-256-ccm"},
	{SUN_CKM_AES_GCM,	ZC_TYPE_GCM,	16,	"aes-128-gcm"},
	{SUN_CKM_AES_GCM,	ZC_TYPE_GCM,	24,	"aes-192-gcm"},
	{SUN_CKM_AES_GCM,	ZC_TYPE_GCM,	32,	"aes-256-gcm"}
};

static int
hkdf_sha512_extract(uint8_t *salt, uint_t salt_len, uint8_t *key_material,
    uint_t km_len, uint8_t *out_buf)
{
	int ret;
	crypto_mechanism_t mech;
	crypto_key_t key;
	crypto_data_t input_cd, output_cd;

	/* initialize sha 256 hmac mechanism */
	mech.cm_type = crypto_mech2id(SUN_CKM_SHA512_HMAC);
	mech.cm_param = NULL;
	mech.cm_param_len = 0;

	/* initialize the salt as a crypto key */
	key.ck_format = CRYPTO_KEY_RAW;
	key.ck_length = BYTES_TO_BITS(salt_len);
	key.ck_data = salt;

	/* initialize crypto data for the input and output data */
	input_cd.cd_format = CRYPTO_DATA_RAW;
	input_cd.cd_offset = 0;
	input_cd.cd_length = km_len;
	input_cd.cd_raw.iov_base = (char *)key_material;
	input_cd.cd_raw.iov_len = input_cd.cd_length;

	output_cd.cd_format = CRYPTO_DATA_RAW;
	output_cd.cd_offset = 0;
	output_cd.cd_length = SHA512_DIGEST_LENGTH;
	output_cd.cd_raw.iov_base = (char *)out_buf;
	output_cd.cd_raw.iov_len = output_cd.cd_length;

	ret = crypto_mac(&mech, &input_cd, &key, NULL, &output_cd, NULL);
	if (ret != CRYPTO_SUCCESS) {
		ret = SET_ERROR(EIO);
		goto error;
	}

	return (0);

error:
	return (ret);
}

static int
hkdf_sha512_expand(uint8_t *extract_key, uint8_t *info, uint_t info_len,
    uint8_t *out_buf, uint_t out_len)
{
	int ret;
	crypto_mechanism_t mech;
	crypto_context_t ctx;
	crypto_key_t key;
	crypto_data_t T_cd, info_cd, c_cd;
	uint_t i, T_len = 0, pos = 0;
	uint8_t c;
	uint_t N = (out_len + SHA512_DIGEST_LENGTH) / SHA512_DIGEST_LENGTH;
	uint8_t T[SHA512_DIGEST_LENGTH];

	if (N > 255)
		return (SET_ERROR(EINVAL));

	/* initialize sha 256 hmac mechanism */
	mech.cm_type = crypto_mech2id(SUN_CKM_SHA512_HMAC);
	mech.cm_param = NULL;
	mech.cm_param_len = 0;

	/* initialize the salt as a crypto key */
	key.ck_format = CRYPTO_KEY_RAW;
	key.ck_length = BYTES_TO_BITS(SHA512_DIGEST_LENGTH);
	key.ck_data = extract_key;

	/* initialize crypto data for the input and output data */
	T_cd.cd_format = CRYPTO_DATA_RAW;
	T_cd.cd_offset = 0;
	T_cd.cd_raw.iov_base = (char *)T;

	c_cd.cd_format = CRYPTO_DATA_RAW;
	c_cd.cd_offset = 0;
	c_cd.cd_length = 1;
	c_cd.cd_raw.iov_base = (char *)&c;
	c_cd.cd_raw.iov_len = c_cd.cd_length;

	info_cd.cd_format = CRYPTO_DATA_RAW;
	info_cd.cd_offset = 0;
	info_cd.cd_length = info_len;
	info_cd.cd_raw.iov_base = (char *)info;
	info_cd.cd_raw.iov_len = info_cd.cd_length;

	for (i = 1; i <= N; i++) {
		c = i;

		T_cd.cd_length = T_len;
		T_cd.cd_raw.iov_len = T_cd.cd_length;

		ret = crypto_mac_init(&mech, &key, NULL, &ctx, NULL);
		if (ret != CRYPTO_SUCCESS) {
			ret = SET_ERROR(EIO);
			goto error;
		}

		ret = crypto_mac_update(ctx, &T_cd, NULL);
		if (ret != CRYPTO_SUCCESS) {
			ret = SET_ERROR(EIO);
			goto error;
		}

		ret = crypto_mac_update(ctx, &info_cd, NULL);
		if (ret != CRYPTO_SUCCESS) {
			ret = SET_ERROR(EIO);
			goto error;
		}

		ret = crypto_mac_update(ctx, &c_cd, NULL);
		if (ret != CRYPTO_SUCCESS) {
			ret = SET_ERROR(EIO);
			goto error;
		}

		T_len = SHA512_DIGEST_LENGTH;
		T_cd.cd_length = T_len;
		T_cd.cd_raw.iov_len = T_cd.cd_length;

		ret = crypto_mac_final(ctx, &T_cd, NULL);
		if (ret != CRYPTO_SUCCESS) {
			ret = SET_ERROR(EIO);
			goto error;
		}

		bcopy(T, out_buf + pos,
		    (i != N) ? SHA512_DIGEST_LENGTH : (out_len - pos));
		pos += SHA512_DIGEST_LENGTH;
	}

	return (0);

error:
	return (ret);
}

/*
 * HKDF is designed to be a relatively fast function for deriving keys from a
 * master key + a salt. We use this function to generate new encryption keys
 * so as to avoid hitting the cryptographic limits of the underlying
 * encryption modes. Note that, for the sake of deriving encryption keys, the
 * info parameter is called the "salt" everywhere else in the code.
 */
static int
hkdf_sha512(uint8_t *key_material, uint_t km_len, uint8_t *salt,
    uint_t salt_len, uint8_t *info, uint_t info_len, uint8_t *output_key,
    uint_t out_len)
{
	int ret;
	uint8_t extract_key[SHA512_DIGEST_LENGTH];

	ret = hkdf_sha512_extract(salt, salt_len, key_material, km_len,
	    extract_key);
	if (ret != 0)
		goto error;

	ret = hkdf_sha512_expand(extract_key, info, info_len, output_key,
	    out_len);
	if (ret != 0)
		goto error;

	return (0);

error:
	return (ret);
}

void
zio_crypt_key_destroy(zio_crypt_key_t *key)
{
	rw_destroy(&key->zk_salt_lock);

	/* free crypto templates */
	crypto_destroy_ctx_template(key->zk_current_tmpl);
	crypto_destroy_ctx_template(key->zk_hmac_tmpl);

	/* zero out sensitive data */
	bzero(key, sizeof (zio_crypt_key_t));
}

int
zio_crypt_key_init(uint64_t crypt, zio_crypt_key_t *key)
{
	int ret;
	crypto_mechanism_t mech;
	uint_t keydata_len;

	ASSERT(key != NULL);
	ASSERT3U(crypt, <, ZIO_CRYPT_FUNCTIONS);

	keydata_len = zio_crypt_table[crypt].ci_keylen;

	/* fill keydata buffers and salt with random data */
	ret = random_get_bytes((uint8_t *)&key->zk_guid, sizeof (uint64_t));
	if (ret != 0)
		goto error;

	ret = random_get_bytes(key->zk_master_keydata, keydata_len);
	if (ret != 0)
		goto error;

	ret = random_get_bytes(key->zk_hmac_keydata, SHA512_HMAC_KEYLEN);
	if (ret != 0)
		goto error;

	ret = random_get_bytes(key->zk_salt, ZIO_DATA_SALT_LEN);
	if (ret != 0)
		goto error;

	/* derive the current key from the master key */
	ret = hkdf_sha512(key->zk_master_keydata, keydata_len, NULL, 0,
	    key->zk_salt, ZIO_DATA_SALT_LEN, key->zk_current_keydata,
	    keydata_len);
	if (ret != 0)
		goto error;

	/* initialize keys for the ICP */
	key->zk_current_key.ck_format = CRYPTO_KEY_RAW;
	key->zk_current_key.ck_data = key->zk_current_keydata;
	key->zk_current_key.ck_length = BYTES_TO_BITS(keydata_len);

	key->zk_hmac_key.ck_format = CRYPTO_KEY_RAW;
	key->zk_hmac_key.ck_data = &key->zk_hmac_key;
	key->zk_hmac_key.ck_length = BYTES_TO_BITS(SHA512_HMAC_KEYLEN);

	/*
	 * Initialize the crypto templates. It's ok if this fails because
	 * this is just an optimization.
	 */
	mech.cm_type = crypto_mech2id(zio_crypt_table[crypt].ci_mechname);
	ret = crypto_create_ctx_template(&mech, &key->zk_current_key,
	    &key->zk_current_tmpl, KM_SLEEP);
	if (ret != CRYPTO_SUCCESS)
		key->zk_current_tmpl = NULL;

	mech.cm_type = crypto_mech2id(SUN_CKM_SHA512_HMAC);
	ret = crypto_create_ctx_template(&mech, &key->zk_hmac_key,
	    &key->zk_hmac_tmpl, KM_SLEEP);
	if (ret != CRYPTO_SUCCESS)
		key->zk_hmac_tmpl = NULL;

	key->zk_crypt = crypt;
	key->zk_salt_count = 0;
	rw_init(&key->zk_salt_lock, NULL, RW_DEFAULT, NULL);

	return (0);

error:
	zio_crypt_key_destroy(key);
	return (ret);
}

static int
zio_crypt_key_change_salt(zio_crypt_key_t *key)
{
	int ret;
	uint8_t salt[ZIO_DATA_SALT_LEN];
	crypto_mechanism_t mech;
	uint_t keydata_len = zio_crypt_table[key->zk_crypt].ci_keylen;

	/* generate a new salt */
	ret = random_get_bytes(salt, ZIO_DATA_SALT_LEN);
	if (ret != 0)
		goto error;

	rw_enter(&key->zk_salt_lock, RW_WRITER);

	/* derive the current key from the master key and the new salt */
	ret = hkdf_sha512(key->zk_master_keydata, keydata_len, NULL, 0,
	    salt, ZIO_DATA_SALT_LEN, key->zk_current_keydata, keydata_len);
	if (ret != 0)
		goto error_unlock;

	/* assign the salt and reset the usage count */
	bcopy(salt, key->zk_salt, ZIO_DATA_SALT_LEN);
	key->zk_salt_count = 0;

	/* destroy the old context template and create the new one */
	crypto_destroy_ctx_template(key->zk_current_tmpl);
	ret = crypto_create_ctx_template(&mech, &key->zk_current_key,
	    &key->zk_current_tmpl, KM_SLEEP);
	if (ret != CRYPTO_SUCCESS)
		key->zk_current_tmpl = NULL;

	rw_exit(&key->zk_salt_lock);

	return (0);

error_unlock:
	rw_exit(&key->zk_salt_lock);
error:
	return (ret);
}

/* See comment above ZIO_CRYPT_MAX_SALT_USAGE definition for details */
int
zio_crypt_key_get_salt(zio_crypt_key_t *key, uint8_t *salt)
{
	int ret;
	boolean_t salt_change;

	rw_enter(&key->zk_salt_lock, RW_READER);

	bcopy(key->zk_salt, salt, ZIO_DATA_SALT_LEN);
	salt_change = (atomic_inc_64_nv(&key->zk_salt_count) ==
	    ZIO_CRYPT_MAX_SALT_USAGE);

	rw_exit(&key->zk_salt_lock);

	if (salt_change) {
		ret = zio_crypt_key_change_salt(key);
		if (ret != 0)
			goto error;
	}

	return (0);

error:
	return (ret);
}

/*
 * This function handles all encryption and decryption in zfs. When
 * encrypting it expects puio to refernce the plaintext and cuio to
 * have enough space for the ciphertext + room for a MAC. On decrypting
 * it expects both puio and cuio to have enough room for a MAC, although
 * the plaintext uio can be dsicarded afterwards. datalen should be the
 * length of only the plaintext / ciphertext in either case.
 */
static int
zio_do_crypt_uio(boolean_t encrypt, uint64_t crypt, crypto_key_t *key,
    crypto_ctx_template_t tmpl, uint8_t *ivbuf, uint_t datalen,
    uio_t *puio, uio_t *cuio, uint8_t *authbuf, uint_t auth_len)
{
	int ret;
	crypto_data_t plaindata, cipherdata;
	CK_AES_CCM_PARAMS ccmp;
	CK_AES_GCM_PARAMS gcmp;
	crypto_mechanism_t mech;
	zio_crypt_info_t crypt_info;
	uint_t plain_full_len, maclen;

	ASSERT3U(crypt, <, ZIO_CRYPT_FUNCTIONS);
	ASSERT3U(key->ck_format, ==, CRYPTO_KEY_RAW);

	/* lookup the encryption info */
	crypt_info = zio_crypt_table[crypt];

	/* the mac will always be the last iovec_t in the cipher uio */
	maclen = cuio->uio_iov[cuio->uio_iovcnt - 1].iov_len;

	ASSERT(maclen <= ZIO_DATA_MAC_LEN);

	/* setup encryption mechanism (same as crypt) */
	mech.cm_type = crypto_mech2id(crypt_info.ci_mechname);

	/* plain length will include the MAC if we are decrypting */
	if (encrypt) {
		plain_full_len = datalen;
	} else {
		plain_full_len = datalen + maclen;
	}

	/*
	 * setup encryption params (currently only AES CCM and AES GCM
	 * are supported)
	 */
	if (crypt_info.ci_crypt_type == ZC_TYPE_CCM) {
		ccmp.ulNonceSize = ZIO_DATA_IV_LEN;
		ccmp.ulAuthDataSize = auth_len;
		ccmp.authData = authbuf;
		ccmp.ulMACSize = maclen;
		ccmp.nonce = ivbuf;
		ccmp.ulDataSize = plain_full_len;

		mech.cm_param = (char *)(&ccmp);
		mech.cm_param_len = sizeof (CK_AES_CCM_PARAMS);
	} else {
		gcmp.ulIvLen = ZIO_DATA_IV_LEN;
		gcmp.ulIvBits = BYTES_TO_BITS(ZIO_DATA_IV_LEN);
		gcmp.ulAADLen = auth_len;
		gcmp.pAAD = authbuf;
		gcmp.ulTagBits = BYTES_TO_BITS(maclen);
		gcmp.pIv = ivbuf;

		mech.cm_param = (char *)(&gcmp);
		mech.cm_param_len = sizeof (CK_AES_GCM_PARAMS);
	}

	/* populate the cipher and plain data structs. */
	plaindata.cd_format = CRYPTO_DATA_UIO;
	plaindata.cd_offset = 0;
	plaindata.cd_uio = puio;
	plaindata.cd_miscdata = NULL;
	plaindata.cd_length = plain_full_len;

	cipherdata.cd_format = CRYPTO_DATA_UIO;
	cipherdata.cd_offset = 0;
	cipherdata.cd_uio = cuio;
	cipherdata.cd_miscdata = NULL;
	cipherdata.cd_length = datalen + maclen;

	/* perform the actual encryption */
	if (encrypt) {
		ret = crypto_encrypt(&mech, &plaindata, key, tmpl, &cipherdata,
		    NULL);
	} else {
		ret = crypto_decrypt(&mech, &cipherdata, key, tmpl, &plaindata,
		    NULL);
	}

	if (ret != CRYPTO_SUCCESS) {
		ret = SET_ERROR(EIO);
		goto error;
	}

	return (0);

error:
	return (ret);
}

int
zio_crypt_key_wrap(crypto_key_t *cwkey, zio_crypt_key_t *key, uint8_t *iv,
    uint8_t *mac, uint8_t *keydata_out, uint8_t *hmac_keydata_out)
{
	int ret;
	uio_t puio, cuio;
	iovec_t plain_iovecs[2], cipher_iovecs[3];
	uint64_t crypt = key->zk_crypt;
	uint64_t le_guid = LE_64(key->zk_guid);
	uint_t enc_len, keydata_len;

	ASSERT3U(crypt, <, ZIO_CRYPT_FUNCTIONS);
	ASSERT3U(cwkey->ck_format, ==, CRYPTO_KEY_RAW);

	keydata_len = zio_crypt_table[crypt].ci_keylen;

	/* generate iv for wrapping the master and hmac key */
	ret = random_get_pseudo_bytes(iv, WRAPPING_IV_LEN);
	if (ret != 0)
		goto error;

	/* initialize uio_ts */
	plain_iovecs[0].iov_base = key->zk_master_keydata;
	plain_iovecs[0].iov_len = keydata_len;
	plain_iovecs[1].iov_base = key->zk_hmac_keydata;
	plain_iovecs[1].iov_len = SHA512_HMAC_KEYLEN;

	cipher_iovecs[0].iov_base = keydata_out;
	cipher_iovecs[0].iov_len = keydata_len;
	cipher_iovecs[1].iov_base = hmac_keydata_out;
	cipher_iovecs[1].iov_len = SHA512_HMAC_KEYLEN;
	cipher_iovecs[2].iov_base = mac;
	cipher_iovecs[2].iov_len = WRAPPING_MAC_LEN;

	enc_len = zio_crypt_table[crypt].ci_keylen + SHA512_HMAC_KEYLEN;
	puio.uio_iov = plain_iovecs;
	puio.uio_iovcnt = 2;
	puio.uio_segflg = UIO_SYSSPACE;
	cuio.uio_iov = cipher_iovecs;
	cuio.uio_iovcnt = 3;
	cuio.uio_segflg = UIO_SYSSPACE;

	/* encrypt the keys and store the resulting ciphertext and mac */
	ret = zio_do_crypt_uio(B_TRUE, crypt, cwkey, NULL, iv, enc_len,
	    &puio, &cuio, (uint8_t *)&le_guid, sizeof (uint64_t));
	if (ret != 0)
		goto error;

	return (0);

error:
	return (ret);
}

int
zio_crypt_key_unwrap(crypto_key_t *cwkey, uint64_t crypt, uint64_t guid,
    uint8_t *keydata, uint8_t *hmac_keydata, uint8_t *iv, uint8_t *mac,
    zio_crypt_key_t *key)
{
	int ret;
	crypto_mechanism_t mech;
	uio_t puio, cuio;
	iovec_t plain_iovecs[2], cipher_iovecs[3];
	uint_t enc_len, keydata_len;
	uint64_t le_guid = LE_64(guid);

	ASSERT3U(crypt, <, ZIO_CRYPT_FUNCTIONS);
	ASSERT3U(cwkey->ck_format, ==, CRYPTO_KEY_RAW);

	keydata_len = zio_crypt_table[crypt].ci_keylen;

	/* initialize uio_ts */
	plain_iovecs[0].iov_base = key->zk_master_keydata;
	plain_iovecs[0].iov_len = keydata_len;
	plain_iovecs[1].iov_base = key->zk_hmac_keydata;
	plain_iovecs[1].iov_len = SHA512_HMAC_KEYLEN;

	cipher_iovecs[0].iov_base = keydata;
	cipher_iovecs[0].iov_len = keydata_len;
	cipher_iovecs[1].iov_base = hmac_keydata;
	cipher_iovecs[1].iov_len = SHA512_HMAC_KEYLEN;
	cipher_iovecs[2].iov_base = mac;
	cipher_iovecs[2].iov_len = WRAPPING_MAC_LEN;

	enc_len = keydata_len + SHA512_HMAC_KEYLEN;
	puio.uio_iov = plain_iovecs;
	puio.uio_segflg = UIO_SYSSPACE;
	puio.uio_iovcnt = 2;
	cuio.uio_iov = cipher_iovecs;
	cuio.uio_iovcnt = 3;
	cuio.uio_segflg = UIO_SYSSPACE;

	/* decrypt the keys and store the result in the output buffers */
	ret = zio_do_crypt_uio(B_FALSE, crypt, cwkey, NULL, iv, enc_len,
	    &puio, &cuio, (uint8_t *)&le_guid, sizeof (uint64_t));
	if (ret != 0)
		goto error;

	/* generate a fresh salt */
	ret = random_get_bytes(key->zk_salt, ZIO_DATA_SALT_LEN);
	if (ret != 0)
		goto error;

	/* derive the current key from the master key */
	ret = hkdf_sha512(key->zk_master_keydata, keydata_len, NULL, 0,
	    key->zk_salt, ZIO_DATA_SALT_LEN, key->zk_current_keydata,
	    keydata_len);
	if (ret != 0)
		goto error;

	/* initialize keys for ICP */
	key->zk_current_key.ck_format = CRYPTO_KEY_RAW;
	key->zk_current_key.ck_data = key->zk_current_keydata;
	key->zk_current_key.ck_length = BYTES_TO_BITS(keydata_len);

	key->zk_hmac_key.ck_format = CRYPTO_KEY_RAW;
	key->zk_hmac_key.ck_data = key->zk_hmac_keydata;
	key->zk_hmac_key.ck_length = BYTES_TO_BITS(SHA512_HMAC_KEYLEN);

	/*
	 * Initialize the crypto templates. It's ok if this fails because
	 * this is just an optimization.
	 */
	mech.cm_type = crypto_mech2id(zio_crypt_table[crypt].ci_mechname);
	ret = crypto_create_ctx_template(&mech, &key->zk_current_key,
	    &key->zk_current_tmpl, KM_SLEEP);
	if (ret != CRYPTO_SUCCESS)
		key->zk_current_tmpl = NULL;

	mech.cm_type = crypto_mech2id(SUN_CKM_SHA512_HMAC);
	ret = crypto_create_ctx_template(&mech, &key->zk_hmac_key,
	    &key->zk_hmac_tmpl, KM_SLEEP);
	if (ret != CRYPTO_SUCCESS)
		key->zk_hmac_tmpl = NULL;

	key->zk_crypt = crypt;
	key->zk_guid = guid;
	key->zk_salt_count = 0;
	rw_init(&key->zk_salt_lock, NULL, RW_DEFAULT, NULL);

	return (0);

error:
	zio_crypt_key_destroy(key);
	return (ret);
}

int
zio_crypt_generate_iv(uint8_t *ivbuf)
{
	int ret;

	/* randomly generate the IV */
	ret = random_get_pseudo_bytes(ivbuf, ZIO_DATA_IV_LEN);
	if (ret != 0)
		goto error;

	return (0);

error:
	bzero(ivbuf, ZIO_DATA_IV_LEN);
	return (ret);
}

int
zio_crypt_do_hmac(zio_crypt_key_t *key, uint8_t *data, uint_t datalen,
    uint8_t *digestbuf)
{
	int ret;
	crypto_mechanism_t mech;
	crypto_data_t in_data, digest_data;
	uint8_t raw_digestbuf[SHA512_DIGEST_LENGTH];

	/* initialize sha512-hmac mechanism and crypto data */
	mech.cm_type = crypto_mech2id(SUN_CKM_SHA512_HMAC);
	mech.cm_param = NULL;
	mech.cm_param_len = 0;

	/* initialize the crypto data */
	in_data.cd_format = CRYPTO_DATA_RAW;
	in_data.cd_offset = 0;
	in_data.cd_length = datalen;
	in_data.cd_raw.iov_base = (char *)data;
	in_data.cd_raw.iov_len = in_data.cd_length;

	digest_data.cd_format = CRYPTO_DATA_RAW;
	digest_data.cd_offset = 0;
	digest_data.cd_length = SHA512_DIGEST_LENGTH;
	digest_data.cd_raw.iov_base = (char *)raw_digestbuf;
	digest_data.cd_raw.iov_len = digest_data.cd_length;

	/* generate the hmac */
	ret = crypto_mac(&mech, &in_data, &key->zk_hmac_key, key->zk_hmac_tmpl,
	    &digest_data, NULL);
	if (ret != CRYPTO_SUCCESS) {
		ret = SET_ERROR(EIO);
		goto error;
	}

	bcopy(raw_digestbuf, digestbuf, ZIO_DATA_MAC_LEN);

	return (0);

error:
	bzero(digestbuf, ZIO_DATA_MAC_LEN);
	return (ret);
}

int
zio_crypt_generate_iv_salt_dedup(zio_crypt_key_t *key, uint8_t *data,
    uint_t datalen, uint8_t *ivbuf, uint8_t *salt)
{
	int ret;
	uint8_t digestbuf[SHA512_DIGEST_LENGTH];

	ret = zio_crypt_do_hmac(key, data, datalen, digestbuf);
	if (ret != 0)
		return (ret);

	bcopy(digestbuf, salt, ZIO_DATA_SALT_LEN);
	bcopy(digestbuf + ZIO_DATA_SALT_LEN, ivbuf, ZIO_DATA_IV_LEN);

	return (0);
}

void
zio_crypt_encode_params_bp(blkptr_t *bp, uint8_t *salt, uint8_t *iv)
{
	uint32_t val32;

	ASSERT(BP_IS_ENCRYPTED(bp));

	bcopy(salt, &bp->blk_dva[2].dva_word[0], sizeof (uint64_t));
	bcopy(iv, &bp->blk_dva[2].dva_word[1], sizeof (uint64_t));
	bcopy(iv + sizeof (uint64_t), &val32, sizeof (uint32_t));
	BP_SET_IV2(bp, val32);
}

void
zio_crypt_decode_params_bp(const blkptr_t *bp, uint8_t *salt, uint8_t *iv)
{
	uint64_t val64;
	uint32_t val32;

	ASSERT(BP_IS_PROTECTED(bp));

	/* for convenience, so callers don't need to check */
	if (BP_IS_AUTHENTICATED(bp)) {
		bzero(salt, ZIO_DATA_SALT_LEN);
		bzero(iv, ZIO_DATA_IV_LEN);
		return;
	}

	if (!BP_SHOULD_BYTESWAP(bp)) {
		bcopy(&bp->blk_dva[2].dva_word[0], salt, sizeof (uint64_t));
		bcopy(&bp->blk_dva[2].dva_word[1], iv, sizeof (uint64_t));

		val32 = (uint32_t)BP_GET_IV2(bp);
		bcopy(&val32, iv + sizeof (uint64_t), sizeof (uint32_t));
	} else {
		val64 = BSWAP_64(bp->blk_dva[2].dva_word[0]);
		bcopy(&val64, salt, sizeof (uint64_t));

		val64 = BSWAP_64(bp->blk_dva[2].dva_word[1]);
		bcopy(&val64, iv, sizeof (uint64_t));

		val32 = BSWAP_32((uint32_t)BP_GET_IV2(bp));
		bcopy(&val32, iv + sizeof (uint64_t), sizeof (uint32_t));
	}
}

void
zio_crypt_encode_mac_bp(blkptr_t *bp, uint8_t *mac)
{
	ASSERT(BP_USES_CRYPT(bp));
	ASSERT3U(BP_GET_TYPE(bp), !=, DMU_OT_OBJSET);

	bcopy(mac, &bp->blk_cksum.zc_word[2], sizeof (uint64_t));
	bcopy(mac + sizeof (uint64_t), &bp->blk_cksum.zc_word[3],
	    sizeof (uint64_t));
}

void
zio_crypt_decode_mac_bp(const blkptr_t *bp, uint8_t *mac)
{
	uint64_t val64;

	ASSERT(BP_USES_CRYPT(bp) || BP_IS_HOLE(bp));

	/* for convenience, so callers don't need to check */
	if (BP_GET_TYPE(bp) == DMU_OT_OBJSET) {
		bzero(mac, ZIO_DATA_MAC_LEN);
		return;
	}

	if (!BP_SHOULD_BYTESWAP(bp)) {
		bcopy(&bp->blk_cksum.zc_word[2], mac, sizeof (uint64_t));
		bcopy(&bp->blk_cksum.zc_word[3], mac + sizeof (uint64_t),
		    sizeof (uint64_t));
	} else {
		val64 = BSWAP_64(bp->blk_cksum.zc_word[2]);
		bcopy(&val64, mac, sizeof (uint64_t));

		val64 = BSWAP_64(bp->blk_cksum.zc_word[3]);
		bcopy(&val64, mac + sizeof (uint64_t), sizeof (uint64_t));
	}
}

void
zio_crypt_encode_mac_zil(void *data, uint8_t *mac)
{
	zil_chain_t *zilc = data;

	bcopy(mac, &zilc->zc_eck.zec_cksum.zc_word[2], sizeof (uint64_t));
	bcopy(mac + sizeof (uint64_t), &zilc->zc_eck.zec_cksum.zc_word[3],
	    sizeof (uint64_t));
}

void
zio_crypt_decode_mac_zil(const void *data, uint8_t *mac)
{
	/*
	 * The ZIL MAC is embedded in the block it protects, which will
	 * not have been byteswapped by the time this function has been called.
	 * As a result, we don't need to worry about byteswapping the MAC.
	 */
	const zil_chain_t *zilc = data;

	bcopy(&zilc->zc_eck.zec_cksum.zc_word[2], mac, sizeof (uint64_t));
	bcopy(&zilc->zc_eck.zec_cksum.zc_word[3], mac + sizeof (uint64_t),
	    sizeof (uint64_t));
}

/*
 * This function is modeled off of zio_crypt_init_uios_dnode(). This function,
 * however, copies bonus buffers instead of parsing them into a uio_t.
 */
void
zio_crypt_copy_dnode_bonus(void *src_data, uint8_t *dst, uint_t datalen)
{
	uint_t i, max_dnp = datalen >> DNODE_SHIFT;
	uint8_t *src;
	dnode_phys_t *dnp, *sdnp, *ddnp;

	src = kmem_alloc(datalen, KM_SLEEP);
	bcopy(src_data, src, datalen);

	sdnp = (dnode_phys_t *)src;
	ddnp = (dnode_phys_t *)dst;

	for (i = 0; i < max_dnp; i += sdnp[i].dn_extra_slots + 1) {
		dnp = &sdnp[i];
		if (dnp->dn_type != DMU_OT_NONE &&
		    DMU_OT_IS_ENCRYPTED(dnp->dn_bonustype) &&
		    dnp->dn_bonuslen != 0) {
			bcopy(DN_BONUS(dnp), DN_BONUS(&ddnp[i]),
			    DN_MAX_BONUS_LEN(dnp));
		}
	}

	kmem_free(src, datalen);
}

static int
zio_crypt_do_dnode_hmac_updates(crypto_context_t ctx, boolean_t byteswap,
    dnode_phys_t *dnp)
{
	int ret, i;
	dnode_phys_t *adnp;
	blkptr_t *curr_bp, *bp;
	blkptr_t tmpbp;
	boolean_t need_bswap = (byteswap ^ !ZFS_HOST_BYTEORDER);
	uint64_t blkprop;
	crypto_data_t cd;
	uint8_t tmp_dncore[offsetof(dnode_phys_t, dn_blkptr)];
	uint8_t mac[ZIO_DATA_MAC_LEN];

	cd.cd_format = CRYPTO_DATA_RAW;
	cd.cd_offset = 0;

	/* authenticate the core dnode (masking out non-portable bits) */
	bcopy(dnp, tmp_dncore, sizeof (tmp_dncore));
	adnp = (dnode_phys_t *)tmp_dncore;
	if (need_bswap) {
		adnp->dn_datablkszsec = BSWAP_16(adnp->dn_datablkszsec);
		adnp->dn_bonuslen = BSWAP_16(adnp->dn_bonuslen);
		adnp->dn_maxblkid = BSWAP_64(adnp->dn_maxblkid);
		adnp->dn_used = BSWAP_64(adnp->dn_used);
	}
	adnp->dn_flags &= DNODE_CRYPT_PORTABLE_FLAGS_MASK;
	adnp->dn_used = 0;

	cd.cd_length = sizeof (tmp_dncore);
	cd.cd_raw.iov_base = (char *)adnp;
	cd.cd_raw.iov_len = cd.cd_length;

	ret = crypto_mac_update(ctx, &cd, NULL);
	if (ret != CRYPTO_SUCCESS) {
		ret = SET_ERROR(EIO);
		goto error;
	}

	for (i = 0; i < dnp->dn_nblkptr + 1; i++) {
		if (i < dnp->dn_nblkptr) {
			curr_bp = &dnp->dn_blkptr[i];
		} else if (dnp->dn_flags & DNODE_FLAG_SPILL_BLKPTR) {
			curr_bp = DN_SPILL_BLKPTR(dnp);
		} else {
			break;
		}

		if (byteswap) {
			tmpbp = *curr_bp;
			byteswap_uint64_array(&tmpbp, sizeof (blkptr_t));
			bp = &tmpbp;
		} else {
			bp = curr_bp;
		}

		blkprop = bp->blk_prop;
		BF64_SET(blkprop, 62, 1, 0);
		BF64_SET(blkprop, 40, 8, 0);
		BF64_SET(blkprop, 16, 16, 0);
		if (byteswap ^ need_bswap)
			blkprop = BSWAP_64(blkprop);

		cd.cd_length = sizeof (uint64_t);
		cd.cd_raw.iov_base = (char *)&blkprop;
		cd.cd_raw.iov_len = cd.cd_length;

		ret = crypto_mac_update(ctx, &cd, NULL);
		if (ret != CRYPTO_SUCCESS) {
			ret = SET_ERROR(EIO);
			goto error;
		}

		zio_crypt_decode_mac_bp(bp, mac);
		cd.cd_length = ZIO_DATA_MAC_LEN;
		cd.cd_raw.iov_base = (char *)mac;
		cd.cd_raw.iov_len = cd.cd_length;

		ret = crypto_mac_update(ctx, &cd, NULL);
		if (ret != CRYPTO_SUCCESS) {
			ret = SET_ERROR(EIO);
			goto error;
		}
	}

	return (0);

error:
	return (ret);
}

/*
 * objset_phys_t blocks introduce a number of exceptions to the normal
 * authentication process. objset_phys_t's contain 2 seperate HMACS for
 * protecting the integrity of their data. The portable_mac protects the
 * the metadnode. This MAC can be sent with a raw send and protects against
 * reordering of data within the metadnode. The local_mac protects the the
 * user accounting objects which are not sent from one system to another.
 *
 * In addition, objset blocks are the only blocks that can be modified and
 * written to disk without the key loaded under certain circumstances. During
 * zil_claim() we need to be able to update the zil_header_t to complete
 * claiming log blocks and during raw receives we need to write out the
 * portable_mac from the send file. Both of these actions are possible
 * because these fields are not protected by either MAC so neither one will
 * need to modify the MACs without the key. However, when the modified blocks
 * are written out they will be byteswapped into the host machine's native
 * endianness which will modify fields protected by the MAC. As a result, MAC
 * calculation for objset blocks works slightly differently from other block
 * types. Where other block types MAC the data in whatever endianness is
 * written to disk, objset blocks always work on little endian values.
 */
int
zio_crypt_do_objset_hmacs(zio_crypt_key_t *key, void *data, uint_t datalen,
    boolean_t byteswap, uint8_t *portable_mac, uint8_t *local_mac)
{
	int ret;
	crypto_mechanism_t mech;
	crypto_context_t ctx;
	crypto_data_t cd;
	objset_phys_t *osp = data;
	uint64_t intval;
	boolean_t need_bswap = (byteswap ^ !ZFS_HOST_BYTEORDER);
	uint8_t raw_portable_mac[SHA512_DIGEST_LENGTH];
	uint8_t raw_local_mac[SHA512_DIGEST_LENGTH];

	/* initialize sha 256 hmac mechanism */
	mech.cm_type = crypto_mech2id(SUN_CKM_SHA512_HMAC);
	mech.cm_param = NULL;
	mech.cm_param_len = 0;

	cd.cd_format = CRYPTO_DATA_RAW;
	cd.cd_offset = 0;

	/* calculate the portable MAC from the portable fields and metadnode */
	ret = crypto_mac_init(&mech, &key->zk_hmac_key, NULL, &ctx, NULL);
	if (ret != CRYPTO_SUCCESS) {
		ret = SET_ERROR(EIO);
		goto error;
	}

	/* add in the os_type */
	intval = (need_bswap) ? osp->os_type : BSWAP_64(osp->os_type);
	cd.cd_length = sizeof (uint64_t);
	cd.cd_raw.iov_base = (char *)&intval;
	cd.cd_raw.iov_len = cd.cd_length;

	ret = crypto_mac_update(ctx, &cd, NULL);
	if (ret != CRYPTO_SUCCESS) {
		ret = SET_ERROR(EIO);
		goto error;
	}

	/* add in the portable os_flags */
	intval = osp->os_flags;
	if (byteswap)
		intval = BSWAP_64(intval);
	intval &= OBJSET_CRYPT_PORTABLE_FLAGS_MASK;
	if (byteswap ^ need_bswap)
		intval = BSWAP_64(intval);

	cd.cd_length = sizeof (uint64_t);
	cd.cd_raw.iov_base = (char *)&intval;
	cd.cd_raw.iov_len = cd.cd_length;

	ret = crypto_mac_update(ctx, &cd, NULL);
	if (ret != CRYPTO_SUCCESS) {
		ret = SET_ERROR(EIO);
		goto error;
	}

	/* add in fields from the metadnode */
	ret = zio_crypt_do_dnode_hmac_updates(ctx, byteswap,
	    &osp->os_meta_dnode);
	if (ret)
		goto error;

	/* store the final digest in a temporary buffer and copy what we need */
	cd.cd_length = SHA512_DIGEST_LENGTH;
	cd.cd_raw.iov_base = (char *)raw_portable_mac;
	cd.cd_raw.iov_len = cd.cd_length;

	ret = crypto_mac_final(ctx, &cd, NULL);
	if (ret != CRYPTO_SUCCESS) {
		ret = SET_ERROR(EIO);
		goto error;
	}

	bcopy(raw_portable_mac, portable_mac, ZIO_OBJSET_MAC_LEN);

	/*
	 * The local MAC protects the user and group accounting. If these
	 * objects are not present, the local MAC is zeroed out.
	 */
	if (osp->os_userused_dnode.dn_type == DMU_OT_NONE &&
	    osp->os_userused_dnode.dn_type == DMU_OT_NONE) {
		bzero(local_mac, ZIO_OBJSET_MAC_LEN);
		return (0);
	}

	/* calculate the local MAC from the userused and groupused dnodes */
	ret = crypto_mac_init(&mech, &key->zk_hmac_key, NULL, &ctx, NULL);
	if (ret != CRYPTO_SUCCESS) {
		ret = SET_ERROR(EIO);
		goto error;
	}

	/* add in the non-portable os_flags */
	intval = osp->os_flags;
	if (byteswap)
		intval = BSWAP_64(intval);
	intval &= ~OBJSET_CRYPT_PORTABLE_FLAGS_MASK;
	if (byteswap ^ need_bswap)
		intval = BSWAP_64(intval);

	cd.cd_length = sizeof (uint64_t);
	cd.cd_raw.iov_base = (char *)&intval;
	cd.cd_raw.iov_len = cd.cd_length;

	ret = crypto_mac_update(ctx, &cd, NULL);
	if (ret != CRYPTO_SUCCESS) {
		ret = SET_ERROR(EIO);
		goto error;
	}

	/* add in fields from the user accounting dnodes */
	ret = zio_crypt_do_dnode_hmac_updates(ctx, byteswap,
	    &osp->os_userused_dnode);
	if (ret)
		goto error;

	ret = zio_crypt_do_dnode_hmac_updates(ctx, byteswap,
	    &osp->os_groupused_dnode);
	if (ret)
		goto error;

	/* store the final digest in a temporary buffer and copy what we need */
	cd.cd_length = SHA512_DIGEST_LENGTH;
	cd.cd_raw.iov_base = (char *)raw_local_mac;
	cd.cd_raw.iov_len = cd.cd_length;

	ret = crypto_mac_final(ctx, &cd, NULL);
	if (ret != CRYPTO_SUCCESS) {
		ret = SET_ERROR(EIO);
		goto error;
	}

	bcopy(raw_local_mac, local_mac, ZIO_OBJSET_MAC_LEN);

	return (0);

error:
	bzero(portable_mac, ZIO_OBJSET_MAC_LEN);
	bzero(local_mac, ZIO_OBJSET_MAC_LEN);
	return (ret);
}

static void
zio_crypt_destroy_uio(uio_t *uio)
{
	if (uio->uio_iov)
		kmem_free(uio->uio_iov, uio->uio_iovcnt * sizeof (iovec_t));
}

int
zio_crypt_do_indirect_mac_checksum(boolean_t generate, void *buf,
    uint_t datalen, boolean_t byteswap, uint8_t *cksum)
{
	blkptr_t *bp, *curr_bp;
	int i, epb = datalen >> SPA_BLKPTRSHIFT;
	uint64_t blkprop;
	SHA512_CTX ctx;
	blkptr_t tmpbp;
	uint8_t digestbuf[SHA512_DIGEST_LENGTH];
	uint8_t mac[ZIO_DATA_MAC_LEN];

	/* checksum all of the MACs from the layer below */
	SHA512_Init(&ctx);
	for (i = 0, curr_bp = buf; i < epb; i++, curr_bp++) {
		if (byteswap) {
			tmpbp = *curr_bp;
			byteswap_uint64_array(&tmpbp, sizeof (blkptr_t));
			bp = &tmpbp;
		} else {
			bp = curr_bp;
		}

		ASSERT(BP_USES_CRYPT(bp) || BP_IS_HOLE(bp));
		ASSERT0(BP_IS_EMBEDDED(bp));

		/*
		 * The top level objset MAC protects all the checksums of all
		 * MACs below. It also protects everything in blk_prop except
		 * for the checksum, dedup, and psize bits.
		 */
		blkprop = bp->blk_prop;
		BF64_SET(blkprop, 62, 1, 0);
		BF64_SET(blkprop, 40, 8, 0);
		BF64_SET(blkprop, 16, 16, 0);
		if (byteswap)
			blkprop = BSWAP_64(blkprop);
		SHA512_Update(&ctx, &blkprop, sizeof (uint64_t));

		zio_crypt_decode_mac_bp(bp, mac);
		SHA512_Update(&ctx, mac, ZIO_DATA_MAC_LEN);
	}
	SHA512_Final(digestbuf, &ctx);

	if (generate) {
		bcopy(digestbuf, cksum, ZIO_DATA_MAC_LEN);
		return (0);
	}

	if (bcmp(digestbuf, cksum, ZIO_DATA_MAC_LEN) != 0)
		return (SET_ERROR(ECKSUM));

	return (0);
}

int
zio_crypt_do_indirect_mac_checksum_data(boolean_t generate, void *data,
    uint_t datalen, boolean_t byteswap, uint8_t *cksum)
{

	int ret;

	ret = zio_crypt_do_indirect_mac_checksum(generate, data, datalen,
	    byteswap, cksum);
	return (ret);
}

/*
 * We do not check for the older zil chain because this feature was not
 * available before the newer zil chain was introduced. The goal here
 * is to encrypt everything except the blkptr_t of a lr_write_t and
 * the zil_chain_t header.
 */
static int
zio_crypt_init_uios_zil(boolean_t encrypt, uint8_t *plainbuf,
    uint8_t *cipherbuf, uint_t datalen, boolean_t byteswap, uio_t *puio,
    uio_t *cuio, uint_t *enc_len, uint8_t **authbuf, uint_t *auth_len,
    boolean_t *no_crypt)
{
	int ret;
	uint64_t txtype;
	uint_t nr_src, nr_dst, lr_len, crypt_len;
	uint_t aad_len = 0, nr_iovecs = 0, total_len = 0;
	iovec_t *src_iovecs = NULL, *dst_iovecs = NULL;
	uint8_t *src, *dst, *slrp, *dlrp, *blkend, *aadp;
	zil_chain_t *zilc;
	lr_t *lr;
	uint8_t *aadbuf = zio_buf_alloc(datalen);

	/* if we are decrypting, the plainbuffer needs an extra iovec */
	if (encrypt) {
		src = plainbuf;
		dst = cipherbuf;
		nr_src = 0;
		nr_dst = 1;
	} else {
		src = cipherbuf;
		dst = plainbuf;
		nr_src = 1;
		nr_dst = 0;
	}

	/* find the start and end record of the log block */
	zilc = (zil_chain_t *)src;
	slrp = src + sizeof (zil_chain_t);
	aadp = aadbuf;
	blkend = src + ((byteswap) ? BSWAP_64(zilc->zc_nused) : zilc->zc_nused);

	/* calculate the number of encrypted iovecs we will need */
	for (; slrp < blkend; slrp += lr_len) {
		lr = (lr_t *)slrp;

		if (!byteswap) {
			txtype = lr->lrc_txtype;
			lr_len = lr->lrc_reclen;
		} else {
			txtype = BSWAP_64(lr->lrc_txtype);
			lr_len = BSWAP_64(lr->lrc_reclen);
		}

		nr_iovecs++;
		if (txtype == TX_WRITE && lr_len != sizeof (lr_write_t))
			nr_iovecs++;
	}

	nr_src += nr_iovecs;
	nr_dst += nr_iovecs;

	/* allocate the iovec arrays */
	if (nr_src != 0) {
		src_iovecs = kmem_alloc(nr_src * sizeof (iovec_t), KM_SLEEP);
		if (!src_iovecs) {
			ret = SET_ERROR(ENOMEM);
			goto error;
		}
	}

	if (nr_dst != 0) {
		dst_iovecs = kmem_alloc(nr_dst * sizeof (iovec_t), KM_SLEEP);
		if (!dst_iovecs) {
			ret = SET_ERROR(ENOMEM);
			goto error;
		}
	}

	/*
	 * Copy the plain zil header over and authenticate everything except
	 * the checksum that will store our MAC. If we are writing the data
	 * the embedded checksum will not have been calculated yet, so we don't
	 * authenticate that.
	 */
	bcopy(src, dst, sizeof (zil_chain_t));
	bcopy(src, aadp, sizeof (zil_chain_t) - sizeof (zio_eck_t));
	aadp += sizeof (zil_chain_t) - sizeof (zio_eck_t);
	aad_len += sizeof (zil_chain_t) - sizeof (zio_eck_t);

	/* loop over records again, filling in iovecs */
	nr_iovecs = 0;
	slrp = src + sizeof (zil_chain_t);
	dlrp = dst + sizeof (zil_chain_t);

	for (; slrp < blkend; slrp += lr_len, dlrp += lr_len) {
		lr = (lr_t *)slrp;

		if (!byteswap) {
			txtype = lr->lrc_txtype;
			lr_len = lr->lrc_reclen;
		} else {
			txtype = BSWAP_64(lr->lrc_txtype);
			lr_len = BSWAP_64(lr->lrc_reclen);
		}

		/* copy the common lr_t */
		bcopy(slrp, dlrp, sizeof (lr_t));
		bcopy(slrp, aadp, sizeof (lr_t));
		aadp += sizeof (lr_t);
		aad_len += sizeof (lr_t);

		if (txtype == TX_WRITE) {
			crypt_len = sizeof (lr_write_t) -
			    sizeof (lr_t) - sizeof (blkptr_t);
			src_iovecs[nr_iovecs].iov_base = slrp + sizeof (lr_t);
			src_iovecs[nr_iovecs].iov_len = crypt_len;
			dst_iovecs[nr_iovecs].iov_base = dlrp + sizeof (lr_t);
			dst_iovecs[nr_iovecs].iov_len = crypt_len;

			/* copy the bp now since it will not be encrypted */
			bcopy(slrp + sizeof (lr_write_t) - sizeof (blkptr_t),
			    dlrp + sizeof (lr_write_t) - sizeof (blkptr_t),
			    sizeof (blkptr_t));
			bcopy(slrp + sizeof (lr_write_t) - sizeof (blkptr_t),
			    aadp, sizeof (blkptr_t));
			aadp += sizeof (blkptr_t);
			aad_len += sizeof (blkptr_t);
			nr_iovecs++;
			total_len += crypt_len;

			if (lr_len != sizeof (lr_write_t)) {
				crypt_len = lr_len - sizeof (lr_write_t);
				src_iovecs[nr_iovecs].iov_base =
				    slrp + sizeof (lr_write_t);
				src_iovecs[nr_iovecs].iov_len = crypt_len;
				dst_iovecs[nr_iovecs].iov_base =
				    dlrp + sizeof (lr_write_t);
				dst_iovecs[nr_iovecs].iov_len = crypt_len;
				nr_iovecs++;
				total_len += crypt_len;
			}
		} else {
			crypt_len = lr_len - sizeof (lr_t);
			src_iovecs[nr_iovecs].iov_base = slrp + sizeof (lr_t);
			src_iovecs[nr_iovecs].iov_len = crypt_len;
			dst_iovecs[nr_iovecs].iov_base = dlrp + sizeof (lr_t);
			dst_iovecs[nr_iovecs].iov_len = crypt_len;
			nr_iovecs++;
			total_len += crypt_len;
		}
	}

	*no_crypt = (nr_iovecs == 0);
	*enc_len = total_len;
	*authbuf = aadbuf;
	*auth_len = aad_len;

	if (encrypt) {
		puio->uio_iov = src_iovecs;
		puio->uio_iovcnt = nr_src;
		cuio->uio_iov = dst_iovecs;
		cuio->uio_iovcnt = nr_dst;
	} else {
		puio->uio_iov = dst_iovecs;
		puio->uio_iovcnt = nr_dst;
		cuio->uio_iov = src_iovecs;
		cuio->uio_iovcnt = nr_src;
	}

	return (0);

error:
	zio_buf_free(aadbuf, datalen);
	if (src_iovecs != NULL)
		kmem_free(src_iovecs, nr_src * sizeof (iovec_t));
	if (dst_iovecs != NULL)
		kmem_free(dst_iovecs, nr_dst * sizeof (iovec_t));

	*enc_len = 0;
	*authbuf = NULL;
	*auth_len = 0;
	*no_crypt = B_FALSE;
	puio->uio_iov = NULL;
	puio->uio_iovcnt = 0;
	cuio->uio_iov = NULL;
	cuio->uio_iovcnt = 0;
	return (ret);
}

static int
zio_crypt_init_uios_dnode(boolean_t encrypt, uint8_t *plainbuf,
    uint8_t *cipherbuf, uint_t datalen, boolean_t byteswap, uio_t *puio,
    uio_t *cuio, uint_t *enc_len, uint8_t **authbuf, uint_t *auth_len,
    boolean_t *no_crypt)
{
	int ret;
	blkptr_t *curr_bp, *bp;
	blkptr_t tmpbp;
	uint64_t blkprop;
	uint_t nr_src, nr_dst, crypt_len;
	uint_t aad_len = 0, nr_iovecs = 0, total_len = 0;
	uint_t i, j, max_dnp = datalen >> DNODE_SHIFT;
	iovec_t *src_iovecs = NULL, *dst_iovecs = NULL;
	uint8_t *src, *dst, *bonus, *bonus_end, *dn_end, *aadp;
	dnode_phys_t *dnp, *adnp, *sdnp, *ddnp;
	uint8_t *aadbuf = zio_buf_alloc(datalen);
	uint8_t mac[ZIO_DATA_MAC_LEN];

	if (encrypt) {
		src = plainbuf;
		dst = cipherbuf;
		nr_src = 0;
		nr_dst = 1;
	} else {
		src = cipherbuf;
		dst = plainbuf;
		nr_src = 1;
		nr_dst = 0;
	}

	sdnp = (dnode_phys_t *)src;
	ddnp = (dnode_phys_t *)dst;
	aadp = aadbuf;

	for (i = 0; i < max_dnp; i += sdnp[i].dn_extra_slots + 1) {
		/*
		 * This block may still be byteswapped. However, all of the
		 * values we use are either uint8_t's (for which byteswapping
		 * is a noop) or a * != 0 check, which will work regardless
		 * of whether or not we byteswap.
		 */
		if (sdnp[i].dn_type != DMU_OT_NONE &&
		    DMU_OT_IS_ENCRYPTED(sdnp[i].dn_bonustype) &&
		    sdnp[i].dn_bonuslen != 0) {
			nr_iovecs++;
		}
	}

	nr_src += nr_iovecs;
	nr_dst += nr_iovecs;

	if (nr_src != 0) {
		src_iovecs = kmem_alloc(nr_src * sizeof (iovec_t), KM_SLEEP);
		if (!src_iovecs) {
			ret = SET_ERROR(ENOMEM);
			goto error;
		}
	}

	if (nr_dst != 0) {
		dst_iovecs = kmem_alloc(nr_dst * sizeof (iovec_t), KM_SLEEP);
		if (!dst_iovecs) {
			ret = SET_ERROR(ENOMEM);
			goto error;
		}
	}

	nr_iovecs = 0;

	for (i = 0; i < max_dnp; i += sdnp[i].dn_extra_slots + 1) {
		dnp = &sdnp[i];
		dn_end = (uint8_t *)(dnp + (dnp->dn_extra_slots + 1));

		/*
		 * Copy everything from the dource to the destination.
		 * Wherever we find an encrypted bonus buffer type, we prepare
		 * an iovec_t instead. The encryption / decryption functions
		 * will replace fill this in for us with the encrypted or
		 * decrypted data
		 */
		if (dnp->dn_type != DMU_OT_NONE &&
		    DMU_OT_IS_ENCRYPTED(dnp->dn_bonustype) &&
		    dnp->dn_bonuslen != 0) {
			bonus = (uint8_t *)DN_BONUS(dnp);
			if (dnp->dn_flags & DNODE_FLAG_SPILL_BLKPTR) {
				bonus_end = (uint8_t *)DN_SPILL_BLKPTR(dnp);
			} else {
				bonus_end = (uint8_t *)dn_end;
			}
			crypt_len = bonus_end - bonus;

			bcopy(dnp, &ddnp[i], bonus - (uint8_t *)dnp);
			src_iovecs[nr_iovecs].iov_base = bonus;
			src_iovecs[nr_iovecs].iov_len = crypt_len;
			dst_iovecs[nr_iovecs].iov_base = DN_BONUS(&ddnp[i]);
			dst_iovecs[nr_iovecs].iov_len = crypt_len;

			if (dnp->dn_flags & DNODE_FLAG_SPILL_BLKPTR) {
				bcopy(bonus_end, DN_SPILL_BLKPTR(&ddnp[i]),
				    sizeof (blkptr_t));
			}

			nr_iovecs++;
			total_len += crypt_len;
		} else {
			bcopy(dnp, &ddnp[i], dn_end - (uint8_t *)dnp);
		}

		/*
		 * Handle authenticated data. We authenticate everything in
		 * the dnode that can be brought over when we do a raw send.
		 * This includes all of the core fields as well as the MACs
		 * stored in the bp checksums. We also include the padding
		 * here in case it ever gets used in the future. Some of
		 * dn_flags and dn_used are not portable so we mask those out.
		 */
		crypt_len = offsetof(dnode_phys_t, dn_blkptr);
		bcopy(dnp, aadp, crypt_len);
		adnp = (dnode_phys_t *)aadp;
		adnp->dn_flags &= DNODE_CRYPT_PORTABLE_FLAGS_MASK;
		adnp->dn_used = 0;
		aadp += crypt_len;
		aad_len += crypt_len;

		for (j = 0; j < dnp->dn_nblkptr + 1; j++) {
			if (j < dnp->dn_nblkptr) {
				curr_bp = &dnp->dn_blkptr[j];
			} else if (dnp->dn_flags & DNODE_FLAG_SPILL_BLKPTR) {
				curr_bp = DN_SPILL_BLKPTR(dnp);
			} else {
				break;
			}

			if (byteswap) {
				tmpbp = *curr_bp;
				byteswap_uint64_array(&tmpbp,
				    sizeof (blkptr_t));
				bp = &tmpbp;
			} else {
				bp = curr_bp;
			}

			blkprop = bp->blk_prop;
			BF64_SET(blkprop, 62, 1, 0);
			BF64_SET(blkprop, 40, 8, 0);
			BF64_SET(blkprop, 16, 16, 0);
			if (byteswap)
				blkprop = BSWAP_64(blkprop);

			crypt_len = sizeof (uint64_t);
			bcopy(&blkprop, aadp, crypt_len);
			aadp += crypt_len;
			aad_len += crypt_len;

			zio_crypt_decode_mac_bp(bp, mac);
			crypt_len = ZIO_DATA_MAC_LEN;
			bcopy(mac, aadp, crypt_len);
			aadp += crypt_len;
			aad_len += crypt_len;
		}
	}

	*no_crypt = (nr_iovecs == 0);
	*enc_len = total_len;
	*authbuf = aadbuf;
	*auth_len = aad_len;

	if (encrypt) {
		puio->uio_iov = src_iovecs;
		puio->uio_iovcnt = nr_src;
		cuio->uio_iov = dst_iovecs;
		cuio->uio_iovcnt = nr_dst;
	} else {
		puio->uio_iov = dst_iovecs;
		puio->uio_iovcnt = nr_dst;
		cuio->uio_iov = src_iovecs;
		cuio->uio_iovcnt = nr_src;
	}

	return (0);

error:
	zio_buf_free(aadbuf, datalen);
	if (src_iovecs != NULL)
		kmem_free(src_iovecs, nr_src * sizeof (iovec_t));
	if (dst_iovecs != NULL)
		kmem_free(dst_iovecs, nr_dst * sizeof (iovec_t));

	*enc_len = 0;
	*authbuf = NULL;
	*auth_len = 0;
	*no_crypt = B_FALSE;
	puio->uio_iov = NULL;
	puio->uio_iovcnt = 0;
	cuio->uio_iov = NULL;
	cuio->uio_iovcnt = 0;
	return (ret);
}

static int
zio_crypt_init_uios_normal(boolean_t encrypt, uint8_t *plainbuf,
    uint8_t *cipherbuf, uint_t datalen, uio_t *puio, uio_t *cuio,
    uint_t *enc_len)
{
	int ret;
	uint_t nr_plain = 1, nr_cipher = 2;
	iovec_t *plain_iovecs = NULL, *cipher_iovecs = NULL;

	/* allocate the iovecs for the plain and cipher data */
	plain_iovecs = kmem_alloc(nr_plain * sizeof (iovec_t),
	    KM_SLEEP);
	if (!plain_iovecs) {
		ret = SET_ERROR(ENOMEM);
		goto error;
	}

	cipher_iovecs = kmem_alloc(nr_cipher * sizeof (iovec_t),
	    KM_SLEEP);
	if (!cipher_iovecs) {
		ret = SET_ERROR(ENOMEM);
		goto error;
	}

	plain_iovecs[0].iov_base = plainbuf;
	plain_iovecs[0].iov_len = datalen;
	cipher_iovecs[0].iov_base = cipherbuf;
	cipher_iovecs[0].iov_len = datalen;

	*enc_len = datalen;
	puio->uio_iov = plain_iovecs;
	puio->uio_iovcnt = nr_plain;
	cuio->uio_iov = cipher_iovecs;
	cuio->uio_iovcnt = nr_cipher;

	return (0);

error:
	if (plain_iovecs != NULL)
		kmem_free(plain_iovecs, nr_plain * sizeof (iovec_t));
	if (cipher_iovecs != NULL)
		kmem_free(cipher_iovecs, nr_cipher * sizeof (iovec_t));

	*enc_len = 0;
	puio->uio_iov = NULL;
	puio->uio_iovcnt = 0;
	cuio->uio_iov = NULL;
	cuio->uio_iovcnt = 0;
	return (ret);
}

static int
zio_crypt_init_uios(boolean_t encrypt, dmu_object_type_t ot, uint8_t *plainbuf,
    uint8_t *cipherbuf, uint_t datalen, boolean_t byteswap, uint8_t *mac,
    uio_t *puio, uio_t *cuio, uint_t *enc_len, uint8_t **authbuf,
    uint_t *auth_len, boolean_t *no_crypt)
{
	int ret;
	iovec_t *mac_iov;

	ASSERT(DMU_OT_IS_ENCRYPTED(ot) || ot == DMU_OT_NONE);

	/* route to handler */
	switch (ot) {
	case DMU_OT_INTENT_LOG:
		ret = zio_crypt_init_uios_zil(encrypt, plainbuf, cipherbuf,
		    datalen, byteswap, puio, cuio, enc_len, authbuf, auth_len,
		    no_crypt);
		break;
	case DMU_OT_DNODE:
		ret = zio_crypt_init_uios_dnode(encrypt, plainbuf, cipherbuf,
		    datalen, byteswap, puio, cuio, enc_len, authbuf, auth_len,
		    no_crypt);
		break;
	default:
		ret = zio_crypt_init_uios_normal(encrypt, plainbuf, cipherbuf,
		    datalen, puio, cuio, enc_len);
		*authbuf = NULL;
		*auth_len = 0;
		*no_crypt = B_FALSE;
		break;
	}

	if (ret != 0)
		goto error;

	/* populate the uios */
	puio->uio_segflg = UIO_SYSSPACE;
	cuio->uio_segflg = UIO_SYSSPACE;

	mac_iov = ((iovec_t *)&cuio->uio_iov[cuio->uio_iovcnt - 1]);
	mac_iov->iov_base = mac;
	mac_iov->iov_len = ZIO_DATA_MAC_LEN;

	return (0);

error:
	return (ret);
}

/*
 * Primary encryption / decryption entrypoint for zio data.
 */
int
zio_do_crypt_data(boolean_t encrypt, zio_crypt_key_t *key, uint8_t *salt,
    dmu_object_type_t ot, uint8_t *iv, uint8_t *mac, uint_t datalen,
    boolean_t byteswap, uint8_t *plainbuf, uint8_t *cipherbuf,
    boolean_t *no_crypt)
{
	int ret;
	boolean_t locked = B_FALSE;
	uint64_t crypt = key->zk_crypt;
	uint_t keydata_len = zio_crypt_table[crypt].ci_keylen;
	uint_t enc_len, auth_len;
	uio_t puio, cuio;
	uint8_t enc_keydata[MASTER_KEY_MAX_LEN];
	crypto_key_t tmp_ckey, *ckey = NULL;
	crypto_ctx_template_t tmpl;
	uint8_t *authbuf = NULL;

	bzero(&puio, sizeof (uio_t));
	bzero(&cuio, sizeof (uio_t));

	/* create uios for encryption */
	ret = zio_crypt_init_uios(encrypt, ot, plainbuf, cipherbuf, datalen,
	    byteswap, mac, &puio, &cuio, &enc_len, &authbuf, &auth_len,
	    no_crypt);
	if (ret != 0)
		return (ret);

	/*
	 * If the needed key is the current one, just use it. Otherwise we
	 * need to generate a temporary one from the given salt + master key.
	 * If we are encrypting, we must return a copy of the current salt
	 * so that it can be stored in the blkptr_t.
	 */
	rw_enter(&key->zk_salt_lock, RW_READER);
	locked = B_TRUE;

	if (bcmp(salt, key->zk_salt, ZIO_DATA_SALT_LEN) == 0) {
		ckey = &key->zk_current_key;
		tmpl = key->zk_current_tmpl;
	} else {
		rw_exit(&key->zk_salt_lock);
		locked = B_FALSE;

		ret = hkdf_sha512(key->zk_master_keydata, keydata_len, NULL, 0,
		    salt, ZIO_DATA_SALT_LEN, enc_keydata, keydata_len);
		if (ret != 0)
			goto error;

		tmp_ckey.ck_format = CRYPTO_KEY_RAW;
		tmp_ckey.ck_data = enc_keydata;
		tmp_ckey.ck_length = BYTES_TO_BITS(keydata_len);

		ckey = &tmp_ckey;
		tmpl = NULL;
	}

	/* perform the encryption / decryption */
	ret = zio_do_crypt_uio(encrypt, key->zk_crypt, ckey, tmpl, iv, enc_len,
	    &puio, &cuio, authbuf, auth_len);
	if (ret != 0)
		goto error;

	if (locked) {
		rw_exit(&key->zk_salt_lock);
		locked = B_FALSE;
	}

	if (authbuf != NULL)
		zio_buf_free(authbuf, datalen);
	if (ckey == &tmp_ckey)
		bzero(enc_keydata, keydata_len);
	zio_crypt_destroy_uio(&puio);
	zio_crypt_destroy_uio(&cuio);

	return (0);

error:
	if (locked)
		rw_exit(&key->zk_salt_lock);
	if (authbuf != NULL)
		zio_buf_free(authbuf, datalen);
	if (ckey == &tmp_ckey)
		bzero(enc_keydata, keydata_len);
	zio_crypt_destroy_uio(&puio);
	zio_crypt_destroy_uio(&cuio);

	return (ret);
}

#if 0
/*
 * Simple wrapper around zio_do_crypt_data() to work with abd's instead of
 * linear buffers.
 */
int
zio_do_crypt_abd(boolean_t encrypt, zio_crypt_key_t *key, uint8_t *salt,
    dmu_object_type_t ot, uint8_t *iv, uint8_t *mac, uint_t datalen,
    boolean_t byteswap, abd_t *pabd, abd_t *cabd, boolean_t *no_crypt)
{
	int ret;
	void *ptmp, *ctmp;

	if (encrypt) {
		ptmp = abd_borrow_buf_copy(pabd, datalen);
		ctmp = abd_borrow_buf(cabd, datalen);
	} else {
		ptmp = abd_borrow_buf(pabd, datalen);
		ctmp = abd_borrow_buf_copy(cabd, datalen);
	}

	ret = zio_do_crypt_data(encrypt, key, salt, ot, iv, mac,
	    datalen, byteswap, ptmp, ctmp, no_crypt);
	if (ret != 0)
		goto error;

	if (encrypt) {
		abd_return_buf(pabd, ptmp, datalen);
		abd_return_buf_copy(cabd, ctmp, datalen);
	} else {
		abd_return_buf_copy(pabd, ptmp, datalen);
		abd_return_buf(cabd, ctmp, datalen);
	}

	return (0);

error:
	if (encrypt) {
		abd_return_buf(pabd, ptmp, datalen);
		abd_return_buf_copy(cabd, ctmp, datalen);
	} else {
		abd_return_buf_copy(pabd, ptmp, datalen);
		abd_return_buf(cabd, ctmp, datalen);
	}

	return (ret);
}
#endif
