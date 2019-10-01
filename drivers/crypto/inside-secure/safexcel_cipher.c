// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2017 Marvell
 *
 * Antoine Tenart <antoine.tenart@free-electrons.com>
 */

#include <asm/unaligned.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/dmapool.h>
#include <crypto/aead.h>
#include <crypto/aes.h>
#include <crypto/authenc.h>
#include <crypto/chacha.h>
#include <crypto/ctr.h>
#include <crypto/internal/des.h>
#include <crypto/gcm.h>
#include <crypto/ghash.h>
#include <crypto/poly1305.h>
#include <crypto/sha.h>
#include <crypto/sm3.h>
#include <crypto/sm4.h>
#include <crypto/xts.h>
#include <crypto/skcipher.h>
#include <crypto/internal/aead.h>
#include <crypto/internal/skcipher.h>

#include "safexcel.h"

enum safexcel_cipher_direction {
	SAFEXCEL_ENCRYPT,
	SAFEXCEL_DECRYPT,
};

enum safexcel_cipher_alg {
	SAFEXCEL_DES,
	SAFEXCEL_3DES,
	SAFEXCEL_AES,
	SAFEXCEL_CHACHA20,
	SAFEXCEL_SM4,
};

struct safexcel_cipher_ctx {
	struct safexcel_context base;
	struct safexcel_crypto_priv *priv;

	u64 cctrl_enc;
	u64 cctrl_dec;
	u32 mode;
	u32 calg;
	enum safexcel_cipher_alg alg;
	u8 aead; /* !=0=AEAD, 2=IPSec ESP AEAD, 3=IPsec ESP GMAC */
	u8 xcm;  /* 0=authenc, 1=GCM, 2 reserved for CCM */
	u32 aadskip;
	u32 blocksz;
	u32 ivmask;
	u32 ctrinit;

	__le32 key[16];
	u32 nonce;
	unsigned int key_len;

	/* All the below is AEAD specific */
	u32 hash_alg;
	u32 state_sz;
	u32 ipad[SHA512_DIGEST_SIZE / sizeof(u32)];
	u32 opad[SHA512_DIGEST_SIZE / sizeof(u32)];

	struct crypto_cipher *hkaes;
	struct crypto_aead *fback;
};

struct safexcel_cipher_req {
	enum safexcel_cipher_direction direction;
	/* Number of result descriptors associated to the request */
	unsigned int rdescs;
	bool needs_inv;
	int  nr_src, nr_dst;
};

inline bool safexcel_skcipher_iv(struct safexcel_cipher_ctx *ctx, u8 *iv,
				struct safexcel_command_desc *cdesc)
{
	if (ctx->mode == CONTEXT_CONTROL_CRYPTO_MODE_CTR_LOAD) {
		upd_tokhdr_set(&cdesc->control_data,
			       EIP197_OPTION_4_TOKEN_IV_CMD, 0);
		/* 32 bit nonce */
		cdesc->control_data.token[0] = ctx->nonce;
		/* 64 bit IV part */
		memcpy(&cdesc->control_data.token[1], iv, 8);
		/* 32 bit counter, start at 1 (big endian!) */
		cdesc->control_data.token[3] = cpu_to_be32(1);
		return true;
	}
	if (ctx->alg == SAFEXCEL_CHACHA20) {
		upd_tokhdr_set(&cdesc->control_data,
			       EIP197_OPTION_4_TOKEN_IV_CMD, 0);
		/* 96 bit nonce part */
		memcpy(&cdesc->control_data.token[0], &iv[4], 12);
		/* 32 bit counter */
		cdesc->control_data.token[3] = *(u32 *)iv;
		return true;
	}
	/* CBC/CFB/OFB */
	upd_tokhdr_set(&cdesc->control_data, ctx->ivmask, 0);
	memcpy(cdesc->control_data.token, iv, ctx->blocksz);
	return ctx->blocksz >> 4; /* 1 if 16, else 0 */
}

static void safexcel_skcipher_token(struct safexcel_cipher_ctx *ctx, u8 *iv,
				    struct safexcel_command_desc *cdesc,
				    struct safexcel_token *atoken,
				    u32 length)
{
	struct safexcel_token *token;
	int ivmax = safexcel_skcipher_iv(ctx, iv, cdesc);

	if (likely(ivmax)) {
		/* No space in cdesc, instruction moves to atoken */
		upd_desc_set(cdesc, 0, 0, 1);
		token = atoken;
	} else {
		/* Everything fits in cdesc */
		token = (struct safexcel_token *)(cdesc->control_data.token + 2);
		/* Need to pad with NOP */
		eip197_noop_token(&token[1]);
	}

	/* buildinstr(*token, opcode, length, stat, flags) */
	build_instr(token, EIP197_TOKEN_OPCODE_DIRECTION, length,
		    EIP197_TOKEN_STAT_BOTH,
		    EIP197_TOKEN_INS_LAST |
		    EIP197_TOKEN_INS_TYPE_CRYPTO |
		    EIP197_TOKEN_INS_TYPE_OUTPUT);
}

/* Generate and extract Y0 - for CCM and GCM */
inline void safexcel_ency0_token(struct safexcel_token *atoken)
{
	/* Obtain enc(Y0) */
	build_instr(atoken, EIP197_TOKEN_OPCODE_INSERT_REMRES, 0, 0,
		    AES_BLOCK_SIZE);
	atoken++;
	build_instr(atoken, EIP197_TOKEN_OPCODE_INSERT, AES_BLOCK_SIZE, 0,
		    EIP197_TOKEN_INS_TYPE_OUTPUT |
		    EIP197_TOKEN_INS_TYPE_CRYPTO);
}

/* The CCM token is really complicated, so keep it separate */
inline void safexcel_ccm_token(struct safexcel_cipher_ctx *ctx, u8 *iv,
			       struct safexcel_command_desc *cdesc,
			       struct safexcel_token *atoken,
			       enum safexcel_cipher_direction direction,
			       u32 cryptlen, u32 assoclen, u32 digestsize)
{
	struct safexcel_token *aadtok;
	u32 atoksize;

	/* Construct IV block B0 for the CBC-MAC */
	u8 *final_iv = (u8 *)cdesc->control_data.token;
	u8 *cbcmaciv = (u8 *)&atoken[1];
	u32 *aadlen = (u32 *)&atoken[5];

	/* buildinstr(*token, opcode, length, stat, flags) */
	build_instr(atoken, EIP197_TOKEN_OPCODE_INSERT,
		    AES_BLOCK_SIZE + ((assoclen > 0) << 1), 0,
		    EIP197_TOKEN_INS_ORIGIN_TOKEN |
		    EIP197_TOKEN_INS_TYPE_HASH);

	if (likely(assoclen)) {
		*aadlen = cpu_to_le32(cpu_to_be16(assoclen));
		atoken += 6;
		atoksize = 11;
	} else {
		atoken += 5;
		atoksize = 10;
	}

	/* Process AAD data */
	build_instr(atoken, EIP197_TOKEN_OPCODE_DIRECTION, assoclen, 0,
		    EIP197_TOKEN_INS_TYPE_HASH);
	atoken++;

	/* Align AAD data towards hash engine */
	aadtok = atoken;
	build_instr(atoken, EIP197_TOKEN_OPCODE_INSERT,
		    assoclen ? (-assoclen - 2) & 15 : 0, 0,
		    EIP197_TOKEN_INS_TYPE_HASH);
	atoken++;

	if (ctx->aead == EIP197_AEAD_TYPE_IPSEC_ESP) {
		/* For ESP mode, skip over the IV. */
		build_instr(atoken, EIP197_TOKEN_OPCODE_DIRECTION,
			    EIP197_AEAD_IPSEC_IV_SIZE, 0, 0);
		atoken++;
		atoksize++;

		/* Length + nonce */
		cdesc->control_data.token[0] = ctx->nonce;
		/* Fixup flags byte */
		*(u32 *)cbcmaciv =
			le32_to_cpu(
				cpu_to_le32(ctx->nonce |
					    ((assoclen > 0) << 6) |
					    ((digestsize - 2) << 2)));
		/* 64 bit IV part */
		memcpy(&cdesc->control_data.token[1], iv, 8);
		memcpy(cbcmaciv + 4, iv, 8);
		/* Start counter at 0 */
		cdesc->control_data.token[3] = 0;
		/* Message length */
		*(u32 *)(cbcmaciv + 12) = cpu_to_be32(cryptlen);
	} else {
		/* Variable length IV part */
		memcpy(final_iv, iv, 15 - iv[0]);
		memcpy(cbcmaciv, iv, 15 - iv[0]);
		/* Start variable length counter at 0 */
		memset(final_iv + 15 - iv[0], 0, iv[0] + 1);
		memset(cbcmaciv + 15 - iv[0], 0, iv[0] - 1);
		/* fixup flags byte */
		cbcmaciv[0] |= ((assoclen > 0) << 6) |
			       ((digestsize - 2) << 2);
		/* insert lower 2 bytes of message length */
		cbcmaciv[14] = cryptlen >> 8;
		cbcmaciv[15] = cryptlen & 255;
	}

	/* Generate and extract enc(Y0) */
	safexcel_ency0_token(atoken);
	atoken += 2;

	if (likely(cryptlen)) {
		/* Process crypto data */
		build_instr(atoken, EIP197_TOKEN_OPCODE_DIRECTION, cryptlen, 0,
			    EIP197_TOKEN_INS_LAST | EIP197_TOKEN_INS_TYPE_ALL);

		/* pad crypto data to the hash engine or NOP */
		atoken++;
		build_instr(atoken, EIP197_TOKEN_OPCODE_INSERT,
			    (-cryptlen) & 15,
			    EIP197_TOKEN_STAT_LAST_HASH,
			    EIP197_TOKEN_INS_TYPE_HASH);
		atoken++;
		atoksize += 2;
	} else {
		/* If no crypto data present, then AAD was last hash data */
		upd_instr_set(aadtok, EIP197_TOKEN_STAT_LAST_HASH,
			      EIP197_TOKEN_INS_LAST);
	}
	if (likely(direction == SAFEXCEL_DECRYPT)) {
		/* Extract ICV */
		build_instr(atoken, EIP197_TOKEN_OPCODE_RETRIEVE, digestsize,
			    EIP197_TOKEN_STAT_BOTH,
			    EIP197_TOKEN_INS_INSERT_HASH_DIGEST);
		atoken++;
		atoksize++;
		/* Verify ICV */
		build_instr(atoken, EIP197_TOKEN_OPCODE_VERIFY,
			    digestsize | EIP197_TOKEN_HASH_RESULT_VERIFY,
			    EIP197_TOKEN_STAT_BOTH,
			    EIP197_TOKEN_INS_TYPE_OUTPUT);

		/* Fixup length of the token in the command descriptor */
		upd_desc_set(cdesc, 0, 0, atoksize);
		return;
	}

	/* Encrypt: Append ICV */
	build_instr(atoken, EIP197_TOKEN_OPCODE_INSERT, digestsize,
		    EIP197_TOKEN_STAT_BOTH,
		    EIP197_TOKEN_INS_TYPE_OUTPUT |
		    EIP197_TOKEN_INS_INSERT_HASH_DIGEST);

	/* Fixup length of the token in the command descriptor */
	upd_desc_set(cdesc, 0, 0, atoksize);
}

/* Generic AEAD token for authenc, GCM, Poly-Chacha */
inline void safexcel_gen_aead_token(struct safexcel_cipher_ctx *ctx, u8 *iv,
				    struct safexcel_command_desc *cdesc,
				    struct safexcel_token *atoken,
				    enum safexcel_cipher_direction direction,
				    u32 cryptlen, u32 assoclen, u32 digestsize)
{
	struct safexcel_token *aadtok = atoken;
	u32 cryptflags = EIP197_TOKEN_INS_LAST | EIP197_TOKEN_INS_TYPE_ALL;
	u32 atoksize = 2;  /* Start with minimum size */

	/* Process AAD data */
	build_instr(atoken, EIP197_TOKEN_OPCODE_DIRECTION, assoclen, 0,
		    EIP197_TOKEN_INS_LAST | EIP197_TOKEN_INS_TYPE_HASH);
	atoken++;

	if (ctx->aead & EIP197_AEAD_TYPE_IPSEC_ESP) { /* Any ESP + CTR */
		/* 32 bit nonce */
		cdesc->control_data.token[0] = ctx->nonce;
		/* 64 bit IV part */
		memcpy(&cdesc->control_data.token[1], iv, 8);
		/* 32 bit counter, start at 0 or 1 (big endian!) */
		cdesc->control_data.token[3] = cpu_to_be32(ctx->ctrinit);

		/* For ESP mode and not GMAC/CTR, skip over the IV */
		build_instr(atoken, EIP197_TOKEN_OPCODE_DIRECTION,
			    ctx->aadskip, 0, 0);
		atoken++;
		atoksize++;
	} else if (ctx->mode != CONTEXT_CONTROL_CRYPTO_MODE_CBC) {
		/* Non-ESP GCM/GMAC or Poly/Chacha */
		/* 96 bit IV part */
		memcpy(&cdesc->control_data.token[0], iv, 12);
		/* 32 bit counter, start at 0 or 1 (big endian!) */
		cdesc->control_data.token[3] = cpu_to_be32(ctx->ctrinit);

		/* Poly-chacha decryption needs a dummy NOP here */
		build_instr(atoken, EIP197_TOKEN_OPCODE_INSERT,
			    4, 0, 0);
		atoken++;
		atoksize++;
	} else {
		/* Authenc CBC, full IV provided as-is */
		memcpy(cdesc->control_data.token, iv, ctx->blocksz);
		if (likely(cryptlen)) {
			goto process_crypt;
		} else {
			/* If no crypto data present, AAD was last hash data */
			upd_instr_set(aadtok, EIP197_TOKEN_STAT_LAST_HASH, 0);
			goto skip_crypt;
		}
	}
	/* Generate and extract enc(Y0) for GCM/GMAC */
	if (ctx->mode == CONTEXT_CONTROL_CRYPTO_MODE_XCM) {
		/* Need to generate and extract enc(Y0) */
		safexcel_ency0_token(atoken);
		atoken += 2;
		atoksize += 2;
		if (unlikely(ctx->aead == EIP197_AEAD_TYPE_IPSEC_ESP_GMAC)) {
			/* Clear LAST bit in ins field of AAD dir instruction */
			upd_instr_clr(aadtok, 0, EIP197_TOKEN_INS_LAST);

			/* Do not send cdata to crypt engine in case of GMAC */
			cryptflags &= ~EIP197_TOKEN_INS_TYPE_CRYPTO;
		} else if (unlikely(!cryptlen)) {
			/* Needed for older HW only ... */
			upd_instr_set(aadtok, EIP197_TOKEN_STAT_LAST_HASH, 0);
			eip197_noop_token(atoken);
			atoken++;
			atoksize++;
			goto skip_crypt;
		}
	}
process_crypt:
	/* Process crypto data */
	build_instr(atoken, EIP197_TOKEN_OPCODE_DIRECTION, cryptlen,
		    EIP197_TOKEN_STAT_LAST_HASH, cryptflags);
	atoken++;
	atoksize++;
skip_crypt:
	if (likely(direction == SAFEXCEL_DECRYPT)) {
		/* Extract ICV */
		build_instr(atoken, EIP197_TOKEN_OPCODE_RETRIEVE, digestsize,
			    EIP197_TOKEN_STAT_BOTH,
			    EIP197_TOKEN_INS_INSERT_HASH_DIGEST);
		atoken++;
		atoksize++;
		/* Verify ICV */
		build_instr(atoken, EIP197_TOKEN_OPCODE_VERIFY,
			    digestsize | EIP197_TOKEN_HASH_RESULT_VERIFY,
			    EIP197_TOKEN_STAT_BOTH,
			    EIP197_TOKEN_INS_TYPE_OUTPUT);

		/* Fixup length of the token in the command descriptor */
		upd_desc_set(cdesc, 0, 0, atoksize);
		return;
	}

	/* Encrypt: Append ICV */
	build_instr(atoken, EIP197_TOKEN_OPCODE_INSERT, digestsize,
		    EIP197_TOKEN_STAT_BOTH,
		    EIP197_TOKEN_INS_TYPE_OUTPUT |
		    EIP197_TOKEN_INS_INSERT_HASH_DIGEST);

	/* Fixup length of the token in the command descriptor */
	upd_desc_set(cdesc, 0, 0, atoksize);
	return;
}

static void safexcel_aead_token(struct safexcel_cipher_ctx *ctx, u8 *iv,
				struct safexcel_command_desc *cdesc,
				struct safexcel_token *atoken,
				enum safexcel_cipher_direction direction,
				u32 cryptlen, u32 assoclen, u32 digestsize)
{
	/* Always 4 dwords of embedded IV  for AEAD modes */
	upd_tokhdr_set(&cdesc->control_data, EIP197_OPTION_4_TOKEN_IV_CMD, 0);

	if (direction == SAFEXCEL_DECRYPT)
		cryptlen -= digestsize;
	assoclen -= ctx->aadskip;

	if (likely(ctx->xcm != EIP197_XCM_MODE_CCM)) {
		safexcel_gen_aead_token(ctx, iv, cdesc, atoken, direction,
					cryptlen, assoclen, digestsize);
	} else {
		safexcel_ccm_token(ctx, iv, cdesc, atoken, direction,
				   cryptlen, assoclen, digestsize);
	}
}

static int safexcel_aes_setkey_size(struct crypto_tfm *tfm,
				    unsigned int len)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	switch (len) {
	case AES_KEYSIZE_128:
		ctx->calg = CONTEXT_CONTROL_CRYPTO_ALG_AES128;
		break;
	case AES_KEYSIZE_192:
		ctx->calg = CONTEXT_CONTROL_CRYPTO_ALG_AES192;
		break;
	case AES_KEYSIZE_256:
		ctx->calg = CONTEXT_CONTROL_CRYPTO_ALG_AES256;
		break;
	default:
		crypto_tfm_set_flags(tfm, CRYPTO_TFM_RES_BAD_KEY_LEN);
		return -EINVAL;
	}
	return 0;
}

static void safexcel_setkey(struct safexcel_cipher_ctx *ctx,
			    const u8 *key, unsigned int len)
{
	struct safexcel_crypto_priv *priv = ctx->priv;

	if (priv->flags & EIP197_TRC_CACHE && ctx->base.ctxr_dma &&
	    (ctx->key_len != len || memcmp(ctx->key, key, len)))
		ctx->base.needs_inv = true;

	memcpy(ctx->key, key, len);
	ctx->key_len = len;
}

static int safexcel_aes_setkey(struct crypto_tfm *tfm,
			       const u8 *key, unsigned int len)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);
	int ret;

	ret = safexcel_aes_setkey_size(tfm, len);
	if (unlikely(ret))
		return ret;
	safexcel_setkey(ctx, key, len);
	return 0;
}

static void safexcel_skcipher_setkey(struct safexcel_cipher_ctx *ctx,
				     const u8 *key, unsigned int len)
{
	safexcel_setkey(ctx, key, len);
	/* Precompute control values for encrypt and decrypt */
	ctx->cctrl_enc = ctx->calg | ((u64)ctx->mode << 32) |
			 CONTEXT_CONTROL_TYPE_CRYPTO_OUT |
			 CONTEXT_CONTROL_KEY_EN |
			 CONTEXT_CONTROL_SIZE(len / sizeof(u32));
	ctx->cctrl_dec = ctx->calg | ((u64)ctx->mode << 32) |
			 CONTEXT_CONTROL_TYPE_CRYPTO_IN |
			 CONTEXT_CONTROL_KEY_EN |
			 CONTEXT_CONTROL_SIZE(len / sizeof(u32));
}

static int safexcel_skcipher_aes_setkey(struct crypto_skcipher *ctfm,
					const u8 *key, unsigned int len)
{
	struct crypto_tfm *tfm = crypto_skcipher_tfm(ctfm);
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);
	int ret;

	ret = safexcel_aes_setkey_size(tfm, len);
	if (unlikely(ret))
		return ret;
	safexcel_skcipher_setkey(ctx, key, len);
	return 0;
}

static int safexcel_aead_setkey(struct crypto_aead *ctfm, const u8 *key,
				unsigned int len)
{
	struct crypto_tfm *tfm = crypto_aead_tfm(ctfm);
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);
	struct safexcel_ahash_export_state istate, ostate;
	struct safexcel_crypto_priv *priv = ctx->priv;
	struct crypto_authenc_keys keys;
	int err = -EINVAL;

	if (unlikely(crypto_authenc_extractkeys(&keys, key, len)))
		goto badkey;

	if (ctx->mode == CONTEXT_CONTROL_CRYPTO_MODE_CTR_LOAD) {
		/* Must have at least space for the nonce here */
		if (unlikely(keys.enckeylen < CTR_RFC3686_NONCE_SIZE))
			goto badkey;
		/* last 4 bytes of key are the nonce! */
		ctx->nonce = *(u32 *)(keys.enckey + keys.enckeylen -
				      CTR_RFC3686_NONCE_SIZE);
		/* exclude the nonce here */
		keys.enckeylen -= CTR_RFC3686_NONCE_SIZE;
	}

	/* Encryption key */
	switch (ctx->alg) {
	case SAFEXCEL_DES:
		err = verify_aead_des_key(ctfm, keys.enckey, keys.enckeylen);
		if (unlikely(err))
			goto badkey_expflags;
		break;
	case SAFEXCEL_3DES:
		err = verify_aead_des3_key(ctfm, keys.enckey, keys.enckeylen);
		if (unlikely(err))
			goto badkey_expflags;
		break;
	case SAFEXCEL_AES:
		err = safexcel_aes_setkey_size(tfm, keys.enckeylen);
		if (unlikely(err))
			goto badkey_expflags;
		break;
	case SAFEXCEL_SM4:
		if (unlikely(keys.enckeylen != SM4_KEY_SIZE))
			goto badkey;
		break;
	default:
		dev_err(priv->dev, "aead: unsupported cipher algorithm\n");
		goto badkey;
	}

	if (priv->flags & EIP197_TRC_CACHE && ctx->base.ctxr_dma &&
	    memcmp(ctx->key, keys.enckey, keys.enckeylen))
		ctx->base.needs_inv = true;

	/* Auth key */
	switch (ctx->hash_alg) {
	case CONTEXT_CONTROL_CRYPTO_ALG_SHA1:
		if (safexcel_hmac_setkey("safexcel-sha1", keys.authkey,
					 keys.authkeylen, &istate, &ostate))
			goto badkey;
		break;
	case CONTEXT_CONTROL_CRYPTO_ALG_SHA224:
		if (safexcel_hmac_setkey("safexcel-sha224", keys.authkey,
					 keys.authkeylen, &istate, &ostate))
			goto badkey;
		break;
	case CONTEXT_CONTROL_CRYPTO_ALG_SHA256:
		if (safexcel_hmac_setkey("safexcel-sha256", keys.authkey,
					 keys.authkeylen, &istate, &ostate))
			goto badkey;
		break;
	case CONTEXT_CONTROL_CRYPTO_ALG_SHA384:
		if (safexcel_hmac_setkey("safexcel-sha384", keys.authkey,
					 keys.authkeylen, &istate, &ostate))
			goto badkey;
		break;
	case CONTEXT_CONTROL_CRYPTO_ALG_SHA512:
		if (safexcel_hmac_setkey("safexcel-sha512", keys.authkey,
					 keys.authkeylen, &istate, &ostate))
			goto badkey;
		break;
	case CONTEXT_CONTROL_CRYPTO_ALG_SM3:
		if (safexcel_hmac_setkey("safexcel-sm3", keys.authkey,
					 keys.authkeylen, &istate, &ostate))
			goto badkey;
		break;
	default:
		dev_err(priv->dev, "aead: unsupported hash algorithmn");
		goto badkey;
	}

	crypto_aead_set_flags(ctfm, crypto_aead_get_flags(ctfm) &
				    CRYPTO_TFM_RES_MASK);

	if (priv->flags & EIP197_TRC_CACHE && ctx->base.ctxr_dma &&
	    (memcmp(ctx->ipad, istate.state, ctx->state_sz) ||
	     memcmp(ctx->opad, ostate.state, ctx->state_sz)))
		ctx->base.needs_inv = true;

	/* Now copy the keys into the context */
	memcpy(ctx->key, keys.enckey, keys.enckeylen);
	ctx->key_len = keys.enckeylen;

	memcpy(ctx->ipad, &istate.state, ctx->state_sz);
	memcpy(ctx->opad, &ostate.state, ctx->state_sz);

	memzero_explicit(&keys, sizeof(keys));

	/* Precompute control values for encrypt and decrypt */
	ctx->cctrl_enc = ctx->calg | ctx->hash_alg | ((u64)ctx->mode << 32) |
			 CONTEXT_CONTROL_DIGEST_HMAC | CONTEXT_CONTROL_KEY_EN |
			 CONTEXT_CONTROL_TYPE_ENCRYPT_HASH_OUT |
			 CONTEXT_CONTROL_SIZE((len + ctx->state_sz * 2) /
					      sizeof(u32));
	ctx->cctrl_dec = ctx->calg | ctx->hash_alg | ((u64)ctx->mode << 32) |
			 CONTEXT_CONTROL_DIGEST_HMAC | CONTEXT_CONTROL_KEY_EN |
			 CONTEXT_CONTROL_TYPE_HASH_DECRYPT_IN |
			 CONTEXT_CONTROL_SIZE((len + ctx->state_sz * 2) /
					      sizeof(u32));
	return 0;

badkey:
	crypto_aead_set_flags(ctfm, CRYPTO_TFM_RES_BAD_KEY_LEN);
badkey_expflags:
	memzero_explicit(&keys, sizeof(keys));
	return err;
}

static void safexcel_context_control(struct safexcel_cipher_ctx *ctx,
				     struct safexcel_cipher_req *sreq,
				     struct safexcel_command_desc *cdesc)
{
	if (sreq->direction == SAFEXCEL_ENCRYPT)
		cdesc->control_data.control = cpu_to_le64(ctx->cctrl_enc);
	else
		cdesc->control_data.control = cpu_to_le64(ctx->cctrl_dec);
}

static int safexcel_handle_req_result(struct safexcel_crypto_priv *priv, int ring,
				      struct crypto_async_request *async,
				      struct scatterlist *src,
				      struct scatterlist *dst,
				      unsigned int cryptlen,
				      struct safexcel_cipher_req *sreq,
				      bool *should_complete, int *ret)
{
	struct skcipher_request *areq = skcipher_request_cast(async);
	struct crypto_skcipher *skcipher = crypto_skcipher_reqtfm(areq);
	struct safexcel_cipher_ctx *ctx = crypto_skcipher_ctx(skcipher);
	struct safexcel_result_desc *rdesc;
	int ndesc = 0;

	*ret = 0;

	if (unlikely(!sreq->rdescs))
		return 0;

	while (sreq->rdescs--) {
		rdesc = safexcel_ring_next_rptr(&priv->ring[ring].rdr);
		if (IS_ERR(rdesc)) {
			dev_err(priv->dev,
				"cipher: result: could not retrieve the result descriptor\n");
			*ret = PTR_ERR(rdesc);
			break;
		}
		ndesc++;
	}
	*ret = safexcel_rdesc_check_errors(priv, rdesc);

	safexcel_complete(priv, ring);

	if (src == dst) {
		dma_unmap_sg(priv->dev, src, sreq->nr_src, DMA_BIDIRECTIONAL);
	} else {
		dma_unmap_sg(priv->dev, src, sreq->nr_src, DMA_TO_DEVICE);
		dma_unmap_sg(priv->dev, dst, sreq->nr_dst, DMA_FROM_DEVICE);
	}

	/*
	 * Update IV in req from last crypto output word for CBC modes
	 */
	if ((!ctx->aead) && (ctx->mode == CONTEXT_CONTROL_CRYPTO_MODE_CBC) &&
	    (sreq->direction == SAFEXCEL_ENCRYPT)) {
		/* For encrypt take the last output word */
		sg_pcopy_to_buffer(dst, sreq->nr_dst, areq->iv,
				   crypto_skcipher_ivsize(skcipher),
				   (cryptlen -
				    crypto_skcipher_ivsize(skcipher)));
	}

	*should_complete = true;

	return ndesc;
}

static int safexcel_send_req(struct crypto_async_request *base, int ring,
			     struct safexcel_cipher_req *sreq,
			     struct scatterlist *src, struct scatterlist *dst,
			     unsigned int cryptlen, unsigned int assoclen,
			     unsigned int digestsize, u8 *iv, int *commands,
			     int *results)
{
	struct skcipher_request *areq = skcipher_request_cast(base);
	struct crypto_skcipher *skcipher = crypto_skcipher_reqtfm(areq);
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(base->tfm);
	struct safexcel_crypto_priv *priv = ctx->priv;
	struct safexcel_desc_ring *cdr = &priv->ring[ring].cdr;
	struct safexcel_desc_ring *rdr = &priv->ring[ring].rdr;
	struct safexcel_command_desc *cdesc;
	struct safexcel_command_desc *first_cdesc = NULL;
	struct safexcel_result_desc *rdesc, *first_rdesc = NULL;
	struct scatterlist *sg;
	unsigned int totlen;
	unsigned int totlen_src = cryptlen + assoclen;
	unsigned int totlen_dst = totlen_src;
	struct safexcel_token *atoken;
	int n_cdesc = 0, n_rdesc = 0;
	int queued, i, ret = 0;
	bool first = true;

	sreq->nr_src = sg_nents_for_len(src, totlen_src);

	if (ctx->aead) {
		/*
		 * AEAD has auth tag appended to output for encrypt and
		 * removed from the output for decrypt!
		 */
		if (sreq->direction == SAFEXCEL_DECRYPT)
			totlen_dst -= digestsize;
		else
			totlen_dst += digestsize;

		memcpy(ctx->base.ctxr->data + ctx->key_len / sizeof(u32),
		       ctx->ipad, ctx->state_sz);
		if (!ctx->xcm)
			memcpy(ctx->base.ctxr->data + (ctx->key_len +
			       ctx->state_sz) / sizeof(u32), ctx->opad,
			       ctx->state_sz);
	} else if ((ctx->mode == CONTEXT_CONTROL_CRYPTO_MODE_CBC) &&
		   (sreq->direction == SAFEXCEL_DECRYPT)) {
		/*
		 * Save IV from last crypto input word for CBC modes in decrypt
		 * direction. Need to do this first in case of inplace operation
		 * as it will be overwritten.
		 */
		sg_pcopy_to_buffer(src, sreq->nr_src, areq->iv,
				   crypto_skcipher_ivsize(skcipher),
				   (totlen_src -
				    crypto_skcipher_ivsize(skcipher)));
	}

	sreq->nr_dst = sg_nents_for_len(dst, totlen_dst);

	/*
	 * Remember actual input length, source buffer length may be
	 * updated in case of inline operation below.
	 */
	totlen = totlen_src;
	queued = totlen_src;

	if (src == dst) {
		sreq->nr_src = max(sreq->nr_src, sreq->nr_dst);
		sreq->nr_dst = sreq->nr_src;
		if (unlikely((totlen_src || totlen_dst) &&
		    (sreq->nr_src <= 0))) {
			dev_err(priv->dev, "In-place buffer not large enough (need %d bytes)!",
				max(totlen_src, totlen_dst));
			return -EINVAL;
		}
		dma_map_sg(priv->dev, src, sreq->nr_src, DMA_BIDIRECTIONAL);
	} else {
		if (unlikely(totlen_src && (sreq->nr_src <= 0))) {
			dev_err(priv->dev, "Source buffer not large enough (need %d bytes)!",
				totlen_src);
			return -EINVAL;
		}
		dma_map_sg(priv->dev, src, sreq->nr_src, DMA_TO_DEVICE);

		if (unlikely(totlen_dst && (sreq->nr_dst <= 0))) {
			dev_err(priv->dev, "Dest buffer not large enough (need %d bytes)!",
				totlen_dst);
			dma_unmap_sg(priv->dev, src, sreq->nr_src,
				     DMA_TO_DEVICE);
			return -EINVAL;
		}
		dma_map_sg(priv->dev, dst, sreq->nr_dst, DMA_FROM_DEVICE);
	}

	memcpy(ctx->base.ctxr->data, ctx->key, ctx->key_len);

	/* The EIP cannot deal with zero length input packets! */
	if (totlen == 0)
		totlen = 1;

	/* command descriptors */
	for_each_sg(src, sg, sreq->nr_src, i) {
		int len = sg_dma_len(sg);

		/* Do not overflow the request */
		if (queued - len < 0)
			len = queued;

		cdesc = safexcel_add_cdesc(cdr, !n_cdesc, !(queued - len),
					   sg_dma_address(sg), len, totlen,
					   ctx->base.ctxr_dma |
					   EIP197_CONTEXT_SMALL, &atoken);
		if (IS_ERR(cdesc)) {
			/* No space left in the command descriptor ring */
			ret = PTR_ERR(cdesc);
			goto cdesc_rollback;
		}
		n_cdesc++;

		if (n_cdesc == 1) {
			first_cdesc = cdesc;
		}

		queued -= len;
		if (!queued)
			break;
	}

	if (unlikely(!n_cdesc)) {
		/*
		 * Special case: zero length input buffer.
		 * The engine always needs the 1st command descriptor, however!
		 */
		first_cdesc = safexcel_add_cdesc(cdr, 1, 1, 0, 0, totlen,
						 ctx->base.ctxr_dma |
						 EIP197_CONTEXT_SMALL, &atoken);
		n_cdesc = 1;
	}

	/* Add context control words and token to first command descriptor */
	safexcel_context_control(ctx, sreq, first_cdesc);
	if (ctx->aead)
		safexcel_aead_token(ctx, iv, first_cdesc, atoken,
				    sreq->direction, cryptlen,
				    assoclen, digestsize);
	else
		safexcel_skcipher_token(ctx, iv, first_cdesc, atoken,
					cryptlen);

	/* result descriptors */
	for_each_sg(dst, sg, sreq->nr_dst, i) {
		bool last = (i == sreq->nr_dst - 1);
		u32 len = sg_dma_len(sg);

		/* only allow the part of the buffer we know we need */
		if (len > totlen_dst)
			len = totlen_dst;
		if (unlikely(!len))
			break;
		totlen_dst -= len;

		/* skip over AAD space in buffer - not written */
		if (assoclen) {
			if (assoclen >= len) {
				assoclen -= len;
				continue;
			}
			rdesc = safexcel_add_rdesc(rdr, first, last,
						   sg_dma_address(sg) +
						   assoclen,
						   len - assoclen);
			assoclen = 0;
		} else {
			rdesc = safexcel_add_rdesc(rdr, first, last,
						   sg_dma_address(sg),
						   len);
		}
		if (IS_ERR(rdesc)) {
			/* No space left in the result descriptor ring */
			ret = PTR_ERR(rdesc);
			goto rdesc_rollback;
		}
		if (first) {
			first_rdesc = rdesc;
			first = false;
		}
		n_rdesc++;
	}

	if (unlikely(first)) {
		/*
		 * Special case: AEAD decrypt with only AAD data.
		 * In this case there is NO output data from the engine,
		 * but the engine still needs a result descriptor!
		 * Create a dummy one just for catching the result token.
		 */
		rdesc = safexcel_add_rdesc(rdr, true, true, 0, 0);
		if (IS_ERR(rdesc)) {
			/* No space left in the result descriptor ring */
			ret = PTR_ERR(rdesc);
			goto rdesc_rollback;
		}
		first_rdesc = rdesc;
		n_rdesc = 1;
	}

	safexcel_rdr_req_set(priv, ring, first_rdesc, base);

	*commands = n_cdesc;
	*results = n_rdesc;
	return 0;

rdesc_rollback:
	for (i = 0; i < n_rdesc; i++)
		safexcel_ring_rollback_wptr(rdr);
cdesc_rollback:
	for (i = 0; i < n_cdesc; i++)
		safexcel_ring_rollback_wptr(cdr);

	if (src == dst) {
		dma_unmap_sg(priv->dev, src, sreq->nr_src, DMA_BIDIRECTIONAL);
	} else {
		dma_unmap_sg(priv->dev, src, sreq->nr_src, DMA_TO_DEVICE);
		dma_unmap_sg(priv->dev, dst, sreq->nr_dst, DMA_FROM_DEVICE);
	}

	return ret;
}

static int safexcel_handle_inv_result(struct safexcel_crypto_priv *priv,
				      int ring,
				      struct crypto_async_request *base,
				      struct safexcel_cipher_req *sreq,
				      bool *should_complete, int *ret)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(base->tfm);
	struct safexcel_result_desc *rdesc;
	int ndesc = 0, enq_ret;

	*ret = 0;

	if (unlikely(!sreq->rdescs))
		return 0;

	while (sreq->rdescs--) {
		rdesc = safexcel_ring_next_rptr(&priv->ring[ring].rdr);
		if (IS_ERR(rdesc)) {
			dev_err(priv->dev,
				"cipher: invalidate: could not retrieve the result descriptor\n");
			*ret = PTR_ERR(rdesc);
			break;
		}
		ndesc++;
	}
	*ret = safexcel_rdesc_check_errors(priv, rdesc);

	safexcel_complete(priv, ring);

	if (ctx->base.exit_inv) {
		dma_pool_free(priv->context_pool, ctx->base.ctxr,
			      ctx->base.ctxr_dma);

		*should_complete = true;

		return ndesc;
	}

	ring = safexcel_select_ring(priv);
	ctx->base.ring = ring;

	spin_lock_bh(&priv->ring[ring].queue_lock);
	enq_ret = crypto_enqueue_request(&priv->ring[ring].queue, base);
	spin_unlock_bh(&priv->ring[ring].queue_lock);

	if (enq_ret != -EINPROGRESS)
		*ret = enq_ret;

	queue_work(priv->ring[ring].workqueue,
		   &priv->ring[ring].work_data.work);

	*should_complete = false;

	return ndesc;
}

static int safexcel_skcipher_handle_result(struct safexcel_crypto_priv *priv,
					   int ring,
					   struct crypto_async_request *async,
					   bool *should_complete, int *ret)
{
	struct skcipher_request *req = skcipher_request_cast(async);
	struct safexcel_cipher_req *sreq = skcipher_request_ctx(req);
	int err;

	if (sreq->needs_inv) {
		sreq->needs_inv = false;
		err = safexcel_handle_inv_result(priv, ring, async, sreq,
						 should_complete, ret);
	} else {
		err = safexcel_handle_req_result(priv, ring, async, req->src,
						 req->dst, req->cryptlen, sreq,
						 should_complete, ret);
	}

	return err;
}

static int safexcel_aead_handle_result(struct safexcel_crypto_priv *priv,
				       int ring,
				       struct crypto_async_request *async,
				       bool *should_complete, int *ret)
{
	struct aead_request *req = aead_request_cast(async);
	struct crypto_aead *tfm = crypto_aead_reqtfm(req);
	struct safexcel_cipher_req *sreq = aead_request_ctx(req);
	int err;

	if (sreq->needs_inv) {
		sreq->needs_inv = false;
		err = safexcel_handle_inv_result(priv, ring, async, sreq,
						 should_complete, ret);
	} else {
		err = safexcel_handle_req_result(priv, ring, async, req->src,
						 req->dst,
						 req->cryptlen + crypto_aead_authsize(tfm),
						 sreq, should_complete, ret);
	}

	return err;
}

static int safexcel_cipher_send_inv(struct crypto_async_request *base,
				    int ring, int *commands, int *results)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(base->tfm);
	struct safexcel_crypto_priv *priv = ctx->priv;
	int ret;

	ret = safexcel_invalidate_cache(base, priv, ctx->base.ctxr_dma, ring);
	if (unlikely(ret))
		return ret;

	*commands = 1;
	*results = 1;

	return 0;
}

static int safexcel_skcipher_send(struct crypto_async_request *async, int ring,
				  int *commands, int *results)
{
	struct skcipher_request *req = skcipher_request_cast(async);
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(req->base.tfm);
	struct safexcel_cipher_req *sreq = skcipher_request_ctx(req);
	struct safexcel_crypto_priv *priv = ctx->priv;
	int ret;

	BUG_ON(!(priv->flags & EIP197_TRC_CACHE) && sreq->needs_inv);

	if (sreq->needs_inv) {
		ret = safexcel_cipher_send_inv(async, ring, commands, results);
	} else {
		struct crypto_skcipher *skcipher = crypto_skcipher_reqtfm(req);
		u8 input_iv[AES_BLOCK_SIZE];

		/*
		 * Save input IV in case of CBC decrypt mode
		 * Will be overwritten with output IV prior to use!
		 */
		memcpy(input_iv, req->iv, crypto_skcipher_ivsize(skcipher));

		ret = safexcel_send_req(async, ring, sreq, req->src,
					req->dst, req->cryptlen, 0, 0, input_iv,
					commands, results);
	}

	sreq->rdescs = *results;
	return ret;
}

static int safexcel_aead_send(struct crypto_async_request *async, int ring,
			      int *commands, int *results)
{
	struct aead_request *req = aead_request_cast(async);
	struct crypto_aead *tfm = crypto_aead_reqtfm(req);
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(req->base.tfm);
	struct safexcel_cipher_req *sreq = aead_request_ctx(req);
	struct safexcel_crypto_priv *priv = ctx->priv;
	int ret;

	BUG_ON(!(priv->flags & EIP197_TRC_CACHE) && sreq->needs_inv);

	if (sreq->needs_inv)
		ret = safexcel_cipher_send_inv(async, ring, commands, results);
	else
		ret = safexcel_send_req(async, ring, sreq, req->src, req->dst,
					req->cryptlen, req->assoclen,
					crypto_aead_authsize(tfm), req->iv,
					commands, results);
	sreq->rdescs = *results;
	return ret;
}

static int safexcel_cipher_exit_inv(struct crypto_tfm *tfm,
				    struct crypto_async_request *base,
				    struct safexcel_cipher_req *sreq,
				    struct safexcel_inv_result *result)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);
	struct safexcel_crypto_priv *priv = ctx->priv;
	int ring = ctx->base.ring;

	init_completion(&result->completion);

	ctx = crypto_tfm_ctx(base->tfm);
	ctx->base.exit_inv = true;
	sreq->needs_inv = true;

	spin_lock_bh(&priv->ring[ring].queue_lock);
	crypto_enqueue_request(&priv->ring[ring].queue, base);
	spin_unlock_bh(&priv->ring[ring].queue_lock);

	queue_work(priv->ring[ring].workqueue,
		   &priv->ring[ring].work_data.work);

	wait_for_completion(&result->completion);

	if (result->error) {
		dev_warn(priv->dev,
			"cipher: sync: invalidate: completion error %d\n",
			 result->error);
		return result->error;
	}

	return 0;
}

static int safexcel_skcipher_exit_inv(struct crypto_tfm *tfm)
{
	EIP197_REQUEST_ON_STACK(req, skcipher, EIP197_SKCIPHER_REQ_SIZE);
	struct safexcel_cipher_req *sreq = skcipher_request_ctx(req);
	struct safexcel_inv_result result = {};

	memset(req, 0, sizeof(struct skcipher_request));

	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				      safexcel_inv_complete, &result);
	skcipher_request_set_tfm(req, __crypto_skcipher_cast(tfm));

	return safexcel_cipher_exit_inv(tfm, &req->base, sreq, &result);
}

static int safexcel_aead_exit_inv(struct crypto_tfm *tfm)
{
	EIP197_REQUEST_ON_STACK(req, aead, EIP197_AEAD_REQ_SIZE);
	struct safexcel_cipher_req *sreq = aead_request_ctx(req);
	struct safexcel_inv_result result = {};

	memset(req, 0, sizeof(struct aead_request));

	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				  safexcel_inv_complete, &result);
	aead_request_set_tfm(req, __crypto_aead_cast(tfm));

	return safexcel_cipher_exit_inv(tfm, &req->base, sreq, &result);
}

static int safexcel_queue_req(struct crypto_async_request *base,
			struct safexcel_cipher_req *sreq,
			enum safexcel_cipher_direction dir)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(base->tfm);
	struct safexcel_crypto_priv *priv = ctx->priv;
	int ret, ring;

	sreq->needs_inv = false;
	sreq->direction = dir;

	if (ctx->base.ctxr) {
		if (priv->flags & EIP197_TRC_CACHE && ctx->base.needs_inv) {
			sreq->needs_inv = true;
			ctx->base.needs_inv = false;
		}
	} else {
		ctx->base.ring = safexcel_select_ring(priv);
		ctx->base.ctxr = dma_pool_zalloc(priv->context_pool,
						 EIP197_GFP_FLAGS(*base),
						 &ctx->base.ctxr_dma);
		if (!ctx->base.ctxr)
			return -ENOMEM;
	}

	ring = ctx->base.ring;

	spin_lock_bh(&priv->ring[ring].queue_lock);
	ret = crypto_enqueue_request(&priv->ring[ring].queue, base);
	spin_unlock_bh(&priv->ring[ring].queue_lock);

	queue_work(priv->ring[ring].workqueue,
		   &priv->ring[ring].work_data.work);

	return ret;
}

static int safexcel_encrypt(struct skcipher_request *req)
{
	return safexcel_queue_req(&req->base, skcipher_request_ctx(req),
			SAFEXCEL_ENCRYPT);
}

static int safexcel_decrypt(struct skcipher_request *req)
{
	return safexcel_queue_req(&req->base, skcipher_request_ctx(req),
			SAFEXCEL_DECRYPT);
}

static int safexcel_skcipher_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);
	struct safexcel_alg_template *tmpl =
		container_of(tfm->__crt_alg, struct safexcel_alg_template,
			     alg.skcipher.base);

	crypto_skcipher_set_reqsize(__crypto_skcipher_cast(tfm),
				    sizeof(struct safexcel_cipher_req));

	ctx->priv = tmpl->priv;

	ctx->base.send = safexcel_skcipher_send;
	ctx->base.handle_result = safexcel_skcipher_handle_result;
	ctx->ivmask = EIP197_OPTION_4_TOKEN_IV_CMD;
	ctx->hash_alg = 0;
	return 0;
}

static int safexcel_cipher_cra_exit(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	memzero_explicit(ctx->key, sizeof(ctx->key));

	/* context not allocated, skip invalidation */
	if (!ctx->base.ctxr)
		return -ENOMEM;

	memzero_explicit(ctx->base.ctxr->data, sizeof(ctx->base.ctxr->data));
	return 0;
}

static void safexcel_skcipher_cra_exit(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);
	struct safexcel_crypto_priv *priv = ctx->priv;
	int ret;

	if (safexcel_cipher_cra_exit(tfm))
		return;

	if (priv->flags & EIP197_TRC_CACHE) {
		ret = safexcel_skcipher_exit_inv(tfm);
		if (ret)
			dev_warn(priv->dev, "skcipher: invalidation error %d\n",
				 ret);
	} else {
		dma_pool_free(priv->context_pool, ctx->base.ctxr,
			      ctx->base.ctxr_dma);
	}
}

static void safexcel_aead_cra_exit(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);
	struct safexcel_crypto_priv *priv = ctx->priv;
	int ret;

	if (safexcel_cipher_cra_exit(tfm))
		return;

	if (priv->flags & EIP197_TRC_CACHE) {
		ret = safexcel_aead_exit_inv(tfm);
		if (ret)
			dev_warn(priv->dev, "aead: invalidation error %d\n",
				 ret);
	} else {
		dma_pool_free(priv->context_pool, ctx->base.ctxr,
			      ctx->base.ctxr_dma);
	}
}

static int safexcel_skcipher_aes_ecb_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	safexcel_skcipher_cra_init(tfm);
	ctx->alg  = SAFEXCEL_AES;
	ctx->calg = CONTEXT_CONTROL_CRYPTO_ALG_AES256;
	ctx->mode = CONTEXT_CONTROL_CRYPTO_MODE_ECB;
	ctx->blocksz = 0;
	ctx->ivmask = EIP197_OPTION_2_TOKEN_IV_CMD;
	return 0;
}

struct safexcel_alg_template safexcel_alg_ecb_aes = {
	.type = SAFEXCEL_ALG_TYPE_SKCIPHER,
	.algo_mask = SAFEXCEL_ALG_AES,
	.alg.skcipher = {
		.setkey = safexcel_skcipher_aes_setkey,
		.encrypt = safexcel_encrypt,
		.decrypt = safexcel_decrypt,
		.min_keysize = AES_MIN_KEY_SIZE,
		.max_keysize = AES_MAX_KEY_SIZE,
		.base = {
			.cra_name = "ecb(aes)",
			.cra_driver_name = "safexcel-ecb-aes",
			.cra_priority = SAFEXCEL_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = AES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct safexcel_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = safexcel_skcipher_aes_ecb_cra_init,
			.cra_exit = safexcel_skcipher_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

static int safexcel_skcipher_aes_cbc_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	safexcel_skcipher_cra_init(tfm);
	ctx->alg  = SAFEXCEL_AES;
	ctx->calg = CONTEXT_CONTROL_CRYPTO_ALG_AES256;
	ctx->blocksz = AES_BLOCK_SIZE;
	ctx->mode = CONTEXT_CONTROL_CRYPTO_MODE_CBC;
	return 0;
}

struct safexcel_alg_template safexcel_alg_cbc_aes = {
	.type = SAFEXCEL_ALG_TYPE_SKCIPHER,
	.algo_mask = SAFEXCEL_ALG_AES,
	.alg.skcipher = {
		.setkey = safexcel_skcipher_aes_setkey,
		.encrypt = safexcel_encrypt,
		.decrypt = safexcel_decrypt,
		.min_keysize = AES_MIN_KEY_SIZE,
		.max_keysize = AES_MAX_KEY_SIZE,
		.ivsize = AES_BLOCK_SIZE,
		.base = {
			.cra_name = "cbc(aes)",
			.cra_driver_name = "safexcel-cbc-aes",
			.cra_priority = SAFEXCEL_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = AES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct safexcel_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = safexcel_skcipher_aes_cbc_cra_init,
			.cra_exit = safexcel_skcipher_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

static int safexcel_skcipher_aes_cfb_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	safexcel_skcipher_cra_init(tfm);
	ctx->alg  = SAFEXCEL_AES;
	ctx->calg = CONTEXT_CONTROL_CRYPTO_ALG_AES256;
	ctx->blocksz = AES_BLOCK_SIZE;
	ctx->mode = CONTEXT_CONTROL_CRYPTO_MODE_CFB;
	return 0;
}

struct safexcel_alg_template safexcel_alg_cfb_aes = {
	.type = SAFEXCEL_ALG_TYPE_SKCIPHER,
	.algo_mask = SAFEXCEL_ALG_AES | SAFEXCEL_ALG_AES_XFB,
	.alg.skcipher = {
		.setkey = safexcel_skcipher_aes_setkey,
		.encrypt = safexcel_encrypt,
		.decrypt = safexcel_decrypt,
		.min_keysize = AES_MIN_KEY_SIZE,
		.max_keysize = AES_MAX_KEY_SIZE,
		.ivsize = AES_BLOCK_SIZE,
		.base = {
			.cra_name = "cfb(aes)",
			.cra_driver_name = "safexcel-cfb-aes",
			.cra_priority = SAFEXCEL_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = 1,
			.cra_ctxsize = sizeof(struct safexcel_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = safexcel_skcipher_aes_cfb_cra_init,
			.cra_exit = safexcel_skcipher_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

static int safexcel_skcipher_aes_ofb_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	safexcel_skcipher_cra_init(tfm);
	ctx->alg  = SAFEXCEL_AES;
	ctx->calg = CONTEXT_CONTROL_CRYPTO_ALG_AES256;
	ctx->blocksz = AES_BLOCK_SIZE;
	ctx->mode = CONTEXT_CONTROL_CRYPTO_MODE_OFB;
	return 0;
}

struct safexcel_alg_template safexcel_alg_ofb_aes = {
	.type = SAFEXCEL_ALG_TYPE_SKCIPHER,
	.algo_mask = SAFEXCEL_ALG_AES | SAFEXCEL_ALG_AES_XFB,
	.alg.skcipher = {
		.setkey = safexcel_skcipher_aes_setkey,
		.encrypt = safexcel_encrypt,
		.decrypt = safexcel_decrypt,
		.min_keysize = AES_MIN_KEY_SIZE,
		.max_keysize = AES_MAX_KEY_SIZE,
		.ivsize = AES_BLOCK_SIZE,
		.base = {
			.cra_name = "ofb(aes)",
			.cra_driver_name = "safexcel-ofb-aes",
			.cra_priority = SAFEXCEL_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = 1,
			.cra_ctxsize = sizeof(struct safexcel_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = safexcel_skcipher_aes_ofb_cra_init,
			.cra_exit = safexcel_skcipher_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

static int safexcel_skcipher_aesctr_setkey(struct crypto_skcipher *ctfm,
					   const u8 *key, unsigned int len)
{
	struct crypto_tfm *tfm = crypto_skcipher_tfm(ctfm);
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	/* last 4 bytes of key are the nonce! */
	ctx->nonce = *(u32 *)(key + len - CTR_RFC3686_NONCE_SIZE);
	/* exclude the nonce here */
	len -= CTR_RFC3686_NONCE_SIZE;

	return safexcel_skcipher_aes_setkey(ctfm, key, len);
}

static int safexcel_skcipher_aes_ctr_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	safexcel_skcipher_cra_init(tfm);
	ctx->alg  = SAFEXCEL_AES;
	ctx->calg = CONTEXT_CONTROL_CRYPTO_ALG_AES256;
	ctx->blocksz = AES_BLOCK_SIZE;
	ctx->mode = CONTEXT_CONTROL_CRYPTO_MODE_CTR_LOAD;
	return 0;
}

struct safexcel_alg_template safexcel_alg_ctr_aes = {
	.type = SAFEXCEL_ALG_TYPE_SKCIPHER,
	.algo_mask = SAFEXCEL_ALG_AES,
	.alg.skcipher = {
		.setkey = safexcel_skcipher_aesctr_setkey,
		.encrypt = safexcel_encrypt,
		.decrypt = safexcel_decrypt,
		/* Add nonce size */
		.min_keysize = AES_MIN_KEY_SIZE + CTR_RFC3686_NONCE_SIZE,
		.max_keysize = AES_MAX_KEY_SIZE + CTR_RFC3686_NONCE_SIZE,
		.ivsize = CTR_RFC3686_IV_SIZE,
		.base = {
			.cra_name = "rfc3686(ctr(aes))",
			.cra_driver_name = "safexcel-ctr-aes",
			.cra_priority = SAFEXCEL_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = 1,
			.cra_ctxsize = sizeof(struct safexcel_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = safexcel_skcipher_aes_ctr_cra_init,
			.cra_exit = safexcel_skcipher_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};



static int safexcel_des_setkey(struct crypto_skcipher *ctfm, const u8 *key,
			       unsigned int len)
{
	struct safexcel_cipher_ctx *ctx = crypto_skcipher_ctx(ctfm);
	int ret;

	ret = verify_skcipher_des_key(ctfm, key);
	safexcel_skcipher_setkey(ctx, key, len);
	return ret;
}

static int safexcel_skcipher_des_cbc_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	safexcel_skcipher_cra_init(tfm);
	ctx->alg  = SAFEXCEL_DES;
	ctx->calg = CONTEXT_CONTROL_CRYPTO_ALG_DES;
	ctx->blocksz = DES_BLOCK_SIZE;
	ctx->ivmask = EIP197_OPTION_2_TOKEN_IV_CMD;
	ctx->mode = CONTEXT_CONTROL_CRYPTO_MODE_CBC;
	return 0;
}

struct safexcel_alg_template safexcel_alg_cbc_des = {
	.type = SAFEXCEL_ALG_TYPE_SKCIPHER,
	.algo_mask = SAFEXCEL_ALG_DES,
	.alg.skcipher = {
		.setkey = safexcel_des_setkey,
		.encrypt = safexcel_encrypt,
		.decrypt = safexcel_decrypt,
		.min_keysize = DES_KEY_SIZE,
		.max_keysize = DES_KEY_SIZE,
		.ivsize = DES_BLOCK_SIZE,
		.base = {
			.cra_name = "cbc(des)",
			.cra_driver_name = "safexcel-cbc-des",
			.cra_priority = SAFEXCEL_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = DES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct safexcel_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = safexcel_skcipher_des_cbc_cra_init,
			.cra_exit = safexcel_skcipher_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

static int safexcel_skcipher_des_ecb_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	safexcel_skcipher_cra_init(tfm);
	ctx->alg  = SAFEXCEL_DES;
	ctx->calg = CONTEXT_CONTROL_CRYPTO_ALG_DES;
	ctx->mode = CONTEXT_CONTROL_CRYPTO_MODE_ECB;
	ctx->blocksz = 0;
	ctx->ivmask = EIP197_OPTION_2_TOKEN_IV_CMD;
	return 0;
}

struct safexcel_alg_template safexcel_alg_ecb_des = {
	.type = SAFEXCEL_ALG_TYPE_SKCIPHER,
	.algo_mask = SAFEXCEL_ALG_DES,
	.alg.skcipher = {
		.setkey = safexcel_des_setkey,
		.encrypt = safexcel_encrypt,
		.decrypt = safexcel_decrypt,
		.min_keysize = DES_KEY_SIZE,
		.max_keysize = DES_KEY_SIZE,
		.base = {
			.cra_name = "ecb(des)",
			.cra_driver_name = "safexcel-ecb-des",
			.cra_priority = SAFEXCEL_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = DES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct safexcel_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = safexcel_skcipher_des_ecb_cra_init,
			.cra_exit = safexcel_skcipher_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

static int safexcel_des3_ede_setkey(struct crypto_skcipher *ctfm,
				   const u8 *key, unsigned int len)
{
	struct safexcel_cipher_ctx *ctx = crypto_skcipher_ctx(ctfm);
	int ret;

	ret = verify_skcipher_des3_key(ctfm, key);
	safexcel_skcipher_setkey(ctx, key, len);
	return ret;
}

static int safexcel_skcipher_des3_cbc_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	safexcel_skcipher_cra_init(tfm);
	ctx->alg  = SAFEXCEL_3DES;
	ctx->calg = CONTEXT_CONTROL_CRYPTO_ALG_3DES;
	ctx->blocksz = DES3_EDE_BLOCK_SIZE;
	ctx->ivmask = EIP197_OPTION_2_TOKEN_IV_CMD;
	ctx->mode = CONTEXT_CONTROL_CRYPTO_MODE_CBC;
	return 0;
}

struct safexcel_alg_template safexcel_alg_cbc_des3_ede = {
	.type = SAFEXCEL_ALG_TYPE_SKCIPHER,
	.algo_mask = SAFEXCEL_ALG_DES,
	.alg.skcipher = {
		.setkey = safexcel_des3_ede_setkey,
		.encrypt = safexcel_encrypt,
		.decrypt = safexcel_decrypt,
		.min_keysize = DES3_EDE_KEY_SIZE,
		.max_keysize = DES3_EDE_KEY_SIZE,
		.ivsize = DES3_EDE_BLOCK_SIZE,
		.base = {
			.cra_name = "cbc(des3_ede)",
			.cra_driver_name = "safexcel-cbc-des3_ede",
			.cra_priority = SAFEXCEL_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = DES3_EDE_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct safexcel_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = safexcel_skcipher_des3_cbc_cra_init,
			.cra_exit = safexcel_skcipher_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

static int safexcel_skcipher_des3_ecb_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	safexcel_skcipher_cra_init(tfm);
	ctx->alg  = SAFEXCEL_3DES;
	ctx->calg = CONTEXT_CONTROL_CRYPTO_ALG_3DES;
	ctx->mode = CONTEXT_CONTROL_CRYPTO_MODE_ECB;
	ctx->blocksz = 0;
	ctx->ivmask = EIP197_OPTION_2_TOKEN_IV_CMD;
	return 0;
}

struct safexcel_alg_template safexcel_alg_ecb_des3_ede = {
	.type = SAFEXCEL_ALG_TYPE_SKCIPHER,
	.algo_mask = SAFEXCEL_ALG_DES,
	.alg.skcipher = {
		.setkey = safexcel_des3_ede_setkey,
		.encrypt = safexcel_encrypt,
		.decrypt = safexcel_decrypt,
		.min_keysize = DES3_EDE_KEY_SIZE,
		.max_keysize = DES3_EDE_KEY_SIZE,
		.base = {
			.cra_name = "ecb(des3_ede)",
			.cra_driver_name = "safexcel-ecb-des3_ede",
			.cra_priority = SAFEXCEL_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = DES3_EDE_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct safexcel_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = safexcel_skcipher_des3_ecb_cra_init,
			.cra_exit = safexcel_skcipher_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

static int safexcel_aead_encrypt(struct aead_request *req)
{
	struct safexcel_cipher_req *creq = aead_request_ctx(req);

	return safexcel_queue_req(&req->base, creq, SAFEXCEL_ENCRYPT);
}

static int safexcel_aead_decrypt(struct aead_request *req)
{
	struct safexcel_cipher_req *creq = aead_request_ctx(req);

	return safexcel_queue_req(&req->base, creq, SAFEXCEL_DECRYPT);
}

static void safexcel_aead_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);
	struct safexcel_alg_template *tmpl =
		container_of(tfm->__crt_alg, struct safexcel_alg_template,
			     alg.aead.base);

	crypto_aead_set_reqsize(__crypto_aead_cast(tfm),
				sizeof(struct safexcel_cipher_req));

	ctx->priv = tmpl->priv;

	ctx->alg  = SAFEXCEL_AES; /* default */
	ctx->calg = CONTEXT_CONTROL_CRYPTO_ALG_AES256;
	ctx->blocksz = AES_BLOCK_SIZE;
	ctx->ivmask = EIP197_OPTION_4_TOKEN_IV_CMD;
	ctx->ctrinit = 1;
	ctx->mode = CONTEXT_CONTROL_CRYPTO_MODE_CBC; /* default */
	ctx->aead = true;
	ctx->base.send = safexcel_aead_send;
	ctx->base.handle_result = safexcel_aead_handle_result;
}

static int safexcel_aead_sha1_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	safexcel_aead_cra_init(tfm);
	ctx->hash_alg = CONTEXT_CONTROL_CRYPTO_ALG_SHA1;
	ctx->state_sz = SHA1_DIGEST_SIZE;
	return 0;
}

struct safexcel_alg_template safexcel_alg_authenc_hmac_sha1_cbc_aes = {
	.type = SAFEXCEL_ALG_TYPE_AEAD,
	.algo_mask = SAFEXCEL_ALG_AES | SAFEXCEL_ALG_SHA1,
	.alg.aead = {
		.setkey = safexcel_aead_setkey,
		.encrypt = safexcel_aead_encrypt,
		.decrypt = safexcel_aead_decrypt,
		.ivsize = AES_BLOCK_SIZE,
		.maxauthsize = SHA1_DIGEST_SIZE,
		.base = {
			.cra_name = "authenc(hmac(sha1),cbc(aes))",
			.cra_driver_name = "safexcel-authenc-hmac-sha1-cbc-aes",
			.cra_priority = SAFEXCEL_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = AES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct safexcel_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = safexcel_aead_sha1_cra_init,
			.cra_exit = safexcel_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

static int safexcel_aead_sha256_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	safexcel_aead_cra_init(tfm);
	ctx->hash_alg = CONTEXT_CONTROL_CRYPTO_ALG_SHA256;
	ctx->state_sz = SHA256_DIGEST_SIZE;
	return 0;
}

struct safexcel_alg_template safexcel_alg_authenc_hmac_sha256_cbc_aes = {
	.type = SAFEXCEL_ALG_TYPE_AEAD,
	.algo_mask = SAFEXCEL_ALG_AES | SAFEXCEL_ALG_SHA2_256,
	.alg.aead = {
		.setkey = safexcel_aead_setkey,
		.encrypt = safexcel_aead_encrypt,
		.decrypt = safexcel_aead_decrypt,
		.ivsize = AES_BLOCK_SIZE,
		.maxauthsize = SHA256_DIGEST_SIZE,
		.base = {
			.cra_name = "authenc(hmac(sha256),cbc(aes))",
			.cra_driver_name = "safexcel-authenc-hmac-sha256-cbc-aes",
			.cra_priority = SAFEXCEL_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = AES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct safexcel_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = safexcel_aead_sha256_cra_init,
			.cra_exit = safexcel_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

static int safexcel_aead_sha224_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	safexcel_aead_cra_init(tfm);
	ctx->hash_alg = CONTEXT_CONTROL_CRYPTO_ALG_SHA224;
	ctx->state_sz = SHA256_DIGEST_SIZE;
	return 0;
}

struct safexcel_alg_template safexcel_alg_authenc_hmac_sha224_cbc_aes = {
	.type = SAFEXCEL_ALG_TYPE_AEAD,
	.algo_mask = SAFEXCEL_ALG_AES | SAFEXCEL_ALG_SHA2_256,
	.alg.aead = {
		.setkey = safexcel_aead_setkey,
		.encrypt = safexcel_aead_encrypt,
		.decrypt = safexcel_aead_decrypt,
		.ivsize = AES_BLOCK_SIZE,
		.maxauthsize = SHA224_DIGEST_SIZE,
		.base = {
			.cra_name = "authenc(hmac(sha224),cbc(aes))",
			.cra_driver_name = "safexcel-authenc-hmac-sha224-cbc-aes",
			.cra_priority = SAFEXCEL_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = AES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct safexcel_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = safexcel_aead_sha224_cra_init,
			.cra_exit = safexcel_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

static int safexcel_aead_sha512_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	safexcel_aead_cra_init(tfm);
	ctx->hash_alg = CONTEXT_CONTROL_CRYPTO_ALG_SHA512;
	ctx->state_sz = SHA512_DIGEST_SIZE;
	return 0;
}

struct safexcel_alg_template safexcel_alg_authenc_hmac_sha512_cbc_aes = {
	.type = SAFEXCEL_ALG_TYPE_AEAD,
	.algo_mask = SAFEXCEL_ALG_AES | SAFEXCEL_ALG_SHA2_512,
	.alg.aead = {
		.setkey = safexcel_aead_setkey,
		.encrypt = safexcel_aead_encrypt,
		.decrypt = safexcel_aead_decrypt,
		.ivsize = AES_BLOCK_SIZE,
		.maxauthsize = SHA512_DIGEST_SIZE,
		.base = {
			.cra_name = "authenc(hmac(sha512),cbc(aes))",
			.cra_driver_name = "safexcel-authenc-hmac-sha512-cbc-aes",
			.cra_priority = SAFEXCEL_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = AES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct safexcel_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = safexcel_aead_sha512_cra_init,
			.cra_exit = safexcel_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

static int safexcel_aead_sha384_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	safexcel_aead_cra_init(tfm);
	ctx->hash_alg = CONTEXT_CONTROL_CRYPTO_ALG_SHA384;
	ctx->state_sz = SHA512_DIGEST_SIZE;
	return 0;
}

struct safexcel_alg_template safexcel_alg_authenc_hmac_sha384_cbc_aes = {
	.type = SAFEXCEL_ALG_TYPE_AEAD,
	.algo_mask = SAFEXCEL_ALG_AES | SAFEXCEL_ALG_SHA2_512,
	.alg.aead = {
		.setkey = safexcel_aead_setkey,
		.encrypt = safexcel_aead_encrypt,
		.decrypt = safexcel_aead_decrypt,
		.ivsize = AES_BLOCK_SIZE,
		.maxauthsize = SHA384_DIGEST_SIZE,
		.base = {
			.cra_name = "authenc(hmac(sha384),cbc(aes))",
			.cra_driver_name = "safexcel-authenc-hmac-sha384-cbc-aes",
			.cra_priority = SAFEXCEL_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = AES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct safexcel_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = safexcel_aead_sha384_cra_init,
			.cra_exit = safexcel_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

static int safexcel_aead_sha1_des3_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	safexcel_aead_sha1_cra_init(tfm);
	ctx->alg = SAFEXCEL_3DES; /* override default */
	ctx->calg = CONTEXT_CONTROL_CRYPTO_ALG_3DES;
	ctx->blocksz = DES3_EDE_BLOCK_SIZE;
	return 0;
}

struct safexcel_alg_template safexcel_alg_authenc_hmac_sha1_cbc_des3_ede = {
	.type = SAFEXCEL_ALG_TYPE_AEAD,
	.algo_mask = SAFEXCEL_ALG_DES | SAFEXCEL_ALG_SHA1,
	.alg.aead = {
		.setkey = safexcel_aead_setkey,
		.encrypt = safexcel_aead_encrypt,
		.decrypt = safexcel_aead_decrypt,
		.ivsize = DES3_EDE_BLOCK_SIZE,
		.maxauthsize = SHA1_DIGEST_SIZE,
		.base = {
			.cra_name = "authenc(hmac(sha1),cbc(des3_ede))",
			.cra_driver_name = "safexcel-authenc-hmac-sha1-cbc-des3_ede",
			.cra_priority = SAFEXCEL_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = DES3_EDE_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct safexcel_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = safexcel_aead_sha1_des3_cra_init,
			.cra_exit = safexcel_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

static int safexcel_aead_sha256_des3_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	safexcel_aead_sha256_cra_init(tfm);
	ctx->alg = SAFEXCEL_3DES; /* override default */
	ctx->calg = CONTEXT_CONTROL_CRYPTO_ALG_3DES;
	ctx->blocksz = DES3_EDE_BLOCK_SIZE;
	return 0;
}

struct safexcel_alg_template safexcel_alg_authenc_hmac_sha256_cbc_des3_ede = {
	.type = SAFEXCEL_ALG_TYPE_AEAD,
	.algo_mask = SAFEXCEL_ALG_DES | SAFEXCEL_ALG_SHA2_256,
	.alg.aead = {
		.setkey = safexcel_aead_setkey,
		.encrypt = safexcel_aead_encrypt,
		.decrypt = safexcel_aead_decrypt,
		.ivsize = DES3_EDE_BLOCK_SIZE,
		.maxauthsize = SHA256_DIGEST_SIZE,
		.base = {
			.cra_name = "authenc(hmac(sha256),cbc(des3_ede))",
			.cra_driver_name = "safexcel-authenc-hmac-sha256-cbc-des3_ede",
			.cra_priority = SAFEXCEL_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = DES3_EDE_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct safexcel_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = safexcel_aead_sha256_des3_cra_init,
			.cra_exit = safexcel_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

static int safexcel_aead_sha224_des3_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	safexcel_aead_sha224_cra_init(tfm);
	ctx->alg = SAFEXCEL_3DES; /* override default */
	ctx->calg = CONTEXT_CONTROL_CRYPTO_ALG_3DES;
	ctx->blocksz = DES3_EDE_BLOCK_SIZE;
	return 0;
}

struct safexcel_alg_template safexcel_alg_authenc_hmac_sha224_cbc_des3_ede = {
	.type = SAFEXCEL_ALG_TYPE_AEAD,
	.algo_mask = SAFEXCEL_ALG_DES | SAFEXCEL_ALG_SHA2_256,
	.alg.aead = {
		.setkey = safexcel_aead_setkey,
		.encrypt = safexcel_aead_encrypt,
		.decrypt = safexcel_aead_decrypt,
		.ivsize = DES3_EDE_BLOCK_SIZE,
		.maxauthsize = SHA224_DIGEST_SIZE,
		.base = {
			.cra_name = "authenc(hmac(sha224),cbc(des3_ede))",
			.cra_driver_name = "safexcel-authenc-hmac-sha224-cbc-des3_ede",
			.cra_priority = SAFEXCEL_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = DES3_EDE_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct safexcel_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = safexcel_aead_sha224_des3_cra_init,
			.cra_exit = safexcel_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

static int safexcel_aead_sha512_des3_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	safexcel_aead_sha512_cra_init(tfm);
	ctx->alg = SAFEXCEL_3DES; /* override default */
	ctx->calg = CONTEXT_CONTROL_CRYPTO_ALG_3DES;
	ctx->blocksz = DES3_EDE_BLOCK_SIZE;
	return 0;
}

struct safexcel_alg_template safexcel_alg_authenc_hmac_sha512_cbc_des3_ede = {
	.type = SAFEXCEL_ALG_TYPE_AEAD,
	.algo_mask = SAFEXCEL_ALG_DES | SAFEXCEL_ALG_SHA2_512,
	.alg.aead = {
		.setkey = safexcel_aead_setkey,
		.encrypt = safexcel_aead_encrypt,
		.decrypt = safexcel_aead_decrypt,
		.ivsize = DES3_EDE_BLOCK_SIZE,
		.maxauthsize = SHA512_DIGEST_SIZE,
		.base = {
			.cra_name = "authenc(hmac(sha512),cbc(des3_ede))",
			.cra_driver_name = "safexcel-authenc-hmac-sha512-cbc-des3_ede",
			.cra_priority = SAFEXCEL_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = DES3_EDE_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct safexcel_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = safexcel_aead_sha512_des3_cra_init,
			.cra_exit = safexcel_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

static int safexcel_aead_sha384_des3_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	safexcel_aead_sha384_cra_init(tfm);
	ctx->alg = SAFEXCEL_3DES; /* override default */
	ctx->calg = CONTEXT_CONTROL_CRYPTO_ALG_3DES;
	ctx->blocksz = DES3_EDE_BLOCK_SIZE;
	return 0;
}

struct safexcel_alg_template safexcel_alg_authenc_hmac_sha384_cbc_des3_ede = {
	.type = SAFEXCEL_ALG_TYPE_AEAD,
	.algo_mask = SAFEXCEL_ALG_DES | SAFEXCEL_ALG_SHA2_512,
	.alg.aead = {
		.setkey = safexcel_aead_setkey,
		.encrypt = safexcel_aead_encrypt,
		.decrypt = safexcel_aead_decrypt,
		.ivsize = DES3_EDE_BLOCK_SIZE,
		.maxauthsize = SHA384_DIGEST_SIZE,
		.base = {
			.cra_name = "authenc(hmac(sha384),cbc(des3_ede))",
			.cra_driver_name = "safexcel-authenc-hmac-sha384-cbc-des3_ede",
			.cra_priority = SAFEXCEL_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = DES3_EDE_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct safexcel_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = safexcel_aead_sha384_des3_cra_init,
			.cra_exit = safexcel_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

static int safexcel_aead_sha1_des_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	safexcel_aead_sha1_cra_init(tfm);
	ctx->alg = SAFEXCEL_DES; /* override default */
	ctx->calg = CONTEXT_CONTROL_CRYPTO_ALG_DES;
	ctx->blocksz = DES_BLOCK_SIZE;
	return 0;
}

struct safexcel_alg_template safexcel_alg_authenc_hmac_sha1_cbc_des = {
	.type = SAFEXCEL_ALG_TYPE_AEAD,
	.algo_mask = SAFEXCEL_ALG_DES | SAFEXCEL_ALG_SHA1,
	.alg.aead = {
		.setkey = safexcel_aead_setkey,
		.encrypt = safexcel_aead_encrypt,
		.decrypt = safexcel_aead_decrypt,
		.ivsize = DES_BLOCK_SIZE,
		.maxauthsize = SHA1_DIGEST_SIZE,
		.base = {
			.cra_name = "authenc(hmac(sha1),cbc(des))",
			.cra_driver_name = "safexcel-authenc-hmac-sha1-cbc-des",
			.cra_priority = SAFEXCEL_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = DES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct safexcel_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = safexcel_aead_sha1_des_cra_init,
			.cra_exit = safexcel_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

static int safexcel_aead_sha256_des_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	safexcel_aead_sha256_cra_init(tfm);
	ctx->alg = SAFEXCEL_DES; /* override default */
	ctx->calg = CONTEXT_CONTROL_CRYPTO_ALG_DES;
	ctx->blocksz = DES_BLOCK_SIZE;
	return 0;
}

struct safexcel_alg_template safexcel_alg_authenc_hmac_sha256_cbc_des = {
	.type = SAFEXCEL_ALG_TYPE_AEAD,
	.algo_mask = SAFEXCEL_ALG_DES | SAFEXCEL_ALG_SHA2_256,
	.alg.aead = {
		.setkey = safexcel_aead_setkey,
		.encrypt = safexcel_aead_encrypt,
		.decrypt = safexcel_aead_decrypt,
		.ivsize = DES_BLOCK_SIZE,
		.maxauthsize = SHA256_DIGEST_SIZE,
		.base = {
			.cra_name = "authenc(hmac(sha256),cbc(des))",
			.cra_driver_name = "safexcel-authenc-hmac-sha256-cbc-des",
			.cra_priority = SAFEXCEL_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = DES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct safexcel_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = safexcel_aead_sha256_des_cra_init,
			.cra_exit = safexcel_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

static int safexcel_aead_sha224_des_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	safexcel_aead_sha224_cra_init(tfm);
	ctx->alg = SAFEXCEL_DES; /* override default */
	ctx->calg = CONTEXT_CONTROL_CRYPTO_ALG_DES;
	ctx->blocksz = DES_BLOCK_SIZE;
	return 0;
}

struct safexcel_alg_template safexcel_alg_authenc_hmac_sha224_cbc_des = {
	.type = SAFEXCEL_ALG_TYPE_AEAD,
	.algo_mask = SAFEXCEL_ALG_DES | SAFEXCEL_ALG_SHA2_256,
	.alg.aead = {
		.setkey = safexcel_aead_setkey,
		.encrypt = safexcel_aead_encrypt,
		.decrypt = safexcel_aead_decrypt,
		.ivsize = DES_BLOCK_SIZE,
		.maxauthsize = SHA224_DIGEST_SIZE,
		.base = {
			.cra_name = "authenc(hmac(sha224),cbc(des))",
			.cra_driver_name = "safexcel-authenc-hmac-sha224-cbc-des",
			.cra_priority = SAFEXCEL_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = DES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct safexcel_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = safexcel_aead_sha224_des_cra_init,
			.cra_exit = safexcel_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

static int safexcel_aead_sha512_des_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	safexcel_aead_sha512_cra_init(tfm);
	ctx->alg = SAFEXCEL_DES; /* override default */
	ctx->calg = CONTEXT_CONTROL_CRYPTO_ALG_DES;
	ctx->blocksz = DES_BLOCK_SIZE;
	return 0;
}

struct safexcel_alg_template safexcel_alg_authenc_hmac_sha512_cbc_des = {
	.type = SAFEXCEL_ALG_TYPE_AEAD,
	.algo_mask = SAFEXCEL_ALG_DES | SAFEXCEL_ALG_SHA2_512,
	.alg.aead = {
		.setkey = safexcel_aead_setkey,
		.encrypt = safexcel_aead_encrypt,
		.decrypt = safexcel_aead_decrypt,
		.ivsize = DES_BLOCK_SIZE,
		.maxauthsize = SHA512_DIGEST_SIZE,
		.base = {
			.cra_name = "authenc(hmac(sha512),cbc(des))",
			.cra_driver_name = "safexcel-authenc-hmac-sha512-cbc-des",
			.cra_priority = SAFEXCEL_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = DES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct safexcel_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = safexcel_aead_sha512_des_cra_init,
			.cra_exit = safexcel_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

static int safexcel_aead_sha384_des_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	safexcel_aead_sha384_cra_init(tfm);
	ctx->alg = SAFEXCEL_DES; /* override default */
	ctx->calg = CONTEXT_CONTROL_CRYPTO_ALG_DES;
	ctx->blocksz = DES_BLOCK_SIZE;
	return 0;
}

struct safexcel_alg_template safexcel_alg_authenc_hmac_sha384_cbc_des = {
	.type = SAFEXCEL_ALG_TYPE_AEAD,
	.algo_mask = SAFEXCEL_ALG_DES | SAFEXCEL_ALG_SHA2_512,
	.alg.aead = {
		.setkey = safexcel_aead_setkey,
		.encrypt = safexcel_aead_encrypt,
		.decrypt = safexcel_aead_decrypt,
		.ivsize = DES_BLOCK_SIZE,
		.maxauthsize = SHA384_DIGEST_SIZE,
		.base = {
			.cra_name = "authenc(hmac(sha384),cbc(des))",
			.cra_driver_name = "safexcel-authenc-hmac-sha384-cbc-des",
			.cra_priority = SAFEXCEL_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = DES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct safexcel_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = safexcel_aead_sha384_des_cra_init,
			.cra_exit = safexcel_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

static int safexcel_aead_sha1_ctr_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	safexcel_aead_sha1_cra_init(tfm);
	ctx->mode = CONTEXT_CONTROL_CRYPTO_MODE_CTR_LOAD; /* override default */
	ctx->aead  = EIP197_AEAD_TYPE_IPSEC_CTR;
	return 0;
}

struct safexcel_alg_template safexcel_alg_authenc_hmac_sha1_ctr_aes = {
	.type = SAFEXCEL_ALG_TYPE_AEAD,
	.algo_mask = SAFEXCEL_ALG_AES | SAFEXCEL_ALG_SHA1,
	.alg.aead = {
		.setkey = safexcel_aead_setkey,
		.encrypt = safexcel_aead_encrypt,
		.decrypt = safexcel_aead_decrypt,
		.ivsize = CTR_RFC3686_IV_SIZE,
		.maxauthsize = SHA1_DIGEST_SIZE,
		.base = {
			.cra_name = "authenc(hmac(sha1),rfc3686(ctr(aes)))",
			.cra_driver_name = "safexcel-authenc-hmac-sha1-ctr-aes",
			.cra_priority = SAFEXCEL_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = 1,
			.cra_ctxsize = sizeof(struct safexcel_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = safexcel_aead_sha1_ctr_cra_init,
			.cra_exit = safexcel_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

static int safexcel_aead_sha256_ctr_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	safexcel_aead_sha256_cra_init(tfm);
	ctx->mode = CONTEXT_CONTROL_CRYPTO_MODE_CTR_LOAD; /* override default */
	ctx->aead  = EIP197_AEAD_TYPE_IPSEC_CTR;
	return 0;
}

struct safexcel_alg_template safexcel_alg_authenc_hmac_sha256_ctr_aes = {
	.type = SAFEXCEL_ALG_TYPE_AEAD,
	.algo_mask = SAFEXCEL_ALG_AES | SAFEXCEL_ALG_SHA2_256,
	.alg.aead = {
		.setkey = safexcel_aead_setkey,
		.encrypt = safexcel_aead_encrypt,
		.decrypt = safexcel_aead_decrypt,
		.ivsize = CTR_RFC3686_IV_SIZE,
		.maxauthsize = SHA256_DIGEST_SIZE,
		.base = {
			.cra_name = "authenc(hmac(sha256),rfc3686(ctr(aes)))",
			.cra_driver_name = "safexcel-authenc-hmac-sha256-ctr-aes",
			.cra_priority = SAFEXCEL_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = 1,
			.cra_ctxsize = sizeof(struct safexcel_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = safexcel_aead_sha256_ctr_cra_init,
			.cra_exit = safexcel_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

static int safexcel_aead_sha224_ctr_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	safexcel_aead_sha224_cra_init(tfm);
	ctx->mode = CONTEXT_CONTROL_CRYPTO_MODE_CTR_LOAD; /* override default */
	ctx->aead  = EIP197_AEAD_TYPE_IPSEC_CTR;
	return 0;
}

struct safexcel_alg_template safexcel_alg_authenc_hmac_sha224_ctr_aes = {
	.type = SAFEXCEL_ALG_TYPE_AEAD,
	.algo_mask = SAFEXCEL_ALG_AES | SAFEXCEL_ALG_SHA2_256,
	.alg.aead = {
		.setkey = safexcel_aead_setkey,
		.encrypt = safexcel_aead_encrypt,
		.decrypt = safexcel_aead_decrypt,
		.ivsize = CTR_RFC3686_IV_SIZE,
		.maxauthsize = SHA224_DIGEST_SIZE,
		.base = {
			.cra_name = "authenc(hmac(sha224),rfc3686(ctr(aes)))",
			.cra_driver_name = "safexcel-authenc-hmac-sha224-ctr-aes",
			.cra_priority = SAFEXCEL_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = 1,
			.cra_ctxsize = sizeof(struct safexcel_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = safexcel_aead_sha224_ctr_cra_init,
			.cra_exit = safexcel_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

static int safexcel_aead_sha512_ctr_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	safexcel_aead_sha512_cra_init(tfm);
	ctx->mode = CONTEXT_CONTROL_CRYPTO_MODE_CTR_LOAD; /* override default */
	ctx->aead  = EIP197_AEAD_TYPE_IPSEC_CTR;
	return 0;
}

struct safexcel_alg_template safexcel_alg_authenc_hmac_sha512_ctr_aes = {
	.type = SAFEXCEL_ALG_TYPE_AEAD,
	.algo_mask = SAFEXCEL_ALG_AES | SAFEXCEL_ALG_SHA2_512,
	.alg.aead = {
		.setkey = safexcel_aead_setkey,
		.encrypt = safexcel_aead_encrypt,
		.decrypt = safexcel_aead_decrypt,
		.ivsize = CTR_RFC3686_IV_SIZE,
		.maxauthsize = SHA512_DIGEST_SIZE,
		.base = {
			.cra_name = "authenc(hmac(sha512),rfc3686(ctr(aes)))",
			.cra_driver_name = "safexcel-authenc-hmac-sha512-ctr-aes",
			.cra_priority = SAFEXCEL_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = 1,
			.cra_ctxsize = sizeof(struct safexcel_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = safexcel_aead_sha512_ctr_cra_init,
			.cra_exit = safexcel_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

static int safexcel_aead_sha384_ctr_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	safexcel_aead_sha384_cra_init(tfm);
	ctx->mode = CONTEXT_CONTROL_CRYPTO_MODE_CTR_LOAD; /* override default */
	ctx->aead  = EIP197_AEAD_TYPE_IPSEC_CTR;
	return 0;
}

struct safexcel_alg_template safexcel_alg_authenc_hmac_sha384_ctr_aes = {
	.type = SAFEXCEL_ALG_TYPE_AEAD,
	.algo_mask = SAFEXCEL_ALG_AES | SAFEXCEL_ALG_SHA2_512,
	.alg.aead = {
		.setkey = safexcel_aead_setkey,
		.encrypt = safexcel_aead_encrypt,
		.decrypt = safexcel_aead_decrypt,
		.ivsize = CTR_RFC3686_IV_SIZE,
		.maxauthsize = SHA384_DIGEST_SIZE,
		.base = {
			.cra_name = "authenc(hmac(sha384),rfc3686(ctr(aes)))",
			.cra_driver_name = "safexcel-authenc-hmac-sha384-ctr-aes",
			.cra_priority = SAFEXCEL_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = 1,
			.cra_ctxsize = sizeof(struct safexcel_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = safexcel_aead_sha384_ctr_cra_init,
			.cra_exit = safexcel_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

static int safexcel_skcipher_aesxts_setkey(struct crypto_skcipher *ctfm,
					   const u8 *key, unsigned int len)
{
	struct crypto_tfm *tfm = crypto_skcipher_tfm(ctfm);
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);
	int ret;

	/* Check for illegal XTS keys */
	ret = xts_verify_key(ctfm, key, len);
	if (ret)
		return ret;

	/* Only half of the key data is cipher key */
	ret = safexcel_aes_setkey_size(tfm, len >> 1);
	if (unlikely(ret))
		return ret;
	safexcel_skcipher_setkey(ctx, key, len);
	return 0;
}

static int safexcel_skcipher_aes_xts_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	safexcel_skcipher_cra_init(tfm);
	ctx->alg  = SAFEXCEL_AES;
	ctx->calg = CONTEXT_CONTROL_CRYPTO_ALG_AES256;
	ctx->blocksz = AES_BLOCK_SIZE;
	ctx->mode = CONTEXT_CONTROL_CRYPTO_MODE_XTS;
	return 0;
}

static int safexcel_encrypt_xts(struct skcipher_request *req)
{
	if (req->cryptlen < XTS_BLOCK_SIZE)
		return -EINVAL;
	return safexcel_queue_req(&req->base, skcipher_request_ctx(req),
				  SAFEXCEL_ENCRYPT);
}

static int safexcel_decrypt_xts(struct skcipher_request *req)
{
	if (req->cryptlen < XTS_BLOCK_SIZE)
		return -EINVAL;
	return safexcel_queue_req(&req->base, skcipher_request_ctx(req),
				  SAFEXCEL_DECRYPT);
}

struct safexcel_alg_template safexcel_alg_xts_aes = {
	.type = SAFEXCEL_ALG_TYPE_SKCIPHER,
	.algo_mask = SAFEXCEL_ALG_AES | SAFEXCEL_ALG_AES_XTS,
	.alg.skcipher = {
		.setkey = safexcel_skcipher_aesxts_setkey,
		.encrypt = safexcel_encrypt_xts,
		.decrypt = safexcel_decrypt_xts,
		/* XTS actually uses 2 AES keys glued together */
		.min_keysize = AES_MIN_KEY_SIZE * 2,
		.max_keysize = AES_MAX_KEY_SIZE * 2,
		.ivsize = XTS_BLOCK_SIZE,
		.base = {
			.cra_name = "xts(aes)",
			.cra_driver_name = "safexcel-xts-aes",
			.cra_priority = SAFEXCEL_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = XTS_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct safexcel_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = safexcel_skcipher_aes_xts_cra_init,
			.cra_exit = safexcel_skcipher_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

static int safexcel_aead_gcm_setkey(struct crypto_aead *ctfm, const u8 *key,
				    unsigned int len)
{
	struct crypto_tfm *tfm = crypto_aead_tfm(ctfm);
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);
	u32 hashkey[AES_BLOCK_SIZE / sizeof(u32)];
	int ret, i;

	ret = safexcel_aes_setkey(tfm, key, len);
	if (unlikely(ret))
		return ret;

	/* Compute hash key by encrypting zeroes with cipher key */
	crypto_cipher_clear_flags(ctx->hkaes, CRYPTO_TFM_REQ_MASK);
	crypto_cipher_set_flags(ctx->hkaes, crypto_aead_get_flags(ctfm) &
				CRYPTO_TFM_REQ_MASK);
	ret = crypto_cipher_setkey(ctx->hkaes, key, len);
	crypto_aead_set_flags(ctfm, crypto_cipher_get_flags(ctx->hkaes) &
			      CRYPTO_TFM_RES_MASK);
	if (unlikely(ret))
		return ret;

	memset(hashkey, 0, AES_BLOCK_SIZE);
	crypto_cipher_encrypt_one(ctx->hkaes, (u8 *)hashkey, (u8 *)hashkey);

	for (i = 0; i < AES_BLOCK_SIZE / sizeof(u32); i++)
		ctx->ipad[i] = cpu_to_be32(hashkey[i]);

	memzero_explicit(hashkey, AES_BLOCK_SIZE);

	/* Precompute control values for encrypt and decrypt */
	ctx->cctrl_enc = ctx->calg | ((u64)ctx->mode << 32) |
			 CONTEXT_CONTROL_CRYPTO_ALG_GHASH |
			 CONTEXT_CONTROL_DIGEST_XCM | CONTEXT_CONTROL_KEY_EN |
			 CONTEXT_CONTROL_SIZE((len + GHASH_BLOCK_SIZE) /
					      sizeof(u32));
	if (ctx->aead == EIP197_AEAD_TYPE_IPSEC_ESP_GMAC)
		ctx->cctrl_enc |= CONTEXT_CONTROL_TYPE_HASH_ENCRYPT_OUT;
	else
		ctx->cctrl_enc |= CONTEXT_CONTROL_TYPE_ENCRYPT_HASH_OUT;
	ctx->cctrl_dec = ctx->calg | ((u64)ctx->mode << 32) |
			 CONTEXT_CONTROL_CRYPTO_ALG_GHASH |
			 CONTEXT_CONTROL_DIGEST_XCM | CONTEXT_CONTROL_KEY_EN |
			 CONTEXT_CONTROL_TYPE_HASH_DECRYPT_IN |
			 CONTEXT_CONTROL_SIZE((len + GHASH_BLOCK_SIZE) /
					      sizeof(u32));
	return 0;
}

static int safexcel_aead_gcm_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	safexcel_aead_cra_init(tfm);
	ctx->hash_alg = CONTEXT_CONTROL_CRYPTO_ALG_GHASH;
	ctx->state_sz = GHASH_BLOCK_SIZE;
	ctx->xcm = EIP197_XCM_MODE_GCM;
	ctx->mode = CONTEXT_CONTROL_CRYPTO_MODE_XCM; /* override default */

	ctx->hkaes = crypto_alloc_cipher("aes", 0, 0);
	if (IS_ERR(ctx->hkaes))
		return PTR_ERR(ctx->hkaes);

	return 0;
}

static void safexcel_aead_gcm_cra_exit(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	crypto_free_cipher(ctx->hkaes);
	safexcel_aead_cra_exit(tfm);
}

static int safexcel_aead_gcm_setauthsize(struct crypto_aead *tfm,
					 unsigned int authsize)
{
	return crypto_gcm_check_authsize(authsize);
}

struct safexcel_alg_template safexcel_alg_gcm = {
	.type = SAFEXCEL_ALG_TYPE_AEAD,
	.algo_mask = SAFEXCEL_ALG_AES | SAFEXCEL_ALG_GHASH,
	.alg.aead = {
		.setkey = safexcel_aead_gcm_setkey,
		.setauthsize = safexcel_aead_gcm_setauthsize,
		.encrypt = safexcel_aead_encrypt,
		.decrypt = safexcel_aead_decrypt,
		.ivsize = GCM_AES_IV_SIZE,
		.maxauthsize = GHASH_DIGEST_SIZE,
		.base = {
			.cra_name = "gcm(aes)",
			.cra_driver_name = "safexcel-gcm-aes",
			.cra_priority = SAFEXCEL_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = 1,
			.cra_ctxsize = sizeof(struct safexcel_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = safexcel_aead_gcm_cra_init,
			.cra_exit = safexcel_aead_gcm_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

static int safexcel_aead_ccm_setkey(struct crypto_aead *ctfm, const u8 *key,
				    unsigned int len)
{
	struct crypto_tfm *tfm = crypto_aead_tfm(ctfm);
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);
	int ret, i;

	ret = safexcel_aes_setkey(tfm, key, len);
	if (unlikely(ret))
		return ret;

	for (i = 0; i < len / sizeof(u32); i++)
		ctx->ipad[i + 2 * AES_BLOCK_SIZE / sizeof(u32)] =
			cpu_to_be32(get_unaligned_le32(key + i * sizeof(u32)));

	ctx->state_sz = 2 * AES_BLOCK_SIZE + len;

	if (len == AES_KEYSIZE_128)
		ctx->hash_alg = CONTEXT_CONTROL_CRYPTO_ALG_XCBC128;
	else if (len == AES_KEYSIZE_192)
		ctx->hash_alg = CONTEXT_CONTROL_CRYPTO_ALG_XCBC192;
	else
		ctx->hash_alg = CONTEXT_CONTROL_CRYPTO_ALG_XCBC256;

	/* Precompute control values for encrypt and decrypt */
	ctx->cctrl_enc = ctx->calg | ctx->hash_alg | ((u64)ctx->mode << 32) |
			 CONTEXT_CONTROL_DIGEST_XCM | CONTEXT_CONTROL_KEY_EN |
			 CONTEXT_CONTROL_TYPE_HASH_ENCRYPT_OUT |
			 CONTEXT_CONTROL_SIZE((len + AES_BLOCK_SIZE) / 2);
	ctx->cctrl_dec = ctx->calg | ctx->hash_alg | ((u64)ctx->mode << 32) |
			 CONTEXT_CONTROL_DIGEST_XCM | CONTEXT_CONTROL_KEY_EN |
			 CONTEXT_CONTROL_TYPE_DECRYPT_HASH_IN |
			 CONTEXT_CONTROL_SIZE((len + AES_BLOCK_SIZE) / 2);
	return 0;
}

static int safexcel_aead_ccm_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	safexcel_aead_cra_init(tfm);
	ctx->hash_alg = CONTEXT_CONTROL_CRYPTO_ALG_XCBC128;
	ctx->state_sz = 3 * AES_BLOCK_SIZE;
	ctx->xcm = EIP197_XCM_MODE_CCM;
	ctx->mode = CONTEXT_CONTROL_CRYPTO_MODE_XCM; /* override default */
	return 0;
}

static int safexcel_aead_ccm_setauthsize(struct crypto_aead *tfm,
					 unsigned int authsize)
{
	/* Borrowed from crypto/ccm.c */
	switch (authsize) {
	case 4:
	case 6:
	case 8:
	case 10:
	case 12:
	case 14:
	case 16:
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int safexcel_ccm_encrypt(struct aead_request *req)
{
	struct safexcel_cipher_req *creq = aead_request_ctx(req);

	if (req->iv[0] < 1 || req->iv[0] > 7)
		return -EINVAL;

	return safexcel_queue_req(&req->base, creq, SAFEXCEL_ENCRYPT);
}

static int safexcel_ccm_decrypt(struct aead_request *req)
{
	struct safexcel_cipher_req *creq = aead_request_ctx(req);

	if (req->iv[0] < 1 || req->iv[0] > 7)
		return -EINVAL;

	return safexcel_queue_req(&req->base, creq, SAFEXCEL_DECRYPT);
}

struct safexcel_alg_template safexcel_alg_ccm = {
	.type = SAFEXCEL_ALG_TYPE_AEAD,
	.algo_mask = SAFEXCEL_ALG_AES | SAFEXCEL_ALG_CBC_MAC_ALL,
	.alg.aead = {
		.setkey = safexcel_aead_ccm_setkey,
		.setauthsize = safexcel_aead_ccm_setauthsize,
		.encrypt = safexcel_ccm_encrypt,
		.decrypt = safexcel_ccm_decrypt,
		.ivsize = AES_BLOCK_SIZE,
		.maxauthsize = AES_BLOCK_SIZE,
		.base = {
			.cra_name = "ccm(aes)",
			.cra_driver_name = "safexcel-ccm-aes",
			.cra_priority = SAFEXCEL_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = 1,
			.cra_ctxsize = sizeof(struct safexcel_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = safexcel_aead_ccm_cra_init,
			.cra_exit = safexcel_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

static int safexcel_skcipher_chacha20_setkey(struct crypto_skcipher *ctfm,
					     const u8 *key, unsigned int len)
{
	struct safexcel_cipher_ctx *ctx = crypto_skcipher_ctx(ctfm);

	if (len != CHACHA_KEY_SIZE) {
		crypto_skcipher_set_flags(ctfm, CRYPTO_TFM_RES_BAD_KEY_LEN);
		return -EINVAL;
	}
	safexcel_skcipher_setkey(ctx, key, len);
	return 0;
}

static int safexcel_skcipher_chacha20_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	safexcel_skcipher_cra_init(tfm);
	ctx->alg  = SAFEXCEL_CHACHA20;
	ctx->calg = CONTEXT_CONTROL_CRYPTO_ALG_CHACHA20;
	ctx->mode = CONTEXT_CONTROL_CHACHA20_MODE_256_32;
	return 0;
}

struct safexcel_alg_template safexcel_alg_chacha20 = {
	.type = SAFEXCEL_ALG_TYPE_SKCIPHER,
	.algo_mask = SAFEXCEL_ALG_CHACHA20,
	.alg.skcipher = {
		.setkey = safexcel_skcipher_chacha20_setkey,
		.encrypt = safexcel_encrypt,
		.decrypt = safexcel_decrypt,
		.min_keysize = CHACHA_KEY_SIZE,
		.max_keysize = CHACHA_KEY_SIZE,
		.ivsize = CHACHA_IV_SIZE,
		.base = {
			.cra_name = "chacha20",
			.cra_driver_name = "safexcel-chacha20",
			.cra_priority = SAFEXCEL_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = 1,
			.cra_ctxsize = sizeof(struct safexcel_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = safexcel_skcipher_chacha20_cra_init,
			.cra_exit = safexcel_skcipher_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

static int safexcel_aead_chachapoly_setkey(struct crypto_aead *ctfm,
				    const u8 *key, unsigned int len)
{
	struct safexcel_cipher_ctx *ctx = crypto_aead_ctx(ctfm);

	if (ctx->aead  == EIP197_AEAD_TYPE_IPSEC_ESP &&
	    len > EIP197_AEAD_IPSEC_NONCE_SIZE) {
		/* ESP variant has nonce appended to key */
		len -= EIP197_AEAD_IPSEC_NONCE_SIZE;
		ctx->nonce = *(u32 *)(key + len);
	}
	if (len != CHACHA_KEY_SIZE) {
		crypto_aead_set_flags(ctfm, CRYPTO_TFM_RES_BAD_KEY_LEN);
		return -EINVAL;
	}
	safexcel_setkey(ctx, key, len);
	return 0;
}

static int safexcel_aead_chachapoly_setauthsize(struct crypto_aead *tfm,
					 unsigned int authsize)
{
	if (authsize != POLY1305_DIGEST_SIZE)
		return -EINVAL;
	return 0;
}

static int safexcel_aead_chachapoly_crypt(struct aead_request *req,
					  enum safexcel_cipher_direction dir)
{
	struct safexcel_cipher_req *creq = aead_request_ctx(req);
	struct crypto_aead *aead = crypto_aead_reqtfm(req);
	struct crypto_tfm *tfm = crypto_aead_tfm(aead);
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);
	struct aead_request *subreq = aead_request_ctx(req);
	u32 key[CHACHA_KEY_SIZE / sizeof(u32) + 1];
	int i, ret = 0;

	/*
	 * Instead of wasting time detecting umpteen silly corner cases,
	 * just dump all "small" requests to the fallback implementation.
	 * HW would not be faster on such small requests anyway.
	 */
	if (likely((ctx->aead != EIP197_AEAD_TYPE_IPSEC_ESP ||
		    req->assoclen >= EIP197_AEAD_IPSEC_IV_SIZE) &&
		   req->cryptlen > POLY1305_DIGEST_SIZE)) {
		return safexcel_queue_req(&req->base, creq, dir);
	}

	/* HW cannot do full (AAD+payload) zero length, use fallback */
	for (i = 0; i < CHACHA_KEY_SIZE / sizeof(u32); i++)
		key[i] = cpu_to_le32(ctx->key[i]);
	if (ctx->aead == EIP197_AEAD_TYPE_IPSEC_ESP) {
		/* ESP variant has nonce appended to the key */
		key[CHACHA_KEY_SIZE / sizeof(u32)] = ctx->nonce;
		ret = crypto_aead_setkey(ctx->fback, (u8 *)key,
					 CHACHA_KEY_SIZE +
					 EIP197_AEAD_IPSEC_NONCE_SIZE);
	} else {
		ret = crypto_aead_setkey(ctx->fback, (u8 *)key,
					 CHACHA_KEY_SIZE);
	}
	if (ret) {
		crypto_aead_clear_flags(aead, CRYPTO_TFM_REQ_MASK);
		crypto_aead_set_flags(aead, crypto_aead_get_flags(ctx->fback) &
					    CRYPTO_TFM_REQ_MASK);
		return ret;
	}

	aead_request_set_tfm(subreq, ctx->fback);
	aead_request_set_callback(subreq, req->base.flags, req->base.complete,
				  req->base.data);
	aead_request_set_crypt(subreq, req->src, req->dst, req->cryptlen,
			       req->iv);
	aead_request_set_ad(subreq, req->assoclen);

	return (dir ==  SAFEXCEL_ENCRYPT) ?
		crypto_aead_encrypt(subreq) :
		crypto_aead_decrypt(subreq);
}

static int safexcel_aead_chachapoly_encrypt(struct aead_request *req)
{
	return safexcel_aead_chachapoly_crypt(req, SAFEXCEL_ENCRYPT);
}

static int safexcel_aead_chachapoly_decrypt(struct aead_request *req)
{
	return safexcel_aead_chachapoly_crypt(req, SAFEXCEL_DECRYPT);
}

static int safexcel_aead_fallback_cra_init(struct crypto_tfm *tfm)
{
	struct crypto_aead *aead = __crypto_aead_cast(tfm);
	struct aead_alg *alg = crypto_aead_alg(aead);
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	safexcel_aead_cra_init(tfm);

	/* Allocate fallback implementation */
	ctx->fback = crypto_alloc_aead(alg->base.cra_name, 0,
				       CRYPTO_ALG_ASYNC |
				       CRYPTO_ALG_NEED_FALLBACK);
	if (IS_ERR(ctx->fback))
		return PTR_ERR(ctx->fback);

	crypto_aead_set_reqsize(aead, max(sizeof(struct safexcel_cipher_req),
					  sizeof(struct aead_request) +
					  crypto_aead_reqsize(ctx->fback)));

	return 0;
}

static int safexcel_aead_chachapoly_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);
	int ret;

	ret = safexcel_aead_fallback_cra_init(tfm);

	ctx->alg  = SAFEXCEL_CHACHA20;
	ctx->calg = CONTEXT_CONTROL_CRYPTO_ALG_CHACHA20;
	ctx->mode = CONTEXT_CONTROL_CRYPTO_MODE_CHACHAPOLY;
	ctx->ctrinit = 0;
	ctx->hash_alg = CONTEXT_CONTROL_CRYPTO_ALG_POLY1305;
	ctx->state_sz = 0; /* Precomputed by HW */
	/* Precompute control values for encrypt and decrypt */
	ctx->cctrl_enc = CONTEXT_CONTROL_CRYPTO_ALG_CHACHA20 |
			 CONTEXT_CONTROL_CRYPTO_ALG_POLY1305 |
			 CONTEXT_CONTROL_TYPE_ENCRYPT_HASH_OUT |
			 CONTEXT_CONTROL_KEY_EN | ((u64)ctx->mode << 32) |
			 CONTEXT_CONTROL_SIZE(CHACHA_KEY_SIZE / sizeof(u32));
	ctx->cctrl_dec = CONTEXT_CONTROL_CRYPTO_ALG_CHACHA20 |
			 CONTEXT_CONTROL_CRYPTO_ALG_POLY1305 |
			 CONTEXT_CONTROL_TYPE_HASH_DECRYPT_IN |
			 CONTEXT_CONTROL_TYPE_CRYPTO_IN |
			 CONTEXT_CONTROL_KEY_EN | ((u64)ctx->mode << 32) |
			 CONTEXT_CONTROL_SIZE(CHACHA_KEY_SIZE / sizeof(u32));
	return ret;
}

static void safexcel_aead_fallback_cra_exit(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	crypto_free_aead(ctx->fback);
	safexcel_aead_cra_exit(tfm);
}

struct safexcel_alg_template safexcel_alg_chachapoly = {
	.type = SAFEXCEL_ALG_TYPE_AEAD,
	.algo_mask = SAFEXCEL_ALG_CHACHA20 | SAFEXCEL_ALG_POLY1305,
	.alg.aead = {
		.setkey = safexcel_aead_chachapoly_setkey,
		.setauthsize = safexcel_aead_chachapoly_setauthsize,
		.encrypt = safexcel_aead_chachapoly_encrypt,
		.decrypt = safexcel_aead_chachapoly_decrypt,
		.ivsize = CHACHAPOLY_IV_SIZE,
		.maxauthsize = POLY1305_DIGEST_SIZE,
		.base = {
			.cra_name = "rfc7539(chacha20,poly1305)",
			.cra_driver_name = "safexcel-chacha20-poly1305",
			/* +1 to put it above HW chacha + SW poly */
			.cra_priority = SAFEXCEL_CRA_PRIORITY + 1,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_KERN_DRIVER_ONLY |
				     CRYPTO_ALG_NEED_FALLBACK,
			.cra_blocksize = 1,
			.cra_ctxsize = sizeof(struct safexcel_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = safexcel_aead_chachapoly_cra_init,
			.cra_exit = safexcel_aead_fallback_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

static int safexcel_aead_chachapolyesp_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);
	int ret;

	ret = safexcel_aead_chachapoly_cra_init(tfm);
	ctx->aead  = EIP197_AEAD_TYPE_IPSEC_ESP;
	ctx->aadskip = EIP197_AEAD_IPSEC_IV_SIZE;
	return ret;
}

struct safexcel_alg_template safexcel_alg_chachapoly_esp = {
	.type = SAFEXCEL_ALG_TYPE_AEAD,
	.algo_mask = SAFEXCEL_ALG_CHACHA20 | SAFEXCEL_ALG_POLY1305,
	.alg.aead = {
		.setkey = safexcel_aead_chachapoly_setkey,
		.setauthsize = safexcel_aead_chachapoly_setauthsize,
		.encrypt = safexcel_aead_chachapoly_encrypt,
		.decrypt = safexcel_aead_chachapoly_decrypt,
		.ivsize = CHACHAPOLY_IV_SIZE - EIP197_AEAD_IPSEC_NONCE_SIZE,
		.maxauthsize = POLY1305_DIGEST_SIZE,
		.base = {
			.cra_name = "rfc7539esp(chacha20,poly1305)",
			.cra_driver_name = "safexcel-chacha20-poly1305-esp",
			/* +1 to put it above HW chacha + SW poly */
			.cra_priority = SAFEXCEL_CRA_PRIORITY + 1,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_KERN_DRIVER_ONLY |
				     CRYPTO_ALG_NEED_FALLBACK,
			.cra_blocksize = 1,
			.cra_ctxsize = sizeof(struct safexcel_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = safexcel_aead_chachapolyesp_cra_init,
			.cra_exit = safexcel_aead_fallback_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

static int safexcel_skcipher_sm4_setkey(struct crypto_skcipher *ctfm,
					const u8 *key, unsigned int len)
{
	struct crypto_tfm *tfm = crypto_skcipher_tfm(ctfm);
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	if (len != SM4_KEY_SIZE) {
		crypto_skcipher_set_flags(ctfm, CRYPTO_TFM_RES_BAD_KEY_LEN);
		return -EINVAL;
	}
	safexcel_skcipher_setkey(ctx, key, len);
	return 0;
}

static int safexcel_sm4_blk_encrypt(struct skcipher_request *req)
{
	/* Workaround for HW bug: EIP96 4.3 does not report blocksize error */
	if (req->cryptlen & (SM4_BLOCK_SIZE - 1))
		return -EINVAL;
	else
		return safexcel_queue_req(&req->base, skcipher_request_ctx(req),
					  SAFEXCEL_ENCRYPT);
}

static int safexcel_sm4_blk_decrypt(struct skcipher_request *req)
{
	/* Workaround for HW bug: EIP96 4.3 does not report blocksize error */
	if (req->cryptlen & (SM4_BLOCK_SIZE - 1))
		return -EINVAL;
	else
		return safexcel_queue_req(&req->base, skcipher_request_ctx(req),
					  SAFEXCEL_DECRYPT);
}

static int safexcel_skcipher_sm4_ecb_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	safexcel_skcipher_cra_init(tfm);
	ctx->alg  = SAFEXCEL_SM4;
	ctx->calg = CONTEXT_CONTROL_CRYPTO_ALG_SM4;
	ctx->mode = CONTEXT_CONTROL_CRYPTO_MODE_ECB;
	ctx->blocksz = 0;
	ctx->ivmask = EIP197_OPTION_2_TOKEN_IV_CMD;
	return 0;
}

struct safexcel_alg_template safexcel_alg_ecb_sm4 = {
	.type = SAFEXCEL_ALG_TYPE_SKCIPHER,
	.algo_mask = SAFEXCEL_ALG_SM4,
	.alg.skcipher = {
		.setkey = safexcel_skcipher_sm4_setkey,
		.encrypt = safexcel_sm4_blk_encrypt,
		.decrypt = safexcel_sm4_blk_decrypt,
		.min_keysize = SM4_KEY_SIZE,
		.max_keysize = SM4_KEY_SIZE,
		.base = {
			.cra_name = "ecb(sm4)",
			.cra_driver_name = "safexcel-ecb-sm4",
			.cra_priority = SAFEXCEL_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = SM4_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct safexcel_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = safexcel_skcipher_sm4_ecb_cra_init,
			.cra_exit = safexcel_skcipher_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

static int safexcel_skcipher_sm4_cbc_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	safexcel_skcipher_cra_init(tfm);
	ctx->alg  = SAFEXCEL_SM4;
	ctx->calg = CONTEXT_CONTROL_CRYPTO_ALG_SM4;
	ctx->blocksz = SM4_BLOCK_SIZE;
	ctx->mode = CONTEXT_CONTROL_CRYPTO_MODE_CBC;
	return 0;
}

struct safexcel_alg_template safexcel_alg_cbc_sm4 = {
	.type = SAFEXCEL_ALG_TYPE_SKCIPHER,
	.algo_mask = SAFEXCEL_ALG_SM4,
	.alg.skcipher = {
		.setkey = safexcel_skcipher_sm4_setkey,
		.encrypt = safexcel_sm4_blk_encrypt,
		.decrypt = safexcel_sm4_blk_decrypt,
		.min_keysize = SM4_KEY_SIZE,
		.max_keysize = SM4_KEY_SIZE,
		.ivsize = SM4_BLOCK_SIZE,
		.base = {
			.cra_name = "cbc(sm4)",
			.cra_driver_name = "safexcel-cbc-sm4",
			.cra_priority = SAFEXCEL_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = SM4_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct safexcel_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = safexcel_skcipher_sm4_cbc_cra_init,
			.cra_exit = safexcel_skcipher_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

static int safexcel_skcipher_sm4_ofb_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	safexcel_skcipher_cra_init(tfm);
	ctx->alg  = SAFEXCEL_SM4;
	ctx->calg = CONTEXT_CONTROL_CRYPTO_ALG_SM4;
	ctx->blocksz = SM4_BLOCK_SIZE;
	ctx->mode = CONTEXT_CONTROL_CRYPTO_MODE_OFB;
	return 0;
}

struct safexcel_alg_template safexcel_alg_ofb_sm4 = {
	.type = SAFEXCEL_ALG_TYPE_SKCIPHER,
	.algo_mask = SAFEXCEL_ALG_SM4 | SAFEXCEL_ALG_AES_XFB,
	.alg.skcipher = {
		.setkey = safexcel_skcipher_sm4_setkey,
		.encrypt = safexcel_encrypt,
		.decrypt = safexcel_decrypt,
		.min_keysize = SM4_KEY_SIZE,
		.max_keysize = SM4_KEY_SIZE,
		.ivsize = SM4_BLOCK_SIZE,
		.base = {
			.cra_name = "ofb(sm4)",
			.cra_driver_name = "safexcel-ofb-sm4",
			.cra_priority = SAFEXCEL_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = 1,
			.cra_ctxsize = sizeof(struct safexcel_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = safexcel_skcipher_sm4_ofb_cra_init,
			.cra_exit = safexcel_skcipher_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

static int safexcel_skcipher_sm4_cfb_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	safexcel_skcipher_cra_init(tfm);
	ctx->alg  = SAFEXCEL_SM4;
	ctx->calg = CONTEXT_CONTROL_CRYPTO_ALG_SM4;
	ctx->blocksz = SM4_BLOCK_SIZE;
	ctx->mode = CONTEXT_CONTROL_CRYPTO_MODE_CFB;
	return 0;
}

struct safexcel_alg_template safexcel_alg_cfb_sm4 = {
	.type = SAFEXCEL_ALG_TYPE_SKCIPHER,
	.algo_mask = SAFEXCEL_ALG_SM4 | SAFEXCEL_ALG_AES_XFB,
	.alg.skcipher = {
		.setkey = safexcel_skcipher_sm4_setkey,
		.encrypt = safexcel_encrypt,
		.decrypt = safexcel_decrypt,
		.min_keysize = SM4_KEY_SIZE,
		.max_keysize = SM4_KEY_SIZE,
		.ivsize = SM4_BLOCK_SIZE,
		.base = {
			.cra_name = "cfb(sm4)",
			.cra_driver_name = "safexcel-cfb-sm4",
			.cra_priority = SAFEXCEL_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = 1,
			.cra_ctxsize = sizeof(struct safexcel_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = safexcel_skcipher_sm4_cfb_cra_init,
			.cra_exit = safexcel_skcipher_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

static int safexcel_skcipher_sm4ctr_setkey(struct crypto_skcipher *ctfm,
					   const u8 *key, unsigned int len)
{
	struct crypto_tfm *tfm = crypto_skcipher_tfm(ctfm);
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	/* last 4 bytes of key are the nonce! */
	ctx->nonce = *(u32 *)(key + len - CTR_RFC3686_NONCE_SIZE);
	/* exclude the nonce here */
	len -= CTR_RFC3686_NONCE_SIZE;

	return safexcel_skcipher_sm4_setkey(ctfm, key, len);
}

static int safexcel_skcipher_sm4_ctr_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	safexcel_skcipher_cra_init(tfm);
	ctx->alg  = SAFEXCEL_SM4;
	ctx->calg = CONTEXT_CONTROL_CRYPTO_ALG_SM4;
	ctx->blocksz = SM4_BLOCK_SIZE;
	ctx->mode = CONTEXT_CONTROL_CRYPTO_MODE_CTR_LOAD;
	return 0;
}

struct safexcel_alg_template safexcel_alg_ctr_sm4 = {
	.type = SAFEXCEL_ALG_TYPE_SKCIPHER,
	.algo_mask = SAFEXCEL_ALG_SM4,
	.alg.skcipher = {
		.setkey = safexcel_skcipher_sm4ctr_setkey,
		.encrypt = safexcel_encrypt,
		.decrypt = safexcel_decrypt,
		/* Add nonce size */
		.min_keysize = SM4_KEY_SIZE + CTR_RFC3686_NONCE_SIZE,
		.max_keysize = SM4_KEY_SIZE + CTR_RFC3686_NONCE_SIZE,
		.ivsize = CTR_RFC3686_IV_SIZE,
		.base = {
			.cra_name = "rfc3686(ctr(sm4))",
			.cra_driver_name = "safexcel-ctr-sm4",
			.cra_priority = SAFEXCEL_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = 1,
			.cra_ctxsize = sizeof(struct safexcel_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = safexcel_skcipher_sm4_ctr_cra_init,
			.cra_exit = safexcel_skcipher_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

static int safexcel_aead_sm4_blk_encrypt(struct aead_request *req)
{
	/* Workaround for HW bug: EIP96 4.3 does not report blocksize error */
	if (req->cryptlen & (SM4_BLOCK_SIZE - 1))
		return -EINVAL;

	return safexcel_queue_req(&req->base, aead_request_ctx(req),
				  SAFEXCEL_ENCRYPT);
}

static int safexcel_aead_sm4_blk_decrypt(struct aead_request *req)
{
	struct crypto_aead *tfm = crypto_aead_reqtfm(req);

	/* Workaround for HW bug: EIP96 4.3 does not report blocksize error */
	if ((req->cryptlen - crypto_aead_authsize(tfm)) & (SM4_BLOCK_SIZE - 1))
		return -EINVAL;

	return safexcel_queue_req(&req->base, aead_request_ctx(req),
				  SAFEXCEL_DECRYPT);
}

static int safexcel_aead_sm4cbc_sha1_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	safexcel_aead_cra_init(tfm);
	ctx->alg = SAFEXCEL_SM4;
	ctx->calg = CONTEXT_CONTROL_CRYPTO_ALG_SM4;
	ctx->blocksz = SM4_BLOCK_SIZE;
	ctx->hash_alg = CONTEXT_CONTROL_CRYPTO_ALG_SHA1;
	ctx->state_sz = SHA1_DIGEST_SIZE;
	return 0;
}

struct safexcel_alg_template safexcel_alg_authenc_hmac_sha1_cbc_sm4 = {
	.type = SAFEXCEL_ALG_TYPE_AEAD,
	.algo_mask = SAFEXCEL_ALG_SM4 | SAFEXCEL_ALG_SHA1,
	.alg.aead = {
		.setkey = safexcel_aead_setkey,
		.encrypt = safexcel_aead_sm4_blk_encrypt,
		.decrypt = safexcel_aead_sm4_blk_decrypt,
		.ivsize = SM4_BLOCK_SIZE,
		.maxauthsize = SHA1_DIGEST_SIZE,
		.base = {
			.cra_name = "authenc(hmac(sha1),cbc(sm4))",
			.cra_driver_name = "safexcel-authenc-hmac-sha1-cbc-sm4",
			.cra_priority = SAFEXCEL_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = SM4_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct safexcel_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = safexcel_aead_sm4cbc_sha1_cra_init,
			.cra_exit = safexcel_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

static int safexcel_aead_fallback_setkey(struct crypto_aead *ctfm,
					 const u8 *key, unsigned int len)
{
	struct crypto_tfm *tfm = crypto_aead_tfm(ctfm);
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	/* Keep fallback cipher synchronized */
	return crypto_aead_setkey(ctx->fback, (u8 *)key, len) ?:
	       safexcel_aead_setkey(ctfm, key, len);
}

static int safexcel_aead_fallback_setauthsize(struct crypto_aead *ctfm,
					      unsigned int authsize)
{
	struct crypto_tfm *tfm = crypto_aead_tfm(ctfm);
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	/* Keep fallback cipher synchronized */
	return crypto_aead_setauthsize(ctx->fback, authsize);
}

static int safexcel_aead_fallback_crypt(struct aead_request *req,
					enum safexcel_cipher_direction dir)
{
	struct crypto_aead *aead = crypto_aead_reqtfm(req);
	struct crypto_tfm *tfm = crypto_aead_tfm(aead);
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);
	struct aead_request *subreq = aead_request_ctx(req);

	aead_request_set_tfm(subreq, ctx->fback);
	aead_request_set_callback(subreq, req->base.flags, req->base.complete,
				  req->base.data);
	aead_request_set_crypt(subreq, req->src, req->dst, req->cryptlen,
			       req->iv);
	aead_request_set_ad(subreq, req->assoclen);

	return (dir ==  SAFEXCEL_ENCRYPT) ?
		crypto_aead_encrypt(subreq) :
		crypto_aead_decrypt(subreq);
}

static int safexcel_aead_sm4cbc_sm3_encrypt(struct aead_request *req)
{
	struct safexcel_cipher_req *creq = aead_request_ctx(req);

	/* Workaround for HW bug: EIP96 4.3 does not report blocksize error */
	if (req->cryptlen & (SM4_BLOCK_SIZE - 1))
		return -EINVAL;
	else if (req->cryptlen || req->assoclen) /* If input length > 0 only */
		return safexcel_queue_req(&req->base, creq, SAFEXCEL_ENCRYPT);

	/* HW cannot do full (AAD+payload) zero length, use fallback */
	return safexcel_aead_fallback_crypt(req, SAFEXCEL_ENCRYPT);
}

static int safexcel_aead_sm4cbc_sm3_decrypt(struct aead_request *req)
{
	struct safexcel_cipher_req *creq = aead_request_ctx(req);
	struct crypto_aead *tfm = crypto_aead_reqtfm(req);

	/* Workaround for HW bug: EIP96 4.3 does not report blocksize error */
	if ((req->cryptlen - crypto_aead_authsize(tfm)) & (SM4_BLOCK_SIZE - 1))
		return -EINVAL;
	else if (req->cryptlen > crypto_aead_authsize(tfm) || req->assoclen)
		/* If input length > 0 only */
		return safexcel_queue_req(&req->base, creq, SAFEXCEL_DECRYPT);

	/* HW cannot do full (AAD+payload) zero length, use fallback */
	return safexcel_aead_fallback_crypt(req, SAFEXCEL_DECRYPT);
}

static int safexcel_aead_sm4cbc_sm3_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);
	int ret;

	ret = safexcel_aead_fallback_cra_init(tfm);
	ctx->alg = SAFEXCEL_SM4;
	ctx->calg = CONTEXT_CONTROL_CRYPTO_ALG_SM4;
	ctx->blocksz = SM4_BLOCK_SIZE;
	ctx->hash_alg = CONTEXT_CONTROL_CRYPTO_ALG_SM3;
	ctx->state_sz = SM3_DIGEST_SIZE;
	return ret;
}

struct safexcel_alg_template safexcel_alg_authenc_hmac_sm3_cbc_sm4 = {
	.type = SAFEXCEL_ALG_TYPE_AEAD,
	.algo_mask = SAFEXCEL_ALG_SM4 | SAFEXCEL_ALG_SM3,
	.alg.aead = {
		.setkey = safexcel_aead_fallback_setkey,
		.setauthsize = safexcel_aead_fallback_setauthsize,
		.encrypt = safexcel_aead_sm4cbc_sm3_encrypt,
		.decrypt = safexcel_aead_sm4cbc_sm3_decrypt,
		.ivsize = SM4_BLOCK_SIZE,
		.maxauthsize = SM3_DIGEST_SIZE,
		.base = {
			.cra_name = "authenc(hmac(sm3),cbc(sm4))",
			.cra_driver_name = "safexcel-authenc-hmac-sm3-cbc-sm4",
			.cra_priority = SAFEXCEL_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_KERN_DRIVER_ONLY |
				     CRYPTO_ALG_NEED_FALLBACK,
			.cra_blocksize = SM4_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct safexcel_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = safexcel_aead_sm4cbc_sm3_cra_init,
			.cra_exit = safexcel_aead_fallback_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

static int safexcel_aead_sm4ctr_sha1_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	safexcel_aead_sm4cbc_sha1_cra_init(tfm);
	ctx->mode = CONTEXT_CONTROL_CRYPTO_MODE_CTR_LOAD;
	ctx->aead  = EIP197_AEAD_TYPE_IPSEC_CTR;
	return 0;
}

struct safexcel_alg_template safexcel_alg_authenc_hmac_sha1_ctr_sm4 = {
	.type = SAFEXCEL_ALG_TYPE_AEAD,
	.algo_mask = SAFEXCEL_ALG_SM4 | SAFEXCEL_ALG_SHA1,
	.alg.aead = {
		.setkey = safexcel_aead_setkey,
		.encrypt = safexcel_aead_encrypt,
		.decrypt = safexcel_aead_decrypt,
		.ivsize = CTR_RFC3686_IV_SIZE,
		.maxauthsize = SHA1_DIGEST_SIZE,
		.base = {
			.cra_name = "authenc(hmac(sha1),rfc3686(ctr(sm4)))",
			.cra_driver_name = "safexcel-authenc-hmac-sha1-ctr-sm4",
			.cra_priority = SAFEXCEL_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = 1,
			.cra_ctxsize = sizeof(struct safexcel_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = safexcel_aead_sm4ctr_sha1_cra_init,
			.cra_exit = safexcel_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

static int safexcel_aead_sm4ctr_sm3_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);
	int ret;

	ret = safexcel_aead_sm4cbc_sm3_cra_init(tfm);
	ctx->mode = CONTEXT_CONTROL_CRYPTO_MODE_CTR_LOAD;
	ctx->aead  = EIP197_AEAD_TYPE_IPSEC_CTR;
	return ret;
}

struct safexcel_alg_template safexcel_alg_authenc_hmac_sm3_ctr_sm4 = {
	.type = SAFEXCEL_ALG_TYPE_AEAD,
	.algo_mask = SAFEXCEL_ALG_SM4 | SAFEXCEL_ALG_SM3,
	.alg.aead = {
		.setkey = safexcel_aead_setkey,
		.encrypt = safexcel_aead_encrypt,
		.decrypt = safexcel_aead_decrypt,
		.ivsize = CTR_RFC3686_IV_SIZE,
		.maxauthsize = SM3_DIGEST_SIZE,
		.base = {
			.cra_name = "authenc(hmac(sm3),rfc3686(ctr(sm4)))",
			.cra_driver_name = "safexcel-authenc-hmac-sm3-ctr-sm4",
			.cra_priority = SAFEXCEL_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = 1,
			.cra_ctxsize = sizeof(struct safexcel_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = safexcel_aead_sm4ctr_sm3_cra_init,
			.cra_exit = safexcel_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

static int safexcel_rfc4106_gcm_setkey(struct crypto_aead *ctfm, const u8 *key,
				       unsigned int len)
{
	struct crypto_tfm *tfm = crypto_aead_tfm(ctfm);
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);
	int ret;

	/* last 4 bytes of key are the nonce! */
	len -= CTR_RFC3686_NONCE_SIZE;
	ret = safexcel_aead_gcm_setkey(ctfm, key, len);
	if (unlikely(ret))
		return ret;
	ctx->nonce = *(u32 *)(key + len);
	return 0;
}

static int safexcel_rfc4106_gcm_setauthsize(struct crypto_aead *tfm,
					    unsigned int authsize)
{
	return crypto_rfc4106_check_authsize(authsize);
}

static int safexcel_rfc4106_encrypt(struct aead_request *req)
{
	return crypto_ipsec_check_assoclen(req->assoclen) ?:
	       safexcel_aead_encrypt(req);
}

static int safexcel_rfc4106_decrypt(struct aead_request *req)
{
	return crypto_ipsec_check_assoclen(req->assoclen) ?:
	       safexcel_aead_decrypt(req);
}

static int safexcel_rfc4106_gcm_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);
	int ret;

	ret = safexcel_aead_gcm_cra_init(tfm);
	ctx->aead  = EIP197_AEAD_TYPE_IPSEC_ESP;
	ctx->aadskip = EIP197_AEAD_IPSEC_IV_SIZE;
	return ret;
}

struct safexcel_alg_template safexcel_alg_rfc4106_gcm = {
	.type = SAFEXCEL_ALG_TYPE_AEAD,
	.algo_mask = SAFEXCEL_ALG_AES | SAFEXCEL_ALG_GHASH,
	.alg.aead = {
		.setkey = safexcel_rfc4106_gcm_setkey,
		.setauthsize = safexcel_rfc4106_gcm_setauthsize,
		.encrypt = safexcel_rfc4106_encrypt,
		.decrypt = safexcel_rfc4106_decrypt,
		.ivsize = GCM_RFC4106_IV_SIZE,
		.maxauthsize = GHASH_DIGEST_SIZE,
		.base = {
			.cra_name = "rfc4106(gcm(aes))",
			.cra_driver_name = "safexcel-rfc4106-gcm-aes",
			.cra_priority = SAFEXCEL_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = 1,
			.cra_ctxsize = sizeof(struct safexcel_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = safexcel_rfc4106_gcm_cra_init,
			.cra_exit = safexcel_aead_gcm_cra_exit,
		},
	},
};

static int safexcel_rfc4543_gcm_setauthsize(struct crypto_aead *tfm,
					    unsigned int authsize)
{
	if (authsize != GHASH_DIGEST_SIZE)
		return -EINVAL;

	return 0;
}

static int safexcel_rfc4543_gcm_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);
	int ret;

	ret = safexcel_aead_gcm_cra_init(tfm);
	ctx->aead  = EIP197_AEAD_TYPE_IPSEC_ESP_GMAC;
	return ret;
}

struct safexcel_alg_template safexcel_alg_rfc4543_gcm = {
	.type = SAFEXCEL_ALG_TYPE_AEAD,
	.algo_mask = SAFEXCEL_ALG_AES | SAFEXCEL_ALG_GHASH,
	.alg.aead = {
		.setkey = safexcel_rfc4106_gcm_setkey,
		.setauthsize = safexcel_rfc4543_gcm_setauthsize,
		.encrypt = safexcel_rfc4106_encrypt,
		.decrypt = safexcel_rfc4106_decrypt,
		.ivsize = GCM_RFC4543_IV_SIZE,
		.maxauthsize = GHASH_DIGEST_SIZE,
		.base = {
			.cra_name = "rfc4543(gcm(aes))",
			.cra_driver_name = "safexcel-rfc4543-gcm-aes",
			.cra_priority = SAFEXCEL_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = 1,
			.cra_ctxsize = sizeof(struct safexcel_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = safexcel_rfc4543_gcm_cra_init,
			.cra_exit = safexcel_aead_gcm_cra_exit,
		},
	},
};

static int safexcel_rfc4309_ccm_setkey(struct crypto_aead *ctfm, const u8 *key,
				       unsigned int len)
{
	struct crypto_tfm *tfm = crypto_aead_tfm(ctfm);
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);
	int ret;

	/* last 4 bytes of key are the nonce! */
	len -= EIP197_AEAD_IPSEC_CCM_NONCE_SIZE;
	ret = safexcel_aead_ccm_setkey(ctfm, key, len);
	if (unlikely(ret))
		return ret;
	/* First byte of the nonce = L = always 3 for RFC4309 (4 byte ctr) */
	*(u8 *)&ctx->nonce = EIP197_AEAD_IPSEC_COUNTER_SIZE - 1;
	/* last 3 bytes of key are the nonce! */
	memcpy((u8 *)&ctx->nonce + 1, key + len,
	       EIP197_AEAD_IPSEC_CCM_NONCE_SIZE);
	return 0;
}

static int safexcel_rfc4309_ccm_setauthsize(struct crypto_aead *tfm,
					    unsigned int authsize)
{
	/* Borrowed from crypto/ccm.c */
	switch (authsize) {
	case 8:
	case 12:
	case 16:
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int safexcel_rfc4309_ccm_encrypt(struct aead_request *req)
{
	struct safexcel_cipher_req *creq = aead_request_ctx(req);

	/* Borrowed from crypto/ccm.c */
	if (req->assoclen != 16 && req->assoclen != 20)
		return -EINVAL;

	return safexcel_queue_req(&req->base, creq, SAFEXCEL_ENCRYPT);
}

static int safexcel_rfc4309_ccm_decrypt(struct aead_request *req)
{
	struct safexcel_cipher_req *creq = aead_request_ctx(req);

	/* Borrowed from crypto/ccm.c */
	if (req->assoclen != 16 && req->assoclen != 20)
		return -EINVAL;

	return safexcel_queue_req(&req->base, creq, SAFEXCEL_DECRYPT);
}

static int safexcel_rfc4309_ccm_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	safexcel_aead_ccm_cra_init(tfm);
	ctx->aead  = EIP197_AEAD_TYPE_IPSEC_ESP;
	ctx->aadskip = EIP197_AEAD_IPSEC_IV_SIZE;
	return 0;
}

struct safexcel_alg_template safexcel_alg_rfc4309_ccm = {
	.type = SAFEXCEL_ALG_TYPE_AEAD,
	.algo_mask = SAFEXCEL_ALG_AES | SAFEXCEL_ALG_CBC_MAC_ALL,
	.alg.aead = {
		.setkey = safexcel_rfc4309_ccm_setkey,
		.setauthsize = safexcel_rfc4309_ccm_setauthsize,
		.encrypt = safexcel_rfc4309_ccm_encrypt,
		.decrypt = safexcel_rfc4309_ccm_decrypt,
		.ivsize = EIP197_AEAD_IPSEC_IV_SIZE,
		.maxauthsize = AES_BLOCK_SIZE,
		.base = {
			.cra_name = "rfc4309(ccm(aes))",
			.cra_driver_name = "safexcel-rfc4309-ccm-aes",
			.cra_priority = SAFEXCEL_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = 1,
			.cra_ctxsize = sizeof(struct safexcel_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = safexcel_rfc4309_ccm_cra_init,
			.cra_exit = safexcel_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};
