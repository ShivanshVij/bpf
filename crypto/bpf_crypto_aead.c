// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2024 Meta, Inc */
#include <linux/bpf.h>
#include <linux/bpf_crypto.h>
#include <crypto/aead.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>

static void *bpf_crypto_aead_alloc_tfm(const char *algo)
{
	struct crypto_aead *aead;

	aead = crypto_alloc_aead(algo, 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(aead))
		return ERR_CAST(aead);

	return aead;
}

static void bpf_crypto_aead_free_tfm(void *tfm)
{
	crypto_free_aead(tfm);
}

static int bpf_crypto_aead_has_algo(const char *algo)
{
	return crypto_has_aead(algo, 0, CRYPTO_ALG_ASYNC);
}

static int bpf_crypto_aead_setkey(void *tfm, const u8 *key, unsigned int keylen)
{
	return crypto_aead_setkey(tfm, key, keylen);
}

static int bpf_crypto_aead_setauthsize(void *tfm, unsigned int authsize)
{
	return crypto_aead_setauthsize(tfm, authsize);
}

static unsigned int bpf_crypto_aead_ivsize(void *tfm)
{
	return crypto_aead_ivsize(tfm);
}

static unsigned int bpf_crypto_aead_statesize(void *tfm)
{
	/* AEAD doesn't have a separate statesize API, return 0 */
	return 0;
}

static u32 bpf_crypto_aead_get_flags(void *tfm)
{
	return crypto_aead_get_flags(tfm);
}

static int bpf_crypto_aead_encrypt(void *tfm, const u8 *src, u8 *dst,
				    unsigned int len, u8 *iv)
{
	struct crypto_aead *aead = tfm;
	struct aead_request *req;
	struct scatterlist sg_src, sg_dst;
	unsigned int authsize = crypto_aead_authsize(aead);
	u8 *src_buf, *dst_buf;
	int err;

	/* For AEAD encryption, output is plaintext_len + authsize */

	req = aead_request_alloc(aead, GFP_ATOMIC);
	if (!req)
		return -ENOMEM;

	/* Allocate temporary buffers suitable for scatterlist */
	src_buf = kmalloc(len, GFP_ATOMIC);
	if (!src_buf) {
		aead_request_free(req);
		return -ENOMEM;
	}

	dst_buf = kmalloc(len + authsize, GFP_ATOMIC);
	if (!dst_buf) {
		kfree(src_buf);
		aead_request_free(req);
		return -ENOMEM;
	}

	/* Copy input data to temporary buffer */
	memcpy(src_buf, src, len);

	sg_init_one(&sg_src, src_buf, len);
	sg_init_one(&sg_dst, dst_buf, len + authsize);

	aead_request_set_tfm(req, aead);
	aead_request_set_crypt(req, &sg_src, &sg_dst, len, iv);
	aead_request_set_ad(req, 0);  /* No associated data for now */

	err = crypto_aead_encrypt(req);

	if (!err) {
		/* Copy result back to output buffer */
		memcpy(dst, dst_buf, len + authsize);
	}

	kfree(dst_buf);
	kfree(src_buf);
	aead_request_free(req);

	return err;
}

static int bpf_crypto_aead_decrypt(void *tfm, const u8 *src, u8 *dst,
				    unsigned int len, u8 *iv)
{
	struct crypto_aead *aead = tfm;
	struct aead_request *req;
	struct scatterlist sg_src, sg_dst;
	unsigned int authsize = crypto_aead_authsize(aead);
	u8 *src_buf, *dst_buf;
	int err;

	/* For AEAD decryption, input includes the auth tag */
	if (len < authsize)
		return -EINVAL;

	req = aead_request_alloc(aead, GFP_ATOMIC);
	if (!req)
		return -ENOMEM;

	/* Allocate temporary buffers suitable for scatterlist */
	src_buf = kmalloc(len, GFP_ATOMIC);
	if (!src_buf) {
		aead_request_free(req);
		return -ENOMEM;
	}

	dst_buf = kmalloc(len - authsize, GFP_ATOMIC);
	if (!dst_buf) {
		kfree(src_buf);
		aead_request_free(req);
		return -ENOMEM;
	}

	/* Copy input data (ciphertext + tag) to temporary buffer */
	memcpy(src_buf, src, len);

	sg_init_one(&sg_src, src_buf, len);
	sg_init_one(&sg_dst, dst_buf, len - authsize);

	aead_request_set_tfm(req, aead);
	aead_request_set_crypt(req, &sg_src, &sg_dst, len, iv);
	aead_request_set_ad(req, 0);  /* No associated data for now */

	err = crypto_aead_decrypt(req);

	if (!err) {
		/* Copy plaintext back to output buffer */
		memcpy(dst, dst_buf, len - authsize);
	}

	kfree(dst_buf);
	kfree(src_buf);
	aead_request_free(req);

	return err;
}

static const struct bpf_crypto_type bpf_crypto_aead_type = {
	.alloc_tfm	= bpf_crypto_aead_alloc_tfm,
	.free_tfm	= bpf_crypto_aead_free_tfm,
	.has_algo	= bpf_crypto_aead_has_algo,
	.setkey		= bpf_crypto_aead_setkey,
	.setauthsize	= bpf_crypto_aead_setauthsize,
	.encrypt	= bpf_crypto_aead_encrypt,
	.decrypt	= bpf_crypto_aead_decrypt,
	.ivsize		= bpf_crypto_aead_ivsize,
	.statesize	= bpf_crypto_aead_statesize,
	.get_flags	= bpf_crypto_aead_get_flags,
	.owner		= THIS_MODULE,
	.name		= "aead",
};

static int __init bpf_crypto_aead_init(void)
{
	return bpf_crypto_register_type(&bpf_crypto_aead_type);
}

static void __exit bpf_crypto_aead_exit(void)
{
	int err = bpf_crypto_unregister_type(&bpf_crypto_aead_type);
	WARN_ON_ONCE(err);
}

module_init(bpf_crypto_aead_init);
module_exit(bpf_crypto_aead_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("AEAD cipher support for BPF");