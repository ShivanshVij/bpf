// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include "bpf_tracing_net.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"
#include "bpf_kfuncs.h"
#include "crypto_common.h"

/* ChaCha20-Poly1305 test vectors */
unsigned char aead_key[32] = {};
u16 udp_test_port = 7778;
u32 aead_authsize = 16;  /* Poly1305 tag is 16 bytes */
u32 key_len;
char algo[128] = {};
char dst[48] = {};  /* Space for plaintext + tag */
int status;
int debug_src_len = 0;
int debug_dst_len = 0;
int debug_decrypt_result = 0;
int encrypt_src_len = 0;
int encrypt_dst_len = 0;

static int skb_dynptr_validate(struct __sk_buff *skb, struct bpf_dynptr *psrc, int data_len)
{
	struct ipv6hdr ip6h;
	struct udphdr udph;
	u32 offset;

	if (skb->protocol != __bpf_constant_htons(ETH_P_IPV6))
		return -1;

	if (bpf_skb_load_bytes(skb, ETH_HLEN, &ip6h, sizeof(ip6h)))
		return -1;

	if (ip6h.nexthdr != IPPROTO_UDP)
		return -1;

	if (bpf_skb_load_bytes(skb, ETH_HLEN + sizeof(ip6h), &udph, sizeof(udph)))
		return -1;

	if (udph.dest != __bpf_htons(udp_test_port))
		return -1;

	offset = ETH_HLEN + sizeof(ip6h) + sizeof(udph);
	if (skb->len < offset + data_len)
		return -1;

	/* Pull data and create dynptr */
	bpf_skb_pull_data(skb, offset + data_len);
	bpf_dynptr_from_skb(skb, 0, psrc);
	bpf_dynptr_adjust(psrc, offset, offset + data_len);

	return 0;
}

SEC("syscall")
int aead_crypto_setup(void *ctx)
{
	struct bpf_crypto_params params = {
		.type = "aead",
		.key_len = key_len,
		.authsize = aead_authsize,
	};
	struct bpf_crypto_ctx *cctx;
	int err;

	status = 0;
	if (key_len > 256) {
		status = -EINVAL;
		return 0;
	}

	__builtin_memcpy(&params.algo, algo, sizeof(algo));
	__builtin_memcpy(&params.key, aead_key, sizeof(aead_key));

	cctx = bpf_crypto_ctx_create(&params, sizeof(params), &err);
	if (!cctx) {
		status = err;
		return 0;
	}

	err = crypto_ctx_insert(cctx);
	if (err && err != -EEXIST)
		status = err;
	return 0;
}

/* Global IV for ChaCha20-Poly1305 (96-bit nonce) */
char aead_iv[12] = {};

SEC("tc")
int decrypt_aead(struct __sk_buff *skb)
{
	struct __crypto_ctx_value *v;
	struct bpf_crypto_ctx *ctx;
	struct bpf_dynptr psrc, pdst, piv;
	int err;

	status = 0;
	/* For decryption, we need ciphertext + tag (32 + 16 = 48 bytes) */
	err = skb_dynptr_validate(skb, &psrc, 48);
	if (err < 0) {
		status = err;
		return TC_ACT_SHOT;
	}

	v = crypto_ctx_value_lookup();
	if (!v) {
		status = -ENOENT;
		return TC_ACT_SHOT;
	}

	ctx = v->ctx;
	if (!ctx) {
		status = -ENOENT;
		return TC_ACT_SHOT;
	}

	/* For AEAD decrypt, input includes tag (48 bytes), output is plaintext only (32 bytes) */
	bpf_dynptr_from_mem(dst, 32, 0, &pdst);  /* Only 32 bytes for plaintext */
	bpf_dynptr_from_mem(aead_iv, sizeof(aead_iv), 0, &piv);

	/* Debug: capture sizes */
	debug_src_len = bpf_dynptr_size(&psrc);
	debug_dst_len = bpf_dynptr_size(&pdst);

	status = bpf_crypto_decrypt(ctx, &psrc, &pdst, &piv);
	debug_decrypt_result = status;
	return TC_ACT_SHOT;
}

SEC("tc")
int encrypt_aead(struct __sk_buff *skb)
{
	struct __crypto_ctx_value *v;
	struct bpf_crypto_ctx *ctx;
	struct bpf_dynptr psrc, pdst, piv;
	int err;

	status = 0;
	/* For encryption, we need plaintext (32 bytes) */
	err = skb_dynptr_validate(skb, &psrc, 32);
	if (err < 0) {
		status = err;
		return TC_ACT_SHOT;
	}

	v = crypto_ctx_value_lookup();
	if (!v) {
		status = -ENOENT;
		return TC_ACT_SHOT;
	}

	ctx = v->ctx;
	if (!ctx) {
		status = -ENOENT;
		return TC_ACT_SHOT;
	}

	/* For AEAD encrypt, output needs space for plaintext + tag */
	bpf_dynptr_from_mem(dst, sizeof(dst), 0, &pdst);
	bpf_dynptr_from_mem(aead_iv, sizeof(aead_iv), 0, &piv);

	/* Debug: capture sizes before encryption */
	encrypt_src_len = bpf_dynptr_size(&psrc);
	encrypt_dst_len = bpf_dynptr_size(&pdst);

	status = bpf_crypto_encrypt(ctx, &psrc, &pdst, &piv);
	return TC_ACT_SHOT;
}

char __license[] SEC("license") = "GPL";