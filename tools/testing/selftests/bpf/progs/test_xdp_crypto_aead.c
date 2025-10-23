// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bpf_kfuncs.h"
#include "crypto_common.h"

#define EINVAL 22
#define ENOENT 2
#define ETH_P_IP 0x0800
#define IPPROTO_UDP 17

/* XDP action codes */
#define XDP_PASS 2
#define XDP_DROP 1

/* ChaCha20-Poly1305 test parameters */
unsigned char aead_key[32] = {};
u16 test_port = 7778;
u32 aead_authsize = 16;  /* Poly1305 tag is 16 bytes */
u32 key_len;
char algo[128] = {};
int status;

/* Test results storage */
char encrypted_result[64] = {};  /* Max 48 bytes ciphertext + tag */
char decrypted_result[48] = {};  /* Max 48 bytes plaintext */
u32 result_len = 0;

/* ChaCha20-Poly1305 IV (96-bit nonce) */
char aead_iv[12] = {};

/* Global buffers for encryption/decryption - needed for BPF verifier */
char encrypt_src_buf[32] = {};
char encrypt_dst_buf[48] = {};  /* 32 bytes plaintext + 16 bytes tag */
char decrypt_src_buf[48] = {};  /* ciphertext + tag */
char decrypt_dst_buf[32] = {};  /* plaintext only */

SEC("syscall")
int xdp_aead_crypto_setup(void *ctx)
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

/* XDP program to encrypt UDP payload */
SEC("xdp")
int xdp_aead_encrypt(struct xdp_md *xdp)
{
	struct __crypto_ctx_value *v;
	struct bpf_crypto_ctx *ctx;
	struct bpf_dynptr psrc, pdst, piv;
	void *data_end = (void *)(long)xdp->data_end;
	void *data = (void *)(long)xdp->data;
	struct ethhdr *eth;
	struct iphdr *iph;
	struct udphdr *udph;
	void *payload;
	u32 payload_len;

	status = 0;

	/* Parse packet headers */
	eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_DROP;

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > data_end)
		return XDP_DROP;

	if (iph->protocol != IPPROTO_UDP)
		return XDP_PASS;

	udph = (void *)iph + iph->ihl * 4;
	if ((void *)(udph + 1) > data_end)
		return XDP_DROP;

	/* Check for our test port */
	if (udph->dest != bpf_htons(test_port))
		return XDP_PASS;

	payload = (void *)(udph + 1);
	payload_len = bpf_ntohs(udph->len) - sizeof(*udph);

	/* Limit payload size for test */
	if (payload_len > 32)
		payload_len = 32;

	if ((void *)payload + payload_len > data_end)
		return XDP_DROP;

	/* Copy payload to buffer - use fixed size for BPF verifier */
	if (payload_len != 32)
		return XDP_DROP;  /* For testing, only handle 32-byte payloads */

	__builtin_memcpy(encrypt_src_buf, payload, 32);

	/* Get crypto context */
	v = crypto_ctx_value_lookup();
	if (!v) {
		status = -ENOENT;
		return XDP_DROP;
	}

	ctx = v->ctx;
	if (!ctx) {
		status = -ENOENT;
		return XDP_DROP;
	}

	/* Create dynptrs for encryption - fixed 32 bytes */
	bpf_dynptr_from_mem(encrypt_src_buf, 32, 0, &psrc);
	bpf_dynptr_from_mem(encrypt_dst_buf, 48, 0, &pdst);  /* 32 + 16 for auth tag */
	bpf_dynptr_from_mem(aead_iv, sizeof(aead_iv), 0, &piv);

	/* Encrypt */
	status = bpf_crypto_encrypt(ctx, &psrc, &pdst, &piv);
	if (status != 0)
		return XDP_DROP;

	/* Store result for verification - fixed size */
	result_len = 48;  /* 32 bytes plaintext + 16 bytes tag */
	__builtin_memcpy(encrypted_result, encrypt_dst_buf, 48);

	return XDP_PASS;
}

/* XDP program to decrypt UDP payload with auth tag */
SEC("xdp")
int xdp_aead_decrypt(struct xdp_md *xdp)
{
	struct __crypto_ctx_value *v;
	struct bpf_crypto_ctx *ctx;
	struct bpf_dynptr psrc, pdst, piv;
	void *data_end = (void *)(long)xdp->data_end;
	void *data = (void *)(long)xdp->data;
	struct ethhdr *eth;
	struct iphdr *iph;
	struct udphdr *udph;
	void *payload;
	u32 payload_len;

	status = 0;

	/* Parse packet headers */
	eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_DROP;

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > data_end)
		return XDP_DROP;

	if (iph->protocol != IPPROTO_UDP)
		return XDP_PASS;

	udph = (void *)iph + iph->ihl * 4;
	if ((void *)(udph + 1) > data_end)
		return XDP_DROP;

	/* Check for our test port */
	if (udph->dest != bpf_htons(test_port))
		return XDP_PASS;

	payload = (void *)(udph + 1);
	payload_len = bpf_ntohs(udph->len) - sizeof(*udph);

	/* For decryption, we expect ciphertext + tag - fixed 48 bytes */
	if (payload_len != 48)
		return XDP_DROP;

	if ((void *)payload + 48 > data_end)
		return XDP_DROP;

	/* Copy payload to buffer - fixed size */
	__builtin_memcpy(decrypt_src_buf, payload, 48);

	/* Get crypto context */
	v = crypto_ctx_value_lookup();
	if (!v) {
		status = -ENOENT;
		return XDP_DROP;
	}

	ctx = v->ctx;
	if (!ctx) {
		status = -ENOENT;
		return XDP_DROP;
	}

	/* Create dynptrs for decryption - fixed sizes */
	bpf_dynptr_from_mem(decrypt_src_buf, 48, 0, &psrc);  /* ciphertext + tag */
	bpf_dynptr_from_mem(decrypt_dst_buf, 32, 0, &pdst);  /* plaintext only */
	bpf_dynptr_from_mem(aead_iv, sizeof(aead_iv), 0, &piv);

	/* Decrypt and verify auth tag */
	status = bpf_crypto_decrypt(ctx, &psrc, &pdst, &piv);
	if (status != 0)
		return XDP_DROP;  /* Auth tag verification failed */

	/* Store result for verification - fixed size */
	result_len = 32;
	__builtin_memcpy(decrypted_result, decrypt_dst_buf, 32);

	return XDP_PASS;
}

char __license[] SEC("license") = "GPL";