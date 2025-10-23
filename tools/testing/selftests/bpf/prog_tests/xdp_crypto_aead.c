// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include "test_xdp_crypto_aead.skel.h"

#define XDP_PASS 2
#define XDP_DROP 1

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

/* Test key for ChaCha20-Poly1305 */
static const unsigned char test_key[32] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};

/* Test IV for ChaCha20-Poly1305 (96 bits) */
static const unsigned char test_iv[12] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c
};

/* Test plaintext */
static const char test_plaintext[] = "Ladies and Gentlemen of the clas";

/* Create a UDP packet for testing */
static void create_udp_packet(char *buf, size_t buf_size,
                             const char *payload, size_t payload_len,
                             __u16 port)
{
	struct ethhdr *eth = (struct ethhdr *)buf;
	struct iphdr *iph = (struct iphdr *)(eth + 1);
	struct udphdr *udph = (struct udphdr *)(iph + 1);
	char *data = (char *)(udph + 1);

	/* Ethernet header */
	memset(eth, 0, sizeof(*eth));
	eth->h_proto = htons(ETH_P_IP);

	/* IP header */
	memset(iph, 0, sizeof(*iph));
	iph->version = 4;
	iph->ihl = 5;
	iph->tot_len = htons(sizeof(*iph) + sizeof(*udph) + payload_len);
	iph->protocol = IPPROTO_UDP;

	/* UDP header */
	memset(udph, 0, sizeof(*udph));
	udph->source = htons(1234);
	udph->dest = htons(port);
	udph->len = htons(sizeof(*udph) + payload_len);

	/* Payload */
	if (payload && payload_len > 0)
		memcpy(data, payload, payload_len);
}

static void test_xdp_aead_basic(void)
{
	struct test_xdp_crypto_aead *skel;
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	char packet_buf[256];
	char encrypted[48] = {};
	char decrypted[32] = {};
	int err, prog_fd;
	size_t packet_size;

	skel = test_xdp_crypto_aead__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel open"))
		return;

	/* Setup AEAD parameters */
	skel->bss->key_len = 32;
	skel->data->aead_authsize = 16;
	memcpy(skel->bss->aead_key, test_key, 32);
	memcpy(skel->bss->aead_iv, test_iv, 12);
	snprintf(skel->bss->algo, sizeof(skel->bss->algo),
	         "rfc7539(chacha20,poly1305)");

	/* Create crypto context */
	prog_fd = bpf_program__fd(skel->progs.xdp_aead_crypto_setup);
	if (!ASSERT_GT(prog_fd, 0, "setup prog fd"))
		goto cleanup;

	err = bpf_prog_test_run_opts(prog_fd, &opts);
	if (err != 0 || opts.retval != 0 || skel->bss->status != 0) {
		/* Try fallback to AES-GCM if ChaCha20 not available */
		skel->bss->key_len = 16;
		snprintf(skel->bss->algo, sizeof(skel->bss->algo), "gcm(aes)");
		skel->bss->status = 0;
		err = bpf_prog_test_run_opts(prog_fd, &opts);
		if (!ASSERT_OK(err, "aead_crypto_setup fallback") ||
		    !ASSERT_OK(skel->bss->status, "aead_crypto_setup fallback status"))
			goto cleanup;
	}

	/* Test encryption */
	create_udp_packet(packet_buf, sizeof(packet_buf),
	                 test_plaintext, 32, 7778);
	packet_size = sizeof(struct ethhdr) + sizeof(struct iphdr) +
	              sizeof(struct udphdr) + 32;

	prog_fd = bpf_program__fd(skel->progs.xdp_aead_encrypt);
	if (!ASSERT_GT(prog_fd, 0, "encrypt prog fd"))
		goto cleanup;

	opts.data_in = packet_buf;
	opts.data_size_in = packet_size;
	opts.data_out = packet_buf;
	opts.data_size_out = sizeof(packet_buf);

	err = bpf_prog_test_run_opts(prog_fd, &opts);
	if (!ASSERT_OK(err, "encrypt run"))
		goto cleanup;
	if (!ASSERT_EQ(opts.retval, XDP_PASS, "encrypt retval"))
		goto cleanup;
	if (!ASSERT_OK(skel->bss->status, "encrypt status"))
		goto cleanup;

	/* Save encrypted result */
	memcpy(encrypted, skel->bss->encrypted_result, 48);
	if (!ASSERT_EQ(skel->bss->result_len, 48, "encrypted length"))
		goto cleanup;

	/* Test decryption */
	create_udp_packet(packet_buf, sizeof(packet_buf),
	                 encrypted, 48, 7778);
	packet_size = sizeof(struct ethhdr) + sizeof(struct iphdr) +
	              sizeof(struct udphdr) + 48;

	prog_fd = bpf_program__fd(skel->progs.xdp_aead_decrypt);
	if (!ASSERT_GT(prog_fd, 0, "decrypt prog fd"))
		goto cleanup;

	/* Reset IV for decryption */
	memcpy(skel->bss->aead_iv, test_iv, 12);

	opts.data_in = packet_buf;
	opts.data_size_in = packet_size;
	opts.data_out = packet_buf;
	opts.data_size_out = sizeof(packet_buf);

	err = bpf_prog_test_run_opts(prog_fd, &opts);
	if (!ASSERT_OK(err, "decrypt run"))
		goto cleanup;
	if (!ASSERT_EQ(opts.retval, XDP_PASS, "decrypt retval"))
		goto cleanup;
	if (!ASSERT_OK(skel->bss->status, "decrypt status"))
		goto cleanup;

	/* Verify decrypted result matches original */
	memcpy(decrypted, skel->bss->decrypted_result, 32);
	if (!ASSERT_EQ(skel->bss->result_len, 32, "decrypted length"))
		goto cleanup;
	if (!ASSERT_MEMEQ(decrypted, test_plaintext, 32, "decrypted data"))
		goto cleanup;

cleanup:
	test_xdp_crypto_aead__destroy(skel);
}

static void test_xdp_aead_auth_failure(void)
{
	struct test_xdp_crypto_aead *skel;
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	char packet_buf[256];
	char encrypted[48] = {};
	int err, prog_fd;
	size_t packet_size;

	skel = test_xdp_crypto_aead__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel open"))
		return;

	/* Setup AEAD parameters */
	skel->bss->key_len = 32;
	skel->data->aead_authsize = 16;
	memcpy(skel->bss->aead_key, test_key, 32);
	memcpy(skel->bss->aead_iv, test_iv, 12);
	snprintf(skel->bss->algo, sizeof(skel->bss->algo),
	         "rfc7539(chacha20,poly1305)");

	/* Create crypto context */
	prog_fd = bpf_program__fd(skel->progs.xdp_aead_crypto_setup);
	err = bpf_prog_test_run_opts(prog_fd, &opts);
	if (err != 0 || opts.retval != 0 || skel->bss->status != 0) {
		/* Try fallback to AES-GCM if ChaCha20 not available */
		skel->bss->key_len = 16;
		snprintf(skel->bss->algo, sizeof(skel->bss->algo), "gcm(aes)");
		skel->bss->status = 0;
		err = bpf_prog_test_run_opts(prog_fd, &opts);
		if (!ASSERT_OK(err, "aead_crypto_setup fallback") ||
		    !ASSERT_OK(skel->bss->status, "aead_crypto_setup fallback status"))
			goto cleanup;
	}

	/* First encrypt */
	create_udp_packet(packet_buf, sizeof(packet_buf),
	                 test_plaintext, 32, 7778);
	packet_size = sizeof(struct ethhdr) + sizeof(struct iphdr) +
	              sizeof(struct udphdr) + 32;

	prog_fd = bpf_program__fd(skel->progs.xdp_aead_encrypt);
	opts.data_in = packet_buf;
	opts.data_size_in = packet_size;
	opts.data_out = packet_buf;
	opts.data_size_out = sizeof(packet_buf);

	err = bpf_prog_test_run_opts(prog_fd, &opts);
	if (!ASSERT_OK(err, "encrypt run") ||
	    !ASSERT_OK(skel->bss->status, "encrypt status"))
		goto cleanup;

	/* Save encrypted result and corrupt the auth tag */
	memcpy(encrypted, skel->bss->encrypted_result, 48);
	encrypted[47] ^= 0xFF;  /* Corrupt last byte of auth tag */
	encrypted[46] ^= 0xAA;  /* Corrupt another byte */

	/* Try to decrypt with corrupted auth tag */
	create_udp_packet(packet_buf, sizeof(packet_buf),
	                 encrypted, 48, 7778);
	packet_size = sizeof(struct ethhdr) + sizeof(struct iphdr) +
	              sizeof(struct udphdr) + 48;

	prog_fd = bpf_program__fd(skel->progs.xdp_aead_decrypt);
	memcpy(skel->bss->aead_iv, test_iv, 12);  /* Reset IV */

	opts.data_in = packet_buf;
	opts.data_size_in = packet_size;
	opts.data_out = packet_buf;
	opts.data_size_out = sizeof(packet_buf);

	err = bpf_prog_test_run_opts(prog_fd, &opts);
	if (!ASSERT_OK(err, "decrypt run"))
		goto cleanup;

	/* Should drop packet due to auth failure */
	if (!ASSERT_EQ(opts.retval, XDP_DROP, "decrypt should drop"))
		goto cleanup;
	if (!ASSERT_NEQ(skel->bss->status, 0, "decrypt should fail"))
		goto cleanup;

cleanup:
	test_xdp_crypto_aead__destroy(skel);
}

void test_xdp_crypto_aead(void)
{
	if (test__start_subtest("basic"))
		test_xdp_aead_basic();
	if (test__start_subtest("auth_failure"))
		test_xdp_aead_auth_failure();
}