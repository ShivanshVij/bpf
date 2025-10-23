// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_alg.h>

#include "test_progs.h"
#include "network_helpers.h"
#include "crypto_aead.skel.h"

#define NS_TEST "crypto_aead_ns"
#define IPV6_IFACE_ADDR "face::2"

/* Test key (32 bytes for ChaCha20-Poly1305 or AES-256) */
static const unsigned char test_key[] = {
	0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
	0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
	0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
	0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
};

/* Test plaintext - exactly 32 bytes */
static const char plain_text[32] = "Ladies and Gentlemen of the clas";

static int opfd = -1, tfmfd = -1;
/* Try different AEAD algorithms */
static const char *aead_algos[] = {
	"gcm(aes)",  /* Most likely to be available */
	"rfc7539(chacha20,poly1305)",  /* ChaCha20-Poly1305 RFC7539 */
	"chacha20poly1305",  /* Alternative name */
	NULL
};
static const char *current_algo = NULL;
static int afalg_key_len = 0;

static int init_afalg_aead(void)
{
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "aead",
	};
	int err, i;

	/* Try different algorithm names */
	for (i = 0; aead_algos[i] != NULL; i++) {
		strncpy((char *)sa.salg_name, aead_algos[i], sizeof(sa.salg_name));
		sa.salg_name[sizeof(sa.salg_name) - 1] = '\0'; /* Ensure null termination */

		tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
		if (tfmfd == -1) {
			err = errno;
			continue;
		}

		if (bind(tfmfd, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
			err = errno;
			close(tfmfd);
			tfmfd = -1;
			continue;
		}

		/* For GCM(AES), we need to use proper key size - try 32 bytes (AES-256) */
		afalg_key_len = sizeof(test_key);
		if (setsockopt(tfmfd, SOL_ALG, ALG_SET_KEY, test_key, afalg_key_len) == -1) {
			err = errno;
			close(tfmfd);
			tfmfd = -1;
			/* If AES-256 fails, try AES-128 (16 bytes) */
			if (strstr(aead_algos[i], "aes")) {
				tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
				if (tfmfd != -1 && bind(tfmfd, (struct sockaddr *)&sa, sizeof(sa)) == 0) {
					afalg_key_len = 16;
					if (setsockopt(tfmfd, SOL_ALG, ALG_SET_KEY, test_key, afalg_key_len) == 0) {
						goto accept_socket;
					}
					close(tfmfd);
					tfmfd = -1;
				}
			}
			continue;
		}

accept_socket:
		/* Most AEAD algorithms have a default authsize, some may need explicit setting */

		opfd = accept(tfmfd, NULL, 0);
		if (opfd == -1) {
			err = errno;
			close(tfmfd);
			tfmfd = -1;
			continue;
		}

		/* Success! */
		current_algo = aead_algos[i];
		printf("AF_ALG AEAD initialized with algorithm: %s\n", current_algo);
		return 0;
	}

	/* All algorithms failed */
	printf("AF_ALG AEAD init failed - no AEAD algorithm available\n");
	return ENOTSUP;
}

static void deinit_afalg(void)
{
	if (tfmfd != -1)
		close(tfmfd);
	if (opfd != -1)
		close(opfd);
}

static int do_crypt_aead(const void *src, void *dst, int size, const void *iv, int ivlen, bool encrypt)
{
	struct msghdr msg = {};
	struct cmsghdr *cmsg;
	char cbuf[256];  /* Enough for control messages */
	struct iovec iov;
	int err;

	if (opfd == -1 || tfmfd == -1)
		return -1;

	memset(cbuf, 0, sizeof(cbuf));

	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);

	/* Set operation */
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(4);
	*(__u32 *)CMSG_DATA(cmsg) = encrypt ? ALG_OP_ENCRYPT : ALG_OP_DECRYPT;

	/* Set IV */
	cmsg = CMSG_NXTHDR(&msg, cmsg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_IV;
	cmsg->cmsg_len = CMSG_LEN(4 + ivlen);
	*((__u32 *)CMSG_DATA(cmsg)) = ivlen;
	memcpy(CMSG_DATA(cmsg) + 4, iv, ivlen);

	iov.iov_base = (char *)src;
	iov.iov_len = size;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	err = sendmsg(opfd, &msg, 0);
	if (err < 0)
		return err;

	return read(opfd, dst, encrypt ? size + 16 : size - 16);
}

void test_crypto_aead(void)
{
	LIBBPF_OPTS(bpf_tc_hook, qdisc_hook, .attach_point = BPF_TC_EGRESS);
	LIBBPF_OPTS(bpf_tc_opts, tc_attach_enc);
	LIBBPF_OPTS(bpf_tc_opts, tc_attach_dec);
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	struct nstoken *nstoken = NULL;
	struct crypto_aead *skel;
	char encrypted[48] = {0};  /* Space for ciphertext + tag */
	char decrypted[32] = {0};  /* Space for decrypted plaintext */
	struct sockaddr_in6 addr;
	char iv[16] = {0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43,
		       0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b};
	int sockfd, err, pfd;
	socklen_t addrlen;
	u16 udp_test_port;
	bool use_afalg = false;
	int iv_len = 12;  /* Default IV size for GCM and ChaCha20-Poly1305 */

	skel = crypto_aead__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel open"))
		return;

	SYS(fail, "ip netns add %s", NS_TEST);
	SYS(fail, "ip -net %s -6 addr add %s/128 dev lo nodad", NS_TEST, IPV6_IFACE_ADDR);
	SYS(fail, "ip -net %s link set dev lo up", NS_TEST);

	nstoken = open_netns(NS_TEST);
	if (!ASSERT_OK_PTR(nstoken, "open_netns"))
		goto fail;

	/* Try to init AF_ALG, but don't fail the test if it doesn't work */
	err = init_afalg_aead();
	if (err != 0) {
		printf("Warning: AF_ALG AEAD init failed, continuing without AF_ALG validation\n");
		printf("This is expected if ChaCha20-Poly1305 is not available in the kernel\n");
		use_afalg = false;
		current_algo = NULL;
	} else {
		use_afalg = true;
	}

	qdisc_hook.ifindex = if_nametoindex("lo");
	if (!ASSERT_GT(qdisc_hook.ifindex, 0, "if_nametoindex lo"))
		goto fail;

	/* Setup AEAD algorithm - try ChaCha20-Poly1305 with different names */
	skel->data->aead_authsize = 16;  /* Poly1305 tag is 16 bytes */
	udp_test_port = skel->data->udp_test_port;
	skel->bss->key_len = 32;  /* ChaCha20 uses 256-bit keys */
	memcpy(skel->bss->aead_key, test_key, 32);

	/* Try different ChaCha20-Poly1305 algorithm names */
	const char *chacha_algos[] = {
		"rfc7539(chacha20,poly1305)",
		"chacha20poly1305",
		"gcm(aes)",  /* Fallback to AES-GCM if ChaCha20-Poly1305 not available */
		NULL
	};

	int algo_idx;
	bool algo_found = false;
	for (algo_idx = 0; chacha_algos[algo_idx] != NULL; algo_idx++) {
		snprintf(skel->bss->algo, 128, "%s", chacha_algos[algo_idx]);

		/* Adjust key size for AES-GCM */
		if (strstr(chacha_algos[algo_idx], "aes")) {
			skel->bss->key_len = 16;  /* Use AES-128 */
		}

		printf("Trying BPF AEAD with algorithm: %s\n", chacha_algos[algo_idx]);

		pfd = bpf_program__fd(skel->progs.aead_crypto_setup);
		if (!ASSERT_GT(pfd, 0, "aead_crypto_setup fd"))
			goto fail;

		err = bpf_prog_test_run_opts(pfd, &opts);
		if (err == 0 && opts.retval == 0 && skel->bss->status == 0) {
			printf("Successfully initialized BPF AEAD with algorithm: %s\n", chacha_algos[algo_idx]);
			algo_found = true;
			break;
		}
		/* Reset status for next try */
		skel->bss->status = 0;
	}

	if (!algo_found) {
		ASSERT_OK(skel->bss->status, "aead_crypto_setup - no algorithm worked");
		goto fail;
	}

	err = bpf_tc_hook_create(&qdisc_hook);
	if (!ASSERT_OK(err, "create qdisc hook"))
		goto fail;

	addrlen = sizeof(addr);
	err = make_sockaddr(AF_INET6, IPV6_IFACE_ADDR, udp_test_port,
			    (void *)&addr, &addrlen);
	if (!ASSERT_OK(err, "make_sockaddr"))
		goto fail;

	/* Set the same IV in BPF program */
	memcpy(skel->bss->aead_iv, iv, iv_len);

	/* Test encryption */
	tc_attach_enc.prog_fd = bpf_program__fd(skel->progs.encrypt_aead);
	err = bpf_tc_attach(&qdisc_hook, &tc_attach_enc);
	if (!ASSERT_OK(err, "attach encrypt filter"))
		goto fail;

	sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (!ASSERT_NEQ(sockfd, -1, "encrypt socket"))
		goto fail;

	err = sendto(sockfd, plain_text, 32, 0, (void *)&addr, addrlen);
	close(sockfd);
	if (!ASSERT_EQ(err, 32, "encrypt send"))
		goto fail;

	printf("Encrypt debug: src_len=%d, dst_len=%d\n",
		skel->bss->encrypt_src_len, skel->bss->encrypt_dst_len);

	if (!ASSERT_OK(skel->bss->status, "encrypt status"))
		goto fail;

	/* Save the encrypted data for later decryption test */
	memcpy(encrypted, skel->bss->dst, 48);

	/* Only compare with AF_ALG if we're using the same algorithm */
	if (use_afalg && current_algo && strstr(current_algo, "chacha20")) {
		char afalg_dst[48] = {0};
		/* Encrypt with AF_ALG for comparison */
		err = do_crypt_aead(plain_text, afalg_dst, 32, iv, iv_len, true);
		if (!ASSERT_GT(err, 0, "AF_ALG encrypt"))
			goto fail;

		/* First 32 bytes should be ciphertext, last 16 should be tag */
		if (!ASSERT_MEMEQ(skel->bss->dst, afalg_dst, 32 + 16, "encrypt AEAD"))
			goto fail;
	} else {
		/* Without AF_ALG comparison, just verify the encryption produced output */
		/* Check that ciphertext is different from plaintext */
		if (!ASSERT_NEQ(memcmp(skel->bss->dst, plain_text, 32), 0, "ciphertext different from plaintext"))
			goto fail;
		printf("AF_ALG comparison skipped (algorithm mismatch or not available)\n");
	}

	tc_attach_enc.flags = tc_attach_enc.prog_fd = tc_attach_enc.prog_id = 0;
	err = bpf_tc_detach(&qdisc_hook, &tc_attach_enc);
	if (!ASSERT_OK(err, "bpf_tc_detach encrypt"))
		goto fail;

	/* Set the same IV in BPF program for decryption */
	memcpy(skel->bss->aead_iv, iv, iv_len);

	/* Test decryption */
	tc_attach_dec.prog_fd = bpf_program__fd(skel->progs.decrypt_aead);
	err = bpf_tc_attach(&qdisc_hook, &tc_attach_dec);
	if (!ASSERT_OK(err, "attach decrypt filter"))
		goto fail;

	sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (!ASSERT_NEQ(sockfd, -1, "decrypt socket"))
		goto fail;

	/* Send the encrypted data (ciphertext + tag) */
	err = sendto(sockfd, encrypted, 32 + 16, 0, (void *)&addr, addrlen);
	close(sockfd);
	if (!ASSERT_EQ(err, 32 + 16, "decrypt send"))
		goto fail;

	printf("Decrypt debug: src_len=%d, dst_len=%d, decrypt_result=%d\n",
		skel->bss->debug_src_len, skel->bss->debug_dst_len, skel->bss->debug_decrypt_result);

	if (!ASSERT_OK(skel->bss->status, "decrypt status"))
		goto fail;

	/* Copy decrypted data */
	memcpy(decrypted, skel->bss->dst, 32);

	/* Only compare with AF_ALG if we're using the same algorithm */
	if (use_afalg && current_algo && strstr(current_algo, "chacha20")) {
		char afalg_plain[32] = {0};
		/* Decrypt with AF_ALG for comparison */
		do_crypt_aead(encrypted, afalg_plain, 32 + 16, iv, iv_len, false);

		if (!ASSERT_MEMEQ(skel->bss->dst, afalg_plain, 32, "decrypt AEAD"))
			goto fail;
	}

	/* Always verify that decrypt(encrypt(plaintext)) == plaintext */
	if (!ASSERT_MEMEQ(decrypted, plain_text, 32, "decrypt returns original plaintext"))
		goto fail;

	tc_attach_dec.flags = tc_attach_dec.prog_fd = tc_attach_dec.prog_id = 0;
	err = bpf_tc_detach(&qdisc_hook, &tc_attach_dec);
	ASSERT_OK(err, "bpf_tc_detach decrypt");

fail:
	close_netns(nstoken);
	deinit_afalg();
	SYS_NOFAIL("ip netns del " NS_TEST " &> /dev/null");
	crypto_aead__destroy(skel);
}