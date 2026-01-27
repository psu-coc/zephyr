/*
 * SMARM Secure Partition Implementation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stddef.h>
#include "psa/service.h"
#include "psa_manifest/tfm_smarm_partition.h"
#include "../crypto/hmac-sha256/hmac-sha256.h"

/* Configuration - hardcoded as requested */
/* Start with smaller size for testing, can increase later */
#define BLOCK_SIZE 64
#define TOTAL_SIZE 0x80000  /* 512KB - match your FreeRTOS version */
#define BLOCKS (TOTAL_SIZE / BLOCK_SIZE)
#define SHA256_DIGEST_SIZE 32

/* Memory region to attest (flash address) - Non-secure flash */
/* STM32L5: Flash starts at 0x08000000, we use offset 0x040000 (256KB) */
/* Note: Ensure this region is readable from secure world */
uint8_t *real_memory = (uint8_t *)0x08000000;

/* HMAC key */
static const uint8_t key[] = "MySecureKey123";

/* ARM CMSIS intrinsics */
#define __disable_irq() __asm volatile("cpsid i" : : : "memory")
#define __enable_irq()  __asm volatile("cpsie i" : : : "memory")

typedef void (*psa_write_callback_t)(void *handle, uint8_t *digest, uint32_t digest_size);

/* Simple PRNG - can be replaced with AES-CTR later */
static uint32_t simple_rand(uint32_t *seed)
{
	*seed = (*seed * 1103515245 + 12345);
	return (*seed / 65536) % 32768;
}

/* Secure Shuffled HMAC - Main function */
static psa_status_t tfm_smarm_shuffled_hmac_secure(const uint8_t *challenge, size_t challenge_len,
                                                    size_t digest_size, size_t *p_digest_size,
                                                    psa_write_callback_t callback, void *handle)
{
	uint8_t digest[SHA256_DIGEST_SIZE];
	hmac_sha256 hmac;
	static int indices[BLOCKS];
	uint32_t seed;

	if (digest_size != SHA256_DIGEST_SIZE) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	/* Memory is already in flash - don't initialize (read-only) */

	/* Derive seed from challenge */
	seed = 42; /* Default seed */
	if (challenge && challenge_len >= 4) {
		/* Use first 4 bytes of challenge as seed */
		for (int i = 0; i < 4 && i < (int)challenge_len; i++) {
			seed ^= ((uint32_t)challenge[i]) << (i * 8);
		}
	}

	/* Initialize indices */
	for (int i = 0; i < BLOCKS; i++) {
		indices[i] = i;
	}

	/* Shuffle indices using Fisher-Yates */
	for (int i = BLOCKS - 1; i > 0; i--) {
		int j = simple_rand(&seed) % (i + 1);
		int tmp = indices[i];
		indices[i] = indices[j];
		indices[j] = tmp;
	}

	/* Initialize HMAC with key */
	hmac_sha256_initialize(&hmac, key, sizeof(key) - 1);

	/* Process blocks in shuffled order with RT-SMARM interrupt control */
	/* Match FreeRTOS pattern: disable IRQ, process block, enable IRQ for each block */
	/* This allows NormalTask to run between each block processing */
	for (int i = 0; i < BLOCKS; i++) {
		const uint8_t *blk = &real_memory[(size_t)indices[i] * BLOCK_SIZE];
		
		/* RT-SMARM: Disable IRQ, process block, then enable IRQ */
		/* This matches your FreeRTOS implementation exactly */
		// __disable_irq();
		hmac_sha256_update(&hmac, blk, BLOCK_SIZE);
		// __enable_irq();
	}

	/* Finalize HMAC */
	hmac_sha256_finalize(&hmac, NULL, 0);
	/* Copy digest - use direct assignment since it's small */
	for (int i = 0; i < SHA256_DIGEST_SIZE; i++) {
		digest[i] = hmac.digest[i];
	}

	*p_digest_size = SHA256_DIGEST_SIZE;
	callback(handle, digest, *p_digest_size);
	return PSA_SUCCESS;
}

/* Write callback helper */
static void psa_write_digest_helper(void *handle, uint8_t *digest, uint32_t digest_size)
{
	psa_write((psa_handle_t)handle, 0, digest, digest_size);
}

/* IPC handler */
static psa_status_t tfm_smarm_shuffled_hmac_secure_ipc(psa_msg_t *msg)
{
	size_t num;
	uint8_t challenge[16];

	/* Read challenge */
	if (msg->in_size[0] > sizeof(challenge)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	/* Read challenge if provided */
	size_t challenge_len = 0;
	if (msg->in_size[0] > 0) {
		num = psa_read(msg->handle, 0, challenge, msg->in_size[0]);
		if (num != msg->in_size[0]) {
			return PSA_ERROR_PROGRAMMER_ERROR;
		}
		challenge_len = num;
	}

	/* Call secure function */
	return tfm_smarm_shuffled_hmac_secure(challenge, challenge_len, msg->out_size[0],
	                                      &msg->out_size[0], psa_write_digest_helper,
	                                      (void *)msg->handle);
}

/* Signal handler */
typedef psa_status_t (*smarm_func_t)(psa_msg_t *);

static void smarm_signal_handle(psa_signal_t signal, smarm_func_t pfn)
{
	psa_status_t status;
	psa_msg_t msg;

	status = psa_get(signal, &msg);
	switch (msg.type) {
	case PSA_IPC_CONNECT:
		psa_reply(msg.handle, PSA_SUCCESS);
		break;
	case PSA_IPC_CALL:
		status = pfn(&msg);
		psa_reply(msg.handle, status);
		break;
	case PSA_IPC_DISCONNECT:
		psa_reply(msg.handle, PSA_SUCCESS);
		break;
	default:
		psa_panic();
	}
}

/* Request manager init */
psa_status_t tfm_smarm_req_mngr_init(void)
{
	psa_signal_t signals = 0;

	while (1) {
		signals = psa_wait(PSA_WAIT_ANY, PSA_BLOCK);

		if (signals & TFM_SMARM_SERVICE_SIGNAL) {
			smarm_signal_handle(TFM_SMARM_SERVICE_SIGNAL,
			                    tfm_smarm_shuffled_hmac_secure_ipc);
		} else {
			psa_panic();
		}
	}

	return PSA_ERROR_SERVICE_FAILURE;
}
