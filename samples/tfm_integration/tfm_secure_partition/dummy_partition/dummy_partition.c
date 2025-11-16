/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <psa/crypto.h>
#include <stdbool.h>
#include <stdint.h>


#include "psa/service.h"
#include "psa_manifest/tfm_dummy_partition.h"
#include "../crypto/hmac-sha256/hmac-sha256.h"
#define NUM_SECRETS 5


/* ARM CMSIS intrinsics - usually available by default */
#define __disable_irq() __asm volatile("cpsid i" : : : "memory")
#define __enable_irq()  __asm volatile("cpsie i" : : : "memory")

struct dp_secret {
	uint8_t secret[16];
};

struct dp_secret secrets[NUM_SECRETS] = {
	{ {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} },
	{ {1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} },
	{ {2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} },
	{ {3, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} },
	{ {4, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} },
};

typedef void (*psa_write_callback_t)(void *handle, uint8_t *digest,
				     uint32_t digest_size);



static psa_status_t tfm_dp_secret_digest(uint32_t secret_index,
			size_t digest_size, size_t *p_digest_size,
			psa_write_callback_t callback, void *handle)
{
	uint8_t digest[32];
	psa_status_t status;

	/* Check that secret_index is valid. */
	if (secret_index >= NUM_SECRETS) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	/* Check that digest_size is valid. */
	if (digest_size != sizeof(digest)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	status = psa_hash_compute(PSA_ALG_SHA_256, secrets[secret_index].secret,
				sizeof(secrets[secret_index].secret), digest,
				digest_size, p_digest_size);

	if (status != PSA_SUCCESS) {
		return status;
	}
	if (*p_digest_size != digest_size) {
		return PSA_ERROR_PROGRAMMER_ERROR;
	}

	callback(handle, digest, digest_size);

	return PSA_SUCCESS;
}

typedef psa_status_t (*dp_func_t)(psa_msg_t *);

static void psa_write_digest(void *handle, uint8_t *digest,
			     uint32_t digest_size)
{
	psa_write((psa_handle_t)handle, 0, digest, digest_size);
}

static psa_status_t tfm_dp_secret_digest_ipc(psa_msg_t *msg)
{
	size_t num = 0;
	uint32_t secret_index;

	if (msg->in_size[0] != sizeof(secret_index)) {
		/* The size of the argument is incorrect */
		return PSA_ERROR_PROGRAMMER_ERROR;
	}

	num = psa_read(msg->handle, 0, &secret_index, msg->in_size[0]);
	if (num != msg->in_size[0]) {
		return PSA_ERROR_PROGRAMMER_ERROR;
	}

	return tfm_dp_secret_digest(secret_index, msg->out_size[0],
				    &msg->out_size[0], psa_write_digest,
				    (void *)msg->handle);
}


//Benstart


#define BLOCK_SIZE 1024 //Ben old 4096
#define TOTAL_SIZE 0x40000   //Ben old 0x40000
#define BLOCKS (TOTAL_SIZE / BLOCK_SIZE)

/* Simulated memory region to attest (in secure world) */
// static uint8_t attestation_memory[TOTAL_SIZE];
uint8_t *attestation_memory = (uint8_t *)0x8040000;
static const uint8_t attestation_key[] = "MySecureKey123";

/* Simple pseudo-random number generator (no stdlib needed) */
static uint32_t simple_rand(uint32_t *seed)
{
	*seed = (*seed * 1103515245 + 12345);
	return (*seed / 65536) % 32768;
}


static psa_status_t tfm_dp_linear_hmac_old(size_t digest_size, size_t *p_digest_size,psa_write_callback_t callback, void *handle)
 {
	uint8_t digest[SHA256_DIGEST_SIZE];
	hmac_sha256 hmac;

	if (digest_size != SHA256_DIGEST_SIZE) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	/* Initialize HMAC with your key */
	hmac_sha256_initialize(&hmac,
			       attestation_key,
			       strlen((const char *)attestation_key));

	/* Process memory (sequential, like your FreeRTOS version) */
	/* If you want the same semantics as your example: single big update */
	hmac_sha256_update(&hmac,
			   (const uint8_t *)attestation_memory,
			   TOTAL_SIZE);

	/* Finalize and get digest */
	hmac_sha256_finalize(&hmac, NULL, 0);
	memcpy(digest, hmac.digest, SHA256_DIGEST_SIZE);

	*p_digest_size = SHA256_DIGEST_SIZE;
	callback(handle, digest, *p_digest_size);

	return PSA_SUCCESS;
 
}

/* Linear HMAC - Sequential block processing */
static psa_status_t tfm_dp_linear_hmac(size_t digest_size, size_t *p_digest_size,
	psa_write_callback_t callback, void *handle)
{
	uint8_t digest[32];
	psa_mac_operation_t operation = PSA_MAC_OPERATION_INIT;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_id;
	psa_status_t status;

	if (digest_size != sizeof(digest)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}

// __disable_irq();


/* Fill memory with test pattern */
// for (int i = 0; i < TOTAL_SIZE; i++) {
// 	attestation_memory[i] = i & 0xFF;
// }

	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
	psa_set_key_algorithm(&attributes, PSA_ALG_HMAC(PSA_ALG_SHA_256));
	psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
	psa_set_key_bits(&attributes, sizeof(attestation_key) * 8);

	status = psa_import_key(&attributes, attestation_key, sizeof(attestation_key), &key_id);
	if (status != PSA_SUCCESS) {
		__enable_irq();  // ✅ Add this - restore interrupts before return
		return status;
	}
	status = psa_mac_sign_setup(&operation, key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256));
	if (status != PSA_SUCCESS) {
		psa_destroy_key(key_id);
		__enable_irq();  // ✅ Add this - restore interrupts before return

		return status;
	}

	// Ben : update the whole memory
	// status = psa_mac_update(&operation, block, TOTAL_SIZE);

	/* Process blocks sequentially (like hmac_sha256_update loop) */
	for (int i = 0; i < BLOCKS; i++) {
		const uint8_t *block = &attestation_memory[i * BLOCK_SIZE];
		// ✅ Use psa_mac_update instead of psa_hash_update
		status = psa_mac_update(&operation, block, BLOCK_SIZE);
		if (status != PSA_SUCCESS) {
			psa_mac_abort(&operation);
			psa_destroy_key(key_id);
			__enable_irq();  // ✅ Add this - restore interrupts before return

			return status;
		}
	}

	/* Finalize HMAC (like hmac_sha256_finalize) */
	status = psa_mac_sign_finish(&operation, digest, digest_size, p_digest_size);
	psa_destroy_key(key_id);

	// __enable_irq();  // ✅ Restore interrupts
	// irq_unlock(keylock);
	if (status != PSA_SUCCESS) {
		return status;
	}

if (*p_digest_size != digest_size) {
return PSA_ERROR_PROGRAMMER_ERROR;
}



callback(handle, digest, digest_size);


return PSA_SUCCESS;

}
/* Shuffled HMAC - Randomized block processing (SMARM) */
static psa_status_t tfm_dp_shuffled_hmac(size_t digest_size, size_t *p_digest_size,
                                          psa_write_callback_t callback, void *handle)
{
	uint8_t digest[32];
	uint8_t temp_block[BLOCK_SIZE];
	psa_hash_operation_t hash_op = PSA_HASH_OPERATION_INIT;
	psa_status_t status;
	static int indices[BLOCKS];
	uint32_t seed = 42; // Fixed seed for reproducibility

	if (digest_size != sizeof(digest)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	/* Fill memory with test pattern */
	for (int i = 0; i < TOTAL_SIZE; i++) {
		attestation_memory[i] = i & 0xFF;
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

	/* Setup hash operation */
	status = psa_hash_setup(&hash_op, PSA_ALG_SHA_256);
	if (status != PSA_SUCCESS) {
		return status;
	}

	/* Process blocks in shuffled order */
	for (int i = 0; i < BLOCKS; i++) {
		uint8_t *block = &attestation_memory[indices[i] * BLOCK_SIZE];
		status = psa_hash_update(&hash_op, block, BLOCK_SIZE);
		if (status != PSA_SUCCESS) {
			psa_hash_abort(&hash_op);
			return status;
		}
	}

	/* Finalize hash */
	status = psa_hash_finish(&hash_op, digest, digest_size, p_digest_size);
	if (status != PSA_SUCCESS) {
		return status;
	}

	if (*p_digest_size != digest_size) {
		return PSA_ERROR_PROGRAMMER_ERROR;
	}

	callback(handle, digest, digest_size);
	return PSA_SUCCESS;
}

/* IPC handlers for new services */
static psa_status_t tfm_dp_linear_hmac_ipc(psa_msg_t *msg)
{
	return tfm_dp_linear_hmac(msg->out_size[0], &msg->out_size[0],
	                          psa_write_digest, (void *)msg->handle);
}

static psa_status_t tfm_dp_shuffled_hmac_ipc(psa_msg_t *msg)
{
	return tfm_dp_shuffled_hmac(msg->out_size[0], &msg->out_size[0],
	                            psa_write_digest, (void *)msg->handle);
}

//Benend





static void dp_signal_handle(psa_signal_t signal, dp_func_t pfn)
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




// psa_status_t tfm_dp_req_mngr_init(void)
// {
// 	psa_signal_t signals = 0;

// 	while (1) {
// 		signals = psa_wait(PSA_WAIT_ANY, PSA_BLOCK);
// 		if (signals & TFM_DP_SECRET_DIGEST_SIGNAL) {
// 			dp_signal_handle(TFM_DP_SECRET_DIGEST_SIGNAL,
// 					 tfm_dp_secret_digest_ipc);
// 		} else {
// 			psa_panic();
// 		}
// 	}

// 	return PSA_ERROR_SERVICE_FAILURE;
// }

psa_status_t tfm_dp_req_mngr_init(void)
{
	psa_signal_t signals = 0;

	while (1) {
		signals = psa_wait(PSA_WAIT_ANY, PSA_BLOCK);
		
		if (signals & TFM_DP_SECRET_DIGEST_SIGNAL) {
			dp_signal_handle(TFM_DP_SECRET_DIGEST_SIGNAL,
			                 tfm_dp_secret_digest_ipc);
		} else if (signals & TFM_DP_LINEAR_HMAC_SIGNAL) {
			dp_signal_handle(TFM_DP_LINEAR_HMAC_SIGNAL,
			                 tfm_dp_linear_hmac_ipc);
		} else if (signals & TFM_DP_SHUFFLED_HMAC_SIGNAL) {
			dp_signal_handle(TFM_DP_SHUFFLED_HMAC_SIGNAL,
			                 tfm_dp_shuffled_hmac_ipc);
		} else {
			psa_panic();
		}
	}

	return PSA_ERROR_SERVICE_FAILURE;
}