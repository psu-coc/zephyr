/*
 * SMARM Partition Interface
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SMARM_PARTITION_H
#define SMARM_PARTITION_H

#include <stdint.h>
#include <stddef.h>
#include <psa/client.h>

#define TFM_SMARM_SERVICE_SID      (0xFFFFF040U)
#define TFM_SMARM_SERVICE_VERSION  (1U)

#define SHA256_DIGEST_SIZE 32

/**
 * @brief Call secure shuffled HMAC function
 *
 * @param challenge Challenge data (16 bytes)
 * @param challenge_len Length of challenge
 * @param digest Output digest buffer (32 bytes)
 * @param digest_size Size of digest buffer (must be 32)
 * @return psa_status_t PSA_SUCCESS on success, error code otherwise
 */
psa_status_t smarm_shuffled_hmac_secure(const uint8_t *challenge,
                                        size_t challenge_len,
                                        uint8_t *digest,
                                        size_t digest_size);

#endif /* SMARM_PARTITION_H */
