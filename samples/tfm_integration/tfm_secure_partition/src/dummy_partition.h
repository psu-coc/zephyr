/*
 * Copyright (c) 2021 Nordic Semiconductor ASA.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

//Benstart
#define TFM_DP_LINEAR_HMAC_SID      (0xFFFFF002U)
#define TFM_DP_LINEAR_HMAC_VERSION  (1U)
#define TFM_DP_LINEAR_HMAC_SIGNAL   (1 << 1)

#define TFM_DP_SHUFFLED_HMAC_SID      (0xFFFFF003U)
#define TFM_DP_SHUFFLED_HMAC_VERSION  (1U)
#define TFM_DP_SHUFFLED_HMAC_SIGNAL   (1 << 2)

/* New function prototypes */
psa_status_t dp_linear_hmac(void *p_digest, size_t digest_size);
psa_status_t dp_shuffled_hmac(void *p_digest, size_t digest_size);

//Benend
psa_status_t dp_secret_digest(uint32_t secret_index,
			      void *p_digest,
			      size_t digest_size);
