/*
 * SMARM Partition Non-Secure Interface
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <tfm_ns_interface.h>
#include "smarm_partition.h"
#include "psa/client.h"
#include "psa_manifest/sid.h"

psa_status_t smarm_shuffled_hmac_secure(const uint8_t *challenge,
                                        size_t challenge_len,
                                        uint8_t *digest,
                                        size_t digest_size)
{
	psa_status_t status;
	psa_handle_t handle;

	psa_invec in_vec[] = {
		{ .base = challenge, .len = challenge_len },
	};

	psa_outvec out_vec[] = {
		{ .base = digest, .len = digest_size }
	};

	handle = psa_connect(TFM_SMARM_SERVICE_SID,
	                     TFM_SMARM_SERVICE_VERSION);
	if (!PSA_HANDLE_IS_VALID(handle)) {
		return PSA_ERROR_GENERIC_ERROR;
	}

	status = psa_call(handle, PSA_IPC_CALL, in_vec, IOVEC_LEN(in_vec),
	                  out_vec, IOVEC_LEN(out_vec));
	psa_close(handle);
	return status;
}
