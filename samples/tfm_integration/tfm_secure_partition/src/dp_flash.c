#include <tfm_ns_interface.h>
#include "psa/client.h"
#include "psa_manifest/sid.h"
#include "dummy_partition.h"
#include "dp_flash.h"

psa_status_t dp_flash_write(struct dp_flash_write_stats *stats)
{
	psa_handle_t handle;
	psa_status_t status;
	psa_outvec out_vec[] = {
		{ .base = stats, .len = sizeof(*stats) },
	};

	handle = psa_connect(TFM_DP_FLASH_WRITE_SID,
			     TFM_DP_FLASH_WRITE_VERSION);
	if (!PSA_HANDLE_IS_VALID(handle)) {
		return PSA_ERROR_CONNECTION_REFUSED;
	}

	status = psa_call(handle, PSA_IPC_CALL, NULL, 0,
			  out_vec, IOVEC_LEN(out_vec));
	psa_close(handle);
	return status;
}