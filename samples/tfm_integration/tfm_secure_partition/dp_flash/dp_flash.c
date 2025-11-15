#include <stdint.h>
#include <stdbool.h>
#include "psa/service.h"
#include "psa_manifest/tfm_dp_flash_partition.h"
#include <cmsis_compiler.h>
#include "dp_flash.h"
#include "cmsis.h"
#include "tfm_plat_defs.h"

#define FLASH_BASE_NS          0x08000000UL
#define FLASH_BANK2_BASE       (FLASH_BASE_NS + 0x00040000UL)
#define PATCH_START            0x08060000UL
#define PATCH_END              0x0807FFFFUL
#define DOUBLEWORD_SIZE        8U
#define TOTAL_WORDS            ((PATCH_END - PATCH_START + 1U) / DOUBLEWORD_SIZE)

static bool ns_ptr_valid(void *ptr, size_t len)
{
	return cmse_check_address_range(ptr, len, CMSE_MPU_NONSECURE);
}

static void flash_ns_unlock(void)
{
	FLASH->NSKEYR = FLASH_KEY1;
	FLASH->NSKEYR = FLASH_KEY2;
}

static void flash_ns_lock(void)
{
	SET_BIT(FLASH->NSCR, FLASH_NSCR_NSLOCK);
}

static psa_status_t flash_program_verify(struct dp_flash_write_stats *stats)
{
	uint32_t success = 0;
	uint32_t failed = 0;
	uint64_t pattern = 0x123456789ABCDEF0ULL;
	uint32_t index = 0;
	uint32_t addr;

	HAL_ICACHE_Disable();
	flash_ns_unlock();
	FLASH->NSSR = 0xFFFFFFFF;

	for (addr = PATCH_START; addr <= PATCH_END; addr += DOUBLEWORD_SIZE) {
		uint64_t value = pattern + index;

		while (FLASH->NSSR & FLASH_NSSR_NSBSY) {
		}
		FLASH->NSSR = 0xFFFFFFFF;
		SET_BIT(FLASH->NSCR, FLASH_NSCR_NSPG);

		*(volatile uint32_t *)(addr) = (uint32_t)(value);
		__ISB();
		*(volatile uint32_t *)(addr + 4U) = (uint32_t)(value >> 32);

		while (FLASH->NSSR & FLASH_NSSR_NSBSY) {
		}
		CLEAR_BIT(FLASH->NSCR, FLASH_NSCR_NSPG);
		index++;
	}

	__DSB();
	__ISB();
	HAL_ICACHE_Invalidate();
	__DSB();
	__ISB();

	index = 0;
	for (addr = PATCH_START; addr <= PATCH_END; addr += DOUBLEWORD_SIZE) {
		uint64_t expected = pattern + index;
		uint64_t actual = *(volatile uint64_t *)addr;

		if (actual == expected) {
			success++;
		} else {
			failed++;
		}
		index++;
	}

	flash_ns_lock();
	HAL_ICACHE_Enable();

	stats->success_words = success;
	stats->failed_words = failed;

	return PSA_SUCCESS;
}

static psa_status_t tfm_dp_flash_write_ipc(psa_msg_t *msg)
{
	struct dp_flash_write_stats stats = {0};

	if (msg->out_size[0] != sizeof(stats)) {
		return PSA_ERROR_PROGRAMMER_ERROR;
	}

	psa_status_t status = flash_program_verify(&stats);

	if (status != PSA_SUCCESS) {
		return status;
	}

	psa_write(msg->handle, 0, &stats, sizeof(stats));
	return PSA_SUCCESS;
}

typedef psa_status_t (*dp_flash_func_t)(psa_msg_t *);

static void dp_flash_signal_handle(psa_signal_t signal, dp_flash_func_t fn)
{
	psa_msg_t msg;
	psa_status_t status = psa_get(signal, &msg);

	switch (msg.type) {
	case PSA_IPC_CONNECT:
		psa_reply(msg.handle, PSA_SUCCESS);
		break;
	case PSA_IPC_CALL:
		status = fn(&msg);
		psa_reply(msg.handle, status);
		break;
	case PSA_IPC_DISCONNECT:
		psa_reply(msg.handle, PSA_SUCCESS);
		break;
	default:
		psa_panic();
	}
}

psa_status_t tfm_dp_flash_req_mngr_init(void)
{
	while (1) {
		psa_signal_t signals = psa_wait(PSA_WAIT_ANY, PSA_BLOCK);

		if (signals & TFM_DP_FLASH_WRITE_SIGNAL) {
			dp_flash_signal_handle(TFM_DP_FLASH_WRITE_SIGNAL,
					       tfm_dp_flash_write_ipc);
		} else {
			psa_panic();
		}
	}
}