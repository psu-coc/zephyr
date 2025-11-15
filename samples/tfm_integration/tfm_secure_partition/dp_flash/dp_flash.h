#pragma once
#include <stdint.h>
#include "psa/service.h"

#define TFM_DP_FLASH_WRITE_SID       (0xFFFFF010U)
#define TFM_DP_FLASH_WRITE_VERSION   (1U)
#define TFM_DP_FLASH_WRITE_SIGNAL    (1U << 3)

struct dp_flash_write_stats {
	uint32_t success_words;
	uint32_t failed_words;
};