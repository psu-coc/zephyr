#include <stdint.h>
#include <psa/client.h>

#define PATCH_REGION_START 0x08060000U
#define PATCH_REGION_SIZE  0x00020000U

struct dp_flash_write_stats {
	uint32_t success_words;
	uint32_t failed_words;
};

psa_status_t dp_flash_write(struct dp_flash_write_stats *stats);