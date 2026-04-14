/*
 * SMARM Experiment - Main Application (Non-Secure World)
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <string.h>
#include "smarm_partition.h"
// t_disabled
#include <stdint.h>
#include "../crypto/hmac-sha256/hmac-sha256.h"
#include "../crypto/aes/aes.h"


/* Configuration */
#define TARGET_FREQ_HZ 10  /* NormalTask frequency (Hz) */
#define NORMAL_TASK_STACK_SIZE 4096
#define EXPERIMENT_TASK_STACK_SIZE 2048

// t_disabled
#define BLOCK_SIZE 4096
#define TOTAL_SIZE 0x80000/* 512KB 0x20000*/
#define BLOCKS (TOTAL_SIZE / BLOCK_SIZE)
#define SHA256_DIGEST_SIZE 32

// uint8_t *real_memory = (uint8_t *)0x20000000;
uint8_t *real_memory = (uint8_t *)0x08000000;

/* HMAC key */
static const uint8_t key[] = "MySecureKey123";

/* AES-CTR PRNG structures and functions (same as secure partition) */
typedef struct {
    struct AES_ctx ctx;
    uint8_t iv[16];
    uint8_t buffer[16];
    int pos;
} aes_ctr_prng_t;

static void aes_ctr_init(aes_ctr_prng_t *prng, const uint8_t key16[16], const uint8_t iv16[16]) {
    AES_init_ctx_iv(&prng->ctx, key16, iv16);
    memcpy(prng->iv, iv16, 16);
    prng->pos = 16; // Force new keystream generation on first call
}

static uint32_t aes_ctr_next_u32(aes_ctr_prng_t *prng) {
    if (prng->pos >= 16) {
        memset(prng->buffer, 0, 16);
        AES_CTR_xcrypt_buffer(&prng->ctx, prng->buffer, 16);
        prng->pos = 0;
    }
    uint32_t val;
    memcpy(&val, &prng->buffer[prng->pos], 4);
    prng->pos += 4;
    return val;
}

static uint32_t prng_uniform_u32(aes_ctr_prng_t *prng, uint32_t n) {
    const uint32_t lim = 0xFFFFFFFFu - (0xFFFFFFFFu % n);
    for (;;) {
        uint32_t r = aes_ctr_next_u32(prng);
        if (r < lim) return r % n;
    }
}

/* Timing statistics structure */
typedef struct {
    uint32_t total_time_ms;           // Total execution time
    uint32_t hmac_update_total_ms;    // Total time for all hmac_sha256_update calls
    uint32_t hmac_update_avg_ms;      // Average time per hmac_sha256_update call
    uint32_t hmac_update_min_ms;      // Minimum time for single hmac_sha256_update
    uint32_t hmac_update_max_ms;      // Maximum time for single hmac_sha256_update
    uint32_t shuffle_time_ms;         // Time for shuffling indices
    uint32_t init_time_ms;            // Time for HMAC initialization
    uint32_t finalize_time_ms;        // Time for HMAC finalization
} smarm_timing_stats_t;

/**
 * Normal-world SMARM function with timing measurements
 * 
 * @param challenge Challenge bytes (used for AES key)
 * @param challenge_len Length of challenge
 * @param digest Output buffer for HMAC digest (32 bytes)
 * @param stats Output structure for timing statistics (can be NULL)
 * @return 0 on success, -1 on error
 */
int smarm_shuffled_hmac_normal(const uint8_t *challenge, size_t challenge_len,
                                uint8_t *digest, smarm_timing_stats_t *stats)
{
    hmac_sha256 hmac;
    static int indices[BLOCKS];
    aes_ctr_prng_t prng;
    uint8_t aes_key[16] = {0};
    uint8_t aes_iv[16] = {0};
    
    /* Timing variables */
    uint32_t start_total, end_total;
    uint32_t start_shuffle, end_shuffle;
    uint32_t start_init, end_init;
    uint32_t start_finalize, end_finalize;
    uint32_t start_update, end_update;
    uint32_t update_time_ms;
    uint32_t cpu_freq_hz = sys_clock_hw_cycles_per_sec();
    
    /* Initialize stats if provided */
    if (stats) {
        memset(stats, 0, sizeof(smarm_timing_stats_t));
        stats->hmac_update_min_ms = UINT32_MAX;
    }
    
    /* Start total timing */
    start_total = k_cycle_get_32();
    
    /* Prepare Key and IV from Challenge */
    if (challenge && challenge_len >= 16) {
        memcpy(aes_key, challenge, 16);
    }
    
    /* Initialize indices */
    for (int i = 0; i < BLOCKS; i++) {
        indices[i] = i;
    }
    
    /* Shuffle indices using AES-CTR PRNG */
    start_shuffle = k_cycle_get_32();
    aes_ctr_init(&prng, aes_key, aes_iv);
    for (int i = BLOCKS - 1; i > 0; i--) {
        uint32_t j = prng_uniform_u32(&prng, i + 1);
        int tmp = indices[i];
        indices[i] = indices[j];
        indices[j] = tmp;
    }
    end_shuffle = k_cycle_get_32();
    
    if (stats) {
        stats->shuffle_time_ms = ((uint64_t)(end_shuffle - start_shuffle) * 1000) / cpu_freq_hz;
    }
    
    /* Initialize HMAC */
    start_init = k_cycle_get_32();
    hmac_sha256_initialize(&hmac, key, sizeof(key) - 1);
    end_init = k_cycle_get_32();
    
    if (stats) {
        stats->init_time_ms = ((uint64_t)(end_init - start_init) * 1000) / cpu_freq_hz;
    }
    
    /* HMAC Loop - measure each update call */
    for (int i = 0; i < BLOCKS; i++) {
        const uint8_t *blk = &real_memory[(size_t)indices[i] * BLOCK_SIZE];
        
        /* Measure hmac_sha256_update execution time */
        start_update = k_cycle_get_32();
		// k_msleep(1000);
        hmac_sha256_update(&hmac, blk, BLOCK_SIZE);
        end_update = k_cycle_get_32();

		uint64_t cycles_diff = (uint64_t)(end_update - start_update);
        /* Convert to milliseconds * 100000 (5 decimal places) */
        uint64_t time_ms_x100000 = (cycles_diff * 100000000ULL) / cpu_freq_hz;
        uint32_t time_ms_int = time_ms_x100000 / 100000;  /* Integer part */
        uint32_t time_ms_frac = time_ms_x100000 % 100000;  /* Fractional part (5 digits) */
        
        /* Print progress at specific intervals */
        if (i == 10 || 
            i == (BLOCKS / 4) ||           /* 25% */
            i == (BLOCKS / 2) ||           /* 50% */
            i == ((BLOCKS - 1) * 98 / 100) ||    /* ~98% - ensure within range */
            i == (BLOCKS - 1)) {           /* Last block */
            uint32_t percent = ((uint64_t)(i + 1) * 100) / BLOCKS;
            // printk("Block %d/%d (%u%%) - Update time: %u.%05u ms\r\n", 
            //        i + 1, BLOCKS, percent, time_ms_int, time_ms_frac);
			printk(" %u.%05u ms\r\n", 
				time_ms_int,time_ms_frac);
        }
        /* Calculate time in milliseconds */
        
        if (stats) {
            stats->hmac_update_total_ms += update_time_ms;
            if (update_time_ms < stats->hmac_update_min_ms) {
                stats->hmac_update_min_ms = update_time_ms;
            }
            if (update_time_ms > stats->hmac_update_max_ms) {
                stats->hmac_update_max_ms = update_time_ms;
            }
        }
    }
    
    /* Calculate average if stats provided */
    if (stats && BLOCKS > 0) {
        stats->hmac_update_avg_ms = stats->hmac_update_total_ms / BLOCKS;
    }
    
    /* Finalize HMAC */
    start_finalize = k_cycle_get_32();
    hmac_sha256_finalize(&hmac, NULL, 0);
    end_finalize = k_cycle_get_32();
    
    if (stats) {
        stats->finalize_time_ms = ((uint64_t)(end_finalize - start_finalize) * 1000) / cpu_freq_hz;
    }
    
    /* Copy digest */
    memcpy(digest, hmac.digest, SHA256_DIGEST_SIZE);
    
    /* End total timing */
    end_total = k_cycle_get_32();
    
    if (stats) {
        stats->total_time_ms = ((uint64_t)(end_total - start_total) * 1000) / cpu_freq_hz;
    }
    
    return 0;
}

void print_smarm_timing_stats(const smarm_timing_stats_t *stats)
{
    if (!stats) return;
    
    printk("\r\n=== SMARM Timing Statistics ===\r\n");
    printk("Total execution time: %u ms\r\n", stats->total_time_ms);
    printk("Shuffle time: %u ms\r\n", stats->shuffle_time_ms);
    printk("HMAC init time: %u ms\r\n", stats->init_time_ms);
    printk("HMAC finalize time: %u ms\r\n", stats->finalize_time_ms);
    printk("HMAC update (total): %u ms\r\n", stats->hmac_update_total_ms);
    printk("HMAC update (avg per block): %u ms\r\n", stats->hmac_update_avg_ms);
    printk("HMAC update (min): %u ms\r\n", stats->hmac_update_min_ms);
    printk("HMAC update (max): %u ms\r\n", stats->hmac_update_max_ms);
    printk("Number of blocks: %d\r\n", BLOCKS);
    printk("================================\r\n\r\n");
}

/* Global counter for NormalTask cycles */
volatile uint32_t g_normal_counter = 0;

/* Mutex for UART output */
K_MUTEX_DEFINE(uart_mutex);

/* Thread A: NormalTask - runs at configurable frequency */
/* Thread A: NormalTask - runs at configurable frequency */
/* Thread A: NormalTask - runs at configurable frequency */
void normal_task_entry_temp(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	uint32_t cpu_hz = sys_clock_hw_cycles_per_sec();
	uint32_t period_cycles = cpu_hz / TARGET_FREQ_HZ;

	uint32_t next_deadline = sys_clock_cycle_get_32();
	uint32_t yield_counter = 0;  /* Add yield counter */
	
	for (;;) {
		uint32_t now = sys_clock_cycle_get_32();
		uint32_t elapsed;
		
		/* Handle counter wrap-around */
		if (now >= next_deadline) {
			elapsed = now - next_deadline;
		} else {
			/* Counter wrapped - calculate correctly */
			elapsed = (UINT32_MAX - next_deadline) + now + 1;
		}
		
		if (elapsed < period_cycles) {
			/* Still waiting - use small delay to reduce CPU usage */
			uint32_t remaining_cycles = period_cycles - elapsed;
			uint32_t remaining_us = ((uint64_t)remaining_cycles * 1000000) / cpu_hz;
			
			/* Use k_busy_wait for small delays, but allow preemption */
			if (remaining_us > 100) {
				k_busy_wait(remaining_us - 50);  /* Leave some margin */
			}
			
			/* Yield periodically to allow higher priority threads */
			if (++yield_counter >= 100) {
				k_yield();
				yield_counter = 0;
			}
		} else {
			/* Deadline reached - increment counter */
			next_deadline += period_cycles;
			g_normal_counter++;
			
			/* IMPORTANT: Add a small delay here to prevent tight loop */
			/* This ensures we don't immediately check again */
			k_busy_wait(10);  /* Small delay, ~10 microseconds */
			k_yield();  /* Always yield after incrementing */
		}
	}
}

static void normal_task_timer_handler(struct k_timer *timer)
{
    ARG_UNUSED(timer);
    g_normal_counter++;  /* Increment exactly every 1ms */
}
K_TIMER_DEFINE(normal_task_timer, normal_task_timer_handler, NULL);

/* Thread A: NormalTask - runs at configurable frequency */
void normal_task_entry(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	const uint32_t period_ms = 1000 / TARGET_FREQ_HZ;
	k_timer_start(&normal_task_timer, K_MSEC(period_ms), K_MSEC(period_ms));

	k_sleep(K_FOREVER);
}

/* Thread B: ExperimentTask - calls Secure Service using PSA APIs */
void experiment_task_entry(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	printk("=== ExperimentTask ENTRY ===\r\n");  /* Add this to verify it runs */

	uint8_t digest[32];
	uint8_t challenge[16];
    psa_status_t status = PSA_SUCCESS;  /* Initialize status */

	printk("ExperimentTask started\r\n");
	k_msleep(2000);

	k_msleep(500); /* let timer run a few cycles before starting rounds */

	/* Run 5 test rounds */
	for (int round = 1; round <= 10; round++) {
		/* Generate challenge for this round */
		uint32_t seed = k_uptime_get_32() + round;
		for (int k = 0; k < 4; k++) {
			uint32_t rnd = seed ^ (seed << 13) ^ (k * 0x5DEECE66D);
			memcpy(&challenge[k * 4], &rnd, 4);
		}
		uint32_t start_cycle = k_cycle_get_32();
		uint32_t start_count = g_normal_counter;

		/* Call secure function using PSA Client API */
		status = smarm_shuffled_hmac_secure(challenge, sizeof(challenge), digest,
						    sizeof(digest));

		uint32_t end_cycle = k_cycle_get_32();
		uint32_t end_count = g_normal_counter;

		uint32_t cpu_hz = sys_clock_hw_cycles_per_sec();

		/* Wall-clock duration from hardware cycle counter (not affected by NS timer starvation) */
		uint32_t duration_ms = (uint32_t)(((uint64_t)(end_cycle - start_cycle) * 1000ULL) /
						  cpu_hz);

		/* NormalTask ticks that should have fired in that wall time */
		uint32_t expected_run = (duration_ms * TARGET_FREQ_HZ) / 1000;

		/* NormalTask ticks that actually fired (k_timer may be delayed during TF-M) */
		uint32_t actual_run = end_count - start_count;

		if (status == PSA_SUCCESS) {
			if (k_mutex_lock(&uart_mutex, K_MSEC(10)) == 0) {
				printk("Round %d: actual=%u expected=%u dur=%u ms\r\n",
				       round, actual_run, expected_run, duration_ms);
				k_mutex_unlock(&uart_mutex);
			}
		} else {
			if (k_mutex_lock(&uart_mutex, K_MSEC(10)) == 0) {
				// printk("Round %d: SMARM call failed: %d\r\n", round, status);
				k_mutex_unlock(&uart_mutex);
			}
		}

		k_msleep(2000); /* Wait 2 seconds between measurements */
	}

	printk("\r\nExperimentTask: All 5 rounds complete.\r\n");
}

/* Thread definitions using K_THREAD_DEFINE */
K_THREAD_STACK_DEFINE(normal_task_stack, NORMAL_TASK_STACK_SIZE);
K_THREAD_STACK_DEFINE(experiment_task_stack, EXPERIMENT_TASK_STACK_SIZE);

K_THREAD_DEFINE(normal_task, NORMAL_TASK_STACK_SIZE,
                normal_task_entry, NULL, NULL, NULL,
                K_PRIO_PREEMPT(3), 0, 0);
// K_THREAD_DEFINE(normal_task, NORMAL_TASK_STACK_SIZE,
// 	normal_task_entry_temp, NULL, NULL, NULL,  /* Use temp version */
// 	K_PRIO_PREEMPT(3), 0, 0);
	
K_THREAD_DEFINE(experiment_task, EXPERIMENT_TASK_STACK_SIZE,
                experiment_task_entry, NULL, NULL, NULL,
                K_PRIO_PREEMPT(6), 0, 0);

int main(void)
{
	printk("\r\n");
	printk("========================================\r\n");
	printk("SMARM Experiment Starting...\r\n");
	printk("========================================\r\n");
	printk("NormalTask: Thread priority 3, %d Hz\r\n", TARGET_FREQ_HZ);
	printk("ExperimentTask: Thread priority 6\r\n");
	printk("Secure Service SID: 0x%08X\r\n", TFM_SMARM_SERVICE_SID);
	printk("========================================\r\n\r\n");

	/* Threads are automatically started by K_THREAD_DEFINE */
	/* Set thread names - K_THREAD_DEFINE creates thread identifiers */
	k_thread_name_set((k_tid_t)&normal_task, "NormalTask");  // Commented out - normal_task is disabled
	k_thread_name_set((k_tid_t)&experiment_task, "ExperimentTask");

	return 0;
}
