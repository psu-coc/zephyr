/*
 * Copyright (c) 2021 Nordic Semiconductor ASA.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <tfm_ns_interface.h>

// #include "dummy_partition.h"
// #include "dp_flash.h"
// Benstart
#include <zephyr/sys/printk.h>
#include <zephyr/timing/timing.h>

#include <zephyr/drivers/flash.h>
#include <zephyr/storage/flash_map.h>


//Experiment
void linear_attestation(void)
{
	uint64_t systick_before, systick_after, systick_diff;
	timing_t cycles_before, cycles_after;
	uint64_t cycles_diff, cycles_ns;
	uint8_t digest[32];
	psa_status_t status;

	timing_init();
	timing_start();


	for (int round = 0; round < 5; round++) {
		
		/* ===== Measure LINEAR HMAC ===== */


		printk("--------------------------------\n");
		printk("Round %d - LINEAR HMAC:\n", round + 1);
		
		systick_before = k_uptime_ticks();
		cycles_before = timing_counter_get();

		// __disable_irq();

		//__disable_irq();
		unsigned int key = irq_lock();
		

		status = dp_linear_hmac(digest, sizeof(digest));
		// __enable_irq();
		// k_msleep(1000);

		//__disable_irq();
		irq_unlock(key);

		cycles_after = timing_counter_get();
		systick_after = k_uptime_ticks();

		systick_diff = systick_after - systick_before;
		cycles_diff = timing_cycles_get(&cycles_before, &cycles_after);
		uint64_t cycles_ns = timing_cycles_to_ns(cycles_diff);
		uint64_t cycles_ms = cycles_ns / 1000000;

		uint64_t systick_ms = k_ticks_to_ms_floor64(systick_diff);

		printk("  TIMER cycles: %llu\n",cycles_after - cycles_before);
		printk("  TIMER ms: %llu\n",cycles_ms);
		printk("  Systick cycles: %llu\n",systick_after - systick_before);
		printk("  Systick ms: %llu\n",systick_ms);

	
	
		// printf("Elapsed: %llu ns (%llu us, %llu ms) raw_cycles=%llu\n", ns, us, ms, cycles);
	
	
		// printk("  Time: %llu ns (%llu cycles)\n", cycles_ns, cycles_diff);
		// printk("  SysTick: %llu ticks\n", systick_diff);
		// printk("  Status: %s\n\n", (status == PSA_SUCCESS) ? "OK" : "ERROR");

		k_msleep(100);

		
		k_sleep(K_MSEC(1000));
	}

	timing_stop();
	printk("=== Comparison Complete ===\n\n");
}


#define PATCH_REGION_START 0x08060000U
#define PATCH_REGION_SIZE  0x00040000U

// static void measure_hot_patch(void)
// {
// 	const struct device *flash_dev =
// 		DEVICE_DT_GET(DT_CHOSEN(zephyr_flash_controller));
// 	struct dp_flash_write_stats stats;
// 	psa_status_t status;

// 	if (!device_is_ready(flash_dev)) {
// 		printk("Flash device not ready\n");
// 		return;
// 	}

// 	timing_init();
// 	timing_start();

// 	while (1) {
// 		/* --- ERASE PHASE --- */
// 		uint64_t erase_tick_before = k_uptime_ticks();
// 		timing_t erase_cycle_before = timing_counter_get();

// 		int rc = flash_erase(flash_dev,
// 				     PATCH_REGION_START,
// 				     PATCH_REGION_SIZE);

// 		timing_t erase_cycle_after = timing_counter_get();
// 		uint64_t erase_tick_after = k_uptime_ticks();

// 		uint64_t erase_ticks = erase_tick_after - erase_tick_before;
// 		uint64_t erase_cycles =
// 			timing_cycles_get(&erase_cycle_before,
// 					  &erase_cycle_after);
// 		uint64_t erase_ns = timing_cycles_to_ns(erase_cycles);

// 		/* Handle erase failure */
// 		if (rc) {
// 			printk("Flash erase failed (%d)\n", rc);
// 			k_sleep(K_SECONDS(10));
// 			continue;
// 		}

// 		/* --- WRITE PHASE (secure world) --- */
// 		uint64_t write_tick_before = k_uptime_ticks();
// 		timing_t write_cycle_before = timing_counter_get();

// 		status = dp_flash_write(&stats);

// 		timing_t write_cycle_after = timing_counter_get();
// 		uint64_t write_tick_after = k_uptime_ticks();

// 		uint64_t write_ticks = write_tick_after - write_tick_before;
// 		uint64_t write_cycles =
// 			timing_cycles_get(&write_cycle_before,
// 					  &write_cycle_after);
// 		uint64_t write_ns = timing_cycles_to_ns(write_cycles);

// 		/* --- OUTPUT --- */
// 		printk("\n=== Hot Patch Timing Measurement ===\n");

// 		printk("\n--- ERASE PHASE ---\n");
// 		printk("Erase time: %llu ms (RTOS)\n",
// 		       k_ticks_to_ms_floor64(erase_ticks));
// 		printk("Erase time: %llu us (cycles)\n", erase_ns / 1000ULL);
// 		printk("Erase time: %llu ns (cycles)\n", erase_ns);

// 		printk("\n--- WRITE PHASE ---\n");
// 		printk("Write time: %llu ms (RTOS)\n",
// 		       k_ticks_to_ms_floor64(write_ticks));
// 		printk("Write time: %llu us (cycles)\n", write_ns / 1000ULL);
// 		printk("Write time: %llu ns (cycles)\n", write_ns);

// 		printk("\n--- STATUS ---\n");
// 		if ((status == PSA_SUCCESS) && (stats.failed_words == 0U)) {
// 			printk("Status: SUCCESS ✅ (%u words)\n",
// 			       stats.success_words);
// 		} else {
// 			printk("Status: FAILED ❌ "
// 			       "(success=%u failed=%u status=%d)\n",
// 			       stats.success_words,
// 			       stats.failed_words,
// 			       status);
// 		}

// 		k_sleep(K_SECONDS(10));
// 	}
// }

void measure_secure_call_drift(void)
{
	uint64_t systick_before, systick_after, systick_diff;
	timing_t cycles_before, cycles_after;
	uint64_t cycles_diff, cycles_ns;
	uint8_t digest[32];
	psa_status_t status;

	// Initialize timing subsystem
	timing_init();
	timing_start();

	printk("\n=== Starting Time Drift Measurement ===\n");
	printk("Calling secure world (dp_secret_digest)...\n\n");

	// Measure 10 rounds
	for (int round = 0; round < 10; round++) {
		
		// Get timestamps BEFORE secure call
		systick_before = k_uptime_ticks();
		cycles_before = timing_counter_get();

		// === CALL SECURE WORLD ===
		status = dp_secret_digest(0, digest, sizeof(digest));

		// Get timestamps AFTER secure call
		cycles_after = timing_counter_get();
		systick_after = k_uptime_ticks();

		// Calculate differences
		systick_diff = systick_after - systick_before;
		cycles_diff = timing_cycles_get(&cycles_before, &cycles_after);
		cycles_ns = timing_cycles_to_ns(cycles_diff);

		// Print results
		printk("Round %d:\n", round + 1);
		printk("  SysTick elapsed: %llu ticks\n", systick_diff);
		printk("  CPU cycles:      %llu cycles\n", cycles_diff);
		printk("  Time (ns):       %llu ns\n", cycles_ns);
		printk("  Status: %s\n\n", (status == PSA_SUCCESS) ? "OK" : "ERROR");

		// Wait 1 second before next round
		k_sleep(K_MSEC(1000));
	}

	timing_stop();
	printk("=== Measurement Complete ===\n\n");
}



int write_8kb_flash(struct device *flash_device, uint8_t start_val) {
	int ret;

	off_t offset = 0x48000; //0x20000;
	int num_pages = 4;
	size_t erase_size = num_pages * FLASH_PAGE_SIZE;

	ret = flash_erase(flash_device, offset, erase_size);
	if (ret) {
		// printf("flash_erase failed (err:%d).\n", ret);
		return ret;
	}
    // printf("Flash erase succeeds\n");

	uint8_t data[FLASH_PAGE_SIZE];
	for(int i = 0; i < 2048; i++) {data[i]= i+start_val;}

	for(int j=0; j<num_pages; j++) {
		ret = flash_write(flash_device, offset+j*FLASH_PAGE_SIZE, &data, FLASH_PAGE_SIZE);
		if (ret) {
			// printf("flash_write failed (err:%d) at page %d.\n", ret, j);
			return ret;
		}
	}
    // printf("Flash write succeeds\n");

	// printf("Reading back...\n");
    uint8_t buf[2048];
	for(int j=0; j<num_pages; j++) {
		ret = flash_read(flash_device, offset+j*FLASH_PAGE_SIZE, buf, FLASH_PAGE_SIZE);
		if (ret) {
			// printf("Read failed: %d\n", ret);
			return ret;
		}

		for(int i = 0; i < 2048; i++) {
			if(buf[i] != data[i]) {
				// printf("Data mismatch at page %d index %d: expected %d, got %d\n", j, i, data[i], buf[i]);
				return -0xab;
			}
		}
	}
	// printf("Flash succeeds\n");
	return ret;
}

int simulate_flash_write(int num_kbs) {

	if(num_kbs%8 != 0) {
		// printf("num_kbs must be multiple of 8\n");
		return -1;
	}

	int ret;
	timing_init(); timing_start();
	const struct device *flash_device;


	flash_device = DEVICE_DT_GET(DT_CHOSEN(zephyr_flash_controller));
	if (!device_is_ready(flash_device)) {
        // printf("Flash device not ready!\n");
        return;
    }
    // printf("Ready to flash %d kb with pagesize 0x%x, disabling interruptsdd first\n", num_kbs, FLASH_PAGE_SIZE);




	uint64_t start = timing_counter_get();
	int64_t t1 = k_uptime_ticks();

	// __disable_irq();
	unsigned int key = irq_lock();
	

	//k_sleep(K_MSEC(1000));

	for(int i=0; i< num_kbs/8; i++) {
		ret = write_8kb_flash(flash_device, i);
		if(ret) {
			// printf("write_8kb_flash failed with %d at i=%d\n", ret, i);
			break;
		}
	}

	
	//__enable_irq();
	irq_unlock(key);

	uint64_t end = timing_counter_get();
	int64_t t2 = k_uptime_ticks();


    uint64_t cycles = end - start;
    uint64_t ns = timing_cycles_to_ns(cycles);
    uint64_t us = ns / 1000;
    uint64_t ms = us / 1000;
	//float s = (float)us/(1000*1000.0f);
	printf("TIMER cycles: %llu\n",cycles);
	printf("TIMER ms: %llu\n",ms);



    // printf("Elapsed: %llu ns (%llu us, %llu ms) raw_cycles=%llu\n", ns, us, ms, cycles);

	int64_t dt_ticks = t2 - t1;
    uint64_t dt_ms = k_ticks_to_ms_floor64(dt_ticks);
	printf("Systick tick: %llu\n",dt_ticks);
	printf("Systick ms: %llu\n",dt_ms);
	// printf("Elapsed (uptime ticks): %llu ms, %llu ticks\n", dt_ms, dt_ticks);


    timing_stop();

}


// Benend

int main(void)
{
	// uint8_t digest[32];

	// for (int key = 0; key < 6; key++) {
	// 	psa_status_t status = dp_secret_digest(key, digest, sizeof(digest));

	// 	if (status == PSA_ERROR_INVALID_ARGUMENT && key == 5) {
	// 		printk("No valid secret for key, received expected error code\n");
	// 	} else if (status != PSA_SUCCESS) {
	// 		printk("Status: %d\n", status);
	// 	} else {
	// 		printk("Digest: ");
	// 		for (int i = 0; i < 32; i++) {
	// 			printk("%02x", digest[i]);
	// 		}
	// 		printk("\n");
	// 	}
	// }

	// Benstart
	// measure_secure_call_drift();
	linear_attestation();
	// measure_hot_patch();
	// for(int i=1; i<=5 ; i++) {
	// 	printf("--------------------------------\n");
	// 	printf("Round %d\n", i);
	// 	simulate_flash_write(128);
	// }

	// Bene
	return 0;
}
