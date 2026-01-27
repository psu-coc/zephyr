/*
 * SMARM Experiment - Main Application (Non-Secure World)
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <string.h>
#include "smarm_partition.h"

/* Configuration */
#define TARGET_FREQ_HZ 1000  /* NormalTask frequency (Hz) */
#define NORMAL_TASK_STACK_SIZE 2048
#define EXPERIMENT_TASK_STACK_SIZE 4096

/* Global counter for NormalTask cycles */
volatile uint32_t g_normal_counter = 0;

/* Mutex for UART output */
K_MUTEX_DEFINE(uart_mutex);

/* Thread A: NormalTask - runs at configurable frequency */
void normal_task_entry_temp(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	const uint32_t period_ms = 1000 / TARGET_FREQ_HZ; /* 1ms for 1000Hz */
	uint32_t loop_counter = 0;
	uint32_t start_time_ms = k_uptime_get_32();
	uint32_t last_print_time_ms = start_time_ms;

	printk("NormalTask started (target: %d Hz = 1 cycle per %u ms)\r\n", 
	       TARGET_FREQ_HZ, period_ms);

	for (;;) {
		/* Control timing - sleep for period */
		// k_msleep(period_ms);
		/* Replace k_msleep(period_ms) with: */

		const uint32_t period_us = (1000 * 1000) / TARGET_FREQ_HZ; /* 1000 us for 1000 Hz */
		k_busy_wait(period_us);

		g_normal_counter++; /* Count cycles */
		loop_counter++;

		k_yield();
		/* Print status every second with actual frequency calculation */
		uint32_t current_time_ms = k_uptime_get_32();
		uint32_t elapsed_ms = current_time_ms - last_print_time_ms;
		
		if (elapsed_ms >= 1000) {
			/* Calculate actual frequency */
			uint32_t actual_freq_x100 = ((uint64_t)loop_counter * 100 * 1000) / elapsed_ms;
			uint32_t actual_freq_int = actual_freq_x100 / 100;
			uint32_t actual_freq_dec = actual_freq_x100 % 100;
			
			// if (k_mutex_lock(&uart_mutex, K_MSEC(10)) == 0) {
			// 	printk("NormalTask: %u cycles in %u ms = %u.%02u Hz (target: %d Hz)\r\n",
			// 		loop_counter, elapsed_ms, actual_freq_int, actual_freq_dec, TARGET_FREQ_HZ);
			// 	k_mutex_unlock(&uart_mutex);
			// }
			
			loop_counter = 0;
			last_print_time_ms = current_time_ms;
		}
	}
}

/* Thread A: NormalTask - runs at configurable frequency */
void normal_task_entry(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	const uint32_t period_ms = 1000 / TARGET_FREQ_HZ; /* 1ms for 1000Hz */
	uint32_t loop_counter = 0;

	// printk("NormalTask started (running at %d Hz)\r\n", TARGET_FREQ_HZ);

	for (;;) {
		/* Control timing - sleep for period */
		k_msleep(period_ms);

		g_normal_counter++; /* Count cycles */
		loop_counter++;

		/* Print status every second */
		if (loop_counter >= TARGET_FREQ_HZ) {
			if (k_mutex_lock(&uart_mutex, K_MSEC(10)) == 0) {
				// printk("NormalTask: %u cycles in 1s\r\n", g_normal_counter);
				k_mutex_unlock(&uart_mutex);
			}
			loop_counter = 0;
		}
	}
}

/* Thread B: ExperimentTask - calls Secure Service using PSA APIs */
void experiment_task_entry(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	uint8_t digest[32];
	uint8_t challenge[16];
	psa_status_t status;

	printk("ExperimentTask started\r\n");
	k_msleep(2000); 

	/* Run 5 test rounds */
	for (int round = 1; round <= 10; round++) {
		/* Generate challenge for this round */
		uint32_t seed = k_uptime_get_32() + round;
		for (int k = 0; k < 4; k++) {
			uint32_t rnd = seed ^ (seed << 13) ^ (k * 0x5DEECE66D);
			memcpy(&challenge[k * 4], &rnd, 4);
		}

		uint32_t start_realtime = k_cycle_get_32();
		uint32_t start_systick = k_uptime_get_32();
		uint32_t start_count = g_normal_counter;

		/* Call secure function using PSA Client API */
		// __disable_irq();
		// k_msleep(1000);
		status = smarm_shuffled_hmac_secure(challenge, sizeof(challenge),digest, sizeof(digest));
		// __enable_irq();
		uint32_t end_realtime = k_cycle_get_32();
		uint32_t end_systick = k_uptime_get_32();
		uint32_t end_count = g_normal_counter;

		if (status == PSA_SUCCESS) {
			uint32_t actual_run = end_count - start_count;
			uint32_t realtime_run = end_realtime - start_realtime;
			uint32_t duration_ms = end_systick - start_systick;

			uint32_t cycles_diff = end_realtime - start_realtime;
			uint32_t cpu_freq_hz = sys_clock_hw_cycles_per_sec();
			uint32_t duration_realtime_ms = ((uint64_t)cycles_diff * 1000) / cpu_freq_hz;
			
			// uint32_t expected_run = duration_ms; /* 1000Hz = 1 cycle/ms */
			// uint32_t expected_run = (duration_ms * TARGET_FREQ_HZ) / 1000;
			// int32_t missed_cycles = (int32_t)expected_run - (int32_t)actual_run;

			if (k_mutex_lock(&uart_mutex, K_MSEC(10)) == 0) {
				printk("\r\n--- Round %d: Attestation Event Analysis ---\r\n", round);
				// printk("Duration (SysTick): %u ms\r\n", duration_ms);
				// printk("Duration (Realtime): %u cycles\r\n", end_realtime - start_realtime);
				// printk("NormalTask Run: %u / %u cycles\r\n", actual_run, expected_run);
				// printk("Missed Cycles: %d\r\n", missed_cycles);

				// printk("cpu_freq_hz: %u \r\n", cpu_freq_hz);
				// printk("Duration (Realtime): %u ms\r\n", duration_realtime_ms);
				// printk("NormalTask Run: %u / %u cycles\r\n", actual_run, realtime_run);

				printk("Experiement Run : %u / %u \r\n", actual_run, cycles_diff);
				/* Calculate FAR */
				// if (expected_run > 0) {
					// uint32_t local_far_x100 = (actual_run * 100) / expected_run;
					// printk("Local FAR: %u.%02u\r\n", local_far_x100 / 100, local_far_x100 % 100);
				// }
				// printk("Digest: ");
				// for (int i = 0; i < 32; i++) {
				// 	printk("%02x", digest[i]);
				// }
				printk("\r\n");
				k_mutex_unlock(&uart_mutex);
			}
		} else {
			if (k_mutex_lock(&uart_mutex, K_MSEC(10)) == 0) {
				printk("Round %d: SMARM call failed: %d\r\n", round, status);
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
	k_thread_name_set((k_tid_t)&normal_task, "NormalTask");
	k_thread_name_set((k_tid_t)&experiment_task, "ExperimentTask");

	return 0;
}
