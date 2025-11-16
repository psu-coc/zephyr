// #include <stdlib.h>
// #include <string.h>
// #include <stdio.h>

// //#include <zephyr.h>
// //#include <sys/printk.h>
// //#include <logging/log.h>
// //#include <shell/shell.h>
// #include <zephyr/kernel.h>
// #include <zephyr/device.h>
// #include <zephyr/drivers/flash.h>
// #include <zephyr/storage/flash_map.h>
// #include <zephyr/device.h>
// //#include <soc.h>

// static const struct device *flash_device;

// uint8_t data[2048];

// void main(void)
// {
//     printk("Flash starting!\n");
// 	int ret;
// 	off_t offset = 0x1F800;
// 	size_t size = 2048;

// 	flash_device = DEVICE_DT_GET(DT_CHOSEN(zephyr_flash_controller));
// 	if (!device_is_ready(flash_device)) {
//         printk("Flash device not ready!\n");
//         return;
//     }

// 	for(int i = 0; i < 2048; i++) {data[i]= i;}
// 	// ret = flash_erase(flash_device, offset, size);
// 	// if (ret) {
// 	// 	printk("flash_erase failed (err:%d).\n", ret);
// 	// 	return;
// 	// }

// 	ret = flash_write(flash_device, offset, &data, FLASH_PAGE_SIZE);
// 	if (ret) {
// 		printk("flash_write failed (err:%d).\n", ret);
// 		return;
// 	}

// 	// ret = flash_write_protection_set(flash_device, true);
// 	// if (ret) {
// 	// 	printk("Failed to enable flash protection (err: %d)."
// 	// 			"\n", ret);
// 	// 	return;
// 	// }

// 	printk("Erase OK");

// 	printk("Reading back...\n");
//     uint8_t buf[2048];
//     ret = flash_read(flash_device, offset, buf, FLASH_PAGE_SIZE);
//     if (ret) {
//         printk("Read failed: %d\n", ret);
//         return;
//     }

// 	for(int i = 0; i < 2048; i++) {
// 		if(buf[i] != data[i]) {
// 			printk("Data mismatch at index %d: expected %d, got %d\n", i, data[i], buf[i]);
// 			return;
// 		}
// 	}
// 	printk("Data verified successfully!\n");

// }


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/storage/flash_map.h>
#include <zephyr/device.h>
#include <zephyr/timing/timing.h>


int main(void)
{
	timing_init(); timing_start();
	const struct device *flash_device;
    printk("Flash shell sample\n");

	int ret;
	off_t offset = 0x48000;
	int num_pages = 2;

	size_t erase_size = num_pages * FLASH_PAGE_SIZE;

	flash_device = DEVICE_DT_GET(DT_CHOSEN(zephyr_flash_controller));
	if (!device_is_ready(flash_device)) {
        printk("Flash device not ready!\n");
        return;
    }
    printk("Ready to flash, disabling interrupts first\n");

	uint64_t start = timing_counter_get();
	int64_t t1 = k_uptime_ticks();


	//__disable_irq();
	unsigned int key = irq_lock();
	ret = flash_erase(flash_device, offset, erase_size);
	if (ret) {
		printk("flash_erase failed (err:%d).\n", ret);
		return;
	}
    printk("Flash erase succeeds\n");

	uint8_t data[FLASH_PAGE_SIZE];
	for(int i = 0; i < 2048; i++) {data[i]= i;}

	for(int j=0; j<num_pages; j++) {
		ret = flash_write(flash_device, offset+j*FLASH_PAGE_SIZE, &data, FLASH_PAGE_SIZE);
		if (ret) {
			printk("flash_write failed (err:%d) at page %d.\n", ret, j);
			return;
		}
	}
    printk("Flash write succeeds\n");

	printk("Reading back...\n");
    uint8_t buf[2048];
	for(int j=0; j<num_pages; j++) {
		ret = flash_read(flash_device, offset+j*FLASH_PAGE_SIZE, buf, FLASH_PAGE_SIZE);
		if (ret) {
			printk("Read failed: %d\n", ret);
			return;
		}

		for(int i = 0; i < 2048; i++) {
			if(buf[i] != data[i]) {
				printk("Data mismatch at page %d index %d: expected %d, got %d\n", j, i, data[i], buf[i]);
				return;
			}
		}
	}
	//__enable_irq();
	irq_unlock(key);

	uint64_t end = timing_counter_get();
	int64_t t2 = k_uptime_ticks();

    uint64_t cycles = end - start;
    uint64_t ns = timing_cycles_to_ns(cycles);
    uint64_t us = ns / 1000;
	float s = (float)us/(1000*1000.0f);

    printk("Elapsed: %llu ns (%llu us, %.3f s) raw_cycles=%llu\n", ns, us, s, cycles);

	int64_t dt_ticks = t2 - t1;
    uint64_t dt_ms = k_ticks_to_ms_floor64(dt_ticks);
	printk("Elapsed (uptime ticks): %llu ms, %llu ticks\n", dt_ms, dt_ticks);


    timing_stop();
	printk("Data verified successfully!\n");

    return 0;
}

