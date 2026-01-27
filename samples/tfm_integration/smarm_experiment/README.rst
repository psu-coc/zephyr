.. zephyr:code-sample:: smarm_experiment
   :name: SMARM Experiment

   Secure Memory Attestation with Real-time Measurements (SMARM/RT-SMARM)

Overview
********

This sample implements a Secure Memory Attestation experiment that measures the
False Alphanumeric Rate (FAR) when secure attestation interrupts real-time tasks.

The experiment consists of:
- **NormalTask**: A real-time task running at 1000Hz that counts cycles
- **SMARM_Experiment_Task**: Calls secure attestation function and measures
  how many NormalTask cycles were interrupted
- **SECURE_ShuffledHMAC_secure**: Secure partition function that performs
  shuffled HMAC-SHA256 attestation using AES-CTR based PRNG

Building and Running
********************

Build for STM32L552ZE-Q board:

.. code-block:: console

   $ west build -b nucleo_l552ze_q/stm32l552xx/ns samples/tfm_integration/smarm_experiment

Flash and monitor:

.. code-block:: console

   $ west flash
   $ minicom -D /dev/ttyACM0 -b 115200

Experiment Configuration
************************

The experiment varies BLOCK_SIZE (256, 512, 1024, 2048, 4096 bytes) to measure
the impact on real-time task interruptions.
