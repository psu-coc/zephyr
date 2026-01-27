#
# Copyright (c) 2024
#
# SPDX-License-Identifier: Apache-2.0
#

add_library(tfm_app_rot_partition_smarm STATIC)

target_include_directories(tfm_app_rot_partition_smarm
    INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    PRIVATE
        ${CMAKE_BINARY_DIR}/smarm_partition
)
target_include_directories(tfm_partitions
    INTERFACE
        ${CMAKE_BINARY_DIR}/smarm_partition
)

target_sources(tfm_app_rot_partition_smarm
    PRIVATE
        smarm_partition.c
        ${CMAKE_CURRENT_LIST_DIR}/../crypto/hmac-sha256/hmac-sha256.c
)

# The generated sources
target_sources(tfm_app_rot_partition_smarm
    PRIVATE
        ${CMAKE_BINARY_DIR}/smarm_partition/auto_generated/intermedia_tfm_smarm_partition.c
)
target_sources(tfm_partitions
    INTERFACE
        ${CMAKE_BINARY_DIR}/smarm_partition/auto_generated/load_info_tfm_smarm_partition.c
)

target_link_libraries(tfm_app_rot_partition_smarm
    PRIVATE
        platform_s
        tfm_sprt
)

target_link_libraries(tfm_spm
    PRIVATE
        tfm_app_rot_partition_smarm
)

############################ Partition Defs ####################################

target_link_libraries(tfm_partitions
    INTERFACE
        tfm_app_rot_partition_smarm
)

target_compile_definitions(tfm_config
    INTERFACE
        TFM_PARTITION_SMARM_PARTITION
)
