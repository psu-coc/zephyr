#
# Copyright (c) 2024
#
# SPDX-License-Identifier: Apache-2.0
#

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

get_target_property(TFM_BINARY_DIR tfm TFM_BINARY_DIR)
configure_file(
  ${CMAKE_CURRENT_LIST_DIR}/smarm_partition/tfm_manifest_list.yaml.in
  ${CMAKE_CURRENT_BINARY_DIR}/smarm_partition/tfm_manifest_list.yaml
)

set_property(TARGET zephyr_property_target
  APPEND PROPERTY TFM_CMAKE_OPTIONS
 -DTFM_EXTRA_MANIFEST_LIST_FILES=${CMAKE_CURRENT_BINARY_DIR}/smarm_partition/tfm_manifest_list.yaml
 -DTFM_EXTRA_PARTITION_PATHS=${CMAKE_CURRENT_LIST_DIR}/smarm_partition
)

project(smarm_experiment)

target_sources(app PRIVATE
  src/main.c
  src/smarm_partition.c
  crypto/aes/aes.c
  crypto/hmac-sha256/hmac-sha256.c
)

target_include_directories(app PRIVATE
  $<TARGET_PROPERTY:tfm,TFM_BINARY_DIR>/api_ns/interface/include
  ${CMAKE_CURRENT_LIST_DIR}/crypto/aes
  ${CMAKE_CURRENT_LIST_DIR}/crypto/hmac-sha256
)

target_compile_definitions(app
    PRIVATE TFM_PARTITION_SMARM_PARTITION
)
