# Copyright (c) 2018 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set(CMAKE_VERBOSE_MAKEFILE ON)

add_vpp_library(nat
  SOURCES
  lib/ipfix_logging.c
  lib/nat_syslog.c
  lib/alloc.c

  INSTALL_HEADERS
  lib/ipfix_logging.h
  lib/nat_syslog.h
  lib/alloc.h
)

add_vpp_plugin(nat
  SOURCES
  nat.c
  nat44_api.c
  in2out_ed.c
  out2in_ed.c
  nat_dpo.c
  nat44_cli.c
  nat44_handoff.c
  nat44_hairpinning.c
  nat44_classify.c
  nat_affinity.c
  nat_format.c
  nat44-ei/nat44_ei.c
  nat44-ei/nat44_ei_ha.c
  nat44-ei/nat44_ei_in2out.c
  nat44-ei/nat44_ei_out2in.c

  MULTIARCH_SOURCES
  in2out_ed.c
  out2in_ed.c
  nat44_classify.c
  nat44_hairpinning.c
  nat44_handoff.c
  nat44-ei/nat44_ei_in2out.c
  nat44-ei/nat44_ei_out2in.c

  API_FILES
  nat44.api
  nat_types.api

  LINK_LIBRARIES nat
)

add_vpp_plugin(dslite
  SOURCES
  dslite/dslite_api.c
  dslite/dslite_dpo.c
  dslite/dslite.c
  dslite/dslite_in2out.c
  dslite/dslite_out2in.c
  dslite/dslite_cli.c
  dslite/dslite_ce_encap.c
  dslite/dslite_ce_decap.c

  MULTIARCH_SOURCES
  dslite/dslite_ce_decap.c
  dslite/dslite_ce_encap.c
  dslite/dslite_in2out.c
  dslite/dslite_out2in.c

  API_FILES
  dslite/dslite.api

  LINK_LIBRARIES nat
)

add_vpp_plugin(nat66
  SOURCES
  nat66/nat66.c
  nat66/nat66_cli.c
  nat66/nat66_api.c
  nat66/nat66_in2out.c
  nat66/nat66_out2in.c

  MULTIARCH_SOURCES
  nat66/nat66_in2out.c
  nat66/nat66_out2in.c

  API_FILES
  nat66/nat66.api
  nat_types.api

  LINK_LIBRARIES nat
)

add_vpp_plugin(det44
  SOURCES
  det44/det44.c
  det44/det44_cli.c
  det44/det44_api.c
  det44/det44_in2out.c
  det44/det44_out2in.c

  MULTIARCH_SOURCES
  det44/det44_in2out.c
  det44/det44_out2in.c

  API_FILES
  det44/det44.api
  nat_types.api

  LINK_LIBRARIES nat
)

add_vpp_plugin(nat64
  SOURCES
  nat64/nat64.c
  nat64/nat64_db.c
  nat64/nat64_cli.c
  nat64/nat64_api.c
  nat64/nat64_in2out.c
  nat64/nat64_out2in.c

  MULTIARCH_SOURCES
  nat64/nat64_in2out.c
  nat64/nat64_out2in.c

  API_FILES
  nat64/nat64.api
  nat_types.api

  LINK_LIBRARIES nat
)

add_vpp_plugin(pnat
  SOURCES
  pnat/pnat.c
  pnat/pnat_node.c
  pnat/pnat_cli.c
  pnat/pnat_api.c

  MULTIARCH_SOURCES
  pnat/pnat_node.c

  API_FILES
  pnat/pnat.api
)

# Unit tests
add_vpp_executable(test_pnat
  SOURCES
  pnat/pnat_test.c
  pnat/pnat_node.c
  pnat/pnat.c
  ../../vnet/ip/ip_checksum.c
  LINK_LIBRARIES vppinfra vlib
  NO_INSTALL
)

if("${CMAKE_VERSION}" VERSION_GREATER_EQUAL "3.13" AND "${CMAKE_C_COMPILER_ID}" MATCHES "(Apple)?[Cc]lang")
  set(TARGET_NAME test_pnat)
  set(COV_SOURCES ${CMAKE_SOURCE_DIR}/plugins/nat/pnat/pnat.c ${CMAKE_SOURCE_DIR}/plugins/nat/pnat/pnat_node.h ${CMAKE_SOURCE_DIR}/plugins/nat/pnat/pnat_node.c)

  message("Building with llvm Code Coverage Tools ${TARGET_NAME}")
  target_compile_options(${TARGET_NAME} PRIVATE -fprofile-instr-generate -fcoverage-mapping)
  target_link_options(${TARGET_NAME} PRIVATE -fprofile-instr-generate -fcoverage-mapping)
  target_compile_options(${TARGET_NAME} PRIVATE -fsanitize=address)
  target_link_options(${TARGET_NAME} PRIVATE -fsanitize=address)

  # llvm-cov
  add_custom_target(${TARGET_NAME}-ccov-preprocessing
    COMMAND LLVM_PROFILE_FILE=${TARGET_NAME}.profraw $<TARGET_FILE:${TARGET_NAME}>
    COMMAND llvm-profdata merge -sparse ${TARGET_NAME}.profraw -o ${TARGET_NAME}.profdata
    DEPENDS ${TARGET_NAME})

  add_custom_target(${TARGET_NAME}-ccov-show
    COMMAND llvm-cov show $<TARGET_FILE:${TARGET_NAME}> -instr-profile=${TARGET_NAME}.profdata -show-line-counts-or-regions ${COV_SOURCES}
    DEPENDS ${TARGET_NAME}-ccov-preprocessing)

  add_custom_target(${TARGET_NAME}-ccov-report
    COMMAND llvm-cov report -show-functions $<TARGET_FILE:${TARGET_NAME}> -instr-profile=${TARGET_NAME}.profdata ${COV_SOURCES}
    DEPENDS ${TARGET_NAME}-ccov-preprocessing)

  add_custom_target(${TARGET_NAME}-ccov
    COMMAND llvm-cov show $<TARGET_FILE:${TARGET_NAME}> -instr-profile=${TARGET_NAME}.profdata -show-line-counts-or-regions -output-dir=${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${TARGET_NAME}-llvm-cov -format="html" ${COV_SOURCES}
    DEPENDS ${TARGET_NAME}-ccov-preprocessing)

  add_custom_command(TARGET ${TARGET_NAME}-ccov POST_BUILD
    COMMAND ;
    COMMENT "Open ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${TARGET_NAME}-llvm-cov/index.html in your browser to view the coverage report."
)
endif()
