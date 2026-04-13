# CMakeLists.txt
# axioma-audit — Layer 6 Cryptographic Audit Ledger
#
# DVEC: v1.3
# DETERMINISM: D1 — Strict Deterministic
# MEMORY: Zero Dynamic Allocation
#
# Copyright (c) 2026 The Murray Family Innovation Trust
# SPDX-License-Identifier: AGPL-3.0-or-later
# Patent: UK GB2521625.0
#
# @traceability SRS-013-SHALL-005

cmake_minimum_required(VERSION 3.10)

project(axioma-audit
    VERSION 0.1.0
    LANGUAGES C
    DESCRIPTION "Axilog Layer 6 Cryptographic Audit Ledger"
)

# ==============================================================================
# C STANDARD CONFIGURATION
# ==============================================================================

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# ==============================================================================
# COMPILER FLAGS (SRS-013-SHALL-005: Static analysis cleanliness)
# ==============================================================================

add_compile_options(
    -Wall
    -Wextra
    -Werror
    -pedantic
    -Wshadow
    -Wconversion
    -Wstrict-prototypes
    -Wmissing-prototypes
    -Wold-style-definition
    -Wpointer-arith
    -Wcast-qual
    -Wcast-align
    -Wwrite-strings
    -Wformat=2
    -Wformat-security
    -Wstrict-overflow=5
    -Wundef
    -Wredundant-decls
    -Wnested-externs
    -Winline
    -Wno-unused-parameter
)

add_compile_options(-fstack-protector-strong)

add_compile_options(
    -ffp-contract=off
    -fno-fast-math
)

# ==============================================================================
# DETERMINISM CLOSURE FLAGS
# ==============================================================================

add_compile_options(
    -fno-strict-aliasing
    -fwrapv
    -fno-tree-vectorize
    -fno-builtin
    -fno-omit-frame-pointer
)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-fno-common)
endif()

# ==============================================================================
# libaxilog (sdk-root) — cryptographic substrate
# sha256.c and commitment.c removed — axilog_sha256/axilog_commit from libaxilog
# ==============================================================================

set(AXILOG_SDK_ROOT "$ENV{HOME}/axilog/sdk-root"
    CACHE PATH "Path to axioma sdk-root installation")

# ==============================================================================
# SOURCE FILES
# sha256.c    — deleted: provided by libaxilog
# commitment.c — deleted: axilog_commit() provided by libaxilog
# ==============================================================================

set(AXIOMA_AUDIT_SOURCES
    src/ledger.c
)

# ==============================================================================
# LIBRARY TARGET
# ==============================================================================

add_library(axioma-audit STATIC ${AXIOMA_AUDIT_SOURCES})

target_include_directories(axioma-audit PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../axioma-spec/include>
    $<BUILD_INTERFACE:${AXILOG_SDK_ROOT}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(axioma-audit PRIVATE
    ${AXILOG_SDK_ROOT}/lib/libaxilog.a
)

# ==============================================================================
# TEST TARGETS
# ==============================================================================

enable_testing()

add_executable(test_commitment tests/identity/test_commitment.c)
target_link_libraries(test_commitment axioma-audit)
add_test(NAME test_commitment COMMAND test_commitment)

add_executable(test_ledger tests/identity/test_ledger.c)
target_link_libraries(test_ledger axioma-audit)
add_test(NAME test_ledger COMMAND test_ledger)

# ==============================================================================
# CUSTOM TARGETS
# ==============================================================================

add_custom_target(test-all
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
    DEPENDS test_commitment test_ledger
    COMMENT "Running all axioma-audit tests"
)

# ==============================================================================
# INSTALLATION
# ==============================================================================

install(TARGETS axioma-audit
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)

install(DIRECTORY include/axilog/
    DESTINATION include/axilog
    FILES_MATCHING PATTERN "*.h"
)

# ==============================================================================
# SUMMARY
# ==============================================================================

message(STATUS "")
message(STATUS "axioma-audit configuration:")
message(STATUS "  Version:     ${PROJECT_VERSION}")
message(STATUS "  C Standard:  C${CMAKE_C_STANDARD}")
message(STATUS "  Build Type:  ${CMAKE_BUILD_TYPE}")
message(STATUS "  Compiler:    ${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION}")
message(STATUS "  SDK Root:    ${AXILOG_SDK_ROOT}")
message(STATUS "")
