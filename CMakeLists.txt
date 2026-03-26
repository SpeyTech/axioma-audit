# CMakeLists.txt
# axioma-audit — Layer 6 Cryptographic Audit Ledger
#
# DVEC: v1.3
# DETERMINISM: D1 — Strict Deterministic
# MEMORY: Zero Dynamic Allocation
#
# Copyright (c) 2026 The Murray Family Innovation Trust
# SPDX-License-Identifier: GPL-3.0-or-later
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

# Core warning flags — zero warnings required
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

# Stack protection (per specification)
add_compile_options(-fstack-protector-strong)

# Disable floating-point optimizations that could affect determinism
add_compile_options(
    -ffp-contract=off
    -fno-fast-math
)

# ==============================================================================
# DETERMINISM CLOSURE FLAGS (Phase 1.5)
# ==============================================================================
# These flags remove compiler optimisation-induced variance and align behaviour
# across toolchains. Required for D1 certification claims.
#
# @traceability DVEC-001 Section 4.1 (Determinism Contract)

add_compile_options(
    # Prevent type-punning optimisations that assume strict aliasing
    -fno-strict-aliasing
    
    # Define signed overflow as wrapping (two's complement)
    # Prevents UB-based optimisations on overflow
    -fwrapv
    
    # Disable auto-vectorisation (SIMD variance across platforms)
    -fno-tree-vectorize
    
    # Use explicit implementations, not compiler builtins
    # Ensures identical codepaths across compilers
    -fno-builtin
    
    # Preserve frame pointer for debugging and stack traces
    -fno-omit-frame-pointer
)

# Platform-specific flags
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    # Require explicit extern for global variables
    add_compile_options(-fno-common)
endif()

# ==============================================================================
# INCLUDE DIRECTORIES
# ==============================================================================

# axioma-audit owns include/axilog/audit.h
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# axioma-spec owns types.h, commitment.h, dvm_compat.h, dvec.h
# Path relative to axilog workspace
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../axioma-spec/include)

# Internal headers (sha256_internal.h)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)

# ==============================================================================
# SOURCE FILES
# ==============================================================================

set(AXIOMA_AUDIT_SOURCES
    src/sha256.c
    src/commitment.c
    src/ledger.c
)

# ==============================================================================
# LIBRARY TARGET
# ==============================================================================

add_library(axioma-audit STATIC ${AXIOMA_AUDIT_SOURCES})

target_include_directories(axioma-audit PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../axioma-spec/include>
    $<INSTALL_INTERFACE:include>
)

# ==============================================================================
# TEST TARGETS
# ==============================================================================

enable_testing()

# Test: commitment
add_executable(test_commitment tests/identity/test_commitment.c)
target_link_libraries(test_commitment axioma-audit)
add_test(NAME test_commitment COMMAND test_commitment)

# Test: ledger
add_executable(test_ledger tests/identity/test_ledger.c)
target_link_libraries(test_ledger axioma-audit)
add_test(NAME test_ledger COMMAND test_ledger)

# ==============================================================================
# CUSTOM TARGETS
# ==============================================================================

# Run all tests
add_custom_target(test-all
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
    DEPENDS test_commitment test_ledger
    COMMENT "Running all axioma-audit tests"
)

# ==============================================================================
# INSTALLATION (optional)
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
message(STATUS "")
