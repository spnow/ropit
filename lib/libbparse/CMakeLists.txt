cmake_minimum_required (VERSION 2.8.9)
project (libbparse)

set (CMAKE_BUILD_TYPE Debug)

ENABLE_TESTING()
SET (CMAKE_CXX_FLAGS        "-g -O0 -Wall -W -fprofile-arcs -ftest-coverage")
SET (CMAKE_C_FLAGS          "-g -O0 -Wall -W -fprofile-arcs -ftest-coverage")

# The version number.
set (BPARSE_VERSION_MAJOR 1)
set (BPARSE_VERSION_MINOR 0)

# configure a header file to pass some of the CMake settings
# to the source code
configure_file (
    "${PROJECT_SOURCE_DIR}/bparse_config.h.in"
    "${PROJECT_BINARY_DIR}/bparse_config.h"
    )

# add the binary tree to the search path for include files
# so that we will find TutorialConfig.h
include_directories("${PROJECT_BINARY_DIR}")
include_directories("${PROJECT_SOURCE_DIR}/inc")

# add the library
add_library(
    libbparse
    STATIC
    src/escape.c  
    src/file_binary.c  
    src/file_elf.c  
    src/file_elf_view.c  
    src/filemap.c  
    src/file_pe.c  
    src/file_pe_view.c  
    src/raw_data.c
    )
target_link_libraries (libbparse
    gcov
    fall4c
    )

