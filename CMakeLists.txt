cmake_minimum_required (VERSION 2.8.9)
project (ropit)

set (CMAKE_BUILD_TYPE Debug)

ENABLE_TESTING()
SET (CMAKE_CXX_FLAGS        "-g -O0 -Wall -W -fprofile-arcs -ftest-coverage")
SET (CMAKE_C_FLAGS          "-g -O0 -Wall -W -fprofile-arcs -ftest-coverage")

# The version number.
set (ROPIT_VERSION_MAJOR 1)
set (ROPIT_VERSION_MINOR 0)

# configure a header file to pass some of the CMake settings
# to the source code
configure_file (
    "${PROJECT_SOURCE_DIR}/ropit_config.h.in"
    "${PROJECT_BINARY_DIR}/ropit_config.h"
    )

# add the binary tree to the search path for include files
# so that we will find TutorialConfig.h
include_directories("${PROJECT_BINARY_DIR}")
include_directories("${PROJECT_SOURCE_DIR}/inc")

# add the executable
# executable testing dictionnary
add_executable (dictionnary_example
    src/data/dictionnary_example.c
    )
target_link_libraries (dictionnary_example
    ropit
    gcov
    )
# test: coverage
add_test(NAME dictionnary_example COMMAND dictionnary_example)

# executable testing dictionnary
add_executable (binstr_to_bin
    tests/binstr_to_bin.c
    )
target_link_libraries (binstr_to_bin
    ropit
    gcov
    )
# test: coverage
add_test(NAME binstr_to_bin COMMAND binstr_to_bin)

install (TARGETS ropit DESTINATION lib)
file (
    COPY ${PROJECT_SOURCE_DIR}/inc/ DESTINATION inc/ropit
    PATTERN inc/*
    )
install (DIRECTORY ${PROJECT_BINARY_DIR}/inc/ropit DESTINATION include)

