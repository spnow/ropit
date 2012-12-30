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

add_subdirectory (lib/bparse)
add_subdirectory (lib/file)
add_subdirectory (lib/gadgets)

find_library (LIBBPARSE
    NAMES bparse libbparse
    HINTS lib
    PATHS lib libbparse
    )

# add the binary tree to the search path for include files
# so that we will find TutorialConfig.h
include_directories("${PROJECT_BINARY_DIR}")
include_directories("${PROJECT_SOURCE_DIR}/inc")
include_directories("${libgadgets_SOURCE_DIR}/inc")
include_directories("${libbparse_SOURCE_DIR}/inc")

# add the executable
# executable testing dictionnary
add_executable (ropit
    ropit.c
    ropit_options.c
    )
target_link_libraries (ropit
    gadgets
    gcov
    bparse
    )
# test: coverage
add_test(NAME ropit COMMAND ropit)

