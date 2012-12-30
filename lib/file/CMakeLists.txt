cmake_minimum_required (VERSION 2.8.9)
project (libfilerop)

set (CMAKE_BUILD_TYPE Debug)

ENABLE_TESTING()
SET (CMAKE_CXX_FLAGS        "-g -O0 -Wall -W -fprofile-arcs -ftest-coverage")
SET (CMAKE_C_FLAGS          "-g -O0 -Wall -W -fprofile-arcs -ftest-coverage")

# The version number.
set (FILEROP_VERSION_MAJOR 1)
set (FILEROP_VERSION_MINOR 0)

# configure a header file to pass some of the CMake settings
# to the source code
configure_file (
    "${PROJECT_SOURCE_DIR}/filerop_config.h.in"
    "${PROJECT_BINARY_DIR}/filerop_config.h"
    )

find_library (LIBBPARSE
    NAMES bparse libbparse
    HINTS ../
    )

# add the binary tree to the search path for include files
# add the binary tree to the search path for include files
# so that we will find TutorialConfig.h
include_directories("${PROJECT_BINARY_DIR}")
include_directories("${PROJECT_SOURCE_DIR}/inc")

# add the library
add_library(
    filerop
    STATIC
    src/byte-order.c
    src/file-gadgets.c
    src/file-ropit.c
    src/file-ropit-metadata.c
    src/file-ropit-section.c
    src/file-test.c
    )
target_link_libraries (filerop
    gcov
    )

