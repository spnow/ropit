cmake_minimum_required (VERSION 2.8.9)
project (libgadgets)

set (CMAKE_BUILD_TYPE Debug)

ENABLE_TESTING()
SET (CMAKE_CXX_FLAGS        "-g -O0 -Wall -W -fprofile-arcs -ftest-coverage")
SET (CMAKE_C_FLAGS          "-g -O0 -Wall -W -fprofile-arcs -ftest-coverage")

# The version number.
set (GADGETS_VERSION_MAJOR 1)
set (GADGETS_VERSION_MINOR 0)

# configure a header file to pass some of the CMake settings
# to the source code
configure_file (
    "${PROJECT_SOURCE_DIR}/gadgets_config.h.in"
    "${PROJECT_BINARY_DIR}/gadgets_config.h"
    )

# add the binary tree to the search path for include files
# so that we will find TutorialConfig.h
include_directories("${PROJECT_BINARY_DIR}")
include_directories("${PROJECT_SOURCE_DIR}/inc")

# add the library
add_library(
    libgadgets
    STATIC
    gadgets.c
    gadgets_cache.c
    gadgets_find.c
    offsets.c
    )
target_link_libraries (libgadgets
    gcov
    )

