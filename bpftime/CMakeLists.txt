cmake_minimum_required(VERSION 3.16.0)

list(
    APPEND
    CMAKE_MODULE_PATH
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake"
)

project(
    ebpf-clock-adjtime
    VERSION "0.1.0"
    LANGUAGES CXX C
)

include(GNUInstallDirs)
include(ebpf)
include(EnableStrictWarnings)

find_package(Bpf REQUIRED)
find_package(spdlog REQUIRED)
find_package(cxxopts REQUIRED)

option(
    ENABLE_TESTING
    "Build and enable tests"
    ON
)

add_subdirectory(bpf)
add_subdirectory(src)


if(ENABLE_TESTING)
    enable_testing()
    add_subdirectory(tests)
endif()
