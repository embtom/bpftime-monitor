add_library(
    bpfutils STATIC
    "include/fdset.h"
    "include/ringbuf.h"
    "include/signalhandler.h"
    "src/fdset.cpp"
    "src/signalhandler.cpp"
)

target_compile_features(bpfutils PUBLIC cxx_std_23)

enable_strict_warnings(bpfutils)

set_target_properties(bpfutils PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_include_directories(
    bpfutils
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
)

target_link_libraries(
    bpfutils
    PUBLIC PkgConfig::bpf
    PRIVATE spdlog::spdlog
)
