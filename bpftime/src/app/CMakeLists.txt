ebpf_build(
    TARGET BPF_BINARY
    SOURCES ${PROJECT_SOURCE_DIR}/bpf/clock_adjtime.bpf.c
    OBJECT BPF_OBJECT
)

ebpf_skeleton(
    TARGET BPF_SKEL
    OBJECT ${BPF_OBJECT}
    SKELETON ${PROJECT_BINARY_DIR}/clock_adjtime.skel.h
)

add_executable(bpftime "main.cpp" ${PROJECT_BINARY_DIR}/clock_adjtime.skel.h)

target_include_directories(bpftime PRIVATE ${PROJECT_BINARY_DIR})

target_link_libraries(
    bpftime
    PRIVATE PkgConfig::bpf
            cxxopts::cxxopts
            bpf_interface
            bpfutils
)

install(TARGETS bpftime RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
