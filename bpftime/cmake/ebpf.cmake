# ------------------------------------------------------------------------------
# ebpf_build
#
# Build one or more eBPF programs (.bpf.c) into ELF object files (.bpf.o)
# using clang. This function does NOT use a CMake toolchain file; it treats
# CMake purely as a build orchestrator and invokes clang directly.
#
# The generated object files:
#   - are rebuilt automatically when sources or dependencies change
#   - can be consumed by bpftool, libbpf, or skeleton generation
#
# Architecture-specific __TARGET_ARCH_xxx is derived from
# CMAKE_SYSTEM_PROCESSOR.
#
# Parameters:
#
#   TARGET (required)
#     Name of the custom target that builds the eBPF objects.
#
#   SOURCES (required)
#     List of eBPF source files (.bpf.c).
#
#   OBJECT (required)
#     Name of a variable in the parent scope that will receive the list of
#     generated .bpf.o files.
#
#   DEPENDS (optional)
#     Additional files or targets that the eBPF build depends on
#     (e.g. vmlinux.h).
#
# Example:
#
#   ebpf_build(
#     TARGET   BPF_BINARY
#     SOURCES  bpf/clock_adjtime.bpf.c
#     OBJECT  OBJECTS
#     DEPENDS  vmlinux.h
#   )
# ------------------------------------------------------------------------------
function(ebpf_build)
    cmake_parse_arguments(
        EBPF
        ""
        "TARGET;OBJECT"
        "SOURCES;DEPENDS"
        ${ARGN}
    )

    if(EBPF_TARGET STREQUAL ""
       OR EBPF_OBJECT STREQUAL ""
       OR NOT EBPF_SOURCES)
        message(FATAL_ERROR "ebpf_build: TARGET, SOURCES, OBJECT are required")
    endif()

    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64")
        set(BPF_ARCH x86)
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
        set(BPF_ARCH arm64)
    else()
        message(FATAL_ERROR "Unsupported arch: ${CMAKE_SYSTEM_PROCESSOR}")
    endif()

    set(out_objects "")

    foreach(src IN LISTS EBPF_SOURCES)
        get_filename_component(base ${src} NAME_WE)
        set(obj ${CMAKE_CURRENT_BINARY_DIR}/${base}.bpf.o)

        add_custom_command(
            OUTPUT ${obj}
            COMMAND clang
                -g -O2
                -target bpf
                -D__TARGET_ARCH_${BPF_ARCH}
                -Wall -Werror
                -fno-stack-protector
                -fno-unwind-tables
                -I${CMAKE_CURRENT_SOURCE_DIR}
                -c ${src}
                -o ${obj}
            DEPENDS
                ${src}
                ${EBPF_DEPENDS}
            COMMENT "Building eBPF program ${src}"
            VERBATIM
        )

        list(APPEND out_objects ${obj})
    endforeach()

    add_custom_target(${EBPF_TARGET} DEPENDS ${out_objects})
    message(STATUS "${out_objects}")
    set(${EBPF_OBJECT} ${out_objects} PARENT_SCOPE)
endfunction()

# ------------------------------------------------------------------------------
# ebpf_skeleton
#
# Generate a libbpf C skeleton header (.skel.h) from a compiled eBPF object
# file using bpftool.
#
# The skeleton is generated as a tracked build output and will only be
# regenerated when the input .bpf.o file changes.
#
# Parameters:
#
#   TARGET (required)
#     Name of the custom target that generates the skeleton.
#
#   OBJECT (required)
#     Path to the compiled eBPF object file (.bpf.o).
#
#   OUT_HEADER (required)
#     Path to the generated skeleton header (.skel.h).
#
# Example:
#
#   ebpf_skeleton(
#     TARGET      BPF_SKEL
#     OBJECT  ${OBJECTS}
#     OUT_HEADER  ${CMAKE_CURRENT_BINARY_DIR}/clock_adjtime.skel.h
#   )
# ------------------------------------------------------------------------------
function(ebpf_skeleton)
    cmake_parse_arguments(
        SKEL
        ""
        "TARGET;OBJECT;SKELETON"
        ""
        ${ARGN}
    )

    if(SKEl_TARGET STREQUAL ""
       OR SKEL_OBJECT STREQUAL ""
       OR SKEL_SKELETON STREQUAL "")
        message(FATAL_ERROR "ebpf_skeleton: TARGET, OBJECT, SKELETON required")
    endif()

    add_custom_command(
        OUTPUT ${SKEL_SKELETON}
        COMMAND bpftool gen skeleton ${SKEL_OBJECT} > ${SKEL_SKELETON}
        DEPENDS ${SKEL_OBJECT}
        COMMENT "Generating eBPF skeleton ${SKEL_SKELETON}"
        VERBATIM
    )

    add_custom_target(
        ${SKEL_TARGET}
        DEPENDS ${SKEL_SKELETON}
    )
endfunction()


