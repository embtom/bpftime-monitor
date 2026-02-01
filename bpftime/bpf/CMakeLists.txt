add_library(bpf_interface INTERFACE)

target_include_directories(bpf_interface INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

target_sources(bpf_interface INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/timex_event.h)
