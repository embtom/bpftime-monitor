message(STATUS "Checking for libbpf ...")

find_package(PkgConfig REQUIRED)
pkg_check_modules(bpf REQUIRED IMPORTED_TARGET libbpf)
