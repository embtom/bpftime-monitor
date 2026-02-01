set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR bpf)

set(CMAKE_C_COMPILER clang)
set(CMAKE_CXX_COMPILER clang++)

# Do not try to run binaries
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

set(_BPF_CFLAGS
  -g
  -O2
  -target bpf
  -D__TARGET_ARCH_arm64
  -Wall
  -Werror
  -fno-stack-protector
  -fno-asynchronous-unwind-tables
  -fno-unwind-tables
  -fno-exceptions
  -fno-rtti
)

string(JOIN " " CMAKE_C_FLAGS_INIT ${_BPF_CFLAGS})
