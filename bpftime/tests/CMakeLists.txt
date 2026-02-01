include(CTest)
include(GoogleTest)

find_package(GTest REQUIRED)

add_executable(unittest demo_test.cpp)

target_link_libraries(
  unittest
  PRIVATE GTest::GTest
  PRIVATE GTest::Main)

gtest_discover_tests(unittest)
