cmake_minimum_required(VERSION 3.14)

# Name the test project and specify the language
project(tdx_attestation_app_tests LANGUAGES CXX)

# GoogleTest requires at least C++14
set(CMAKE_CXX_STANDARD 14)

include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)

# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

include_directories(
    ../
    ../src
)

# Create the test executable and link the necessary libraries
add_executable(tdx_attestation_app_tests
  Utils_Test.cpp
  AttestClient_Test.cpp
  main.cpp
)

target_link_libraries(tdx_attestation_app_tests
  gtest
  gtest_main
)

# Enable testing and add the test
enable_testing()
add_test(NAME tdx_attestation_app_tests COMMAND tdx_attestation_app_tests)