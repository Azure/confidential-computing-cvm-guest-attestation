cmake_minimum_required(VERSION 3.5)
project(azure-protected-secrets-tool-tests)

add_definitions(-DPLATFORM_UNIX -DUNIT_TEST)

include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)
include(GoogleTest)

# nlohmann_json is fetched by the parent CMakeLists.txt via FetchContent when
# built as part of the main build. When built standalone (e.g. in WSL for local
# testing), fall back to a find_package so the target is still available.
if(NOT TARGET nlohmann_json::nlohmann_json)
    find_package(nlohmann_json REQUIRED)
endif()

add_executable(azure-protected-secrets-tool-tests
    test_cli_common.cpp
    test_cmd_is_cvm.cpp
    test_cmd_validate_imds.cpp
    test_cmd_unprotect_secret.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../../SecretsProvisioningSample/cli_common.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../../SecretsProvisioningSample/cmd_is_cvm.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../../SecretsProvisioningSample/cmd_validate_imds.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../../SecretsProvisioningSample/cmd_unprotect_secret.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../../CvmHelper/src/CvmHelper.cpp
)

target_include_directories(azure-protected-secrets-tool-tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../SecretsProvisioningSample
    ${CMAKE_CURRENT_SOURCE_DIR}/../..
    ${CMAKE_CURRENT_SOURCE_DIR}/../../CvmHelper/inc
    ${CMAKE_BINARY_DIR}/generated
)

target_link_libraries(azure-protected-secrets-tool-tests
    GTest::gtest_main
    pthread
    ssl
    crypto
    nlohmann_json::nlohmann_json
)
