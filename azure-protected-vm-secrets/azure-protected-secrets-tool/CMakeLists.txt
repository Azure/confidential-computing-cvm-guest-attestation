cmake_minimum_required(VERSION 3.5)
project(azure-protected-secrets-tool)

add_definitions(-DPLATFORM_UNIX -DDYNAMIC_SAMPLE)

set(SAMPLE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../SecretsProvisioningSample)

set(CLI_SOURCES
    ${SAMPLE_DIR}/main.cpp
    ${SAMPLE_DIR}/cli_common.cpp
    ${SAMPLE_DIR}/cmd_is_cvm.cpp
    ${SAMPLE_DIR}/cmd_is_secrets_enabled.cpp
    ${SAMPLE_DIR}/cmd_unprotect_secret.cpp
    ${SAMPLE_DIR}/cmd_validate_imds.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../CvmHelper/src/CvmHelper.cpp
)

add_executable(azure-protected-secrets-tool ${CLI_SOURCES})

target_include_directories(azure-protected-secrets-tool PRIVATE
    ${SAMPLE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${CMAKE_CURRENT_SOURCE_DIR}/../CvmHelper/inc
    ${CMAKE_BINARY_DIR}/generated
)

target_link_libraries(azure-protected-secrets-tool DynamicSecretsProvisioningLibrary)

add_subdirectory(tests)
