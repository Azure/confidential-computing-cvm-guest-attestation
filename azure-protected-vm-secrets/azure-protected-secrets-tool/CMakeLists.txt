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

# Link the SHARED library. Renamed from `DynamicSecretsProvisioningLibrary`
# -> `azure_protected_vm_secrets`; see
# DynamicSecretsProvisioningLibrary/CMakeLists.txt for the rationale.
target_link_libraries(azure-protected-secrets-tool azure_protected_vm_secrets)

include(GNUInstallDirs)
install(TARGETS azure-protected-secrets-tool RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

add_subdirectory(tests)
