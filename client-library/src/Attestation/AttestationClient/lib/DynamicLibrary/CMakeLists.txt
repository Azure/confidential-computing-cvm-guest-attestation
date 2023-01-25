cmake_minimum_required(VERSION 3.5)

#MUST be same as the version in the latest entry in debian/changelog file.
project(azguestattestation VERSION 1.0.2)

set(CMAKE_PROJECT_TARGET azguestattestation)

add_definitions (-DPLATFORM_UNIX)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../LinuxTpm/include
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${CMAKE_CURRENT_SOURCE_DIR}/../..
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_SOURCE_DIR}/../external/jsoncpp-0.10.7/src
    ${CMAKE_SOURCE_DIR}/../external/VbsVmCrypto
)

add_library(${CMAKE_PROJECT_TARGET} SHARED ../../AttestationHelperBase64.cpp
                                           ../../AttestationHelperJson.cpp
                                           ../AttestationClientImpl.cpp
                                           ../AttestationClient.cpp
                                           ../AttestationParameters.cpp
                                           ../TpmInfo.cpp
                                           ../Logging.cpp
                                           ../TpmUnseal.cpp
                                           ../NativeConverter.cpp
                                           ../AttestationLibUtils.cpp
                                           ../ImdsOperations.cpp
                                           ../IsolationInfo.cpp
                                           ../HclReportParser.cpp
                                           ../HttpClient.cpp
                                           ${CMAKE_SOURCE_DIR}/../external/jsoncpp-0.10.7/src/jsoncpp.cpp)

target_link_libraries(${CMAKE_PROJECT_TARGET} Tpm2)
target_link_libraries(${CMAKE_PROJECT_TARGET} curl)

set_target_properties(${CMAKE_PROJECT_TARGET} PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(${CMAKE_PROJECT_TARGET} PROPERTIES SOVERSION 1)
