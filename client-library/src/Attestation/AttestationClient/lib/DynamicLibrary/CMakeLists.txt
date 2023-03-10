cmake_minimum_required(VERSION 3.5)

option(BUILD_SHARED_LIBS "Build shared libraries" ON)

#MUST be same as the version in the latest entry in debian/changelog file.
project(azguestattestation VERSION 1.0.2)

set(CMAKE_PROJECT_TARGET azguestattestation)

include(GNUInstallDirs)
find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(RapidJSON REQUIRED)

add_definitions (-DPLATFORM_UNIX)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../LinuxTpm/include
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${CMAKE_CURRENT_SOURCE_DIR}/../..
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../external/jsoncpp-0.10.7/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../external/SnpVmReport
)

add_library(${CMAKE_PROJECT_TARGET} ../../AttestationHelperBase64.cpp
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
                                           ../../../../external/jsoncpp-0.10.7/src/jsoncpp.cpp)
target_include_directories(${CMAKE_PROJECT_TARGET} INTERFACE ../include)
target_include_directories(${CMAKE_PROJECT_TARGET} PRIVATE ${OPENSSL_INCLUDE_DIR} ${RAPIDJSON_INCLUDE_DIRS})
target_link_libraries(${CMAKE_PROJECT_TARGET} Tpm2)
target_link_libraries(${CMAKE_PROJECT_TARGET} CURL::libcurl)

set_target_properties(${CMAKE_PROJECT_TARGET} PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(${CMAKE_PROJECT_TARGET} PROPERTIES SOVERSION 1)

install(TARGETS ${CMAKE_PROJECT_TARGET}
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${CMAKE_PROJECT_TARGET}1"
)