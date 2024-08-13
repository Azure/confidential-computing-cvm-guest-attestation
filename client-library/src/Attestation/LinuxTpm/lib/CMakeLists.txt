cmake_minimum_required (VERSION 3.5)

set (CMAKE_PROJECT_TARGET Tpm2)
project (Linux${CMAKE_PROJECT_TARGET})

find_package(Tss2 REQUIRED)
include_directories(${TSS2_INCLUDE_DIRS})

find_path(CRYPTO_INCLUDE_DIR NAMES openssl PATHS /usr/local/openssl/include
                                            NO_DEFAULT_PATH)

include_directories (${CMAKE_CURRENT_SOURCE_DIR}/../include
                    ${CRYPTO_INCLUDE_DIR}
)

file(GLOB SOURCES "*.cpp")

find_library(CRYPTO_LIB NAMES libcrypto.a PATHS /usr/local/openssl/lib64
                                           NO_DEFAULT_PATH)
find_library(SSL_LIB NAMES libssl.a PATHS /usr/local/openssl/lib64
                                           NO_DEFAULT_PATH)

add_library(${CMAKE_PROJECT_TARGET} ${SOURCES})
target_link_libraries(${CMAKE_PROJECT_TARGET} ${TSS2_LIBRARIES})
target_link_libraries(${CMAKE_PROJECT_TARGET} ${CRYPTO_LIB})
target_link_libraries(${CMAKE_PROJECT_TARGET} ${SSL_LIB})
target_link_libraries(${CMAKE_PROJECT_TARGET} pthread)
target_link_libraries(${CMAKE_PROJECT_TARGET} dl)
target_link_libraries(${CMAKE_PROJECT_TARGET} tss2-mu)
set_property(TARGET ${CMAKE_PROJECT_TARGET} PROPERTY POSITION_INDEPENDENT_CODE ON)
