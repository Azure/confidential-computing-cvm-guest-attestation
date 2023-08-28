cmake_minimum_required(VERSION 3.5)

project(AzureAttestSKR)

set(CMAKE_PROJECT_TARGET AzureAttestSKR)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# define TRACE constant for extensive logging.
if (CMAKE_BUILD_TYPE MATCHES Debug)
    add_definitions (-DTRACE)
endif()

add_definitions (-DPLATFORM_UNIX)

include_directories(
     /usr/include/azguestattestation1
     /usr/include/jsoncpp
)

link_directories (
    /usr/lib
    /usr/lib/x86_64-linux-gnu
)

add_executable(${CMAKE_PROJECT_TARGET}
    AttestationUtil.cpp
    Logger.cpp
    Main.cpp
)

target_link_libraries(${CMAKE_PROJECT_TARGET} azguestattestation curl jsoncpp crypto)
