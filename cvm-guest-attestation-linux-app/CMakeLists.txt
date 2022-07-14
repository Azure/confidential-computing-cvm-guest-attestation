cmake_minimum_required(VERSION 3.5)

project(AttestationClient)

set(CMAKE_PROJECT_TARGET AttestationClient)

add_definitions (-DPLATFORM_UNIX)

include_directories(
     /usr/include/azguestattestation1
     /usr/include/jsoncpp
)

link_directories (
    /usr/lib
    /usr/lib/x86_64-linux-gnu
)

add_executable(${CMAKE_PROJECT_TARGET} main.cpp
                                       Utils.cpp
                                       )

target_link_libraries(${CMAKE_PROJECT_TARGET} azguestattestation)
target_link_libraries(${CMAKE_PROJECT_TARGET} curl)
target_link_libraries(${CMAKE_PROJECT_TARGET} jsoncpp)