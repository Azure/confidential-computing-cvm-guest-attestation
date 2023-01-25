cmake_minimum_required(VERSION 3.5)
project(TpmUtil)

set(CMAKE_PROJECT_TARGET LinuxTpmUtil)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib
)

find_package(Tss2 REQUIRED)
include_directories(${TSS2_INCLUDE_DIRS})

add_executable(${CMAKE_PROJECT_TARGET} main.cpp TestUtil.cpp)
target_link_libraries(${CMAKE_PROJECT_TARGET} Tpm2)
target_link_libraries(${CMAKE_PROJECT_TARGET} ${TSS2_LIBRARIES})
target_link_libraries(${CMAKE_PROJECT_TARGET} stdc++fs)
