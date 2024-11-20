cmake_minimum_required(VERSION 3.5)

set(CMAKE_PROJECT_TARGET LinuxTpmTests)
project(Linux${CMAKE_PROJECT_TARGET})

# Add GTest
find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

# Add GMock
find_package(GMock REQUIRED)
include_directories(${GMOCK_INCLUDE_DIRS})

find_package(Tss2 REQUIRED)
include_directories(${TSS2_INCLUDE_DIRS})

# Add local includes
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib
)

add_executable(${CMAKE_PROJECT_TARGET} TpmTests.cpp TpmMocks.cpp)

target_link_libraries(${CMAKE_PROJECT_TARGET} ${GTEST_LIBRARIES} pthread)
target_link_libraries(${CMAKE_PROJECT_TARGET} ${GMOCK_LIBRARIES})
target_link_libraries(${CMAKE_PROJECT_TARGET} Tpm2)
