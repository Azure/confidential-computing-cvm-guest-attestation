cmake_minimum_required (VERSION 3.5)

set (CMAKE_PROJECT_TARGET Tpm2)
project (Linux${CMAKE_PROJECT_TARGET})

find_package(Tss2 REQUIRED)
include_directories(${TSS2_INCLUDE_DIRS})

include_directories (${CMAKE_CURRENT_SOURCE_DIR}/../include)

file(GLOB SOURCES "*.cpp")

add_library(${CMAKE_PROJECT_TARGET} STATIC ${SOURCES})
target_link_libraries(${CMAKE_PROJECT_TARGET} ${TSS2_LIBRARIES})
target_link_libraries(${CMAKE_PROJECT_TARGET} ssl crypto)
target_link_libraries(${CMAKE_PROJECT_TARGET} dl)
target_link_libraries(${CMAKE_PROJECT_TARGET} tss2-mu)
set_property(TARGET ${CMAKE_PROJECT_TARGET} PROPERTY POSITION_INDEPENDENT_CODE ON)
