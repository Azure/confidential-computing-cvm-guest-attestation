cmake_minimum_required(VERSION 3.5)

project(TssStaticShim)
set(CMAKE_PROJECT_TARGET TssStaticShim)

find_package(Tss2 REQUIRED)
include_directories(${TSS2_INCLUDE_DIRS})

add_library(${CMAKE_PROJECT_TARGET} mssim_shim.cpp)

