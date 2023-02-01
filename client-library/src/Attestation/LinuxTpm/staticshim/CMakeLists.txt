cmake_minimum_required(VERSION 3.5)

project(TssStaticShim)
set(CMAKE_PROJECT_TARGET TssStaticShim)

add_library(${CMAKE_PROJECT_TARGET} mssim_shim.cpp)

