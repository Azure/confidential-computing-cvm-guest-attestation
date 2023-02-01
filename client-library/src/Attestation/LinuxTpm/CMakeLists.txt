cmake_minimum_required(VERSION 3.5)
project(Client)

project (TpmBuild)

add_subdirectory(staticshim)
add_subdirectory(lib)
add_subdirectory(testclient)
add_subdirectory(unittests)
