cmake_minimum_required(VERSION 3.5)

project(TdxAttest)

set(CMAKE_PROJECT_TARGET TdxAttest)

add_definitions(-DPLATFORM_UNIX)

include_directories(
    /usr/include/azguestattestation1
    /usr/include/jsoncpp
    src/
)

link_directories(
    /usr/lib
    /usr/lib/x86_64-linux-gnu
)

add_executable(${CMAKE_PROJECT_TARGET}
    main.cpp
    src/HttpClient.cpp)

target_link_libraries(${CMAKE_PROJECT_TARGET} azguestattestation)
target_link_libraries(${CMAKE_PROJECT_TARGET} curl)
target_link_libraries(${CMAKE_PROJECT_TARGET} jsoncpp)