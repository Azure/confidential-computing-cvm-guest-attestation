cmake_minimum_required(VERSION 3.5)

project(AttestationClient)

include(GNUInstallDirs)
find_package(CURL REQUIRED)
find_package(Boost REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(jsoncpp REQUIRED)

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
					Logger.cpp
                                       )

target_link_libraries(${CMAKE_PROJECT_TARGET} azguestattestation)
target_link_libraries(${CMAKE_PROJECT_TARGET}
    CURL::libcurl
    Boost::boost
    nlohmann_json::nlohmann_json
)
target_link_libraries(${CMAKE_PROJECT_TARGET} jsoncpp_lib)
install(TARGETS ${CMAKE_PROJECT_TARGET}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
