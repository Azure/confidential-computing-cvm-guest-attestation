cmake_minimum_required(VERSION 3.5)
project (SecretsProvisioningUT)

add_definitions (-DPLATFORM_UNIX)

set (CMAKE_PROJECT_TARGET SecretsProvisioningUT)
project (Linux${CMAKE_PROJECT_TARGET})

include_directories(${TSS2_INCLUDE_DIRS} ../ ../generated/)

# GoogleTest: prefer system packages (Fedora ships gtest-devel and gmock-devel
# as separate packages; on systems where they're bundled, find_package(GTest)
# alone will set up GTest::gmock_main). Fall back to FetchContent for build
# environments without either. Fedora guidelines forbid bundling system
# libraries: index.adoc §Bundling, §Build Time Network Access.
find_package(GTest QUIET)
if(GTest_FOUND AND NOT TARGET GTest::gmock_main)
    # gtest-devel was found but gmock_main isn't an imported target. On
    # Fedora-style splits, gmock-devel ships its own CMake config.
    find_package(GMock QUIET)
    if(NOT TARGET GTest::gmock_main)
        set(GTest_FOUND FALSE)
    endif()
endif()
if(NOT GTest_FOUND)
    include(FetchContent)
    FetchContent_Declare(
      googletest
      URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
    )
    # For Windows: Prevent overriding the parent project's compiler/linker settings
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
endif()
include(GoogleTest)
# Add the test executable
add_executable(${CMAKE_PROJECT_TARGET}
   ErrorMessageTest.cpp
   BcryptTests.cpp
   # TpmMocks.cpp
   # test.cpp
   JwtTests.cpp
   SigningTests.cpp
   PolicyTests.cpp
   VersionTest.cpp
)
# Link the test executable with Google Test and our library
target_link_libraries(${CMAKE_PROJECT_TARGET} 
   GTest::gtest_main
   GTest::gmock_main
   pthread
)
target_link_libraries(${CMAKE_PROJECT_TARGET} 
   SecretsProvisioningLibrary
)
