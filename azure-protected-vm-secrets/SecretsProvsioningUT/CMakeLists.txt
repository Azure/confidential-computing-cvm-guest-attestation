cmake_minimum_required(VERSION 3.5)
project (SecretsProvisioningUT)

add_definitions (-DPLATFORM_UNIX)

set (CMAKE_PROJECT_TARGET SecretsProvisioningUT)
project (Linux${CMAKE_PROJECT_TARGET})

include_directories(${TSS2_INCLUDE_DIRS} ../)

# Find Google Test package
# find_package(GTest REQUIRED)
# include_directories(${GTEST_INCLUDE_DIRS})
include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)
# find_package(GTest REQUIRED)
# include_directories(${GTEST_INCLUDE_DIRS})
include(GoogleTest)
# Add the test executable
add_executable(${CMAKE_PROJECT_TARGET}
   BcryptTests.cpp
   # TpmMocks.cpp
   # test.cpp
   JwtTests.cpp
   SigningTests.cpp
   PolicyTests.cpp
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
