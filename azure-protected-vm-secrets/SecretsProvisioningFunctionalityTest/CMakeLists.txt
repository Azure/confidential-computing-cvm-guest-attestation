cmake_minimum_required(VERSION 3.5)
project (SecretsProvisioningFunctionalityTest)

add_definitions (-DPLATFORM_UNIX)

set (CMAKE_PROJECT_TARGET SecretsProvisioningFunctionalityTest)
project (Linux${CMAKE_PROJECT_TARGET})


# Try to find Tss2
find_path(TSS2_INCLUDE_DIR NAMES tss2 PATHS ${SYSTEM_LIBRARY_PREFIX}/usr/local/include ${SYSTEM_LIBRARY_PREFIX}/usr/include NO_DEFAULT_PATH)

# Invalidate cache to force cmake to lookup the libraries again
set (TSS2_ESYS TSS2_ESYS-NOTFOUND)
set (TSS2_SYS TSS2_SYS-NOTFOUND)
set (TSS2_MU TSS2_MU-NOTFOUND)
set (TSS2_TCTI_DEVICE TSS2_TCTI_DEVICE-NOTFOUND)
set (TSS2_RC TSS2_RC-NOTFOUND)

find_library(TSS2_ESYS names libtss2-esys.a tss2-esys PATHS /usr/local/lib /usr/lib /usr/lib/x86_64-linux-gnu/ NO_DEFAULT_PATH)
find_library(TSS2_SYS names libtss2-sys.a tss2-sys PATHS /usr/local/lib /usr/lib /usr/lib/x86_64-linux-gnu/  NO_DEFAULT_PATH)
find_library(TSS2_MU NAMES libtss2-mu.a tss2-mu PATHS /usr/local/lib /usr/lib /usr/lib/x86_64-linux-gnu/  NO_DEFAULT_PATH)
find_library(TSS2_TCTI_DEVICE NAMES libtss2-tcti-device.a tss2-tcti-device PATHS /usr/local/lib /usr/lib /usr/lib/x86_64-linux-gnu/  NO_DEFAULT_PATH)
find_library(TSS2_RC NAMES libtss2-rc.a tss2-rc PATHS /usr/local/lib /usr/lib /usr/lib/x86_64-linux-gnu/  NO_DEFAULT_PATH)

set(TSS2_LIBRARIES ${TSS2_ESYS} ${TSS2_SYS} ${TSS2_MU} ${TSS2_TCTI_DEVICE} dl ${TSS2_RC})

set(TSS2_INCLUDE_DIRS ${TSS2_INCLUDE_DIR})

include_directories(${TSS2_INCLUDE_DIRS} ../)

set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

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

include_directories("../SecretsProvisioningSample/")
file(GLOB SOURCES "*.cpp" "../SecretsProvisioningSample/SecretsProvisioningSample.cpp")


add_executable(${CMAKE_PROJECT_TARGET} ${SOURCES})
target_link_libraries(${CMAKE_PROJECT_TARGET} ${TSS2_LIBRARIES})
target_link_libraries(${CMAKE_PROJECT_TARGET} OpenSSL::Crypto)
target_link_libraries(${CMAKE_PROJECT_TARGET} ${SSL_LIB})
# Link the test executable with Google Test and our library
target_link_libraries(${CMAKE_PROJECT_TARGET} 
   GTest::gtest_main
   GTest::gmock_main
)
target_link_libraries(${CMAKE_PROJECT_TARGET} pthread)
target_link_libraries(${CMAKE_PROJECT_TARGET} SecretsProvisioningLibrary)
target_link_libraries(${CMAKE_PROJECT_TARGET} dl)
target_link_libraries(${CMAKE_PROJECT_TARGET} tss2-mu)
set_property(TARGET ${CMAKE_PROJECT_TARGET} PROPERTY POSITION_INDEPENDENT_CODE ON)