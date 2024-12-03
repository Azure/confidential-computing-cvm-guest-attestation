# Try to find GTest
find_path(GTEST_INCLUDE_DIR NAMES gtest PATHS ${SYSTEM_LIBRARY_PREFIX}/usr/local/include ${SYSTEM_LIBRARY_PREFIX}/usr/include)

find_library(GTEST_LIBRARY NAMES libgtest gtest PATHS ${SYSTEM_LIBRARY_PREFIX}/usr/local/lib ${SYSTEM_LIBRARY_PREFIX}/usr/lib)
find_library(GTEST_MAIN_LIBRARY NAMES libgtest_main gtest_main PATHS ${SYSTEM_LIBRARY_PREFIX}/usr/local/lib ${SYSTEM_LIBRARY_PREFIX}/usr/lib)

set(GTEST_LIBRARIES ${GTEST_LIBRARY} ${GTEST_MAIN_LIBRARY})
set(GTEST_INCLUDE_DIRS ${GTEST_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(GTEST DEFAULT_MSG GTEST_LIBRARY GTEST_MAIN_LIBRARY GTEST_INCLUDE_DIR)
