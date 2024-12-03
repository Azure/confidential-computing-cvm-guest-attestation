# Try to find GMock
find_path(GMOCK_INCLUDE_DIR NAMES gmock PATHS ${SYSTEM_LIBRARY_PREFIX}/usr/local/include ${SYSTEM_LIBRARY_PREFIX}/usr/include)

find_library(GMOCK_LIBRARY NAMES libgmock gmock PATHS ${SYSTEM_LIBRARY_PREFIX}/usr/local/lib ${SYSTEM_LIBRARY_PREFIX}/usr/lib)
find_library(GMOCK_MAIN_LIBRARY NAMES libgmock_main gmock_main PATHS ${SYSTEM_LIBRARY_PREFIX}/usr/local/lib ${SYSTEM_LIBRARY_PREFIX}/usr/lib)

set(GMOCK_LIBRARIES ${GMOCK_LIBRARY} ${GMOCK_MAIN_LIBRARY})
set(GMOCK_INCLUDE_DIRS ${GMOCK_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(GMOCK DEFAULT_MSG GMOCK_LIBRARY GMOCK_MAIN_LIBRARY GMOCK_INCLUDE_DIR)
