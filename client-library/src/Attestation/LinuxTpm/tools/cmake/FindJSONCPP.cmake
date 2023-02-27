# Try to find JsonCpp
find_path(JSON_INCLUDE_DIR NAMES json PATHS ${SYSTEM_LIBRARY_PREFIX}/usr/local/include/jsoncpp
                                            ${SYSTEM_LIBRARY_PREFIX}/usr/include/jsoncpp
                                            NO_DEFAULT_PATH)

find_library(JSON_LIBRARY NAMES jsoncpp libjsoncpp.a PATHS ${SYSTEM_LIBRARY_PREFIX}/usr/local/lib
                                                           ${SYSTEM_LIBRARY_PREFIX}/usr/lib
                                                           ${SYSTEM_LIBRARY_PREFIX}/usr/lib/x86_64-linux-gnu
                                                           NO_DEFAULT_PATH)

set(JSON_LIBRARY ${JSON_LIBRARY})
set(JSON_INCLUDE_DIR ${JSON_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(JSONCPP DEFAULT_MSG JSON_LIBRARY JSON_INCLUDE_DIR)
