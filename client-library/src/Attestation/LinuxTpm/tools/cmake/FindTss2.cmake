# Try to find Tss2
find_path(TSS2_INCLUDE_DIR NAMES tss2 PATHS ${SYSTEM_LIBRARY_PREFIX}/usr/local/include ${SYSTEM_LIBRARY_PREFIX}/usr/include NO_DEFAULT_PATH)

# Invalidate cache to force cmake to lookup the libraries again
set (TSS2_ESYS TSS2_ESYS-NOTFOUND)
set (TSS2_SYS TSS2_SYS-NOTFOUND)
set (TSS2_MU TSS2_MU-NOTFOUND)
set (TSS2_TCTI_DEVICE TSS2_TCTI_DEVICE-NOTFOUND)

set(TSS2_LIB_PATHS /usr/local/lib /usr/lib /usr/lib/${CMAKE_LIBRARY_ARCHITECTURE})
find_library(TSS2_ESYS names libtss2-esys.a tss2-esys PATHS ${TSS2_LIB_PATHS} NO_DEFAULT_PATH)
find_library(TSS2_SYS names libtss2-sys.a tss2-sys PATHS ${TSS2_LIB_PATHS} NO_DEFAULT_PATH)
find_library(TSS2_MU NAMES libtss2-mu.a tss2-mu PATHS ${TSS2_LIB_PATHS} NO_DEFAULT_PATH)
find_library(TSS2_TCTI_DEVICE NAMES libtss2-tcti-device.a tss2-tcti-device PATHS ${TSS2_LIB_PATHS} NO_DEFAULT_PATH)

include(FindPkgConfig)
pkg_check_modules(gcrypt REQUIRED IMPORTED_TARGET libgcrypt)
set(TSS2_LIBRARIES ${TSS2_ESYS} ${TSS2_SYS} ${TSS2_MU} ${TSS2_TCTI_DEVICE} PkgConfig::gcrypt dl TssStaticShim)

set(TSS2_INCLUDE_DIRS ${TSS2_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(TSS2 DEFAULT_MSG TSS2_ESYS TSS2_SYS TSS2_MU TSS2_TCTI_DEVICE TSS2_INCLUDE_DIR)
