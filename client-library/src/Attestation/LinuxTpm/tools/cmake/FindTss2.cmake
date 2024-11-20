# Try to find Tss2
find_path(TSS2_INCLUDE_DIR NAMES tss2 PATHS /usr/local/attestationtpm2-tss/include NO_DEFAULT_PATH)

# Invalidate cache to force cmake to lookup the libraries again
set (TSS2_ESYS TSS2_ESYS-NOTFOUND)
set (TSS2_SYS TSS2_SYS-NOTFOUND)
set (TSS2_MU TSS2_MU-NOTFOUND)
set (TSS2_TCTI_DEVICE TSS2_TCTI_DEVICE-NOTFOUND)

find_library(TSS2_ESYS names libtss2-esys.a tss2-esys PATHS /usr/local/attestationtpm2-tss/lib NO_DEFAULT_PATH)
find_library(TSS2_SYS names libtss2-sys.a tss2-sys PATHS /usr/local/attestationtpm2-tss/lib NO_DEFAULT_PATH)
find_library(TSS2_MU NAMES libtss2-mu.a tss2-mu PATHS /usr/local/attestationtpm2-tss/lib NO_DEFAULT_PATH)
find_library(TSS2_TCTI_DEVICE NAMES libtss2-tcti-device.a tss2-tcti-device PATHS /usr/local/attestationtpm2-tss/lib NO_DEFAULT_PATH)

set(TSS2_LIBRARIES ${TSS2_ESYS} ${TSS2_SYS} ${TSS2_MU} ${TSS2_TCTI_DEVICE} gcrypt dl TssStaticShim)

set(TSS2_INCLUDE_DIRS ${TSS2_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(TSS2 DEFAULT_MSG TSS2_ESYS TSS2_SYS TSS2_MU TSS2_TCTI_DEVICE TSS2_INCLUDE_DIR)
