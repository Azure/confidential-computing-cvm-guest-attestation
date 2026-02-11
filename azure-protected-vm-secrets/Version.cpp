#include <Version.h>

extern "C" const char* secrets_library_version() {
    return SECRETS_LIB_VERSION_STRING;
}