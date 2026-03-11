#pragma once

// Version access function
#ifdef __cplusplus
extern "C" {
#endif

#ifdef DYNAMICSECRETSPROVISIONINGLIBRARY_EXPORTS
__declspec(dllexport)
#endif
const char* secrets_library_version();

#ifdef __cplusplus
}
#endif