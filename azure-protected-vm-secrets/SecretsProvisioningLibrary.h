// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

/*
* Function to unprotect a secret using the JWT token
* @param jwt: The JWT token
* @param jwtlen: The length of the JWT token
* @param output_secret: The output secret. This is a pointer to a char array that will be allocated by the function.
* @return: The length of the output secret. If the function fails, it will return a negative number.
*/
#ifdef __cplusplus
extern "C" {
#endif // __cplusplus
#ifdef DYNAMICSECRETSPROVISIONINGLIBRARY_EXPORTS
__declspec( dllexport )
#endif // DYNAMICSECRETSPROVISIONINGLIBRARY_EXPORTS
    long unprotect_secret(char* jwt, unsigned int jwtlen, unsigned int policy, char** output_secret, unsigned int* eval_policy);
#ifdef DYNAMICSECRETSPROVISIONINGLIBRARY_EXPORTS
__declspec( dllexport )
#endif // DYNAMICSECRETSPROVISIONINGLIBRARY_EXPORTS
    long unprotect_secret_wide(wchar_t* jwt, unsigned int jwtlen, unsigned int policy, wchar_t** output_secret, unsigned int* eval_policy);
#ifdef DYNAMICSECRETSPROVISIONINGLIBRARY_EXPORTS
__declspec(dllexport)
#endif // DYNAMICSECRETSPROVISIONINGLIBRARY_EXPORTS
    void free_secret(char* secret);
#ifdef DYNAMICSECRETSPROVISIONINGLIBRARY_EXPORTS
__declspec(dllexport)
#endif // DYNAMICSECRETSPROVISIONINGLIBRARY_EXPORTS
    void free_secret_wide(wchar_t* secret);
#ifdef DYNAMICSECRETSPROVISIONINGLIBRARY_EXPORTS
__declspec(dllexport)
#endif // DYNAMICSECRETSPROVISIONINGLIBRARY_EXPORTS
const char* get_error_message(long error_code);
#ifdef __cplusplus
}
#endif // __cplusplus