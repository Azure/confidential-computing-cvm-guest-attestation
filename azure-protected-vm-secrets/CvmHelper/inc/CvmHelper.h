#pragma once


// These values need documentation
#define HV_ISOLATION_TYPE_NONE 0x0
#define HV_ISOLATION_TYPE_VBS  0x1
#define HV_ISOLATION_TYPE_SNP  0x2
#define HV_ISOLATION_TYPE_TDX  0x3

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef enum {
    IM_RESULT_NO_ISOLATION = HV_ISOLATION_TYPE_NONE,
    IM_RESULT_VBS_ISOLATION = HV_ISOLATION_TYPE_VBS,
    IM_RESULT_SNP_ISOLATION = HV_ISOLATION_TYPE_SNP,
    IM_RESULT_TDX_ISOLATION = HV_ISOLATION_TYPE_TDX,

    // Failure values start at 0x10 to leave room for future isolation types
    IM_RESULT_NO_HYPERVISOR = 0x10,
    IM_RESULT_NO_HYPERV = 0x11,
	IM_RESULT_NO_ISOLATION_CONFIG = 0x12
} IsolationModeResult;

#ifndef _M_X64
inline IsolationModeResult GetIsolationMode(void)
{
    return IM_RESULT_NO_ISOLATION;
}
#else
IsolationModeResult GetIsolationMode(void);
#endif

/**
 * @brief Checks if the current environment is running on a Confidential Virtual Machine (CVM).
 * 
 * This function determines whether the code is executing within an Azure Confidential VM
 * environment by checking relevant system properties and attestation capabilities.
 * 
 * @return true if running on a Confidential Virtual Machine, false otherwise
 * 
 * @note This function is exposed as a C interface for compatibility across different
 *       programming languages and can be called from both C and C++ code.
 */
#ifndef _M_X64
inline bool IsConfidentialVM(void)
{
    return false;
}
#else
bool IsConfidentialVM(void);
#endif

#ifdef __cplusplus
}
#endif // __cplusplus