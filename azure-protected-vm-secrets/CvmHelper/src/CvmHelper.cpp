// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Platform-portable CvmHelper: detects Hyper-V isolation type via CPUID.
// Windows uses MSVC intrinsics; Linux uses GCC/Clang __cpuid_count.

#ifdef PLATFORM_UNIX
#include <cstdint>
#include <cstring>
#else
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>
#endif

#include "../inc/CvmHelper.h"

// --- CPUID abstraction ---------------------------------------------------
#ifdef UNIT_TEST
    extern "C" void test_cpuid(int cpuInfo[4], int leaf);
    #define CPUID(info, leaf) test_cpuid(info, leaf)
#elif defined(PLATFORM_UNIX)
    #include <cpuid.h>
    static inline void linux_cpuid(int cpuInfo[4], int leaf)
    {
        unsigned int eax, ebx, ecx, edx;
        __cpuid_count(leaf, 0, eax, ebx, ecx, edx);
        cpuInfo[0] = static_cast<int>(eax);
        cpuInfo[1] = static_cast<int>(ebx);
        cpuInfo[2] = static_cast<int>(ecx);
        cpuInfo[3] = static_cast<int>(edx);
    }
    #define CPUID(info, leaf) linux_cpuid(info, leaf)
#else
    #define CPUID(info, leaf) __cpuid(info, leaf)
#endif

// --- Portable integer types ----------------------------------------------
#ifdef PLATFORM_UNIX
typedef uint32_t UINT32;
typedef uint64_t UINT64;
#endif

#define CPUID_LEAF_FEATURE_INFO 0x1

// Source https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/feature-discovery
#define HV_CPUID_LEAF_HYPERVISOR_PRESENT 0x40000000
#define HV_CPUID_LEAF_HYPERVISOR_INTERFACE 0x40000001
#define HV_CPUID_LEAF_HYPERVISOR_FEATURES 0x40000003

#define HV_CPUID_LEAF_HYPERVISOR_ISOLATION_CONFIG 0x4000000C // Needs documentation

// Multi-char literal values (same encoding on x86 little-endian)
#define VENDOR_MICR 0x7263694D  // "Micr"
#define VENDOR_OSOF 0x666F736F  // "osof"
#define VENDOR_T_HV 0x76482074  // "t Hv"
#define INTERFACE_HV1 0x31237648 // "Hv#1"

#pragma pack(push, 1)

// Source
// https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/datatypes/hv_partition_privilege_mask
typedef struct
{
    // Access to virtual MSRs
    UINT64 AccessVpRunTimeReg : 1;
    UINT64 AccessPartitionReferenceCounter : 1;
    UINT64 AccessSynicRegs : 1;
    UINT64 AccessSyntheticTimerRegs : 1;
    UINT64 AccessIntrCtrlRegs : 1;
    UINT64 AccessHypercallMsrs : 1;
    UINT64 AccessVpIndex : 1;
    UINT64 AccessResetReg : 1;
    UINT64 AccessStatsReg : 1;
    UINT64 AccessPartitionReferenceTsc : 1;
    UINT64 AccessGuestIdleReg : 1;
    UINT64 AccessFrequencyRegs : 1;
    UINT64 Reserved : 1;
    UINT64 AccessReenlightenmentControls : 1;
    UINT64 Reserved1 : 18;

    // Access to hypercalls
    UINT64 CreatePartitions : 1;
    UINT64 AccessPartitionId : 1;
    UINT64 AccessMemoryPool : 1;
    UINT64 Reserved2 : 1;
    UINT64 PostMessages : 1;
    UINT64 SignalEvents : 1;
    UINT64 CreatePort : 1;
    UINT64 ConnectPort : 1;
    UINT64 AccessStats : 1;
    UINT64 Reserved3 : 2;
    UINT64 Debugging : 1;
    UINT64 CpuManagement : 1;
    UINT64 Reserved4 : 1;
    UINT64 Reserved5 : 1;
    UINT64 Reserved6 : 1;
    UINT64 AccessVSM : 1;
    UINT64 AccessVpRegisters : 1;
    UINT64 Reserved7 : 1;
    UINT64 Reserved8 : 1;
    UINT64 EnableExtendedHypercalls : 1;
    UINT64 StartVirtualProcessor : 1;
	UINT64 IsolationFeatures : 1; // Needs documentation
    UINT64 Reserved9 : 9;
} HV_PARTITION_PRIVILEGE_MASK;

typedef union {
    UINT32 AsUINT32[4];

    struct
    {
        UINT32 Eax;
        UINT32 Ebx;
        UINT32 Ecx;
        UINT32 Edx;
    };

    struct
    {
        HV_PARTITION_PRIVILEGE_MASK PartitionPrivilegeMask;
        UINT32 Reserved[2];
	} HvFeatureDiscovery;

    struct 
    {
        UINT32 MaxFunction;
        UINT32 VendorId[3];
	} HvVendorAndMaxFunction;

    struct
    {
        UINT32 VendorId;
        UINT32 Reserved[3];
    } HvVendorInterface;

    struct
    {
        UINT32 Reserved;
		UINT32 IsolationType : 4; // Needs documentation
        UINT32 Reserved1: 28;
        UINT32 Reserved2;
		UINT32 Reserved3;
	} HvIsolationType;

    struct {
        UINT32 Reserved[2];
        UINT32 Reserved1: 31;
		UINT32 Hypervisor: 1; // Bit 31 of ECX indicates hypervisor presence
		UINT32 Reserved2;
    } CpuFeatureDiscovery;
} HV_CPUID_RESULT;

#pragma pack(pop)

// Compile-time validation
static_assert(sizeof(HV_CPUID_RESULT) == 16, "HV_CPUID_RESULT must be 16 bytes for CPUID");
static_assert(sizeof(HV_PARTITION_PRIVILEGE_MASK) == 8, "HV_PARTITION_PRIVILEGE_MASK must be 8 bytes");


#ifdef __cplusplus
extern "C" {
#endif // __cplusplus
bool IsConfidentialVM(void)
{
    IsolationModeResult mode = GetIsolationMode();
    return (mode == IM_RESULT_SNP_ISOLATION || mode == IM_RESULT_TDX_ISOLATION);
}

IsolationModeResult GetIsolationMode(void)
{
	// Check for Hypervisor presence
	HV_CPUID_RESULT cpuidResult;
#ifdef PLATFORM_UNIX
	std::memset(&cpuidResult, 0, sizeof(cpuidResult));
#else
	cpuidResult = { 0 };
#endif
	UINT32 HvMaxFunction = 0;
	CPUID((int*)cpuidResult.AsUINT32, CPUID_LEAF_FEATURE_INFO);
    if (!cpuidResult.CpuFeatureDiscovery.Hypervisor)
    {
        return IM_RESULT_NO_HYPERVISOR;
	}

	CPUID((int*)cpuidResult.AsUINT32, HV_CPUID_LEAF_HYPERVISOR_PRESENT);
    if (cpuidResult.HvVendorAndMaxFunction.VendorId[0] != VENDOR_MICR ||
        cpuidResult.HvVendorAndMaxFunction.VendorId[1] != VENDOR_OSOF ||
        cpuidResult.HvVendorAndMaxFunction.VendorId[2] != VENDOR_T_HV)
    {
        return IM_RESULT_NO_HYPERV;
    }

	HvMaxFunction = cpuidResult.HvVendorAndMaxFunction.MaxFunction;

    CPUID((int*)cpuidResult.AsUINT32, HV_CPUID_LEAF_HYPERVISOR_INTERFACE);
    if (cpuidResult.HvVendorInterface.VendorId != INTERFACE_HV1)
    {
        return IM_RESULT_NO_HYPERV;
    }

	// Check for isolation presence
	CPUID((int*)cpuidResult.AsUINT32, HV_CPUID_LEAF_HYPERVISOR_FEATURES);
    if (!cpuidResult.HvFeatureDiscovery.PartitionPrivilegeMask.IsolationFeatures)
    {
        return IM_RESULT_NO_ISOLATION;
	}

    if (HvMaxFunction < HV_CPUID_LEAF_HYPERVISOR_ISOLATION_CONFIG)
    {
        return IM_RESULT_NO_ISOLATION_CONFIG;
    }

	// Check for supported isolation types
	CPUID((int*)cpuidResult.AsUINT32, HV_CPUID_LEAF_HYPERVISOR_ISOLATION_CONFIG);
    return (IsolationModeResult)cpuidResult.HvIsolationType.IsolationType;
}
#ifdef __cplusplus
}
#endif // __cplusplus
