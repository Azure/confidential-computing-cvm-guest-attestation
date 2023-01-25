/*++

Copyright (c) 2014  Microsoft Corporation

Module Name:

    vbsvmcrypto.h

Abstract:

    Contains type definitions used by the crypto and attesation in Isolated VM.

Author:

    Jingbo Wu (jingbowu) 17-April-2018 - Created

Revision History:

--*/

/*
History: 
    This header file is copied from the below NuGet version published by the cosine team
    NuGet Version: microsoft.windows.igvmagent.amd64fre.10.0.25114.1000-220505-1700.rs-onecore-base2-hyp.nupkg
*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(push)
#pragma pack(1)

//
// Hashing algorithm ID to use for SK Secure Signing using IDK_S
// The value used is CALG_SHA_256 = (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_256).
// (Copied from VSM_SK_SECURE_SIGNING_HASH_ALG_SHA_256)
//
#define SVC_VSM_SK_SECURE_SIGNING_HASH_ALG_SHA_256 (32780)

#define VBS_VM_REPORT_PKG_HEADER_VERSION_CURRENT (1)
#define VBS_VM_REPORT_SIGNATURE_SCHEME_SHA256_RSA_PSS_SHA256 (1)

//
// VBS Report package header
//

typedef struct VBS_VM_REPORT_PKG_HEADER
{
    uint32_t PackageSize;
    uint32_t Version;
    uint32_t SignatureScheme;
    uint32_t SignatureSize;
    uint32_t Reserved;

} VBS_VM_REPORT_PKG_HEADER;

//
// VBS Report body
//

#define VBS_VM_IDENTITY_SVN_CURRENT (1)
#define VBS_VM_SHA256_SIZE (32)
#define VBS_VM_HOST_DATA_SIZE (32)

typedef struct _VBS_VM_IDENTITY
{
    //
    // Owner ID is the runtime ID assigned to VBS VM when the instance is created.
    // It is an input parameter when VM is created.
    //
    uint8_t OwnerId[VBS_VM_SHA256_SIZE];

    //
    // Measurement is the hash of VBS VM (memory pages, VP, page tables etc.).
    //
    uint8_t Measurement[VBS_VM_SHA256_SIZE];

    //
    // The value of the signer measurement (SHA256 of Signer RSA key pub).
    // V1 VBS VM only supports Windows signed binaries.
    //
    uint8_t Signer[VBS_VM_SHA256_SIZE];

    //
    // Data passed by the host on VM creation.
    //
    uint8_t HostData[VBS_VM_HOST_DATA_SIZE];

    //
    // SVN of VBS VM platform isolation support, which including SK extention and
    // hypervisor to support VM isolation.
    //
    uint32_t PlatformIsolationSvn;

    //
    // SVN of secure kernel.
    //
    uint32_t SecureKernelSvn;

    //
    // SVN of VBS platform boot chain.
    //
    uint32_t PlatformBootChainSvn;

    //
    // The guest VTL level that CreateReport called from.
    //
    uint32_t GuestVtl;

    uint8_t Reserved2[32];

} VBS_VM_IDENTITY;

#define VBS_VM_LENGTH_16 (16)
#define VBS_VM_FLAG_DEBUG_ENABLED         (0x00000001)

//
// VBS VM Module description.
//
typedef struct _VBS_VM_MODULE
{
    uint8_t ImageHash[VBS_VM_SHA256_SIZE];

    //
    // The value of the signer measurement (SHA256 of Signer RSA key pub).
    // V1 VBS VM supports sigStruct signing rather than individual image signing.
    //
    uint8_t Signer[VBS_VM_SHA256_SIZE];

    //
    // User configured data when image is compiled. {ImageId, FamilyId} represents product ID.
    //
    uint8_t FamilyId[VBS_VM_LENGTH_16];
    uint8_t ImageId[VBS_VM_LENGTH_16];

    //
    // VBS VM security attributes that describe the runtime policy. For example, debug policy.
    //
    uint32_t Attributes;

    //
    // VBS VM module security version.
    //
    uint32_t Svn;

    //
    // The VTL where the root module runs.
    //
    uint32_t Vtl;

    uint8_t Reserved[32];

} VBS_VM_MODULE;

#define VBS_VM_REPORT_VERSION_CURRENT (1)
#define VBS_VM_REPORT_DATA_LENGTH (64)
#define VBS_VM_NUMBER_OF_MODULES  (2)
#define VBS_VM_MAX_SIGNATURE_SIZE (256)
typedef struct _VBS_VM_REPORT
{
    VBS_VM_REPORT_PKG_HEADER Header;

    uint32_t Version;

    uint8_t ReportData[VBS_VM_REPORT_DATA_LENGTH];

    // The identity conatins the module information and VBS platform security
    // properties.
    VBS_VM_IDENTITY Identity;

    VBS_VM_MODULE Modules[VBS_VM_NUMBER_OF_MODULES];
    uint8_t Signature[VBS_VM_MAX_SIGNATURE_SIZE];

} VBS_VM_REPORT;

//
// AMD SEV-SNP Report (per spec).
//
typedef struct _SNP_SIGNATURE
{
    uint8_t RComponent[72];
    uint8_t SComponent[72];
    uint8_t RSVD[368];
} SNP_SIGNATURE;

typedef struct _SNP_SVN
{
    uint64_t BootLoaderSvn:8;
    uint64_t TeeSvn:8;
    uint64_t Rsvd:32;
    uint64_t SnpFwSvn:8;
    uint64_t MicrocodeSvn:8;
} SNP_SVN;

#define SNP_ATTESTATION_VERSION (1)
#define SNP_VMPL_HCL (0)
#define SNP_SIGNATURE_ALGO (0x102) // ECDSA P-384 with SHA-384
#define SNP_REPORT_DATA_LENGTH (64)
typedef struct _SNP_VM_REPORT
{
    uint32_t SnpVersion;
    uint32_t SnpGuestSvn;
    union {
        uint64_t Asuint64_t;
        struct {
            uint64_t AbiMinor:8;
            uint64_t AbiMajor:8;
            uint64_t SmtAllowed:1;
            uint64_t RsvdTrue:1;
            uint64_t MigrateMaAllowed:1;
            uint64_t DebugAllowed:1;
            uint64_t RsvdFalse:44;
        } u;
    } SnpPolicy;
    uint8_t  SnpFamilyId[16];
    uint8_t  SnpImageId[16];
    uint32_t SnpVMPL;
    uint32_t SnpSignatureAlgo;
    uint64_t SnpPlatformVersion;
    union {
        uint64_t Asuint64_t;
        struct {
            uint64_t SmtEnabled:1;
            uint64_t TsmeEnabled:1;
            uint64_t Rsvd:62;
        } u;
    } SnpPlatformInfo;
    union {
        uint32_t Asuint32_t;
        struct {
            uint32_t AuthorKeyEnabled:1;
            uint32_t Rsvd:31;
        } u;
    } SnpReportFlags;
    uint32_t SnpReserved1;
    // Payload includes 512 bits of user data,
    // which is used to carry a SHA256 hash of a larger buffer
    uint8_t  SnpReportData[SNP_REPORT_DATA_LENGTH];
    uint8_t  SnpMeasurement[48];
    uint8_t  SnpHostData[32];
    uint8_t  SnpIdKeyDigest[48];
    uint8_t  SnpAuthorKeyDigest[48];
    uint8_t  SnpReportId[32];
    uint8_t  SnpReportIdMa[32];
    union {
        uint64_t Asuint64_t;
        SNP_SVN Svn;
    } SnpReportedTcb;
    uint8_t  SnpReserved2[24];
    uint8_t  SnpChipId[64];
    union {
        uint64_t Asuint64_t;
        SNP_SVN Svn;
    } SnpCommittedSvn;
    uint64_t SnpCommittedVersion;
    union {
        uint64_t Asuint64_t;
        SNP_SVN Svn;
    } SnpLaunchSvn;
    uint8_t  SnpReserved3[168];
    SNP_SIGNATURE  SnpSignature;
} SNP_VM_REPORT;

//
// Union of different signed isolation reports.
//
typedef struct _HW_ATTESTATION
{
    union
    {
        SNP_VM_REPORT SnpReport; // SnpReportData holds hash of HclData
        VBS_VM_REPORT VbsReport; // ReportData holds hash of HclData
    } Report;
} HW_ATTESTATION;

//
// Extended data the HCL will provided, hashed in signed report.
//

// Report Type
typedef enum _IGVM_REPORT_TYPE
{
    InvalidReport = 0,
    VbsVmReport,
    SnpVmReport,
    TvmReport
} IGVM_REPORT_TYPE, *PIGVM_REPORT_TYPE;

// Request type
typedef enum _IGVM_REQUEST_TYPE
{
    InvalidRequest = 0,
    KeyReleaseRequest,
    AkCertRequest
} IGVM_REQUEST_TYPE, *PIGVM_REQUEST_TYPE;

// Hash algorithm used for content of Report Data
typedef enum _IGVM_HASH_TYPE
{
    InvalidHash = 0,
    Sha256Hash,
    Sha384Hash,
    Sha512Hash
} IGVM_HASH_TYPE, *PIGVM_HASH_TYPE;

#define IGVM_ATTEST_VERSION_CURRENT  (1)

//
// User data, used for host attestation requests.
//
typedef struct _IGVM_REQUEST_DATA
{
    // Overall size of payload.
    uint32_t DataSize;

    // Version of this structure, currently IGVM_ATTEST_VERSION_CURRENT (1).
    uint32_t Version;

    // The type of isolation that generated this report.
    IGVM_REPORT_TYPE ReportType;

    // The hash used in Report Data.
    IGVM_HASH_TYPE ReportDataHashType;

    // Size of data blob.
    uint32_t VariableDataSize;

    // Data holds AkPub or Transport Key.
    uint8_t VariableData[];
} IGVM_REQUEST_DATA;

#define ATTESTATION_SIGNATURE 0x414C4348 // HCLA
#define ATTESTATION_VERSION (1)

//
// Unmeasured data used to provide transport sanity and versioning.
//
typedef struct _ATTESTATION_HEADER
{
    uint32_t Signature;
    uint32_t Version;
    uint32_t ReportSize;
    IGVM_REQUEST_TYPE RequestType;
    uint32_t Reserved[4];
} ATTESTATION_HEADER;

//
// Attestation report delivered to host attestation agent.
//
typedef struct _ATTESTATION_REPORT
{
    ATTESTATION_HEADER Header; // Not measured
    HW_ATTESTATION HwReport; // Signed report
    IGVM_REQUEST_DATA HclData; // HCL sourced data
} ATTESTATION_REPORT;


#define VBS_VM_AES_GCM_KEY_LENGTH 32

//
// Attestation response structures.
//

//
// Definitions for key release request.
//
#define IGVM_KEY_MESSAGE_HEADER_VERSION_1 (1)

typedef struct _IGVM_KEY_MESSAGE_HEADER
{
    uint32_t DataSize;
    uint32_t Version;
    uint8_t Payload[];
} IGVM_KEY_MESSAGE_HEADER;


//
// Definitions for certificate request.
//

#define IGVM_CERT_MESSAGE_HEADER_VERSION_1 (1)

typedef struct _IGVM_CERT_MESSAGE_HEADER
{
    uint32_t DataSize;
    uint32_t Version;
    uint8_t Payload[];

} IGVM_CERT_MESSAGE_HEADER;

#pragma pack(pop)

#ifdef __cplusplus
}
#endif

