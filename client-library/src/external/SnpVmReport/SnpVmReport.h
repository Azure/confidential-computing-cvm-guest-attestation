//-------------------------------------------------------------------------------------------------
// <copyright file="SnpVmReport.h" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(push)
#pragma pack(1)

//
// AMD SEV-SNP Report per spec (https://www.amd.com/en/support/tech-docs/sev-secure-nested-paging-firmware-abi-specification)
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
    } Report;
} HW_ATTESTATION;

//
// Extended data the HCL will provided, hashed in signed report.
//

// Report Type
typedef enum _IGVM_REPORT_TYPE
{
    InvalidReport = 0,
    ReservedReportType,
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