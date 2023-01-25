//-------------------------------------------------------------------------------------------------
// <copyright file="TpmMockData.h" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#pragma once

#define MOCK_HANDLE 1

//
// EK Cert Data
//
#define MOCK_EK_CERT_PACKET_SIZE 20
#define MOCK_EK_CERT_SIZE (MOCK_EK_CERT_PACKET_SIZE*3)

//
// EK Pub/Priv Data
//
#define MOCK_TPM_PUBLIC_SIZE 10

//
// AIK Cert Data
//
#define MOCK_AIK_CERT_PACKET_SIZE 20
#define MOCK_AIK_CERT_SIZE (MOCK_AIK_CERT_PACKET_SIZE*3)

//
// SNP Report Data
//
#define MOCK_HCL_REPORT_PACKET_SIZE 20
#define MOCK_HCL_REPORT_SIZE (MOCK_HCL_REPORT_PACKET_SIZE*3)

//
// PCR Values Data
//
#define MOCK_PCRS_READ_COUNT 8
#define MOCK_MAX_PCR_COUNT (MOCK_PCRS_READ_COUNT*3)