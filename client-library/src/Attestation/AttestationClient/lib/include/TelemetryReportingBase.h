//-------------------------------------------------------------------------------------------------
// <copyright file="TelemetryReportingBase.h" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#pragma once
#include <string>
#include <memory.h>

namespace attest {
    class TelemetryReportingBase {
    public:
        enum class EventLevel {
            SUCCESS,
            INIT_ERROR,
            INTERNAL_ERROR,
            PLATFORM_ERROR,
            ATTESTATION_FAILURE,
            DECRYPTION_FAILURE,
            REPORT_HEALTH_FAILURE,

            // AK Renew events
            AK_RENEW_CERT_PARSING_FAILURE,
            AK_RENEW_CERT_EXPIRY_CALCULATION_FAILURE,
            AK_RENEW_CERT_DAYS_TILL_EXPIRY,
            AK_RENEW_UNEXPECTED_ERROR,
            AK_RENEW_EMPTY_VM_ID,
            AK_RENEW_EMPTY_CERT_RESPONSE,
            AK_RENEW_EMPTY_RENEWED_CERT,
            AK_RENEW_GET_RESPONSE_SUCCESS,
            AK_RENEW_SUCCESS,
            AK_RENEW_RESPONSE,
            AK_RENEW_RESPONSE_PARSING_FAILURE,
            AK_RENEW_RESPONSE_PARSING_SUCCESS,
            AK_CERT_PROVISION_FAILURE,
            AK_CERT_GET_ISSUER,
            AK_GET_PUB,
            AK_CERT_GET_SUBJECT,
            AK_CERT_PARSING_FAILURE,
            AK_CERT_GET_THUMBPRINT,
            AK_RENEWED_CERT,
            AK_CERT_QUERY_GUID,
            TPM_CERT_OPS,

            // IMDS events
            IMDS_GET_VM_ID,
            IMDS_RENEW_AK,
            IMDS_QUERY_AK,
            IMDS_QUERY_VCek_CERT,
            IMDS_RENEW_AK_URL,
            IMDS_AKRENEW_REQUEST_BODY,

            VM_SECURITY_TYPE,
            SNP_REPORT_STATUS,
            CURL_CONNECTION_FAILURE
        };

        virtual void UpdateEvent(
            const std::string& task_type,
            const std::string& message,
            const EventLevel& event_level
        ) = 0;

        virtual bool WriteEvents() = 0;
    };

    void SetTelemetryReporting (const std::shared_ptr<TelemetryReportingBase> telemetry_reporting);
}