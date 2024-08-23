//-------------------------------------------------------------------------------------------------
// <copyright file="TpmCertOperations.cpp" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#include <string>
#include <cstring>
#include <json/json.h>
#include <chrono>
#include <thread>
#include <math.h>
#include <fstream>
#include <iostream>
#include <unordered_map>
#include <stdio.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <regex>
#include "Logging.h"
#include "Tpm.h"
#include "AttestationHelper.h"
#include "AttestationLibUtils.h"
#include "ImdsClient.h"
#include "AttestationLibTelemetry.h"
#include "Exceptions.h"
#include "TpmCertOperations.h"
using namespace attest;

#define AK_CERT_RENEWAL_THRESHOLD -90
#define QUERY_RENEWED_CERT_AFTER_SECONDS 60

constexpr char CERTIFICATE_HEADER[] = "-----BEGIN CERTIFICATE-----\n";
constexpr char CERTIFICATE_FOOTER[] = "\n-----END CERTIFICATE-----";
constexpr char ak_renew_sync_api_version[] = "2023-07-01";
constexpr char ak_renew_async_api_version[] = "2021-12-01";

AttestationResult TpmCertOperations::IsAkCertRenewalRequired(bool& is_ak_renewal_required) {
	AttestationResult result = AttestationResult(AttestationResult::ErrorCode::SUCCESS);
	try {
		std::string ak_cert;
		if ((result = ReadAkCertFromTpm(ak_cert)).code_ != AttestationResult::ErrorCode::SUCCESS) {
			return result;
		}

		size_t ak_cert_len = ak_cert.length();
		BIO* cert_bio = BIO_new(BIO_s_mem());
		BIO_write(cert_bio, ak_cert.c_str(), ak_cert_len);
		X509* ak_cert_x509 = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
		if (!ak_cert_x509) {
			CLIENT_LOG_ERROR("Unable to parse AK cert in memory");
			if(telemetry_reporting.get() != nullptr) {
        		telemetry_reporting->UpdateEvent("AkRenew", 
													"Unable to parse Ak Cert in memory", 
													TelemetryReportingBase::EventLevel::AK_RENEW_CERT_PARSING_FAILURE);
			}
			
			result.code_ = AttestationResult::ErrorCode::ERROR_AK_CERT_PARSING;
			result.description_ = "Failed to pass Ak cert in memory";
			return result;
		}

		if ((result = IsAkCertProvisioned(ak_cert_x509)).code_ != AttestationResult::ErrorCode::SUCCESS) {
			return result;
		}

		ASN1_TIME* not_after = X509_get_notAfter(ak_cert_x509);
		int diff_days = 0;
		if (!ASN1_TIME_diff(&diff_days, NULL, not_after, NULL)) {
			CLIENT_LOG_ERROR("ASN1_TIME_diff() failed while checking notAfter time.");
			if(telemetry_reporting.get() != nullptr) {
        		telemetry_reporting->UpdateEvent("AkRenew", 
													"Failed while checking notAfter time",
													TelemetryReportingBase::EventLevel::AK_RENEW_CERT_EXPIRY_CALCULATION_FAILURE);
			}

			result.code_ = AttestationResult::ErrorCode::ERROR_AK_CERT_PARSING;
			result.description_ = "Failed while checking Ak Cert validity";
			return result;
		}

		BIO_free(cert_bio);
		X509_free(ak_cert_x509);
		CLIENT_LOG_INFO("Number of days left in AK cert expiry - %d", diff_days);
		if(telemetry_reporting.get() != nullptr) {
        	telemetry_reporting->UpdateEvent("AkRenew", 
												std::to_string(-1*diff_days), 
												TelemetryReportingBase::EventLevel::AK_RENEW_CERT_DAYS_TILL_EXPIRY);
		}

		// Check if the certificate has already expired or is going to expire within next 90 days
		// If yes, return true
		if (diff_days >= AK_CERT_RENEWAL_THRESHOLD) {
			is_ak_renewal_required = true;
			return result;
		}
	}
	catch (const std::exception& e) {
		CLIENT_LOG_ERROR("Unexpected error occured in IsAkCertRenewalRequired method %s", e.what());
		if(telemetry_reporting.get() != nullptr) {
        	telemetry_reporting->UpdateEvent("AkRenew",
												"Unexpected Error in renewing AkCert",
												TelemetryReportingBase::EventLevel::AK_RENEW_UNEXPECTED_ERROR);
		}

		result.code_ = AttestationResult::ErrorCode::ERROR_AK_CERT_RENEW;
		result.description_ = e.what();
	}

	return result;
}

AttestationResult TpmCertOperations::RenewAndReplaceAkCert() {
	AttestationResult result = AttestationResult(AttestationResult::ErrorCode::SUCCESS);

	try {
		ImdsClient imds;
		std::string vm_id = imds.GetVmId();
		if (vm_id.empty()) {
			CLIENT_LOG_ERROR("Failed to get vm id");
			if(telemetry_reporting.get() != nullptr) {
        		telemetry_reporting->UpdateEvent("AkRenew", 
													"Failed to get vm id", 
													TelemetryReportingBase::EventLevel::AK_RENEW_EMPTY_VM_ID);
			}

			result.code_ = AttestationResult::ErrorCode::ERROR_AK_CERT_RENEW;
			result.description_ = "Failed to get VM id from IMDS";
			return result;
		}

		Tpm tpm;
		std::string request_id = attest::utils::Uuid();
		std::string ak_cert;
		if ((result = ReadAkCertFromTpm(ak_cert)).code_ != AttestationResult::ErrorCode::SUCCESS) {
			CLIENT_LOG_ERROR("Failed to read AK Cert from TPM");
			return result;
		}

		std::string ak_cert_renew_response = imds.RenewAkCert(ak_cert, vm_id, request_id, ak_renew_sync_api_version);
		if (telemetry_reporting.get() != nullptr) {
			telemetry_reporting->UpdateEvent("AkRenew",
												ak_cert_renew_response, TelemetryReportingBase::EventLevel::AK_RENEW_RESPONSE);
		}

		std::string renewed_cert = std::string();
		if (!ak_cert_renew_response.empty()) {
			if (telemetry_reporting.get() != nullptr) {
				telemetry_reporting->UpdateEvent("AkRenew",
												"Successfully retrived AkCert response from Thim",
												TelemetryReportingBase::EventLevel::AK_RENEW_GET_RESPONSE_SUCCESS);
			}
		
			renewed_cert = ParseAndGetAkCert(ak_cert_renew_response);
		
			if (renewed_cert.empty()) {
				CLIENT_LOG_ERROR("Failed to get AkCertPem from response.");
				if (telemetry_reporting.get() != nullptr) {
					telemetry_reporting->UpdateEvent("AkRenew", 
													"Failed to get AkCertPem from response", 
													TelemetryReportingBase::EventLevel::AK_RENEW_RESPONSE_PARSING_FAILURE);
				}
				result.code_ = AttestationResult::ErrorCode::ERROR_AK_CERT_RENEW;
				result.description_ = "Failed to get AkCert Pem from response";
				return result;
			}

		} else {
			CLIENT_LOG_ERROR("Failed to renew Ak cert using sync api");
			if(telemetry_reporting.get() != nullptr) {
        		telemetry_reporting->UpdateEvent("AkRenew", 
													"Failed to renew Ak Cert using sync api", 
													TelemetryReportingBase::EventLevel::AK_RENEW_EMPTY_CERT_RESPONSE);
			}

			CLIENT_LOG_INFO("Retrying Ak renew using async api");
			request_id = attest::utils::Uuid();
			ak_cert_renew_response = imds.RenewAkCert(ak_cert, vm_id, request_id, ak_renew_async_api_version);

			// sleep for 60 seconds
			std::this_thread::sleep_for(std::chrono::seconds(QUERY_RENEWED_CERT_AFTER_SECONDS));
			request_id = attest::utils::Uuid();
			renewed_cert = imds.QueryAkCert(ak_cert_renew_response, vm_id, request_id);
			if (renewed_cert.empty()) {
				CLIENT_LOG_INFO("Failed to query Ak cert using async api");
				if(telemetry_reporting.get() != nullptr) {
        			telemetry_reporting->UpdateEvent("AkRenew", 
														"Failed to query Ak Cert using async api", 
														TelemetryReportingBase::EventLevel::AK_RENEW_EMPTY_RENEWED_CERT);
				}
				
				result.code_ = AttestationResult::ErrorCode::ERROR_AK_CERT_RENEW;
				result.description_ = "Failed to query Ak cert using async api";
				return result;
			}
		}

		if (telemetry_reporting.get() != nullptr) {
			telemetry_reporting->UpdateEvent("AkRenew", 
											renewed_cert, 
											TelemetryReportingBase::EventLevel::AK_RENEWED_CERT);
		}

		// write renewed cert to TPM
		std::vector<unsigned char> cert_der = attest::base64::base64_to_binary(
			RemoveCertHeaderAndFooter(renewed_cert));
		tpm.WriteAikCert(cert_der);
		CLIENT_LOG_INFO("Successfully renewed AK cert");
		if(telemetry_reporting.get() != nullptr) {
        	telemetry_reporting->UpdateEvent("AkRenew", 
												"Successfully renewed Ak Cert", 
												TelemetryReportingBase::EventLevel::AK_RENEW_SUCCESS);
		}
	}
	catch (const std::exception& e) {
		CLIENT_LOG_ERROR("Unexpected error occured in RenewAndReplaceAkCert method %s", e.what());
		if(telemetry_reporting.get() != nullptr) {
        	telemetry_reporting->UpdateEvent("AkRenew", 
												"Unexpted Error in RenewAndReplaceAkCert", 
												TelemetryReportingBase::EventLevel::AK_RENEW_UNEXPECTED_ERROR);
		}
		
		result.code_ = AttestationResult::ErrorCode::ERROR_AK_CERT_RENEW;
		result.description_ = "Unexpected erropr in RenewAndReplaceAkCert";
	}

	return result;
}

AttestationResult TpmCertOperations::ReadAkCertFromTpm(std::string& ak_cert) {
	AttestationResult result = AttestationResult(AttestationResult::ErrorCode::SUCCESS);

	try {
		Tpm tpm;
		ak_cert = std::string(CERTIFICATE_HEADER)  + 
			attest::base64::binary_to_base64(tpm.GetAIKCert()) + 
			std::string(CERTIFICATE_FOOTER);
		
		if (telemetry_reporting.get() != nullptr) {
			telemetry_reporting->UpdateEvent("AkRenew",
												"Successfully fetched the Ak Cert from TPM",
												TelemetryReportingBase::EventLevel::TPM_CERT_OPS);
		}

		CLIENT_LOG_INFO("Successfully fetched the AK cert from TPM");
		return result;
	} catch (const Tss2Exception& e) {
		CLIENT_LOG_ERROR("Exception while reading the certificate from TPM: %s", e.what());
		result.code_ = AttestationResult::ErrorCode::ERROR_TPM_OPERATION_FAILURE;
		result.tpm_error_code_ = e.get_rc();
		result.description_ = std::string(e.what());
	} catch (const std::exception& e) {
		CLIENT_LOG_ERROR("Unknown Exception while reading the certificate from TPM: %s", e.what());
		result.code_ = AttestationResult::ErrorCode::ERROR_TPM_INTERNAL_FAILURE;
		result.description_ = std::string(e.what());
	}

	// report failure in telemetry.
	if (telemetry_reporting.get() != nullptr) {
		telemetry_reporting->UpdateEvent("AkRenew", 
										"Failed to read Ak cert from TPM with error: " + result.description_, 
										TelemetryReportingBase::EventLevel::TPM_CERT_OPS);
	}

	return result;
}

std::string TpmCertOperations::RemoveCertHeaderAndFooter(const std::string& pem_cert) {
	std::string cert;
	if (pem_cert.empty()) {
		return cert;
	}

	cert = std::regex_replace(pem_cert, std::regex("\r"), "");
	cert = std::regex_replace(cert, std::regex(std::string(CERTIFICATE_HEADER)), "");
	cert = std::regex_replace(cert, std::regex(std::string(CERTIFICATE_FOOTER)), "");
	cert = std::regex_replace(cert, std::regex("\n"), "");
	return cert;
}

AttestationResult TpmCertOperations::IsAkCertProvisioned(X509* ak_cert_x509) {
	
	constexpr char Trusted_VM_CERT_ISSUER_NAME_PREFIX[] = "/CN=MICROSOFT AZURE TRUSTED VM RSA";
	AttestationResult result = AttestationResult(AttestationResult::ErrorCode::SUCCESS);

	const char* cert_issuer_name = X509_NAME_oneline(X509_get_issuer_name(ak_cert_x509), 0, 0);
	std::string s_cert_issuer_name = std::string(cert_issuer_name);
	CLIENT_LOG_INFO("Ak Cert issuer name %s", s_cert_issuer_name.c_str());
	if (telemetry_reporting.get() != nullptr) {
        telemetry_reporting->UpdateEvent("AkCertProvisioning", 
													s_cert_issuer_name, 
													TelemetryReportingBase::EventLevel::AK_CERT_GET_ISSUER);
	}

	const char* cert_subject_name = X509_NAME_oneline(X509_get_subject_name(ak_cert_x509), 0, 0);
	std::string s_cert_subject_name = std::string(cert_subject_name);
	CLIENT_LOG_INFO("Ak Cert subject name %s", s_cert_subject_name.c_str());
	if (telemetry_reporting.get() != nullptr) {
        telemetry_reporting->UpdateEvent("AkCertProvisioning", 
													s_cert_subject_name, 
													TelemetryReportingBase::EventLevel::AK_CERT_GET_SUBJECT);
	}

	unsigned char ak_cert_thumbprint[SHA256_DIGEST_LENGTH];
	if (X509_digest(ak_cert_x509, EVP_sha256(), ak_cert_thumbprint, NULL) != 1) {
    	CLIENT_LOG_ERROR("X509_Digest() failed while calculating thumbprint");
		if(telemetry_reporting.get() != nullptr) {
        	telemetry_reporting->UpdateEvent("AkCertProvisioning", 
												"Failed while calculating thumbprint",
												TelemetryReportingBase::EventLevel::AK_CERT_PARSING_FAILURE);
		}
	}

	std::string s_ak_cert_thumbprint = attest::base64::binary_to_base64(std::vector<unsigned char>(ak_cert_thumbprint, ak_cert_thumbprint + sizeof(ak_cert_thumbprint)/sizeof(unsigned char))).c_str();
	if (telemetry_reporting.get() != nullptr) {
        telemetry_reporting->UpdateEvent("AkCertProvisioning", 
													s_ak_cert_thumbprint, 
													TelemetryReportingBase::EventLevel::AK_CERT_GET_THUMBPRINT);
	}

	std::string ak_pub;
	if ((result = ReadAikPubFromTpm(ak_pub)).code_ != AttestationResult::ErrorCode::SUCCESS) {
		if (telemetry_reporting.get()!= nullptr){
			telemetry_reporting->UpdateEvent("AkCertProvisioning",
												"Failed while reading AkPub" + result.description_,
												TelemetryReportingBase::EventLevel::AK_GET_PUB);
		}
	}

	if (telemetry_reporting.get() != nullptr) {
		telemetry_reporting->UpdateEvent("AkCertProvisioning", 
											ak_pub, 
											TelemetryReportingBase::EventLevel::AK_GET_PUB);
	}

	if (s_cert_issuer_name.find(std::string(Trusted_VM_CERT_ISSUER_NAME_PREFIX)) != std::string::npos) {
		result.code_ = AttestationResult::ErrorCode::ERROR_AK_CERT_PROVISIONING_FAILED;
		result.description_ = "AkCert provisioning failed";
		return result;
	}

	return result;
}

AttestationResult TpmCertOperations::ReadAikPubFromTpm(std::string& ak_pub) {
	AttestationResult result= AttestationResult(AttestationResult::ErrorCode::SUCCESS);
	try{
		Tpm tpm;
		
		Buffer aik_pub = tpm.GetAIKPub();
		CLIENT_LOG_INFO("Successfully fetched Aikpub from Tpm");

		ak_pub = base64::binary_to_base64(aik_pub);
		return result;
	} catch (const Tss2Exception& e) {
		CLIENT_LOG_ERROR("Exception while reading the Ak Pub from TPM: %s", e.what());
		result.code_ = AttestationResult::ErrorCode::ERROR_TPM_OPERATION_FAILURE;
		result.tpm_error_code_ = e.get_rc();
		result.description_ = e.what();
	} catch (const std::exception& e) {
		CLIENT_LOG_ERROR("UnknownException while reading the Ak Pub from TPM: %s", e.what());
		result.code_ = AttestationResult::ErrorCode::ERROR_TPM_INTERNAL_FAILURE;
		result.description_ = e.what();
	}

	if (telemetry_reporting.get() != nullptr) {
		CLIENT_LOG_ERROR("Failed to read Ak pub from Tpm: %s", result.description_.c_str());
		telemetry_reporting->UpdateEvent("TpmCertOperations", 
										"Failed to read Ak Pub from Tpm" + result.description_, 
										TelemetryReportingBase::EventLevel::TPM_CERT_OPS);
	}

	return result;
}


std::string TpmCertOperations::ParseAndGetAkCert(const std::string& json_response) {
	Json::Value json_obj;
	Json::Reader reader;
	bool success = reader.parse(json_response.c_str(), json_obj);
	if (!success) {
		return std::string();
	}
	
	std::string ak_cert = json_obj.get(JSON_AK_CERT_PEM, "").asString();
	std::string cert_query_id = json_obj.get(JSON_AK_CERT_QUERY_ID, "").asString();
	
	CLIENT_LOG_INFO("AK Cert Query guid: %s", cert_query_id.c_str());
	CLIENT_LOG_INFO("Renewed Ak Cert: %s", ak_cert.c_str());
	if (!cert_query_id.empty()) {
		if (telemetry_reporting.get() != nullptr) {
			telemetry_reporting->UpdateEvent("AkRenew", 
											cert_query_id, 
											TelemetryReportingBase::EventLevel::AK_CERT_QUERY_GUID);
		}
	}

	return ak_cert;
}
