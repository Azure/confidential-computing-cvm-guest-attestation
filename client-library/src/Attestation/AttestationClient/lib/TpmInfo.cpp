//-------------------------------------------------------------------------------------------------
// <copyright file="Tpm.h" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#include "AttestationHelper.h"

#include "TpmInfo.h"
#include "AttestationLibConst.h"

namespace attest {

bool TpmInfo::Validate() const {
    //Check if any of the tpm values are not set.
    if(aik_cert_.empty() ||
       aik_pub_.empty() ||
       pcr_values_.pcrs.empty() ||
       encryption_key_.certifyInfo.empty() ||
       encryption_key_.encryptionKey.empty() ||
       encryption_key_.certifyInfoSignature.empty()) {
        return false;
    }
    return true;
}

Json::Value TpmInfo::ToJson() const {
    Json::Value tpm_info;
    std::string aik_cert_encoded = base64::binary_to_base64(aik_cert_);
    std::string aik_pub_encoded = base64::binary_to_base64(aik_pub_);
    std::string pcr_quote_encoded = base64::binary_to_base64(pcr_quote_.quote);
    std::string pcr_signature_encoded = base64::binary_to_base64(pcr_quote_.signature);
    std::string enc_key_encoded = base64::binary_to_base64(encryption_key_.encryptionKey);
    std::string enc_key_certify_info_encoded = base64::binary_to_base64(
                                                        encryption_key_.certifyInfo);
    std::string enc_key_certify_info_sig_encoded = base64::binary_to_base64(
                                                        encryption_key_.certifyInfoSignature);

    tpm_info[JSON_AIK_CERT_KEY] = aik_cert_encoded;
    tpm_info[JSON_AIK_PUB_KEY] = aik_pub_encoded;
    tpm_info[JSON_PCR_QUOTE_KEY] = pcr_quote_encoded;
    tpm_info[JSON_PCR_SIGNATURE_KEY] = pcr_signature_encoded;
    tpm_info[JSON_ENC_PUB_KEY] = enc_key_encoded;
    tpm_info[JSON_ENC_KEY_CERTIFY_INFO] = enc_key_certify_info_encoded;
    tpm_info[JSON_ENC_KEY_CERTIFY_INFO_SIGNATURE] = enc_key_certify_info_sig_encoded;

    Json::Value pcr_set(Json::arrayValue);
    Json::Value pcrs(Json::arrayValue);
    for(auto const& pcr: pcr_values_.pcrs) {
        Json::Value pcr_obj;
        pcr_obj[JSON_PCR_INDEX_KEY] = pcr.index;

        std::string digest_encoded = base64::binary_to_base64(pcr.digest);
        pcr_obj[JSON_PCR_DIGEST_KEY] = digest_encoded;
        pcr_set.append(pcr.index);
        pcrs.append(pcr_obj);
    }
    tpm_info[JSON_PCR_SET_KEY] = pcr_set;
    tpm_info[JSON_PCRS_KEY] = pcrs;
    return tpm_info;
}
}// attest
