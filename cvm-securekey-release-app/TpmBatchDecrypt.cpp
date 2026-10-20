//-------------------------------------------------------------------------------------------------
// <copyright file="TpmBatchDecrypt.cpp" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#include "TpmBatchDecrypt.h"

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <stdexcept>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>

namespace
{
// Linux attestation PCR list (AttestationLibUtils.cpp GetAttestationPcrList): PCRs 0-7.
constexpr uint8_t AttestationPcrMask = 0xFF;
constexpr uint32_t AttestationPcrCount = 8;

std::runtime_error TssError(const char *what, TSS2_RC rc)
{
    std::ostringstream oss;
    oss << what << " failed: TSS2_RC=0x" << std::hex << rc;
    return std::runtime_error(oss.str());
}
} // namespace

struct TpmBatchDecryptor::Impl
{
    TSS2_TCTI_CONTEXT *tcti = nullptr;
    ESYS_CONTEXT *esys = nullptr;
    ESYS_TR key = ESYS_TR_NONE;
    TPML_PCR_SELECTION selection{};
    TPM2B_DIGEST pcr_digest{};
    double key_create_ms = 0;

    ~Impl()
    {
        if (esys != nullptr)
        {
            if (key != ESYS_TR_NONE)
            {
                Esys_FlushContext(esys, key);
            }
            Esys_Finalize(&esys);
        }
        if (tcti != nullptr)
        {
            Tss2_TctiLdr_Finalize(&tcti);
        }
    }

    /// Start a session of the given type and apply PolicyPCR, matching
    /// Tss2Session::Start + Tss2Session::PolicyPcr in the client library.
    ESYS_TR StartPcrPolicySession(TPM2_SE type)
    {
        TPM2B_NONCE nonce_caller{};
        nonce_caller.size = TPM2_SHA1_DIGEST_SIZE;
        TPMT_SYM_DEF symmetric{};
        symmetric.algorithm = TPM2_ALG_NULL;

        ESYS_TR session = ESYS_TR_NONE;
        TSS2_RC rc = Esys_StartAuthSession(esys, ESYS_TR_NONE, ESYS_TR_NONE,
                                           ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                           &nonce_caller, type, &symmetric,
                                           TPM2_ALG_SHA256, &session);
        if (rc != TSS2_RC_SUCCESS)
        {
            throw TssError("Esys_StartAuthSession", rc);
        }
        rc = Esys_PolicyPCR(esys, session, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                            &pcr_digest, &selection);
        if (rc != TSS2_RC_SUCCESS)
        {
            Esys_FlushContext(esys, session);
            throw TssError("Esys_PolicyPCR", rc);
        }
        return session;
    }

    uint32_t GetPcrCount()
    {
        TPMI_YES_NO more = TPM2_NO;
        TPMS_CAPABILITY_DATA *caps = nullptr;
        TSS2_RC rc = Esys_GetCapability(esys, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                        TPM2_CAP_TPM_PROPERTIES, TPM2_PT_PCR_COUNT, 1,
                                        &more, &caps);
        if (rc != TSS2_RC_SUCCESS)
        {
            throw TssError("Esys_GetCapability(PCR_COUNT)", rc);
        }
        uint32_t count = 0;
        if (caps->data.tpmProperties.count > 0 &&
            caps->data.tpmProperties.tpmProperty[0].property == TPM2_PT_PCR_COUNT)
        {
            count = caps->data.tpmProperties.tpmProperty[0].value;
        }
        free(caps);
        if (count < AttestationPcrCount)
        {
            throw std::runtime_error("TPM reports fewer PCRs than required for attestation");
        }
        return count;
    }

    /// SHA-256 over the concatenated PCR 0-7 SHA-256 values (Tss2Util::GeneratePcrDigest).
    void ComputePcrDigest()
    {
        TPML_PCR_SELECTION remaining = selection;
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> md(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
        if (!md || EVP_DigestInit_ex(md.get(), EVP_sha256(), nullptr) != 1)
        {
            throw std::runtime_error("EVP_DigestInit_ex(sha256) failed");
        }

        uint32_t read = 0;
        while (read < AttestationPcrCount)
        {
            uint32_t update_counter = 0;
            TPML_PCR_SELECTION *sel_out = nullptr;
            TPML_DIGEST *values = nullptr;
            TSS2_RC rc = Esys_PCR_Read(esys, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                       &remaining, &update_counter, &sel_out, &values);
            if (rc != TSS2_RC_SUCCESS)
            {
                throw TssError("Esys_PCR_Read", rc);
            }
            const uint32_t count = values->count;
            for (uint32_t i = 0; i < count; ++i)
            {
                EVP_DigestUpdate(md.get(), values->digests[i].buffer, values->digests[i].size);
            }
            for (uint8_t i = 0; i < remaining.pcrSelections[0].sizeofSelect; ++i)
            {
                remaining.pcrSelections[0].pcrSelect[i] &=
                    static_cast<uint8_t>(~sel_out->pcrSelections[0].pcrSelect[i]);
            }
            free(sel_out);
            free(values);
            if (count == 0)
            {
                throw std::runtime_error("Esys_PCR_Read returned no PCR values");
            }
            read += count;
        }

        unsigned int len = 0;
        if (EVP_DigestFinal_ex(md.get(), pcr_digest.buffer, &len) != 1)
        {
            throw std::runtime_error("EVP_DigestFinal_ex failed");
        }
        pcr_digest.size = static_cast<UINT16>(len);
    }

    void CreateEphemeralKey()
    {
        // Policy digest via a trial session (Tss2Util::GetEphemeralKeyPolicyDigest).
        ESYS_TR trial = StartPcrPolicySession(TPM2_SE_TRIAL);
        TPM2B_DIGEST *policy = nullptr;
        TSS2_RC rc = Esys_PolicyGetDigest(esys, trial, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &policy);
        Esys_FlushContext(esys, trial);
        if (rc != TSS2_RC_SUCCESS)
        {
            throw TssError("Esys_PolicyGetDigest", rc);
        }

        // Template (Tss2Util::PopulateEphemeralKeyPublicTemplate).
        TPM2B_PUBLIC in_public{};
        in_public.publicArea.type = TPM2_ALG_RSA;
        in_public.publicArea.nameAlg = TPM2_ALG_SHA256;
        in_public.publicArea.objectAttributes = (TPMA_OBJECT_DECRYPT |
                                                 TPMA_OBJECT_FIXEDTPM |
                                                 TPMA_OBJECT_FIXEDPARENT |
                                                 TPMA_OBJECT_SENSITIVEDATAORIGIN |
                                                 TPMA_OBJECT_NODA);
        in_public.publicArea.unique.rsa.size = 256;
        in_public.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
        in_public.publicArea.parameters.rsaDetail.exponent = 0;
        in_public.publicArea.parameters.rsaDetail.keyBits = 2048;
        in_public.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_NULL;
        std::memcpy(in_public.publicArea.authPolicy.buffer, policy->buffer, policy->size);
        in_public.publicArea.authPolicy.size = policy->size;
        free(policy);

        TPM2B_SENSITIVE_CREATE in_sensitive{};
        TPM2B_DATA outside_info{};
        TPML_PCR_SELECTION creation_pcr{};
        TPM2B_PUBLIC *out_public = nullptr;

        const auto start = std::chrono::steady_clock::now();
        rc = Esys_CreatePrimary(esys, ESYS_TR_RH_NULL, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                                &in_sensitive, &in_public, &outside_info, &creation_pcr,
                                &key, &out_public, nullptr, nullptr, nullptr);
        key_create_ms = std::chrono::duration<double, std::milli>(
                            std::chrono::steady_clock::now() - start).count();
        free(out_public);
        if (rc != TSS2_RC_SUCCESS)
        {
            key = ESYS_TR_NONE;
            throw TssError("Esys_CreatePrimary(ephemeral key)", rc);
        }
    }
};

TpmBatchDecryptor::TpmBatchDecryptor() : impl_(new Impl)
{
    Impl &s = *impl_;
    TSS2_RC rc = Tss2_TctiLdr_Initialize(nullptr, &s.tcti);
    if (rc != TSS2_RC_SUCCESS)
    {
        throw TssError("Tss2_TctiLdr_Initialize", rc);
    }
    rc = Esys_Initialize(&s.esys, s.tcti, nullptr);
    if (rc != TSS2_RC_SUCCESS)
    {
        throw TssError("Esys_Initialize", rc);
    }

    // PCR selection (Tss2Util::GetTssPcrSelection): one SHA-256 bank, PCRs 0-7,
    // sizeofSelect derived from the TPM's PCR count.
    s.selection.count = 1;
    s.selection.pcrSelections[0].hash = TPM2_ALG_SHA256;
    s.selection.pcrSelections[0].sizeofSelect = static_cast<UINT8>(s.GetPcrCount() / 8);
    s.selection.pcrSelections[0].pcrSelect[0] = AttestationPcrMask;

    s.ComputePcrDigest();
    s.CreateEphemeralKey();
}

TpmBatchDecryptor::~TpmBatchDecryptor() = default;

double TpmBatchDecryptor::key_create_ms() const
{
    return impl_->key_create_ms;
}

std::vector<unsigned char> TpmBatchDecryptor::Decrypt(const std::vector<unsigned char> &ciphertext)
{
    Impl &s = *impl_;
    if (ciphertext.empty() || ciphertext.size() > TPM2_MAX_RSA_KEY_BYTES)
    {
        throw std::runtime_error("Transport ciphertext size is invalid for RSA-2048");
    }

    ESYS_TR session = s.StartPcrPolicySession(TPM2_SE_POLICY);

    TPM2B_PUBLIC_KEY_RSA cipher{};
    std::memcpy(cipher.buffer, ciphertext.data(), ciphertext.size());
    cipher.size = static_cast<UINT16>(ciphertext.size());

    TPMT_RSA_DECRYPT scheme{};
    scheme.scheme = TPM2_ALG_OAEP;
    scheme.details.oaep.hashAlg = TPM2_ALG_SHA256;

    TPM2B_PUBLIC_KEY_RSA *plain = nullptr;
    TSS2_RC rc = Esys_RSA_Decrypt(s.esys, s.key, session, ESYS_TR_NONE, ESYS_TR_NONE,
                                  &cipher, &scheme, nullptr, &plain);
    // The policy session may already be gone if continueSession was cleared; ignore flush errors.
    Esys_FlushContext(s.esys, session);
    if (rc != TSS2_RC_SUCCESS)
    {
        throw TssError("Esys_RSA_Decrypt(ephemeral key)", rc);
    }

    std::vector<unsigned char> out(plain->buffer, plain->buffer + plain->size);
    OPENSSL_cleanse(plain->buffer, plain->size);
    free(plain);
    return out;
}
