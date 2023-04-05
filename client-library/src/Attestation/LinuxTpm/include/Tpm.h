//-------------------------------------------------------------------------------------------------
// <copyright file="Tpm.h" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#pragma once

#include <memory>
#include <vector>

#include "AttestationTypes.h"
#include "TssWrapper.h"

/**
 * Unified TPM interface that supports basic TPM functionality needed for
 * remote attestation
 */
class Tpm
{
public:

    Tpm();

    attest::Buffer GetAIKCert() const;
    attest::Buffer GetAIKPub() const;
    attest::PcrQuote GetPCRQuote(
        const attest::PcrList& pcrs, attest::HashAlg hashAlg) const;
    attest::PcrSet GetPCRValues(
        const attest::PcrList& pcrs, attest::HashAlg hashAlg) const;
    attest::Buffer GetTcgLog() const;
    attest::Buffer GetEkPubWithoutPersisting() const;
    attest::Buffer GetEkPub() const;
    attest::Buffer GetEkNvCert() const;
    attest::TpmVersion GetVersion() const;
    attest::Buffer Unseal(
        const attest::Buffer& importablePublic,
        const attest::Buffer& importablePrivate,
        const attest::Buffer& encryptedSeed,
        const attest::PcrSet& pcrSet,
        const attest::HashAlg hashAlg,
        const bool usePcrAuth = true) const;
    void RemovePersistentEk() const;

    attest::Buffer UnpackAiKPubToRSA(attest::Buffer& aikPubMarshaled) const;
    attest::PcrQuote UnpackPcrQuoteToRSA(attest::PcrQuote& pcrQuoteMarshaled) const;

    attest::EphemeralKey GetEphemeralKey(const attest::PcrSet& pcrSet) const;

    attest::Buffer DecryptWithEphemeralKey(const attest::PcrSet& pcrSet,
                                           const attest::Buffer& encryptedBlob,
                                           const attest::RsaScheme rsaWrapAlgId = attest::RsaScheme::RsaEs,
                                           const attest::RsaHashAlg rsaHashAlgId = attest::RsaHashAlg::RsaSha1) const;

    void WriteAikCert(const attest::Buffer& aikCert) const;
    attest::Buffer GetHCLReport() const;

private:
    std::unique_ptr<TssWrapper> tssWrapper;
};
