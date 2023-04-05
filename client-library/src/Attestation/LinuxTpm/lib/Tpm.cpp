//-------------------------------------------------------------------------------------------------
// <copyright file="Tpm.cpp" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#include <memory>
#include <vector>
#include "Exceptions.h"
#include "Tpm.h"
#include "TssWrapper.h"
#include "Tss2Wrapper.h"

Tpm::Tpm()
{
    this->tssWrapper = std::make_unique<Tss2Wrapper>();
}

attest::Buffer Tpm::GetAIKCert() const
{
    return this->tssWrapper->GetAIKCert();
}

attest::Buffer Tpm::GetAIKPub() const
{
    return this->tssWrapper->GetAIKPub();
}

attest::PcrQuote Tpm::GetPCRQuote(const attest::PcrList& pcrs, attest::HashAlg hashAlg) const
{
    return this->tssWrapper->GetPCRQuote(pcrs, hashAlg);
}

attest::PcrSet Tpm::GetPCRValues(const attest::PcrList& pcrs, attest::HashAlg hashAlg) const
{
    return this->tssWrapper->GetPCRValues(pcrs, hashAlg);
}

attest::Buffer Tpm::GetTcgLog() const
{
    return this->tssWrapper->GetTcgLog();
}

attest::Buffer Tpm::GetEkPubWithoutPersisting() const
{
    return this->tssWrapper->GetEkPubWithoutPersisting();
}

attest::Buffer Tpm::GetEkPub() const
{
    return this->tssWrapper->GetEkPub();
}

attest::Buffer Tpm::GetEkNvCert() const
{
    return this->tssWrapper->GetEkNvCert();
}

attest::TpmVersion Tpm::GetVersion() const
{
    return this->tssWrapper->GetVersion();
}

attest::Buffer Tpm::Unseal(
    const attest::Buffer& importablePublic,
    const attest::Buffer& importablePrivate,
    const attest::Buffer& encryptedBlob,
    const attest::PcrSet& pcrSet,
    const attest::HashAlg hashAlg,
    const bool usePcrAuth) const
{
    return this->tssWrapper->Unseal(importablePublic, importablePrivate,
            encryptedBlob, pcrSet, hashAlg, usePcrAuth);
}

void Tpm::RemovePersistentEk() const
{
    return this->tssWrapper->RemovePersistentEk();
}

attest::Buffer Tpm::UnpackAiKPubToRSA(attest::Buffer& aikPubMarshaled) const
{
    return this->tssWrapper->UnpackAiKPubToRSA(aikPubMarshaled);
}

attest::PcrQuote Tpm::UnpackPcrQuoteToRSA(attest::PcrQuote& pcrQuoteMarshaled) const
{
    return this->tssWrapper->UnpackPcrQuoteToRSA(pcrQuoteMarshaled);
}

attest::EphemeralKey Tpm::GetEphemeralKey(const attest::PcrSet& pcrSet) const
{
    return this->tssWrapper->GetEphemeralKey(pcrSet);
}

attest::Buffer Tpm::DecryptWithEphemeralKey(const attest::PcrSet& pcrSet,
                                            const attest::Buffer& encryptedBlob,
                                            const attest::RsaScheme rsaWrapAlgId,
                                            const attest::RsaHashAlg rsaHashAlgId) const
{
    return this->tssWrapper->DecryptWithEphemeralKey(pcrSet, encryptedBlob, rsaWrapAlgId, rsaHashAlgId);
}

void Tpm::WriteAikCert(const attest::Buffer& aikCert) const
{
    this->tssWrapper->WriteAikCert(aikCert);
}

attest::Buffer Tpm::GetHCLReport() const
{
    return this->tssWrapper->GetHCLReport();
}
