//-------------------------------------------------------------------------------------------------
// <copyright file="TssWrapper.h" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#pragma once

#include <vector>

#include "AttestationTypes.h"

/**
 * Abstract public interface which wraps TPM tss libraries to provide necessary
 * functionality for remote attestation regardless of TPM implementation
 */
class TssWrapper
{
public:
    TssWrapper(){}
    virtual ~TssWrapper(){}

    /**
     * Retrieves the EK certificate
     *
     * returns: EK certificate in x.509 format
     */
    virtual std::vector<unsigned char> GetEkNvCert() = 0;

    /**
     * Retrieves the EK pub. If EK does not exist, generate it. But do not persist it.
     *
     * returns: Binary packed TPM2B_PUBLIC strucure containing EK pub
     */
    virtual std::vector<unsigned char> GetEkPubWithoutPersisting() = 0;

    /**
     * Retrieves the EK pub. If EK does not exist, generate it.
     *
     * returns: Binary packed TPM2B_PUBLIC strucure containing EK pub
     */
    virtual std::vector<unsigned char> GetEkPub() = 0;

    /**
     * Retrieves the AIK certificate
     *
     * returns: AIK certificate in x.509 format
     */
    virtual std::vector<unsigned char> GetAIKCert() = 0;

    /**
     * Retrieves the AIK public key
     *
     * returns: Binary packed TPM2B_PUBLIC strucure containing AIK pub
     */
    virtual std::vector<unsigned char> GetAIKPub() = 0;

    /**
     * Retrieves the quote over specified PCRs in bank signed by AIK pub
     *
     * param[in] pcrs: vector of PCR indices to get quote over
     * param[in] hashAlg: hash algorithm for PCR bank to get quote from
     *
     * returns: PcrQuote structure containing
     *      a binary packed TPM2B_ATTEST strucure containing PCR quote
     *      a binary packed TPMT_SIGNATURE structure containing
     *          signature over quote using AIK pub
     */
    virtual attest::PcrQuote GetPCRQuote(
        const attest::PcrList& pcrs, attest::HashAlg hashAlg) = 0;

    /**
     * Retrieves the values over specified PCRs in bank
     *
     * param[in] pcrs: vector of PCR indices to get values from
     * param[in] hashAlg: hash algorithm for PCR bank to get values from
     *
     * returns: PcrSet structure containing a vector of PCR indices and their values
     */
    virtual attest::PcrSet GetPCRValues(
        const attest::PcrList& pcrs, attest::HashAlg hashAlg) = 0;

    /**
     * Retrieve the TCG log
     *
     * returns: Buffer containing the TCG bios measurement log
     */
    virtual std::vector<unsigned char> GetTcgLog() = 0;

    /**
     * Get version of the TPM on this machine
     *
     * returns: Version of the TPM
     */
    virtual attest::TpmVersion GetVersion() = 0;

    /**
     * Unseal encryptedSeed using the TPM Ek saved in NV index
     *
     * param[in] importablePublic: Public portion of object to be unsealed
     * param[in] importablePrivate: Private portion of object to be unsealed
     * param[in] encryptedSeed: Encrypted symmetric key seed to be used for unsealing
     * param[in] pcrSet: PCRs which object was sealed to
     * param[in] hashAlg: Algorithm used to generate PCR digest in pcrSet
     *
     * returns: Clear text data of sealed object
     */
    virtual std::vector<unsigned char> Unseal(
                const std::vector<unsigned char>& importablePublic,
                const std::vector<unsigned char>& importablePrivate,
                const std::vector<unsigned char>& encryptedSeed,
                const attest::PcrSet& pcrSet,
                const attest::HashAlg hashAlg,
                const bool usePcrAuth = true) = 0;

    /**
     * Unseal encryptedSeed using the TPM Ek which is generated from Spec
     *
     * param[in] importablePublic: Public portion of object to be unsealed
     * param[in] importablePrivate: Private portion of object to be unsealed
     * param[in] encryptedSeed: Encrypted symmetric key seed to be used for unsealing
     * param[in] pcrSet: PCRs which object was sealed to
     * param[in] hashAlg: Algorithm used to generate PCR digest in pcrSet
     *
     * returns: Clear text data of sealed object
     */
    virtual std::vector<unsigned char> UnsealWithEkFromSpec(
        const std::vector<unsigned char>& importablePublic,
        const std::vector<unsigned char>& importablePrivate,
        const std::vector<unsigned char>& encryptedSeed,
        const attest::PcrSet& pcrSet,
        const attest::HashAlg hashAlg,
        const bool usePcrAuth = true) = 0;

    /**
     * Removes the EK from TPM NVRAM
     */
    virtual void RemovePersistentEk() = 0;

    /**
     * Unpack the serialized aik pub key to RSA key.
     *
     * param[in] aikPubMarshaled The serialized aik public key.
     *
     * returns: Aik public RSA key
     */
    virtual attest::Buffer UnpackAiKPubToRSA(attest::Buffer& aikPubMarshaled) = 0;

    /**
     * Unpack serialized pcr quote into raw pcr quote and RSA signature of the
     * pcr quote.
     *
     * param[in] pcrQuoteMarshaled PcrQuote structure object that contains
     * the serialized pcr quote and serialized signature.
     *
     * return: PcrQuote structure that contains raw pcr quote and its RSA signature.
     */
    virtual attest::PcrQuote UnpackPcrQuoteToRSA(attest::PcrQuote& pcrQuoteMarshaled) = 0;

    /**
     * Creates an ephemeral key along with a certifyInfo object for the key that
     * is signed with the AIK.
     *
     * param[in] pcrSet PcrSet that will be used to create the Ephemeral key auth policy
     *
     * returns: An attest::EphemeralKey object.
     */
    virtual attest::EphemeralKey GetEphemeralKey(const attest::PcrSet& pcrSet) = 0;

    /**
     * Decrypt the given encrypted blob with an ephemeral key that will be created using a
     * ephemeral key template.
     *
     * param[in] pcrSet PcrSet that will be used to create the Ephemeral key auth policy
     * param[in] encryptedBlob: Encrypted data that needs to be decrypted.
     * param[in] rsaWrapAlgId: RSA wrap algorithm id. Defaults to TPM2_ALG_RSAES for backward compatibility.
     * param[in] rsaHashAlgId: RSA hash algorithm id. Defaults to TPM2_ALG_SHA1 for backward compatibility.
     * returns: Decrypted data.
     */
    virtual attest::Buffer DecryptWithEphemeralKey(const attest::PcrSet& pcrSet,
                                                   const attest::Buffer& encryptedBlob,
                                                   const attest::RsaScheme rsaWrapAlgId,
                                                   const attest::RsaHashAlg rsaHashAlgId) = 0;
    /**
    * Writes AIK cert to TPM
    *
    * param[in] aikCert: The renewed AIK cert
    *
    */
    virtual void WriteAikCert(const attest::Buffer& aikCert) = 0;

    /**
     * Retrieves the HCL report for CVMs
     */
    virtual attest::Buffer GetHCLReport() = 0;

    /**
     * Creates the EK Pub key along with a certifyInfo object for the key that
     * is signed with the AIK.
     *
     * returns: An attest::EphemeralKey object representing the Ek Pub and its certification info.
     */
    virtual attest::EphemeralKey GetEkPubWithCertification() = 0;
};
