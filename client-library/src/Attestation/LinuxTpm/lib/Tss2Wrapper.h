//-------------------------------------------------------------------------------------------------
// <copyright file="Tss2Wrapper.h" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------
#pragma once

#include <vector>
#include <memory>

#include "TssWrapper.h"
#include "Tss2Ctx.h"
#include "Tss2Memory.h"

#define TCG_LOG_PATH "/sys/kernel/security/tpm0/binary_bios_measurements"

/**
 * A wrapper for the TPM2 TSS libraries
 */
class Tss2Wrapper : public TssWrapper
{
public:
    Tss2Wrapper();
    virtual ~Tss2Wrapper(){}

    /**
     * Retrieves the EK certificate
     *
     * returns: EK certificate in x.509 format
     */
    std::vector<unsigned char> GetEkNvCert() override;

    /**
     * Check the EK pub. If EK is not null, marshall it.
     * 
     * return: marshalled EK pub.
     */
    std::vector<unsigned char> CheckAndMarshalEkPub(TPM2B_PUBLIC const* pubPtr);

    /**
     * Retrieves the EK pub. If EK does not exist, generate it. But do not persist it.
     *
     * returns: Binary packed TPM2B_PUBLIC strucure containing EK pub
     */
    std::vector<unsigned char> GetEkPubWithoutPersisting() override;

    /**
     * Retrieves the EK pub. If EK does not exist, generate it.
     *
     * returns: Binary packed TPM2B_PUBLIC strucure containing EK pub
     */
    std::vector<unsigned char> GetEkPub() override;

    /**
     * Retrieves the AIK certificate
     *
     * returns: AIK certificate in x.509 format
     */
    std::vector<unsigned char> GetAIKCert() override;

    /**
     * Retrieves the AIK public key
     *
     * returns: Binary packed TPM2B_PUBLIC strucure containing AIK pub
     */
    std::vector<unsigned char> GetAIKPub() override;

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
    attest::PcrQuote GetPCRQuote(
       const attest::PcrList& pcrs, attest::HashAlg hashAlg) override;

    /**
     * Retrieves the values over specified PCRs in bank
     *
     * param[in] pcrs: vector of PCR indices to get values from
     * param[in] hashAlg: hash algorithm for PCR bank to get values from
     *
     * returns: PcrSet structure containing a vector of PCR indices and their values
     */
    attest::PcrSet GetPCRValues(
        const attest::PcrList& pcrs, attest::HashAlg hashAlg) override;

    /**
     * Retrieve the TCG log
     *
     * returns: Buffer containing the TCG bios measurement log
     */
    std::vector<unsigned char> GetTcgLog() override;

    /**
     * Get version of the TPM on this machine
     *
     * returns: Version of the TPM
     */
    attest::TpmVersion GetVersion() override;

    /**
     * Unseal encryptedSeed using the TPM
     *
     * param[in] importablePublic: Public portion of object to be unsealed
     * param[in] importablePrivate: Private portion of object to be unsealed
     * param[in] encryptedSeed: Encrypted symmetric key seed to be used for unsealing
     * param[in] pcrSet: PCRs which object was sealed to
     * param[in] hashAlg: Algorithm used to generate PCR digest in pcrSet
     *
     * returns: Clear text data of sealed object
     */
    std::vector<unsigned char> Unseal(
        const std::vector<unsigned char>& importablePublic,
        const std::vector<unsigned char>& importablePrivate,
        const std::vector<unsigned char>& encryptedSeed,
        const attest::PcrSet& pcrSet,
        const attest::HashAlg hashAlg,
        const bool usePcrAuth = true) override;

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
        const bool usePcrAuth = true) override;

    //TODO: Move this to Tss2Utils as this function does not use Tpm context in
    //any way.
    /**
     * Unpack the serialized aik pub key to RSA key.
     *
     * param[in] aikPubMarshaled The serialized aik public key.
     *
     * returns: Aik public RSA key
     */
    attest::Buffer UnpackAiKPubToRSA(attest::Buffer& aikPubMarshaled) override;

    //TODO: Move this to Tss2Utils as this function does not use Tpm context in
    //any way.
    /**
     * Unpack serialized pcr quote into raw pcr quote and RSA signature of the
     * pcr quote.
     *
     * param[in] pcrQuoteMarshaled PcrQuote structure object that contains
     * the serialized pcr quote and serialized signature.
     *
     * return: PcrQuote structure that contains raw pcr quote and its RSA signature.
     */
    attest::PcrQuote UnpackPcrQuoteToRSA(attest::PcrQuote& pcrQuoteMarshaled) override;

    /**
     * Creates an ephemeral key along with a certifyInfo object for the key that
     * is signed with the AIK.
     *
     * param[in] pcrSet PcrSet that will be used to create the Ephemeral key auth policy
     *
     * returns: An attest::EphemeralKey object.
     */
    attest::EphemeralKey GetEphemeralKey(const attest::PcrSet& pcrSet) override;

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
    attest::Buffer DecryptWithEphemeralKey(const attest::PcrSet& pcrSet,
                                           const attest::Buffer& encryptedBlob,
                                           const attest::RsaScheme rsaWrapAlgId = attest::RsaScheme::RsaEs,
                                           const attest::RsaHashAlg rsaHashAlgId  = attest::RsaHashAlg::RsaSha1) override;

    /**
     * Removes the EK from TPM NVRAM
     */
    void RemovePersistentEk() override;

    /**
     * Retrive the TCG log from file
     *
     * param[in] fname: Name of tcglog file
     *
     * returns: Buffer containing the TCG bios measurement log
     */
    static std::vector<unsigned char> GetTcgLogFromFile(std::string fname);

    /**
    * Writes AIK cert to TPM
    *
    * param[in] aikCert: The renewed AIK cert
    * 
    */
    void WriteAikCert(const std::vector<unsigned char>& aikCert) override;

    /**
     * Retrieves the HCL report for CVMs
     */
    attest::Buffer GetHCLReport() override;

    /**
     * Retrieves the Ek Pub certified by the AIK
     */
    attest::EphemeralKey GetEkPubWithCertification() override;

private:
    /**
     * Certifies the key with AK, generates the ephemeral buffer AND Flushes the provided primary handle
     *
     * param[in] outPubPtr: The Public key that should be outputted in the returned Ephemeral structure
     * param[in] primaryHandle: The ESYS handle of the outPublic key which needs to be certified
     *
     * returns: The ephemeral structure containing the public key and the certification info
     */
    attest::EphemeralKey GetCertifiedKeyAndFlushHandle(const unique_c_ptr<TPM2B_PUBLIC>& outPubPtr, ESYS_TR primaryHandle);


    /**
     * Unseal encryptedSeed using the TPM key
     *
     * param[in] keyHandle: TPM encryption key handle
     * param[in] importablePublic: Public portion of object to be unsealed
     * param[in] importablePrivate: Private portion of object to be unsealed
     * param[in] encryptedSeed: Encrypted symmetric key seed to be used for unsealing
     * param[in] pcrSet: PCRs which object was sealed to
     * param[in] hashAlg: Algorithm used to generate PCR digest in pcrSet
     *
     * returns: Clear text data of sealed object
     */
    std::vector<unsigned char> UnsealInternal(
        ESYS_TR keyHandle,
        const std::vector<unsigned char>& importablePublic,
        const std::vector<unsigned char>& importablePrivate,
        const std::vector<unsigned char>& encryptedSeed,
        const attest::PcrSet& pcrSet,
        const attest::HashAlg hashAlg,
        bool usePcrAuth);

    std::unique_ptr<Tss2Ctx> ctx;
};
