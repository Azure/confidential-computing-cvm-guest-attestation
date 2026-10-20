//-------------------------------------------------------------------------------------------------
// <copyright file="TpmBatchDecrypt.h" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#pragma once

#include <memory>
#include <vector>

/// Decrypts many secure-unwrap transport values with a single instance of the
/// attestation ephemeral key.
///
/// The guest attestation library re-creates the ephemeral key
/// (TPM2_CreatePrimary under the NULL hierarchy, ~200 ms on a vTPM) on every
/// Decrypt() call. Because the key is derived deterministically from the NULL
/// seed, the template, and the PCR policy, creating it once and reusing it for
/// a whole batch yields the same key MAA certified at a fraction of the cost.
///
/// The key template and PCR policy MUST stay identical to the client library's
/// Tss2Util::PopulateEphemeralKeyPublicTemplate / GetEphemeralKeyPolicyDigest
/// (client-library/src/Attestation/LinuxTpm/lib/Tss2Util.cpp); otherwise the
/// TPM derives a different key and every decrypt fails.
class TpmBatchDecryptor
{
public:
    TpmBatchDecryptor();
    ~TpmBatchDecryptor();
    TpmBatchDecryptor(const TpmBatchDecryptor &) = delete;
    TpmBatchDecryptor &operator=(const TpmBatchDecryptor &) = delete;

    /// RSA-OAEP (SHA-256) decrypt with the ephemeral key. Not thread-safe.
    std::vector<unsigned char> Decrypt(const std::vector<unsigned char> &ciphertext);

    /// Time spent creating the ephemeral key (TPM2_CreatePrimary), in ms.
    double key_create_ms() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
