#pragma once
#include <vector>
#include <memory>

// Chaining mode for AES encryption and decryption
// Currently only GCM is supported
enum ChainingMode
{
    CBC,
    GCM
};

class AesChainingInfo
{
public:
    virtual ~AesChainingInfo() = default;
    virtual void SetNonce(const std::vector<unsigned char> &nonce) = 0;
    virtual std::vector<unsigned char> GetNonce() = 0;
    virtual void SetInitVector(const std::vector<unsigned char> &initVector) = 0;
    virtual std::vector<unsigned char> GetInitVector() = 0;

};

#ifndef PLATFORM_UNIX
#endif

class AesWrapper
{
public:
    virtual ~AesWrapper() = default;
    virtual void SetKey(std::vector<unsigned char> &key) = 0;
    virtual std::unique_ptr<AesChainingInfo> SetChainingInfo(const std::vector<unsigned char> &nonce) = 0;
    virtual std::vector<unsigned char> Encrypt(const std::vector<unsigned char> &data, AesChainingInfo *chainingInfo) const = 0;
    virtual std::vector<unsigned char> Decrypt(const std::vector<unsigned char> &ciphertext, AesChainingInfo *chainingInfo) const = 0;
};

// Factory class for creating AES wrappers
class AesCreator {
public:
    virtual ~AesCreator() = default;
    virtual std::unique_ptr<AesWrapper> CreateAesWrapper() const = 0;
};