#include <openssl/evp.h>
#include <memory>
#include <cstddef>
#include "../AesWrapper.h"

//typedef std::basic_string<char, std::char_traits<char>, zallocator<char> > secure_string;
//using EVP_CIPHER_CTX_ptr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;

const size_t KEY_SIZE = 32;
const size_t BLOCK_SIZE = 16;
const size_t NONCE_SIZE = 12;

class OsslAesChainingInfo
{
    public:
        //virtual OsslAesChainingInfo();
        virtual ~OsslAesChainingInfo();
        virtual void SetNonce(const std::vector<unsigned char> &nonce) noexcept;
        virtual std::vector<unsigned char> GetNonce() noexcept;
        virtual void SetInitVector(const std::vector<unsigned char> &initVector) noexcept;
        virtual std::vector<unsigned char> GetInitVector() noexcept;
};


class OsslGcmChainingInfo: public AesChainingInfo
{
    public:
        OsslGcmChainingInfo();
        ~OsslGcmChainingInfo();
    void SetNonce(const std::vector<unsigned char> &nonce) noexcept; 
    void SetInitVector(const std::vector<unsigned char> &initVector) noexcept;
    std::vector<unsigned char> GetNonce() noexcept;
    std::vector<unsigned char> GetInitVector() noexcept;
private:
    std::vector<unsigned char> nonce;
    std::vector<unsigned char> initVector;
    std::vector<unsigned char> authTag;
};

// Wrapper class for AES encryption and decryption
class OsslGcmWrapper : public AesWrapper
{
public:
    OsslGcmWrapper();

    ~OsslGcmWrapper();

    // Set the key to be used for encryption and decryption
    // key: The key to be used for encryption and decryption
    // return: void
    void SetKey(std::vector<unsigned char> &key);

    // Initialize the authInfo structure and set the nonce to be used
    // for encryption and decryption
    // nonce: The nonce to be used for encryption and decryption
    // return: void
    std::unique_ptr<AesChainingInfo> SetChainingInfo(const std::vector<unsigned char> &nonce);

    // Encrypt the data using the key and chaining mode set
    // data: The data to be encrypted
    // return: The encrypted data
    std::vector<unsigned char> Encrypt(const std::vector<unsigned char> &data, AesChainingInfo *chainingInfo) const;

    // Decrypt the data using the key and chaining mode set
    // ciphertext: The data to be decrypted
    // return: The decrypted data
    std::vector<unsigned char> Decrypt(const std::vector<unsigned char> &ciphertext, AesChainingInfo *chainingInfo) const;

private:
    EVP_CIPHER_CTX* ctx;
    std::vector<unsigned char> key;
};

class OsslGcmCreator : public AesCreator {
public:
    std::unique_ptr<AesWrapper> CreateAesWrapper() const override {
        return std::make_unique<OsslGcmWrapper>();
    }
};
