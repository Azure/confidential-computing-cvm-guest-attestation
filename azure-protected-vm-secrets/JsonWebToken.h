// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once
#include <vector>
#include <nlohmann/json.hpp>
#include "ReturnCodes.h"
using json = nlohmann::json;

#define X509_SUBJECT_NAME_SUFFIX ".SecureCPSProvisioning.cloudapp.net"

namespace utf8_sanitizer
{
    std::vector<unsigned char> wide_to_utf8(const std::vector<wchar_t>& wide_vec);
    std::vector<wchar_t> utf8_to_wide(const std::vector<unsigned char>& utf8_vec);
}

namespace encoders
{
    std::string base64_encode(std::vector<unsigned char> value);
    std::string base64_url_encode(std::vector<unsigned char> value);
    std::vector<unsigned char> base64_decode(std::string base64);
    std::vector<unsigned char> base64_url_decode(std::string base64Url);
}

class JsonWebToken
{
public:
    JsonWebToken(const char* alg = "RS256");
    ~JsonWebToken();
    static bool isRealJwtWide(const wchar_t* token, unsigned int tokenLen, const std::vector<std::pair<std::string, std::string>>& requiredFields);
    static bool isRealJwt(const char* token, unsigned int tokenLen, const std::vector<std::pair<std::string, std::string>>& requiredFields = {});
    void SetHeader(json header);
    void SetPayload(json payload);
    void SetSignature(std::vector<unsigned char> signature);
    std::string CreateToken();
    const json& getHeader() const;
    void ParseToken(std::string const&token, bool verify, const std::string& expectedSubjectSuffix = X509_SUBJECT_NAME_SUFFIX);
    template <class T>
    void addClaim(const char* key, T value) {
        this->jwt[key] = value;
    }
    json getClaims();
    std::vector<unsigned char> getSignature();

private:
    json header;
    json jwt;
    std::vector<unsigned char> signature;
};


class JwtError : public std::runtime_error {
private:
    std::string description;
    ErrorCode lib_rc;
public:
    JwtError(const std::string& description, ErrorCode rc=ErrorCode::GeneralError)
        : std::runtime_error(description) {
		this->lib_rc = rc;
    }
    void SetLibRC(ErrorCode rc) { this->lib_rc = rc; }
    ErrorCode GetLibRC() { return this->lib_rc; }
};