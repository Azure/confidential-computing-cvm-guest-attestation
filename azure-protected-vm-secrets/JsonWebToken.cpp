// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <nlohmann/json.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/algorithm/string.hpp>
#include "JsonWebToken.h"
#ifndef PLATFORM_UNIX
#include "BcryptError.h"
#include "Windows/WincryptX509.h"
#else
#include "Linux/OsslError.h"
#include "Linux/OsslX509.h"
#include <codecvt>
#include <locale>
#endif // !PLATFORM_UNIX
#include "LibraryLogger.h"
#include "BaseX509.h"

using json = nlohmann::json;
using namespace SecretsLogger;


namespace utf8_sanitizer
{
    // Converts a wide character vector to UTF-8 bytes
    std::vector<unsigned char> wide_to_utf8(const std::vector<wchar_t>& wide_vec) {
        if (wide_vec.empty()) return {};
    #ifdef _WIN32
        int size = WideCharToMultiByte(CP_UTF8, 0, wide_vec.data(), (int)wide_vec.size(), nullptr, 0, nullptr, nullptr);
        if (size == 0) {
            // Error in size calculation, return empty vector
            return {};
        }
        std::vector<unsigned char> result(size);
        int actual_size = WideCharToMultiByte(CP_UTF8, 0, wide_vec.data(), (int)wide_vec.size(), reinterpret_cast<char*>(result.data()), size, nullptr, nullptr);
        if (actual_size == 0) {
            // Error in conversion, return empty vector
            return {};
        }
        return result;
    #else
        // Simple conversion assuming wchar_t is 2 or 4 bytes, just truncating to lower byte
        // If wchar_t contains non-ASCII characters, this will produce invalid UTF-8
        // this will be caught by Base64 decoder or JSON parser
        try {
            std::wstring wide_str(wide_vec.begin(), wide_vec.end());
            std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
            std::string utf8_str = converter.to_bytes(wide_str);
            return std::vector<unsigned char>(utf8_str.begin(), utf8_str.end());
        }
        catch (const std::exception&) {
            // If conversion fails, return empty vector
            return {};
        }
    #endif
    }

    // Converts UTF-8 bytes to wide character vector
    std::vector<wchar_t> utf8_to_wide(const std::vector<unsigned char>& utf8_vec) {
        if (utf8_vec.empty()) return {};
    #ifdef _WIN32
        int size = MultiByteToWideChar(CP_UTF8, 0, reinterpret_cast<const char*>(utf8_vec.data()), (int)utf8_vec.size(), nullptr, 0);
        if (size == 0) {
            // Error in size calculation, return empty vector
            return {};
        }
        std::vector<wchar_t> result(size);
        int actual_size = MultiByteToWideChar(CP_UTF8, 0, reinterpret_cast<const char*>(utf8_vec.data()), (int)utf8_vec.size(), result.data(), size);
        if (actual_size == 0) {
            // Error in conversion, return empty vector
            return {};
        }
        return result;
    #else
        try {
            std::string utf8_str(utf8_vec.begin(), utf8_vec.end());
            std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
            std::wstring wide_str = converter.from_bytes(utf8_str);
            return std::vector<wchar_t>(wide_str.begin(), wide_str.end());
        }
        catch (const std::exception&) {
            // Fallback to simple conversion
            std::vector<wchar_t> result;
            for (unsigned char c : utf8_vec) {
                result.push_back(static_cast<wchar_t>(c));
            }
            return result;
        }
    #endif
    }
}

namespace encoders
{
    std::string base64_encode(std::vector<unsigned char> value) {
        using namespace boost::archive::iterators;
        using It = base64_from_binary<transform_width<std::vector<unsigned char>::const_iterator, 6, 8>>;
        auto tmp = std::string(It(std::begin(value)), It(std::end(value)));
        return tmp.append((3 - value.size() % 3) % 3, '=');
    }

    std::string base64_url_encode(std::vector<unsigned char> value) {
        std::string base64 = base64_encode(value);
        boost::replace_all(base64, "+", "-");
        boost::replace_all(base64, "/", "_");
        return base64;
    }

    std::vector<unsigned char> base64_decode(std::string base64) {
        using namespace boost::archive::iterators;
        using It = transform_width<binary_from_base64<std::string::const_iterator>, 8, 6>;
        std::vector<unsigned char> base64DecodedVector(It(std::begin(base64)), It(std::end(base64)));
        std::size_t num_padding_chars = std::count(base64.rbegin(), base64.rend(), '=');
        if (num_padding_chars > 0) {
            base64DecodedVector.resize(base64DecodedVector.size() - num_padding_chars);
        }
        return base64DecodedVector;
    }

    std::vector<unsigned char> base64_url_decode(std::string base64Url) {
        boost::replace_all(base64Url, "-", "+");
        boost::replace_all(base64Url, "_", "/");
        return base64_decode(base64Url);
    }
}

JsonWebToken::JsonWebToken(const char *alg)
{
    this->header = {};
    // TODO: Validate alg is supported or raise exception
    this->header["alg"] = alg;
    this->header["typ"] = "JWT";
}

JsonWebToken::~JsonWebToken()
{
}

bool JsonWebToken::isRealJwtWide(const wchar_t* token, unsigned int tokenLen, 
                               const std::vector<std::pair<std::string, std::string>>& requiredFields) {
    try {
        // Convert wide string to UTF-8 first
        std::vector<wchar_t> wideVec(token, token + tokenLen);
        std::vector<unsigned char> utf8Vec = utf8_sanitizer::wide_to_utf8(wideVec);
        
        // Use existing implementation
        return isRealJwt(reinterpret_cast<const char*>(utf8Vec.data()), static_cast<unsigned int>(utf8Vec.size()), requiredFields);
    }
    catch (const std::exception& e) {
        LIBSECRETS_LOG(LogLevel::Error, "JWT Validation Error", 
                       "Exception during wide JWT validation: %s", e.what());
        return false;
    }
    catch (...) {
        LIBSECRETS_LOG(LogLevel::Error, "JWT Validation Error", 
                       "Unknown exception during wide JWT validation");
        return false;
    }
}

bool JsonWebToken::isRealJwt(const char* token, unsigned int tokenLen, const std::vector<std::pair<std::string, std::string>>& requiredFields)
{
    std::string tokenStr(token, token + tokenLen);
    size_t firstDot = tokenStr.find('.');
    size_t lastDot = tokenStr.rfind('.');
    if (firstDot == std::string::npos || lastDot == std::string::npos || firstDot == lastDot || std::count(tokenStr.begin(), tokenStr.end(), '.') != 2)
        return false; // Not a 3-part token

    std::string headerBase64 = tokenStr.substr(0, firstDot);
    std::string headerJson;
    try {
        std::vector<unsigned char> decoded = encoders::base64_url_decode(headerBase64);
        headerJson.assign(decoded.begin(), decoded.end());
        nlohmann::json header = nlohmann::json::parse(headerJson);

        if (!header.contains("alg") || !header["alg"].is_string()) {
            return false;
        }
        // If no custom fields requested, accept token
        if (requiredFields.empty())
            return true;

        // Otherwise, check all required custom fields
        for (const auto& [field, expectedValue] : requiredFields) {
            if (!header.contains(field) || header[field] != expectedValue)
                return false;
        }
        return true;
    }
    catch (const nlohmann::json::parse_error& e) {
        LIBSECRETS_LOG(LogLevel::Error, "JSON Parse Error\n", "Error message: %s\n", e.what());
        return false;
    }
    catch (const std::exception& e) {
        LIBSECRETS_LOG(LogLevel::Error, "Exception\n", "Error message: %s\n", e.what());
        return false;
    }
    catch (...) {
        LIBSECRETS_LOG(LogLevel::Error, "Unknown Error\n", "An unknown error occurred\n");
        return false;
    }
}

json JsonWebToken::getClaims()
{
    return this->jwt;
}

const json& JsonWebToken::getHeader() const
{
    return this->header;
}

std::vector<unsigned char> JsonWebToken::getSignature()
{
    return this->signature;
}

void JsonWebToken::SetHeader(json header)
{
    this->header = header;
}

void JsonWebToken::SetPayload(json payload)
{
    this->jwt = payload;
}

void JsonWebToken::SetSignature(std::vector<unsigned char> signature)
{
    this->signature = signature;
}

std::string JsonWebToken::CreateToken()
{
    std::vector<unsigned char> token;
    std::string header = this->header.dump();
	this->jwt["iat"] = time(0);
	this->addClaim("exp", time(0) + 1800); // 30 minutes. This mirrors the service.
    std::string payload = this->jwt.dump();
    std::string headerBase64 = encoders::base64_url_encode(std::vector<unsigned char>(header.begin(), header.end()));
    std::string payloadBase64 = encoders::base64_url_encode(std::vector<unsigned char>(payload.begin(), payload.end()));
    std::string signatureBase64 = encoders::base64_url_encode(this->signature);
    std::string tokenString = headerBase64 + "." + payloadBase64 + "." + signatureBase64;
    token = std::vector<unsigned char>(tokenString.begin(), tokenString.end());
    return tokenString;
}

void JsonWebToken::ParseToken(std::string const&token, bool verify, const std::string& expectedSubjectSuffix)
{
    std::vector<unsigned char> tokenVector(token.begin(), token.end());
    std::string headerBase64 = "";
    std::string payloadBase64 = "";
    std::string signatureBase64 = "";
    std::string header = "";
    std::string payload = "";
    std::string signature = "";
    size_t first = std::string::npos;
    size_t last = std::string::npos;
    if (tokenVector.size() < 2) {
        throw JwtError("Invalid JWT token.");
    }
    first = token.find_first_of('.');
    last = token.find_last_of('.');

    if (first == std::string::npos || last == std::string::npos || first == last) {
        throw JwtError("Invalid JWT token.");
    }
    headerBase64 = std::string(tokenVector.begin(), tokenVector.begin() + first);
    first++;
    payloadBase64 = std::string(tokenVector.begin() + first, tokenVector.begin() + last);
    last++;
    signatureBase64 = std::string(tokenVector.begin() + last, tokenVector.end());
    if (!headerBase64.empty()) {
        try {
            std::vector<unsigned char> headerVector = encoders::base64_url_decode(headerBase64);
            header = std::string(headerVector.begin(), headerVector.end());
            this->header = json::parse(header);
        }
        catch (const boost::archive::iterators::dataflow_exception& e) {
            LIBSECRETS_LOG(LogLevel::Error, "Base64 Decode Error\n",
                "Error message %s\n", e.what());
            throw JwtError(std::string("Base64 decoding failed: ") + e.what(), ErrorCode::ParsingError_Base64_b64Error);
        }
        catch (json::parse_error& e) {
            LIBSECRETS_LOG(LogLevel::Error, "Json Parse Error\n",
                "Error message %s\n", e.what());
            throw JwtError(e.what(), ErrorCode::ParsingError_Jwt_jsonParseError);
        }
        catch (...) {
            LIBSECRETS_LOG(LogLevel::Error, "Json Parse Error\n",
                "Generic Parsing Error\n");
            throw JwtError("Failed to parse header.", ErrorCode::ParsingError_Jwt_jsonParseError);
        }
    }
    if (!payloadBase64.empty()) {
        try {
            std::vector<unsigned char> payloadVector = encoders::base64_url_decode(payloadBase64);
            payload = std::string(payloadVector.begin(), payloadVector.end());
            this->jwt = json::parse(payload);
        }
        catch (const boost::archive::iterators::dataflow_exception& e) {
            LIBSECRETS_LOG(LogLevel::Error, "Base64 Decode Error\n",
                "Error message %s\n", e.what());
            throw JwtError(std::string("Base64 decoding failed: ") + e.what(),  ErrorCode::ParsingError_Base64_b64Error);
        }
        catch (json::parse_error& e) {
            LIBSECRETS_LOG(LogLevel::Error, "Json Parse Error\n",
                "Error message %s\n", e.what());
            throw JwtError(e.what(), ErrorCode::ParsingError_Jwt_jsonParseError);
        }
        catch (...) {
            LIBSECRETS_LOG(LogLevel::Error, "Json Parse Error\n",
                "Generic Parsing Error\n");
            throw JwtError("Failed to parse payload.", ErrorCode::ParsingError_Jwt_jsonParseError);
        }
    }
    if (!signatureBase64.empty()) {
        if (verify) {
            std::string signed_portion = token.substr(0, token.find_last_of('.'));
#ifndef PLATFORM_UNIX
			std::unique_ptr<WincryptX509> x509 = std::make_unique<WincryptX509>();
#else
            std::unique_ptr<OsslX509> x509 = std::make_unique<OsslX509>();
#endif
            try {
                this->signature = encoders::base64_url_decode(signatureBase64);
                auto chain = this->header["x5c"];
                if (!chain.is_array() || chain.empty()) {
                    throw std::runtime_error("x5c header missing or malformed.");
                }
                // Load intermediates
                for (size_t i = 1; i < chain.size(); ++i) {
                    x509->LoadIntermediateCertificate(chain[i].get<std::string>().c_str());
                }

                // Load leaf
                x509->LoadLeafCertificate(chain[0].get<std::string>().c_str());
                if (!x509->VerifyCertChain(expectedSubjectSuffix)) {
                    throw JwtError("Failed to verify certificate chain.", ErrorCode::CryptographyError_Signing_certChainError);
                }
                else {
                    LIBSECRETS_LOG(
                        LogLevel::Debug, "Successfully Verified Certificate chain\n", "");
                }
                std::vector<unsigned char> signed_data(signed_portion.begin(), signed_portion.end());
                if (!x509->VerifySignature(signed_data, this->signature)) {
                    throw JwtError("Failed to verify signature.", ErrorCode::CryptographyError_Signing_verifyError);
                }
                else {
                    LIBSECRETS_LOG(
                        LogLevel::Debug, "Successfully Verified Signature\n", "");
                }
            }
            catch (const boost::archive::iterators::dataflow_exception& e) {
                LIBSECRETS_LOG(LogLevel::Error, "Base64 Decode Error\n",
                    "Error message %s\n", e.what());
                throw JwtError(std::string("Base64 decoding failed: ") + e.what(), ErrorCode::ParsingError_Base64_b64Error);
            }
            catch (json::out_of_range& e) {
                // No x5c header
                LIBSECRETS_LOG(LogLevel::Error, "Json Parse Error\n",
                    "Error message %s\n", e.what());
                throw JwtError(e.what(), ErrorCode::ParsingError_Jwt_jsonParseError);
            }
#ifndef PLATFORM_UNIX
            catch (WinCryptError& e) {
                // Certificate chain verification failed
                LIBSECRETS_LOG(LogLevel::Error, "WinCrypt Error\n",
                    "Error message %s\n", e.what());
                throw JwtError("WinCrypt error: " + std::string(e.what()) + e.GetErrorMessage(), e.GetLibRC());
            }
            catch (BcryptError &e) {
                // Signature verification failed
                LIBSECRETS_LOG(LogLevel::Error, "Bcrypt Verification\n",
                    "Bcrypt status 0x%x occurred\n Message %s\t Bcrypt Info%s",
                    e.getStatusCode(), e.what(), e.getErrorInfo());
                throw JwtError(e.getErrorInfo(), e.GetLibRC());
            }
#else
			catch (OsslError& e) {
				// Certificate chain verification failed
				LIBSECRETS_LOG(LogLevel::Error, "Openssl Error\n",
					"Error message %s\n", e.what());
				throw JwtError(e.what());
			}
#endif
        }
    }
    else {
        LIBSECRETS_LOG(LogLevel::Debug, "JWT Information\n",
            "No signature found in token\n");
    }
}