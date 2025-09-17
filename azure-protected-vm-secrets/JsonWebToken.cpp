// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "pch.h"
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
#endif // !PLATFORM_UNIX
#include "LibraryLogger.h"
#include "BaseX509.h"

using json = nlohmann::json;
using namespace SecretsLogger;

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

json JsonWebToken::getClaims()
{
    return this->jwt;
}

json JsonWebToken::getHeader()
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

void JsonWebToken::ParseToken(std::string const&token, bool verify)
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
        catch (json::parse_error& e) {
            LIBSECRETS_LOG(LogLevel::Error, "Json Parse Error\n",
                "Error message %s\n", e.what());
            throw JwtError(e.what());
        }
        catch (...) {
            LIBSECRETS_LOG(LogLevel::Error, "Json Parse Error\n",
                "Generic Parsing Error\n");
            throw JwtError("Failed to parse header.");
        }
    }
    if (!payloadBase64.empty()) {
        std::vector<unsigned char> payloadVector = encoders::base64_url_decode(payloadBase64);
        payload = std::string(payloadVector.begin(), payloadVector.end());
        try {
            this->jwt = json::parse(payload);
			if (this->jwt["exp"].is_number() && this->jwt["iat"].is_number()) {
				// Check if the token is expired or not yet valid
				// In Azure, the token expiration is set to 30 minutes after
				// the token is issued & signed.
				/*time_t exp = this->jwt["exp"];
                time_t iat = this->jwt["iat"];
				time_t now = time(0);
				if (now > exp) {
                    // ParseError, Jwt subclass, timeError
                    throw JwtError("Token has expired.",
                        ErrorCode::ParsingError_Jwt_timeError);
				}
				if (now < iat) {
                    // ParseError, Jwt subclass, timeError
                    throw JwtError("Token is not yet valid.",
                        ErrorCode::ParsingError_Jwt_timeError);
				}*/
			}
        }
        catch (json::parse_error& e) {
            LIBSECRETS_LOG(LogLevel::Error, "Json Parse Error\n",
                "Error message %s\n", e.what());
            throw JwtError(e.what());
        }
        catch (...) {
            LIBSECRETS_LOG(LogLevel::Error, "Json Parse Error\n",
                "Generic Parsing Error\n");
            throw JwtError("Failed to parse payload.");
        }
    }
    if (!signatureBase64.empty()) {
        this->signature = encoders::base64_url_decode(signatureBase64);
        if (verify) {
            std::string signed_portion = token.substr(0, token.find_last_of('.'));
#ifndef PLATFORM_UNIX
			std::unique_ptr<WincryptX509> x509 = std::make_unique<WincryptX509>();
#else
            std::unique_ptr<OsslX509> x509 = std::make_unique<OsslX509>();
#endif
            try {
                std::for_each(std::begin(INTERMEDIATE_CERTS), std::end(INTERMEDIATE_CERTS),
                    [&](const auto cert) { x509->LoadIntermediateCertificate(cert); } );
                x509->LoadLeafCertificate(std::string(this->header["x5c"]).c_str());
                if (!x509->VerifyCertChain()) {
                    throw JwtError("Failed to verify certificate chain.");
                }
                else {
                    LIBSECRETS_LOG(
                        LogLevel::Debug, "Successfully Verified Certificate chain\n", "");
                }
                std::vector<unsigned char> signed_data(signed_portion.begin(), signed_portion.end());
                if (!x509->VerifySignature(signed_data, this->signature)) {
                    throw JwtError("Failed to verify certificate chain.");
                }
                else {
                    LIBSECRETS_LOG(
                        LogLevel::Debug, "Successfully Verified Signature\n", "");
                }
            }
            catch (json::out_of_range& e) {
                // No x5c header
                LIBSECRETS_LOG(LogLevel::Error, "Json Parse Error\n",
                    "Error message %s\n", e.what());
                throw JwtError(e.what());
            }
#ifndef PLATFORM_UNIX
            catch (WinCryptError& e) {
                // Certificate chain verification failed
                LIBSECRETS_LOG(LogLevel::Error, "WinCrypt Error\n",
                    "Error message %s\n", e.what());
                throw JwtError(e.what());
            }
            catch (BcryptError &e) {
                // Signature verification failed
                LIBSECRETS_LOG(LogLevel::Error, "Bcrypt Verification\n",
                    "Bcrypt status 0x%x occurred\n Message %s\t Bcrypt Info%s",
                    e.getStatusCode(), e.what(), e.getErrorInfo());
                throw JwtError(e.getErrorInfo());
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