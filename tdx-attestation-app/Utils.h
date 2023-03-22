#pragma once

#include <string>
#include <vector>

#define AMBER_API_KEY_NAME "AMBER_API_KEY"

typedef struct AttestationData {
    std::string attestation_url;
    std::string evidence;
    std::string claims;
    std::string api_key;
} AttestationData;

/**
 * Given a base64url encoded string, convert it to binary byte vector
 *
 * param[in] base64_data : string of base64url encoded data
 *
 * returns: vector of unsigned char (byte)
 */
std::vector<unsigned char> base64url_to_binary(const std::string &base64_data);

/**
 * Given a binary byte vector, convert it to base64url encoded string
 *
 * param[in] binary_data:  vector of unsigned char (byte)
 *
 * returns: string of base64url encoded data
 */
std::string binary_to_base64url(const std::vector<unsigned char> &binary_data);

/**
 * Given a binary byte vector, convert it to base64url encoded string
 *
 * param[in] url: the endpoint to send the request to
 * param[in] encoded_quote: base64url encoded quote
 * param[in] encoded_quote: base64url encoded json object used durin report generation
 *
 * returns: a json web token
 */
std::string Attest(AttestationData &attestation_data);