#pragma once
#include <vector>

/**
 * Get MSI token from Instance metadata service
 *
 * returns: the MSI token as string
 */
std::string GetMSI();

/**
 * Given a base64 encoded string, convert it to binary byte vector
 *
 * param[in] base64_data : string of base64 encoded data
 *
 * returns: vector of unsigned char (byte)
 */
std::vector<unsigned char> base64_to_binary(const std::string& base64_data);

/**
 * Given binary byte vector, convert it to base64 encoded string.
 *
 * param[in] binary_data: vector of unsigned char (byte)
 *
 * returns string of data which represents base64 encoded input byte array.
 */
std::string binary_to_base64(const std::vector<unsigned char>& binary_data);

/**
 * Given binary byte vector, convert it to base64 url encoded string.
 *
 * param[in] binary_data: vector of unsigned char (byte)
 *
 * returns string of data which represents base64 url encoded input byte array.
 */
std::string binary_to_base64url(const std::vector<unsigned char>& binary_data);

/**
 * Given a base64 url encoded string, convert it to binary byte vector
 *
 * param[in] base64url_data : string of base64 url encoded data
 *
 * returns: vector of unsigned char (byte)
 */
std::vector<unsigned char> base64url_to_binary(const std::string& base64url_data);
