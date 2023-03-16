#pragma once

#include <string>
#include <vector>

/**
 * Given a base64 encoded string, convert it to binary byte vector
 *
 * param[in] base64_data : string of base64 encoded data
 *
 * returns: vector of unsigned char (byte)
 */
std::vector<unsigned char> base64_to_binary(const std::string& base64_data);
