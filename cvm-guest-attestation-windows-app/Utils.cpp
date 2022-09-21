#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <ctime>
#include <thread>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/algorithm/string.hpp>
#include <AttestationClient.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h> 
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "Utils.h"

std::vector<unsigned char> base64_to_binary(const std::string& base64_data)
{
    using namespace boost::archive::iterators;
    using It = transform_width<binary_from_base64<std::string::const_iterator>, 8, 6>;
    return boost::algorithm::trim_right_copy_if(std::vector<unsigned char>(It(std::begin(base64_data)), It(std::end(base64_data))), [](char c) {
        return c == '\0';
        });
}

std::string binary_to_base64(const std::vector<unsigned char>& binary_data)
{
    using namespace boost::archive::iterators;
    using It = base64_from_binary<transform_width<std::vector<unsigned char>::const_iterator, 6, 8>>;
    auto tmp = std::string(It(std::begin(binary_data)), It(std::end(binary_data)));
    return tmp.append((3 - binary_data.size() % 3) % 3, '=');
}

std::string binary_to_base64url(const std::vector<unsigned char>& binary_data)
{
    using namespace boost::archive::iterators;
    using It = base64_from_binary<transform_width<std::vector<unsigned char>::const_iterator, 6, 8>>;
    auto tmp = std::string(It(std::begin(binary_data)), It(std::end(binary_data)));

    // For encoding to base64url, replace "+" with "-" and "/" with "_"
    boost::replace_all(tmp, "+", "-");
    boost::replace_all(tmp, "/", "_");

    // We do not need to add padding characters while url encoding.
    return tmp;
}

std::vector<unsigned char> base64url_to_binary(const std::string& base64_data)
{
    std::string stringData = base64_data;

    // While decoding base64 url, replace - with + and _ with + and 
    // use stanard base64 decode. we dont need to add padding characters. underlying library handles it.
    boost::replace_all(stringData, "-", "+");
    boost::replace_all(stringData, "_", "/");

    return base64_to_binary(stringData);
}

std::string base64_decode(const std::string& data) {
    using namespace boost::archive::iterators;
    using It = transform_width<binary_from_base64<std::string::const_iterator>, 8, 6>;
    return boost::algorithm::trim_right_copy_if(std::string(It(std::begin(data)), It(std::end(data))), [](char c) {
        return c == '\0';
    });
}