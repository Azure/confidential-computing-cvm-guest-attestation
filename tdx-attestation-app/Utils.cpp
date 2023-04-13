#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/algorithm/string.hpp>
#include "Utils.h"
#include <cstdlib>
#include "HttpClient.h"
#include <nlohmann/json.hpp>

using json = nlohmann::json;

using namespace std;

std::string binary_to_base64url(const std::vector<unsigned char> &binary_data) {
    using namespace boost::archive::iterators;
    using It = base64_from_binary<transform_width<std::vector<unsigned char>::const_iterator, 6, 8>>;
    auto tmp = std::string(It(std::begin(binary_data)), It(std::end(binary_data)));

    // For encoding to base64url, replace "+" with "-" and "/" with "_"
    boost::replace_all(tmp, "+", "-");
    boost::replace_all(tmp, "/", "_");

    // We do not need to add padding characters while url encoding.
    return tmp;
}

std::vector<unsigned char> base64url_to_binary(const std::string &base64_data) {
    using namespace boost::archive::iterators;
    using It = transform_width<binary_from_base64<std::string::const_iterator>, 8, 6>;
    std::string stringData = base64_data;

    // While decoding base64 url, replace - with + and _ with + and
    // use stanard base64 decode. we dont need to add padding characters. underlying library handles it.
    boost::replace_all(stringData, "-", "+");
    boost::replace_all(stringData, "_", "/");

    return std::vector<unsigned char>(It(std::begin(stringData)), It(std::end(stringData)));
}

std::string base64url_to_base64(const std::string &base64_data) {
    std::string stringData = base64_data;

    // While decoding base64 url, replace - with + and _ with + and
    // use stanard base64 decode. we dont need to add padding characters. underlying library handles it.
    boost::replace_all(stringData, "-", "+");
    boost::replace_all(stringData, "_", "/");

    // Needs to calculate the padding needed at the end
    int padding = (4 - base64_data.size() % 4) % 4;
    for (int i = 0; i < padding; i++) {
        stringData.push_back('=');
    }

    return stringData;
}

bool case_insensitive_compare(const std::string &str1, const std::string &str2) {
    std::string lower_str1 = str1;
    std::string lower_str2 = str2;

    std::transform(lower_str1.begin(), lower_str1.end(), lower_str1.begin(), ::tolower);
    std::transform(lower_str2.begin(), lower_str2.end(), lower_str2.begin(), ::tolower);
    return lower_str2 == lower_str1;
}

std::string Attest(AttestationData &attestation_data) {
    std::string url = attestation_data.attestation_url;
    std::string encoded_quote = attestation_data.evidence;
    std::string encoded_claims = attestation_data.claims;
    std::string attestation_type = attestation_data.attestation_type;

    // headers needed for requests
    std::vector<std::string> headers = {
        "Accept:application/json",
        "Content-Type:application/json"
    };

    // checks where we are sending the request
    std::stringstream stream;
    if (case_insensitive_compare(attestation_type, "maa")) {
        stream << "{\"quote\":\"" << encoded_quote << "\",\"runtimeData\":{\"data\":\"" << encoded_claims << "\",\"dataType\":\"JSON\"}}";
    }
    else if (case_insensitive_compare(attestation_type, "amber")) {
        std::string api_key_header = "x-api-key:" + attestation_data.api_key;
        headers.push_back(api_key_header.c_str());
        stream << "{\"quote\":\"" << base64url_to_base64(encoded_quote) << "\"";

        if (!encoded_claims.empty()) {
            stream << ",\"user_data\":\"" << base64url_to_base64(encoded_claims) << "\"";
        }
        stream << "}";
    }
    else {
        throw std::runtime_error("Attestation type was not provided");
    }

    std::string response;
    std::string request_body = stream.str();
    HttpClient http_client;

    std::cout << "Starting attestation request..." << std::endl;
    std::cout << "Attestation endpoint: " << url << std::endl;

    int status = http_client.InvokeHttpRequest(
        response,
        url,
        HttpClient::HttpVerb::POST,
        headers,
        request_body);

    if (status != 0) {
        std::stringstream stream;
        stream << "Failed to reach attestation endpoint. Error Code: " << std::to_string(status);
        throw std::runtime_error(stream.str());
    }

    if (response.empty()) {
        throw std::runtime_error("Empty reponse received from attestation endpoint");
    }

    json json_response = json::parse(response);

    std::string jwt_token = json_response["token"];

    return jwt_token;
}