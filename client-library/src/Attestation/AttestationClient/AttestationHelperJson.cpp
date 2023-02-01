//------------------------------------------------------------------------------------------------- 
// <copyright file="AttestationHelperJson.cpp" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#include "rapidjson/writer.h"
#include "rapidjson/reader.h"
#include "rapidjson/stringbuffer.h"
#include "AttestationHelper.h"

#include <boost/algorithm/string.hpp>
#include <iostream>
#include <time.h>

/* See header */
std::string attest::json::get_json(
    std::vector<unsigned char> aikCert,
    std::vector<unsigned char> aikPub,
    attest::PcrQuote pcrQuote,
    std::vector<unsigned char> pcrHash,
    attest::PcrSet pcrValues,
    std::vector<unsigned char> tcgLog)
{
    std::string aikcert_str = attest::base64::binary_to_base64(aikCert);
    std::string aikpub_str = attest::base64::binary_to_base64(aikPub);
    std::string pcrquote_str = attest::base64::binary_to_base64(pcrQuote.quote);
    std::string pcrsig_str = attest::base64::binary_to_base64(pcrQuote.signature);
    std::string pcrhash_str = attest::base64::binary_to_base64(pcrHash);
    std::string tcglog_str = attest::base64::binary_to_base64(tcgLog);

    rapidjson::StringBuffer s;
    rapidjson::Writer<rapidjson::StringBuffer> writer(s);
    writer.StartObject();
    writer.Key("is_windows");
#ifdef PLATFORM_UNIX
    writer.Bool(false);
#else
    writer.Bool(true);
#endif //PLATFORM_UNIX
    writer.Key("aik_cert");
    writer.String(aikcert_str.c_str());
    writer.Key("aik_pub");
    writer.String(aikpub_str.c_str());
    writer.Key("pcr_quote");
    writer.String(pcrquote_str.c_str());
    writer.Key("pcr_signature");
    writer.String(pcrsig_str.c_str());
    writer.Key("pcr_hash");
    writer.String(pcrhash_str.c_str());
    writer.Key("tcg_log");
    writer.String(tcglog_str.c_str());
    writer.Key("pcr_values");
    writer.StartArray();
    for (auto pcrValue : pcrValues.pcrs)
    {
        std::string value_str = attest::base64::binary_to_base64(pcrValue.digest);
        writer.StartObject();
        writer.Key("index");
        writer.Uint(pcrValue.index);
        writer.Key("value");
        writer.String(value_str.c_str());
        writer.EndObject();
    }
    writer.EndArray();
    writer.EndObject();

    return s.GetString();
}

struct MyHandler : public rapidjson::BaseReaderHandler<rapidjson::UTF8<>, MyHandler> {
    bool Null() { std::cout << std::endl; return true; }
    bool Bool(bool b) { std::cout << std::boolalpha << b << std::endl; return true; }
    bool Int(int i) { std::cout << i << std::endl; return true; }
    bool Uint(unsigned u) { std::cout << u << std::endl; return true; }
    bool Int64(int64_t i) { std::cout << i << std::endl; return true; }
    bool Uint64(uint64_t u) { std::cout << u << std::endl; return true; }
    bool Double(double d) { std::cout << d << std::endl; return true; }
    bool String(const char* str, rapidjson::SizeType length, bool copy) { std::cout << str << std::endl; return true; }
    bool StartObject() { return true; }
    bool Key(const char* str, rapidjson::SizeType length, bool copy) { std::cout << str << " : "; return true; }
    bool EndObject(rapidjson::SizeType memberCount) { return true; }
    bool StartArray() { std::cout << "StartArray()" << std::endl; return true; }
    bool EndArray(rapidjson::SizeType elementCount) { std::cout << "EndArray(" << elementCount << ")" << std::endl; return true; }
};

void attest::json::parse_json(std::string response)
{
    std::cout << std::endl << "Parsing Response" << std::endl << std::endl;

    std::vector<std::string> response_split;
    boost::split(response_split, response, [](char c){return c == '.';});
    std::vector<unsigned char> response_payload_vector = attest::base64::base64url_to_binary(response_split[1]);
    std::string response_payload_str = std::string(response_payload_vector.begin(), response_payload_vector.end());
    std::vector<char> response_payload = std::vector<char>(response_payload_str.begin(), response_payload_str.end());

    MyHandler handler;
    rapidjson::Reader reader;
    rapidjson::StringStream ss(response_payload.data());
    reader.Parse(ss, handler);
}
