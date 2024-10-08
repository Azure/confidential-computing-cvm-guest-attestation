//------------------------------------------------------------------------------------------------- 
// <copyright file="AttestationHelper.cpp" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#ifndef PLATFORM_UNIX 
#include <windows.h>
#endif
#include "AttestationHelper.h"

/* See header */
std::vector<unsigned char> attest::base64::base64_to_binary(const std::string& base64_data)
{
    using namespace boost::archive::iterators;
    using It = transform_width<binary_from_base64<std::string::const_iterator>, 8, 6>;

    std::vector<unsigned char> binary_data(It(std::begin(base64_data)), It(std::end(base64_data)));

    // remove padding from the end; preserve any zero bytes that are part of the original data
    std::size_t num_padding_chars = std::count(base64_data.rbegin(), base64_data.rend(), '=');
    if (num_padding_chars > 0) {
        binary_data.resize(binary_data.size() - num_padding_chars);
    }

    return binary_data;
}

/* See header */
std::string attest::base64::binary_to_base64(const std::vector<unsigned char>& binary_data)
{
    using namespace boost::archive::iterators;
    using It = base64_from_binary<transform_width<std::vector<unsigned char>::const_iterator, 6, 8>>;
    auto tmp = std::string(It(std::begin(binary_data)), It(std::end(binary_data)));
    return tmp.append((3 - binary_data.size() % 3) % 3, '=');
}

/* See header */
std::string attest::base64::binary_to_base64url(const std::vector<unsigned char>& binary_data)
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

/* See header */
std::vector<unsigned char> attest::base64::base64url_to_binary(const std::string& base64_data)
{
    std::string stringData = base64_data;

    // While decoding base64 url, replace - with + and _ with + and 
    // use stanard base64 decode. we dont need to add padding characters. underlying library handles it.
    boost::replace_all(stringData, "-", "+");
    boost::replace_all(stringData, "_", "/");

    return base64_to_binary(stringData);
}

/* See header */
std::string attest::base64::base64_encode(const std::string& data) {
    using namespace boost::archive::iterators;
    using It = base64_from_binary<transform_width<std::string::const_iterator, 6, 8>>;
    auto tmp = std::string(It(std::begin(data)), It(std::end(data)));
    return tmp.append((3 - data.size() % 3) % 3, '=');
}

/* See header */
std::string attest::base64::base64_decode(const std::string& data) {
    using namespace boost::archive::iterators;
    using It = transform_width<binary_from_base64<std::string::const_iterator>, 8, 6>;
    return boost::algorithm::trim_right_copy_if(std::string(It(std::begin(data)), It(std::end(data))), [](char c) {
        return c == '\0';
    });
}

/* See header */
std::string attest::utils::Uuid() {
    boost::uuids::uuid uuid = boost::uuids::random_generator()();
    return boost::uuids::to_string(uuid);
}

/* See header */
std::string attest::utils::GetCurrentUtcTime() {
    std::string timestamp_default_format = "%Y-%m-%dT%H:%M:%SZ";
    time_t rawtime;
    struct tm timeinfo = {};
    char ts_buffer[100] = { 0 };

    time_t calendar_t = time(&rawtime);
    if (calendar_t == -1) {
        return std::string();
    }

#ifdef PLATFORM_UNIX
    localtime_r(&rawtime, &timeinfo);
#else
    localtime_s(&timeinfo, &rawtime);
#endif
    strftime(ts_buffer, 100, timestamp_default_format.c_str(), &timeinfo);
    return std::string(ts_buffer);
}

/* See header */
unsigned long attest::utils::TimeSinceEpochMillisec() {
    using namespace std::chrono;
    return (unsigned long)std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

/* See header */
unsigned long attest::utils::GetPid() {
#ifdef PLATFORM_UNIX
    return (unsigned long) getpid();
#else
    return GetCurrentProcessId();
#endif
}