//------------------------------------------------------------------------------------------------- 
// <copyright file="AttestationHelper.h" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#include <string>
#include <vector>
#include <string>
#include <chrono>

namespace attest
{
    namespace base64
    {
        /**
         * Given a base64 string, convert it to a binary byte vector
         * 
         * param[in] base64_data: string of base64 encoded data
         * 
         * returns: vector of unsigned char (byte) which represents the
         *          binary encoding of the input data
         */
        std::vector<unsigned char> base64_to_binary(const std::string& base64_data);

        /**
         * Given a binary byte vector, convert it to a base64 encoded string
         * 
         * param[in] binary_data: vector of unsigned char (byte)
         * 
         * returns: string of data which represents the binary encoding of the input data
         */
        std::string binary_to_base64(const std::vector<unsigned char>& binary_data);

        /**
         * Given binary byte vector, convert it to base64 url encoded string.
         * 
         * param[in] binary_data: vector of unsigned char (byte)
         * 
         * returns string of data which represents base64 encoded input byte array.
         */
        std::string binary_to_base64url(const std::vector<unsigned char>& binary_data);

        /**
         * Given a base64 url encoded string, convert it to binary byte vector
         * 
         * param[in] base64_data : string of base64 url encoded data
         * 
         * returns: vector of unsigned char (byte)
         */
        std::vector<unsigned char> base64url_to_binary(const std::string& base64_data);

        /**
         * Given a string, convert it to base64 encoded string
         *
         * param[in] data : string data
         *
         * returns: base64 encoded string
         */
        std::string base64_encode(const std::string& data);

        /**
         * Given a string, convert it to base64 encoded string
         *
         * param[in] data : string data
         *
         * returns: base64 encoded string
         */
        std::string base64_decode(const std::string& data);
    }

    namespace utils
    {
        /**
        * @brief This function gets current time in epochs [Time elapsed since 1/1/1970 00:00:00 GMT] [in milliseconds]
        * @return the unix timestamp in milliseconds
        */
        unsigned long TimeSinceEpochMillisec();

        /**
        * @brief This function gets current time in UTC
        * @return the current UTC timestamp
        */
        std::string GetCurrentUtcTime();

        /**
        * @brief This function generates a uuid
        * @return uuid
        */
        std::string Uuid();

        /**
        * @brief This function gets the process id of the caller
        * @return the process id
        */
        unsigned long GetPid();
    }
}