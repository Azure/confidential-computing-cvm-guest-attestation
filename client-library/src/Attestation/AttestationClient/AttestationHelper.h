//------------------------------------------------------------------------------------------------- 
// <copyright file="AttestationHelper.h" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#include <string>
#include <vector>
#include <Tpm.h>

namespace attest
{
    namespace json
    {
        /**
         * Given raw data for aikCert, aikPub, pcrQuote, pcrValues, tcgLog,
         * encodes raw data to Base64 strings and creates a json body out of
         * the encoded data for sending to service
         * 
         * param[in] aikCert: binary aik certificate
         * param[in] aikPub: binary aik public key
         * param[in] pcrQuote: struct of binary pcr quote and signature
         * param[in] pcrHash: vector containing sha256 hash of pcr values
         * param[in] pcrValues: vector of pcrvalues with each entry containing
         *                      pcr index and binary pcr digest
         * param[in] aikPub: binary tcg log
         * 
         * returns: String of Json body structured as such:
         *      {
         *          aik_cert: base64 encoding of aikCert
         *          aik_pub: base64 encoding of aikPub
         *          pcr_quote: base64 encoding of pcrQuote.quote
         *          pcr_signature: base64 encoding of pcrQuote.signature
         *          pcr_hash: base64 encoding of pcrHash
         *          tcg_log: base64 encoding of tcgLog
         *          pcr_values: [
         *              { ... },
         *              { index: pcr index, value: base64 encoding of pcr digest at index },
         *              { ... }
         *          ]
         *      }
         */
        std::string get_json(
            std::vector<unsigned char> aikCert,
            std::vector<unsigned char> aikPub,
            attest::PcrQuote pcrQuote,
            std::vector<unsigned char> pcrHash,
            attest::PcrSet pcrValues,
            std::vector<unsigned char> tcgLog);
        
        void parse_json(std::string response);
    }

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
         * Given a base64 string, convert it to plaintext string
         *
         * param[in] data : base64 encoded string data
         *
         * returns: plaintext string
         */
        std::string base64_decode(const std::string& data);

        /**
         * Given a base64 string, convert it to plaintext string without removing null bytes
         *
         * param[in] data : base64 encoded string data
         *
         * returns: plaintext string
         */
        std::string base64_decode_no_trim(const std::string &data);
    }
}