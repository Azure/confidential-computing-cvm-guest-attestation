#include <iostream>
#include <stdarg.h>
#include <vector>
#include <iostream>
#include <string>
#include <fstream>
#include "AttestationClient.h"
#include <boost/algorithm/string.hpp>
#include "Logger.h"
#include "Utils.h"
#include <json/json.h>

#ifndef PLATFORM_UNIX
static char *optarg = nullptr;
static int optind = 1;
static int getopt(int argc, char *const argv[], const char *optstring)
{
  // Error and -1 returns are the same as for getopt(), plus '?'
  //  for an ambiguous match or an extraneous parameter.
  if (
      (argv == nullptr) ||
      (optind >= argc) ||
      (argv[optind][0] != '-') ||
      (argv[optind][0] == 0))
  {
    return -1;
  }

  int opt = argv[optind][1];
  const char *p = strchr(optstring, opt);

  if (p == NULL)
  {
    return '?';
  }
  if (p[1] == ':')
  {
    optind++;
    if (optind >= argc)
    {
      return '?';
    }
    optarg = argv[optind];
    optind++;
  }
  return opt;
}
#endif //! PLATFORM_UNIX

void usage(char *programName)
{
  printf("Usage: %s -o [output filename] -n <nonce>\n", programName);
}

int main(int argc, char *argv[]) {
  std::string output_filename;
  std::string nonce;
  int opt;
  int o_flag = 0;

      while ((opt = getopt(argc, argv, "n:o:")) != -1)
  {
    switch (opt) {
    case 'o':
        o_flag = 1;
        output_filename.assign(optarg);
        break;
    case 'n':
        nonce.assign(optarg);
        break;
    case ':':
      fprintf(stderr, "Option needs a value\n");
      exit(1);
    default:
      usage(argv[0]);
      exit(1);
    }
  }

  if (o_flag == 0) {
    fprintf(stderr, "%s: missing -o option\n", argv[0]);
    usage(argv[0]);
    exit(1);
  }

  try {
    AttestationClient *attestation_client = nullptr;
    Logger *log_handle = new Logger();

    // Initialize attestation client
    if (!Initialize(log_handle, &attestation_client)) {
      printf("Failed to create attestation client object\n");
      Uninitialize();
      exit(1);
    }
    attest::AttestationResult result;

    bool has_quote = true;
    std::string quote_data;
    std::string client_payload = "{\"nonce\":\"" + nonce + "\"}";

    // get verifiable quote
    result = attestation_client->GetHardwarePlatformEvidence(quote_data, (unsigned char *)client_payload.c_str());
    if (result.code_ != attest::AttestationResult::ErrorCode::SUCCESS) {
      has_quote = false;
    }

    if (has_quote) {
      std::ofstream output_file(output_filename, std::ios::out | std::ios::binary);

      // Parses the returned json
      Json::Value root;
      Json::Reader reader;
      bool parsing_successful = reader.parse(quote_data, root);
      if (!parsing_successful) {
          result.code_ = attest::AttestationResult::ErrorCode::ERROR_INVALID_JSON_RESPONSE;
          result.description_ = std::string("Invalid JSON ");
      }

      std::string encoded_quote = root["Quote"].asString();
      if (encoded_quote.empty()) {
          result.code_ = attest::AttestationResult::ErrorCode::ERROR_EMPTY_TD_QUOTE;
          result.description_ = std::string("Empty Quote received from IMDS Quote Endpoint");
      }

      // decode the base64 encoded quote to raw bytes
      std::vector<unsigned char> quote_bytes = base64_to_binary(encoded_quote);

      // write quote to output file
      output_file.write((char*)quote_bytes.data(), quote_bytes.size());
      output_file.close();
    }

    Uninitialize();
  }
  catch (std::exception &e) {
    printf("Exception occured. Details - %s", e.what());
    exit(1);
  }
}