#include <iostream>
#include <stdarg.h>
#include <vector>
#include <AttestationClient.h>
#include <AttestationLogger.h>
#include <iostream>
#include <string>
#include <algorithm>
#include <thread>
#include <boost/algorithm/string.hpp>
#include <nlohmann/json.hpp>
#include "Utils.h"
#include "Logger.h"

using json = nlohmann::json;
using namespace std;

#ifndef PLATFORM_UNIX
static char *optarg = nullptr;
static int optind = 1;
static int getopt(int argc, char *const argv[], const char *optstring) {
  // Error and -1 returns are the same as for getopt(), plus '?'
  //  for an ambiguous match or an extraneous parameter.
  if (
      (argv == nullptr) ||
      (optind >= argc) ||
      (argv[optind][0] != '-') ||
      (argv[optind][0] == 0)) {
    return -1;
  }

  int opt = argv[optind][1];
  const char *p = strchr(optstring, opt);

  if (p == NULL) {
    return '?';
  }
  if (p[1] == ':') {
    optind++;
    if (optind >= argc) {
      return '?';
    }
    optarg = argv[optind];
    optind++;
  }
  return opt;
}
#endif //! PLATFORM_UNIX

void usage(char *programName) {
  printf("Usage: %s [arguments]\n", programName);
  printf("   Options:\n");
  printf("\t-c Config file\n");
  printf("\t-h Print this help menu\n\n");
  printf("   Examples:\n");
  printf("\t%s -c config.json\n", programName);
  printf("\t%s -h\n", programName);
}

int main(int argc, char *argv[]) {
  std::string config_filename;
  std::string claims_filename;

  int opt;
  while ((opt = getopt(argc, argv, "c:h")) != -1) {
    switch (opt) {
    case 'c':
      config_filename.assign(optarg);
      break;
    case 'h':
      usage(argv[0]);
      exit(0);
    case ':':
      fprintf(stderr, "Option needs a value\n");
      exit(1);
    default:
      usage(argv[0]);
      exit(1);
    }
  }

  try {
    // user must provide a config file
    if (config_filename.empty()) {
      fprintf(stderr, "Config file is missing\n");
      usage(argv[0]);
      exit(1);
    }

    // set attestation request based on config file
    std::ifstream config_file(config_filename);
    json config = json::parse(config_file);
    config_file.close();

    std::string output_filename = config["output_filename"];
    std::string attestation_url = config["attestation_url"];
    std::string attestation_type = config["attestation_type"];
    std::string api_key = config["api_key"];

    // check for user claims
    std::string client_payload;
    json user_claims = config["claims"];
    if (!user_claims.is_null()) {
      client_payload = user_claims.dump();
    }

    // Check the attestation url being used
    if (attestation_url.empty()) {
      fprintf(stderr, "Attestation url endpoint is missing\n");
      usage(argv[0]);
      exit(1);
    }
    else {
      // if attesting with Amber, we need to make sure an API token was provided
      // or it was added as an environment variable
      if (api_key.empty() && case_insensitive_compare(attestation_type, "amber")) {
        const char *api_key_value = std::getenv(AMBER_API_KEY_NAME);
        if (api_key_value == nullptr) {
          fprintf(stderr, "Attestation endpoint API key value missing\n");
          usage(argv[0]);
          exit(1);
        }
        api_key = std::string(api_key_value);
      }
    }

    AttestationClient *attestation_client = nullptr;
    Logger *log_handle = new Logger();

    // Initialize attestation client
    if (!Initialize(log_handle, &attestation_client)) {
      fprintf(stderr, "Failed to create attestation client object\n");
      Uninitialize();
      exit(1);
    }
    attest::AttestationResult result;

    bool has_quote = true;
    std::string quote_data;

    // get verifiable quote
    result = attestation_client->GetHardwarePlatformEvidence(quote_data, client_payload);
    if (result.code_ != attest::AttestationResult::ErrorCode::SUCCESS) {
      has_quote = false;
    }

    if (has_quote) {
      // Parses the returned json response
      json json_response = json::parse(quote_data);

      std::string encoded_quote = json_response["quote"];
      if (encoded_quote.empty()) {
          result.code_ = attest::AttestationResult::ErrorCode::ERROR_EMPTY_TD_QUOTE;
          result.description_ = std::string("Empty Quote received from IMDS Quote Endpoint");
      }

      // decode the base64url encoded quote to raw bytes
      std::vector<unsigned char> quote_bytes = base64url_to_binary(encoded_quote);

      // check if user wants to save the td quote
      if (!output_filename.empty()) {
          std::ofstream output_file(output_filename, std::ios::out | std::ios::binary);
          output_file.write((char *)quote_bytes.data(), quote_bytes.size());
          output_file.close();

          std::stringstream stream;
          stream << "Quote output file generated: " << output_filename;

          cout << stream.str() << endl;;
      }

      std::string encoded_claims =
          binary_to_base64url(std::vector<unsigned char>(client_payload.begin(), client_payload.end()));

      AttestationData attestation_data = {
        attestation_url,
        attestation_type,
        encoded_quote,
        encoded_claims,
        api_key
      };

      std::string jwt_token = Attest(attestation_data);

      if (jwt_token.empty()) {
        fprintf(stderr, "Empty token received\n");
        exit(1);
      }

      cout << "Guest attestation passed successfully!!" << endl;
      cout << "TOKEN:\n" << endl;
      std::cout << jwt_token << std::endl
                << std::endl;
    }

    Uninitialize();
  }
  catch (std::exception &e) {
    cout << "Exception occured. Details - " << e.what() << endl;
    exit(1);
  }
}