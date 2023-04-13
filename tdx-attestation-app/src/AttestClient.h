
#pragma once

#include <fstream>
#include <iostream>
#include <unordered_map>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "HttpClient.h"
#include "Utils.h"

typedef struct Config {
  std::string attestation_url;
  std::string attestation_type;
  std::string evidence;
  std::string claims;
  std::string api_key;
} Config;

std::string VerifyEvidence(const Config &config, HttpClient &http_client);