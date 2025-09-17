// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once
#include <string>
#include <vector>

void GenerateKey();
void RemoveKey();
bool IsKeyPresent();
void GetVmidFromSmbios();
void IsCvm();
std::string Encrypt(const char* data);
std::string Decrypt(const char* jwt);