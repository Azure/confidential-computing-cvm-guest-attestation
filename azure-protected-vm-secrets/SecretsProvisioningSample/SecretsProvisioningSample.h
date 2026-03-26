// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once
#include <string>
#include <vector>
#include "../CommonTypes.h"

void GenerateKey();
void RemoveKey();
bool IsKeyPresent();
void GetVmidFromSmbios();
void IsCvm();
std::string Encrypt(const char* data);
std::string EncryptWithPadding(const char* data, RsaPaddingScheme paddingScheme);
std::string EncryptWide(const wchar_t* data);
std::string EncryptWideWithPadding(const wchar_t* data, RsaPaddingScheme paddingScheme);
std::string Decrypt(const char* jwt);