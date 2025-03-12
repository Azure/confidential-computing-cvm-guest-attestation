#pragma once
#include <string>
#include <vector>

void GenerateKey();
void RemoveKey();
bool IsKeyPresent();
void GetVmidFromSmbios();
std::string Encrypt(const char* data);
std::string Decrypt(const char* jwt);