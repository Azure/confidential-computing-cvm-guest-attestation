// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <iostream>
#include <sstream>
#include <iomanip>

std::string formatHexBuffer(const unsigned char* buffer, int size) {
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < size; ++i) {
        ss << std::setfill('0') << (int)buffer[i];
    }
    return ss.str();
}