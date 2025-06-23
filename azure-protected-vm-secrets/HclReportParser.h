// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once
#include <vector>

class HclReportParser {
public:
    bool IsValidHclReport(const std::vector<unsigned char>& hclReport) const;
};
