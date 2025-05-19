// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once
#include <tss2/tss2_rc.h>
#include <string>
#include <stdexcept>
#include "ReturnCodes.h"



class TpmError : public std::runtime_error {
private:
    TSS2_RC rc;
    ErrorCode lib_rc;
public:
    TpmError(TSS2_RC rc, const std::string& description, ErrorCode librc = ErrorCode::Success)
        : std::runtime_error(description), rc(rc) {
        this->lib_rc = librc;
    }
    void SetLibRC(ErrorCode librc) { this->lib_rc = librc; }
    ErrorCode GetLibRC() { return this->lib_rc; }
    TSS2_RC getReturnCode() const { return rc; }
    const char * getTPMError() const { return  Tss2_RC_Decode(rc); }
};