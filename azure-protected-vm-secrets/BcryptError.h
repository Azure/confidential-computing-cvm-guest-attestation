// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once
#define UMDF_USING_NTSTATUS
#include <windows.h>
#include <bcrypt.h>
#ifndef _NTSTATUS_
#include <ntstatus.h>
#endif
#include <string>
#include <stdexcept>
#include <sstream>
#include "ReturnCodes.h"

class BcryptError : public std::runtime_error {
private:
    NTSTATUS status;
    ErrorCode lib_rc;
public:
    BcryptError(NTSTATUS status, const std::string& description, ErrorCode rc = ErrorCode::GeneralError)
        : lib_rc(rc), std::runtime_error(description), status(status) {}

    NTSTATUS getStatusCode() const { return status; }
    const char* getErrorInfo() const {
        switch (status) {
        case STATUS_AUTH_TAG_MISMATCH:
            return "(Bcrypt) Auth tag mismatch";
            break;
        case STATUS_NOT_FOUND:
            return "(Bcrypt) Not Found";
            break;
        case STATUS_NO_MEMORY:
            return "(Bcrypt) No Memory";
            break;
        case STATUS_INVALID_PARAMETER:
            return "(Bcrypt) Invalid parameter";
            break;
        case STATUS_INVALID_HANDLE:
            return "(Bcrypt) Invalid handle";
            break;
        case STATUS_NOT_SUPPORTED:
            return "(Bcrypt) Not supported";
            break;
        case STATUS_BUFFER_TOO_SMALL:
            return "(Bcrypt) Buffer Too Small";
            break;
        case STATUS_INVALID_BUFFER_SIZE:
            return "(Bcrypt) Invalid Buffer Size";
            break;
        case STATUS_INVALID_SIGNATURE:
            return "(Bcrypt) Invalid Signature";
            break;
        default:
            return "(Bcrypt) Unknown error";
            break;
        }
    }

    void SetLibRC(ErrorCode rc) { lib_rc = rc; }
    ErrorCode GetLibRC() { return lib_rc; }
};

class WinCryptError : public std::runtime_error {
private:
    DWORD errorcode;
    ErrorCode lib_rc;
public:
    WinCryptError(const std::string& description, DWORD errorcode, ErrorCode rc = ErrorCode::GeneralError)
        : lib_rc(rc), std::runtime_error(description), errorcode(errorcode) {}
    void SetLibRC(ErrorCode rc) { lib_rc = rc; }
    ErrorCode GetLibRC() { return lib_rc; }
    std::string GetErrorMessage() {
        std::ostringstream ss;
        ss << "WinCryptError: " << what();
        if (errorcode != 0) {
            ss << errorcode;
        }
        return ss.str();
    }
};