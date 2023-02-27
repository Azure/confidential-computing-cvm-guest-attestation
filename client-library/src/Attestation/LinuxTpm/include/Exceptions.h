//-------------------------------------------------------------------------------------------------
// <copyright file="Exceptions.h" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#pragma once

#include <stdexcept>
#include <system_error>
#include <string>
#include <tss2/tss2_esys.h>
#include <openssl/evp.h>

#include "ExceptionUtil.h"

/*
 * Custom C++ exceptions
 */

class NotImplemented : public std::logic_error
{
public:
    NotImplemented() : std::logic_error("Function not yet implemented") {};
};

class FileNotFound : public std::runtime_error
{
public:
    FileNotFound() : std::runtime_error("File not found") {};
};

/**
 * Exception for errors from the tpm2-tss C library. Contains a message, as
 * well as a tss2 return code.
 */
class Tss2Exception : public std::system_error {
public:
    Tss2Exception(const std::string& desc, TSS2_RC rc) :
        std::system_error(std::error_code(rc, std::generic_category()))
    {
        this->rc = rc;
        this->description = "tpm2-tss exception : message=" + desc + ", code=" + std::to_string(rc);
    }

    const char* what() const throw() { return description.c_str(); }

    TSS2_RC get_rc() const {
        auto code = std::system_error::code();
        return (TSS2_RC)code.value();
    }

private:
    TSS2_RC rc;
    std::string description;
};

