// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once
#include <tss2/tss2_esys.h>

#include <memory>

class TssCtx
{
public:
    TssCtx();
    virtual ~TssCtx();

    virtual ESYS_CONTEXT* Get();

private:
    ESYS_CONTEXT* ctx = nullptr;
    std::unique_ptr<unsigned char[]> tctiCtx = nullptr;

    TSS2_TCTI_CONTEXT* InitializeTcti();
};