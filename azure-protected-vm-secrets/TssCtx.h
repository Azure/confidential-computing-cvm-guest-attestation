// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once
#include <tss2/tss2_sys.h>

#include <memory>

class TssCtx
{
public:
    TssCtx();
    virtual ~TssCtx();

    virtual TSS2_SYS_CONTEXT* Get();

private:
    std::unique_ptr<unsigned char[]> sysCtxBuf = nullptr;
    std::unique_ptr<unsigned char[]> tctiCtx = nullptr;

    TSS2_TCTI_CONTEXT* InitializeTcti();
};