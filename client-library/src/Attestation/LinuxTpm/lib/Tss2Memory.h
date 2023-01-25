//------------------------------------------------------------------------------------------------- 
// <copyright file="Tss2Memory.h" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#pragma once

#include <tss2/tss2_esys.h>
#include <memory>
#include "MemoryUtil.h"
#include "Exceptions.h"

//
// TSS2 memory helpers
//

/**
 * Acts like a unique_ptr, managing the lifetime of an ESYS_TR object.
 * More info about ESYS_TR: 
 * https://tpm2-tss.readthedocs.io/en/latest/group___e_s_y_s___t_r.html#ga65d10db3b0b31fcd709e692f1545d30f
 */
class unique_esys_tr {
public:
    /**
     * Constructs an empty unique_esys_tr with a given context.
     *
     * Ideally, the lifetime of the ESYS_TR should be maintained in this class
     * but since there are multiple ways to initialize ESYS_TR object. we are
     * creating it outside and initializing it with this object.
     */
    unique_esys_tr(ESYS_CONTEXT* ctx) : unique_esys_tr(0, ctx) {
    }

    /**
     * Constructs unique_esys_tr with a given context to manage lifetime of
     * ESYS_TR handle object. 
     */
    unique_esys_tr(ESYS_TR trHandle, ESYS_CONTEXT* ctx) {
        this->ctx = ctx;
        this->handle = trHandle;
    }

    //Disallowing the copy and assignment to ensure single resource management responsibility.
    unique_esys_tr(unique_esys_tr &rhs) = delete;
    unique_esys_tr& operator=(unique_esys_tr &rhs) = delete;

    unique_esys_tr(unique_esys_tr &&rhs) {
        this->ctx = rhs.ctx;
        this->handle = rhs.handle;
        rhs.handle = 0;
        rhs.ctx = nullptr;
    }

    unique_esys_tr& operator=(unique_esys_tr &&rhs) {
        //no-op for assignment to itself.
        if (this != &rhs)
        {
            this->ctx = rhs.ctx;
            this->handle = rhs.handle;
            rhs.handle = 0;
            rhs.ctx = nullptr;
        }
        return *this;
    }

    ~unique_esys_tr() {
        /* 
        In most of the cases the desctuction of this object will result to 
        move being called which means the Esys_TR_Close won't be called. 
        This also means that the command handles contained by CTX object 
        will be cleared at the end when ctx object will be cleared. */
        if (this->handle != 0) {
            TSS2_RC ret = Esys_TR_Close(ctx, &handle);
            if ( ret != TSS2_RC_SUCCESS)
            {
                fprintf(stdout, "~unique_esys_tr(): Error in Esys_TR_Close\n");

            }
        }
    }

    /**
     * Invalidate this handle because it has been closed elsewhere
     */
    void invalidate() {
        handle = 0;
    }

    /**
     * Get a pointer to the handle member. Use for allowing tss2 functions
     * to set handle
     */
    ESYS_TR* get_ptr() {
        return &handle;
    }

    /**
     * Get ESYS_TR handle
     */
    ESYS_TR get() {
        return handle;
    }

private:
    ESYS_TR handle;
    ESYS_CONTEXT* ctx;
};
