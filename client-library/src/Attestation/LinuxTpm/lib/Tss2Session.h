//------------------------------------------------------------------------------------------------- 
// <copyright file="Tss2Session.h" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------
#include <tss2/tss2_tpm2_types.h>

#include "Tss2Memory.h"

class Tss2Session
{
public:
    Tss2Session(ESYS_CONTEXT* ctx);
    ~Tss2Session();

    /**
     * Starts an auth session with the TPM
     *
     * param[in] sessionType: Type of session to start
     */
    void Start(TPM2_SE sessionType);

    /**
     * Restarts an auth session with the TPM. This will clear
     * any policies on the session.
     *
     * param[in] sessionType: Type of session to start
     */
    void Restart(TPM2_SE sessionType);

    /**
     * Ends this session and flushes it from the TPM context
     */
    void Flush();

    /**
     * Sets a policy on this session to use a secret (will always use the TPM
     * password session) that authorizes use of the object referred to by `authorityHandle`
     *
     * param[in] objectHandle: Object that the standard password session ESYS_TR_PASSWORD
     * will provide access to
     */
    void PolicySecret(ESYS_TR authorityHandle);

    /**
     * Sets the PCR policy for this session. TPM must have the PCR state
     * described by `digest` and `pcrSelection` for objects that are protected
     * by PCR policy.
     *
     * param[in] digest: Hash of PCR values refered to in `pcrSelection`
     * param[in] pcrSelection: Selection of PCR banks and indices
     */
    void PolicyPcr(TPM2B_DIGEST& digest, TPML_PCR_SELECTION& pcrSelection);

    /**
     * Authorizes this session to send `command` to the TPM
     */
    void PolicyCommandCode(TPM2_CC command);

    /**
     * Sets an empty auth value for this session
     */
    void PolicyAuthValue();

    /**
     * Gets a digest of this session's authorization
     *
     * returns: Digest of this session's authorization
     */
    unique_c_ptr<TPM2B_DIGEST> GetDigest();

    /**
     * Gets the ESYS handle to this session
     */
    ESYS_TR GetHandle();


private:
    unique_esys_tr sessionHandle;
    ESYS_CONTEXT* ctx;
};
