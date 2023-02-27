#pragma once
#ifdef DEBUG_TSS_STRUCT
// ############## ADDED FOR DEBUGGING PURPOSE ONLY #############
// This file is added to facilitate TSS structs debug information.
//
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tpm2_types.h>


typedef UINT32 IESYSC_PARAM_ENCRYPT;
typedef UINT32 IESYSC_PARAM_DECRYPT;
#define DECRYPT                        1    /**< Parameter decryption by TPM */
#define NO_DECRYPT                     0    /**< No parameter decryption by TPM */

/** Type of policy authorization
 */
typedef UINT32 IESYSC_TYPE_POLICY_AUTH;
typedef struct
{
	TPM2B_NAME                             bound_entity;    /**< Entity to which the session is bound */
	TPM2B_ENCRYPTED_SECRET                encryptedSalt;    /**< Encrypted salt which can be provided by application */
	TPM2B_DATA                                     salt;    /**< Salt computed if no encrypted salt is provided */
	TPMT_SYM_DEF                              symmetric;    /**< Algorithm selection for parameter encryption */
	TPMI_ALG_HASH                              authHash;    /**< Hashalg used for authorization */
	TPM2B_DIGEST                             sessionKey;    /**< sessionKey used for KDFa to compute symKey */
	TPM2_SE                                 sessionType;    /**< Type of the session (HMAC, Policy) */
	TPMA_SESSION                      sessionAttributes;    /**< Flags which define the session behaviour */
	TPMA_SESSION                  origSessionAttributes;    /**< Copy of flags which define the session behaviour */
	TPM2B_NONCE                             nonceCaller;    /**< Nonce computed by the ESAPI for every session call */
	TPM2B_NONCE                                nonceTPM;    /**< Nonce which is returned by the TPM for every session call */
	IESYSC_PARAM_ENCRYPT                        encrypt;    /**< Indicate parameter encryption by the TPM */
	IESYSC_PARAM_DECRYPT                        decrypt;    /**< Indicate parameter decryption by the TPM */
	IESYSC_TYPE_POLICY_AUTH         type_policy_session;    /**< Field to store markers for policy sessions */
	UINT16                             sizeSessionValue;    /**< Size of sessionKey plus optionally authValue */
	BYTE                 sessionValue[2 * sizeof(TPMU_HA)];    /**< sessionKey || AuthValue */
	UINT16                                sizeHmacValue;    /**< Size of sessionKey plus optionally authValue */
} IESYS_SESSION;

typedef union
{
	TPM2B_PUBLIC                           rsrc_key_pub;    /**< Public info for key objects */
	TPM2B_NV_PUBLIC                         rsrc_nv_pub;    /**< Public info for NV ram objects */
	IESYS_SESSION                          rsrc_session;    /**< Internal esapi session information */
	TPMS_EMPTY                               rsrc_empty;    /**< no specialized date for resource */
} IESYS_RSRC_UNION;
typedef UINT32                  IESYSC_RESOURCE_TYPE;
typedef struct
{
	TPM2_HANDLE                                  handle;    /**< Handle used by TPM */
	TPM2B_NAME                                     name;    /**< TPM name of the object */
	IESYSC_RESOURCE_TYPE                       rsrcType;    /**< Selector for resource type */
	IESYS_RSRC_UNION                               misc;    /**< Resource specific information */
} IESYS_RESOURCE;
typedef struct RSRC_NODE_T
{
	ESYS_TR esys_handle;        /**< The ESYS_TR handle used by the application
									 to reference this entry. */
	TPM2B_AUTH auth;            /**< The authValue for this resource object. */
	IESYS_RESOURCE rsrc;        /**< The meta data for this resource object. */
	struct RSRC_NODE_T * next;  /**< The next object in the linked list. */
} RSRC_NODE_T;



typedef struct
{
	ESYS_TR tpmKey;
	ESYS_TR bind;
	TPM2_SE sessionType;
	TPMI_ALG_HASH authHash;
	TPM2B_NONCE *nonceCaller;
	TPM2B_NONCE nonceCallerData;
	TPMT_SYM_DEF *symmetric;
	TPMT_SYM_DEF symmetricData;
} StartAuthSession_IN;

typedef union
{
	StartAuthSession_IN StartAuthSession;
} IESYS_CMD_IN_PARAM;

/** The states for the ESAPI's internal state machine */
enum _ESYS_STATE
{
	_ESYS_STATE_INIT = 0,     /**< The initial state after creation or after
								   finishing a command. A new command can only
								   be issued in this state. */
	_ESYS_STATE_SENT,         /**< The state after sending a command to the TPM
								   before receiving a response. */
	_ESYS_STATE_RESUBMISSION, /**< The state after receiving a response from the
								   TPM that requires resending of the command.*/
	_ESYS_STATE_INTERNALERROR /**< A non-recoverable error occured within the
								   ESAPI code. */
};
struct ESYS_CONTEXT
{
	enum _ESYS_STATE state;      /**< The current state of the ESAPI context. */
	TSS2_SYS_CONTEXT *sys;       /**< The SYS context used internally to talk to
									  the TPM. */
	ESYS_TR esys_handle_cnt;     /**< The next free ESYS_TR number. */
	RSRC_NODE_T *rsrc_list;      /**< The linked list of all ESYS_TR objects. */
	int32_t timeout;             /**< The timeout to be used during
									  Tss2_Sys_ExecuteFinish. */
	ESYS_TR session_type[3];     /**< The list of TPM session handles in the
									  current command execution. */
	RSRC_NODE_T *session_tab[3]; /**< The list of TPM session meta data in the
									  current command execution. */
	int encryptNonceIdx;         /**< The index of the encrypt session. */
	TPM2B_NONCE *encryptNonce;   /**< The nonce of the encrypt session, or NULL
									  if no encrypt session exists. */
	int authsCount;              /**< The number of session provided during the
									  command. */
	int submissionCount;         /**< The current number of submissions of this
									  command to the TPM. */
	TPM2B_DATA salt;             /**< The salt used during a StartAuthSession.*/
	IESYS_CMD_IN_PARAM in;       /**< Temporary storage for Input parameters
									  needed in corresponding _Finish function*/
	ESYS_TR esys_handle;         /**< Temporary storage for the object's TPM
									  handle during Esys_TR_FromTPMPublic. */
	TSS2_TCTI_CONTEXT *tcti_app_param;/**< The TCTI context provided by the
										   application during Esys_Initialize()
										   to be returned from Esys_GetTcti().*/
	void *dlhandle;              /**< The handle of dlopen if the tcti was
									  automatically loaded. */
	IESYS_SESSION *enc_session;  /**< Ptr to the enc param session.
									  Used to restore session attributes */
};

#endif // DEBUG_TSS_STRUCT
