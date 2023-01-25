#include <tss2/tss2_tcti_mssim.h>

// Since we're statically linking this tool for arm, we can't link both libtss2-tcti-device
// and libtss2-tcti-mssim. They have some of the same structures so there is a
// linker error. We don't use mssim (a usermode tpm simulator), so we just won't
// link this library and we'll shim the mssim initialization function.
TSS2_RC Tss2_Tcti_Mssim_Init(TSS2_TCTI_CONTEXT *tctiContext, size_t *contextSize, const char *conf)
{
    return 1;
}
