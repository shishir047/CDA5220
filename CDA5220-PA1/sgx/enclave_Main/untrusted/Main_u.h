#ifndef MAIN_U_H__
#define MAIN_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_MYNEWUNTRUSTEDMAIN_PRINT_DEFINED__
#define OCALL_MYNEWUNTRUSTEDMAIN_PRINT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_MyNewUntrustedMain_print, (int* value));
#endif
#ifndef OCALL_PRINT_FROM_UNTRUSTED_DEFINED__
#define OCALL_PRINT_FROM_UNTRUSTED_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_from_untrusted, (int* value));
#endif
#ifndef OCALL_MAIN_SAMPLE_DEFINED__
#define OCALL_MAIN_SAMPLE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_Main_sample, (const char* str));
#endif

sgx_status_t ecall_lib(sgx_enclave_id_t eid);
sgx_status_t ecall_MyNewTrustedMain_print(sgx_enclave_id_t eid, int* value);
sgx_status_t ecall_print_int_value(sgx_enclave_id_t eid, int* value);
sgx_status_t ecall_Main_sample(sgx_enclave_id_t eid, int* retval);
sgx_status_t ecall_lib1_sample(sgx_enclave_id_t eid, int* retval);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
