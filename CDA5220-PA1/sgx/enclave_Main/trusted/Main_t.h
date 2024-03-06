#ifndef MAIN_T_H__
#define MAIN_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void ecall_lib(int* value);
void ecall_MyNewTrustedMain_print(int* value);
void ecall_print_int_value(int* value);
int ecall_Main_sample(void);
int ecall_lib1_sample(void);

sgx_status_t SGX_CDECL ocall_MyNewUntrustedMain_print(int* value);
sgx_status_t SGX_CDECL ocall_print_from_untrusted(int* value);
sgx_status_t SGX_CDECL ocall_Main_sample(const char* str);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
