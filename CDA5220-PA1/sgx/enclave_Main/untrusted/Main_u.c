#include "Main_u.h"
#include <errno.h>

typedef struct ms_ecall_lib_t {
	int* ms_value;
} ms_ecall_lib_t;

typedef struct ms_ecall_MyNewTrustedMain_print_t {
	int* ms_value;
} ms_ecall_MyNewTrustedMain_print_t;

typedef struct ms_ecall_print_int_value_t {
	int* ms_value;
} ms_ecall_print_int_value_t;

typedef struct ms_ecall_Main_sample_t {
	int ms_retval;
} ms_ecall_Main_sample_t;

typedef struct ms_ecall_lib1_sample_t {
	int ms_retval;
} ms_ecall_lib1_sample_t;

typedef struct ms_ocall_MyNewUntrustedMain_print_t {
	int* ms_value;
} ms_ocall_MyNewUntrustedMain_print_t;

typedef struct ms_ocall_print_from_untrusted_t {
	int* ms_value;
} ms_ocall_print_from_untrusted_t;

typedef struct ms_ocall_Main_sample_t {
	const char* ms_str;
} ms_ocall_Main_sample_t;

static sgx_status_t SGX_CDECL Main_ocall_MyNewUntrustedMain_print(void* pms)
{
	ms_ocall_MyNewUntrustedMain_print_t* ms = SGX_CAST(ms_ocall_MyNewUntrustedMain_print_t*, pms);
	ocall_MyNewUntrustedMain_print(ms->ms_value);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Main_ocall_print_from_untrusted(void* pms)
{
	ms_ocall_print_from_untrusted_t* ms = SGX_CAST(ms_ocall_print_from_untrusted_t*, pms);
	ocall_print_from_untrusted(ms->ms_value);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Main_ocall_Main_sample(void* pms)
{
	ms_ocall_Main_sample_t* ms = SGX_CAST(ms_ocall_Main_sample_t*, pms);
	ocall_Main_sample(ms->ms_str);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[3];
} ocall_table_Main = {
	3,
	{
		(void*)Main_ocall_MyNewUntrustedMain_print,
		(void*)Main_ocall_print_from_untrusted,
		(void*)Main_ocall_Main_sample,
	}
};
sgx_status_t ecall_lib(sgx_enclave_id_t eid, int* value)
{
	sgx_status_t status;
	ms_ecall_lib_t ms;
	ms.ms_value = value;
	status = sgx_ecall(eid, 0, &ocall_table_Main, &ms);
	return status;
}

sgx_status_t ecall_MyNewTrustedMain_print(sgx_enclave_id_t eid, int* value)
{
	sgx_status_t status;
	ms_ecall_MyNewTrustedMain_print_t ms;
	ms.ms_value = value;
	status = sgx_ecall(eid, 1, &ocall_table_Main, &ms);
	return status;
}

sgx_status_t ecall_print_int_value(sgx_enclave_id_t eid, int* value)
{
	sgx_status_t status;
	ms_ecall_print_int_value_t ms;
	ms.ms_value = value;
	status = sgx_ecall(eid, 2, &ocall_table_Main, &ms);
	return status;
}

sgx_status_t ecall_Main_sample(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_ecall_Main_sample_t ms;
	status = sgx_ecall(eid, 3, &ocall_table_Main, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_lib1_sample(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_ecall_lib1_sample_t ms;
	status = sgx_ecall(eid, 4, &ocall_table_Main, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

