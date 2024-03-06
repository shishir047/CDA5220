#include "Main_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_ecall_lib(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_lib_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_lib_t* ms = SGX_CAST(ms_ecall_lib_t*, pms);
	ms_ecall_lib_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_lib_t), ms, sizeof(ms_ecall_lib_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_value = __in_ms.ms_value;
	size_t _len_value = sizeof(int);
	int* _in_value = NULL;

	CHECK_UNIQUE_POINTER(_tmp_value, _len_value);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_value != NULL && _len_value != 0) {
		if ( _len_value % sizeof(*_tmp_value) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_value = (int*)malloc(_len_value);
		if (_in_value == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_value, _len_value, _tmp_value, _len_value)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	ecall_lib(_in_value);

err:
	if (_in_value) free(_in_value);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_MyNewTrustedMain_print(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_MyNewTrustedMain_print_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_MyNewTrustedMain_print_t* ms = SGX_CAST(ms_ecall_MyNewTrustedMain_print_t*, pms);
	ms_ecall_MyNewTrustedMain_print_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_MyNewTrustedMain_print_t), ms, sizeof(ms_ecall_MyNewTrustedMain_print_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_value = __in_ms.ms_value;
	size_t _len_value = sizeof(int);
	int* _in_value = NULL;

	CHECK_UNIQUE_POINTER(_tmp_value, _len_value);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_value != NULL && _len_value != 0) {
		if ( _len_value % sizeof(*_tmp_value) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_value = (int*)malloc(_len_value);
		if (_in_value == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_value, _len_value, _tmp_value, _len_value)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	ecall_MyNewTrustedMain_print(_in_value);

err:
	if (_in_value) free(_in_value);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_print_int_value(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_print_int_value_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_print_int_value_t* ms = SGX_CAST(ms_ecall_print_int_value_t*, pms);
	ms_ecall_print_int_value_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_print_int_value_t), ms, sizeof(ms_ecall_print_int_value_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_value = __in_ms.ms_value;
	size_t _len_value = sizeof(int);
	int* _in_value = NULL;

	CHECK_UNIQUE_POINTER(_tmp_value, _len_value);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_value != NULL && _len_value != 0) {
		if ( _len_value % sizeof(*_tmp_value) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_value = (int*)malloc(_len_value);
		if (_in_value == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_value, _len_value, _tmp_value, _len_value)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	ecall_print_int_value(_in_value);

err:
	if (_in_value) free(_in_value);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_Main_sample(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_Main_sample_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_Main_sample_t* ms = SGX_CAST(ms_ecall_Main_sample_t*, pms);
	ms_ecall_Main_sample_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_Main_sample_t), ms, sizeof(ms_ecall_Main_sample_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	int _in_retval;


	_in_retval = ecall_Main_sample();
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_lib1_sample(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_lib1_sample_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_lib1_sample_t* ms = SGX_CAST(ms_ecall_lib1_sample_t*, pms);
	ms_ecall_lib1_sample_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_lib1_sample_t), ms, sizeof(ms_ecall_lib1_sample_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	int _in_retval;


	_in_retval = ecall_lib1_sample();
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[5];
} g_ecall_table = {
	5,
	{
		{(void*)(uintptr_t)sgx_ecall_lib, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_MyNewTrustedMain_print, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_print_int_value, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_Main_sample, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_lib1_sample, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[3][5];
} g_dyn_entry_table = {
	3,
	{
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_MyNewUntrustedMain_print(int* value)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_value = sizeof(int);

	ms_ocall_MyNewUntrustedMain_print_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_MyNewUntrustedMain_print_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(value, _len_value);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (value != NULL) ? _len_value : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_MyNewUntrustedMain_print_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_MyNewUntrustedMain_print_t));
	ocalloc_size -= sizeof(ms_ocall_MyNewUntrustedMain_print_t);

	if (value != NULL) {
		if (memcpy_verw_s(&ms->ms_value, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_value % sizeof(*value) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, value, _len_value)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_value);
		ocalloc_size -= _len_value;
	} else {
		ms->ms_value = NULL;
	}

	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_print_from_untrusted(int* value)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_value = sizeof(int);

	ms_ocall_print_from_untrusted_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_from_untrusted_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(value, _len_value);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (value != NULL) ? _len_value : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_from_untrusted_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_from_untrusted_t));
	ocalloc_size -= sizeof(ms_ocall_print_from_untrusted_t);

	if (value != NULL) {
		if (memcpy_verw_s(&ms->ms_value, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_value % sizeof(*value) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, value, _len_value)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_value);
		ocalloc_size -= _len_value;
	} else {
		ms->ms_value = NULL;
	}

	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_Main_sample(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_Main_sample_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_Main_sample_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_Main_sample_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_Main_sample_t));
	ocalloc_size -= sizeof(ms_ocall_Main_sample_t);

	if (str != NULL) {
		if (memcpy_verw_s(&ms->ms_str, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}

	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

