#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include "Main.h"
#include "Main_t.h"  /* print_string */

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_Main_sample(buf);
}

int ecall_Main_sample()
{

	//Calling new Untrusted function in Main.cpp
	int uValue = 2;
	printf("Defining New Untrusted Function : Calling from Main.cpp\n");
	ocall_print_from_untrusted(&uValue);

	//Calling function from Main.cpp in newly created Untrusted file
	int value_NewUntrustedMain = 10;
	printf("\nCreating Another Untrusted File in Untrusted: Calling from Main.cpp\n");
	ocall_MyNewUntrustedMain_print(&value_NewUntrustedMain);

	//Calling function from Main.cpp in newly created Trusted file
	int value_NewTrustedMain = 11;
	printf("\nCreating Another Trusted File in Trusted: Calling from Main.cpp\n");
	ecall_MyNewTrustedMain_print(&value_NewTrustedMain);



    return 0;
}



void ecall_print_int_value(int* value){
	if(value != NULL) {
		printf("Trusted Value: %d\n\n", *value);
	}
}

void ecall_lib(int* value){
	//Calling ecall_lib1_sample() from main after adding a Trusted Static Library
		printf("\nAdding a Trusted Static Library: Calling from Main.cpp \n");
		printf("%d \n", ecall_lib1_sample());
		printf("\n\n\n\n");
}

