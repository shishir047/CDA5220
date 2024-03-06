#include <stdarg.h>
#include <stdio.h>

#include "Main.h"
#include "Main_t.h"


void ecall_MyNewTrustedMain_print(int* value){
	if(value != NULL) {
		printf("MyNewTrustedMain Value: %d\n\n", *value);
	}
}

