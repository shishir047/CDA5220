#include <string.h>
#include <assert.h>

#include <unistd.h>
#include <pwd.h>
#include <libgen.h>
#include <stdlib.h>

# define MAX_PATH FILENAME_MAX


#include <sgx_urts.h>
#include "sample.h"

#include "Main_u.h"


void ocall_MyNewUntrustedMain_print(int* value) {
    if (value != NULL) {

        printf("MyNewUntrustedMain Value: %d\n\n", *value);
    }
}
