#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int
main(int argc, char *argv[])
{
    int result;
    result = mem_free();
    printf("Free memory in bytes: %d\n", result);
    exit(0);
}
