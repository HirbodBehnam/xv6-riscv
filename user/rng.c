#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int
main(int argc, char *argv[])
{
    if (argc <= 1) {
        printf("rng: pass the number of numbers to generate as the first argument.\n");
        exit(0);
    }
    int to_generate = atoi(argv[1]);
    char *buffer = sbrk(to_generate);
    rng_read(to_generate, buffer);
    for (int i = 0; i < to_generate; i++)
        printf("%d ", (int) buffer[i]);
    printf("\n");
    exit(0);
}