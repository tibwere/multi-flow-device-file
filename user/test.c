#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "mfdf.h"

int main()
{
    char buff[4096];

    int fd = mfdf_open("/dev/mf", MFDF_READ_WRITE);
    if (fd == -1) {
        fprintf(stderr, "Errore nell'apertura del file\n");
        exit(1);
    }

    printf("Write return value: %ld\n", mfdf_printf_low(fd, "Hello everyone I'm %s and I'm writing on file descriptor %d", "Simone", fd));
    printf("Write return value: %ld\n", mfdf_printf_high(fd, "This is a very important message"));

    memset(buff, 0x0, 4096);
    printf("Read return value: %ld\n", mfdf_prio_gets(fd, LOW_PRIO, buff, 4096));
    printf("This is what I read: \"%s\"\n", buff);

    memset(buff, 0x0, 4096);
    printf("Read return value: %ld\n", mfdf_prio_gets(fd, HIGH_PRIO, buff, 4096));
    printf("This is what I read: \"%s\"\n", buff);
}
