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

    printf("La scrittura ha restituito %ld\n", mfdf_printf_low(fd, "Ciao a tutti sono %s e sto scrivendo sul file descriptor %d", "Simone", fd));
    printf("La scrittura ha restituito %ld\n", mfdf_printf_high(fd, "Questa à una scrittura super importante"));

    memset(buff, 0x0, 4096);
    printf("La lettura ha restituito: %ld\n", mfdf_prio_gets(fd, LOW_PRIO, buff, 4096));
    printf("Questo è ciò che ho letto: %s\n", buff);

    memset(buff, 0x0, 4096);
    printf("La lettura ha restituito: %ld\n", mfdf_prio_gets(fd, HIGH_PRIO, buff, 4096));
    printf("Questo è ciò che ho letto: %s\n", buff);
}
