#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>
#include "user.h"

ssize_t mfdf_prio_printf(int fd, int prio, const char *restrict format, ...)
{
    ssize_t ret;
    char buff[4096];

    memset(buff, 0x0, 4096);

    if(prio != KEEP_PRIO)
        if (mfdf_set_priority(fd, prio))
            return -1;

    va_list args;
    va_start(args, format);
    vsnprintf(buff, 4096, format, args);
    ret = write(fd,buff,strlen(buff));
    va_end(args);
    return ret;
}

ssize_t mfdf_prio_gets(int fd, int prio, char *buff, size_t len)
{
    if(prio != KEEP_PRIO)
        if (mfdf_set_priority(fd, prio))
            return -1;

    return read(fd, buff, len);
}
