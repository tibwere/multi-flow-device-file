#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include "user.h"

/**
 * Printf-like version of the write on the multi-flow device file
 *
 * @fd:     file descriptor
 * @prio:   priority indicator (LOW_PRIO or HIGH_PRIO)
 * @format: format string (as in printf)
 * @...:    arguments va_list
 */
ssize_t mfdf_prio_printf(int fd, int prio, const char *restrict format, ...)
{
        ssize_t ret;
        char buff[4096];

        memset(buff, 0x0, 4096);

        if(prio != KEEP_PRIO && mfdf_set_priority(fd, prio))
                return -1;

        va_list args;
        va_start(args, format);
        vsnprintf(buff, 4096, format, args);
        ret = write(fd,buff,strlen(buff));
        va_end(args);
        return ret;
}


/**
 * Reading wrapper from multi-flow device file
 *
 * @fd:   file descriptor
 * @prio: priority indicator (LOW_PRIO or HIGH_PRIO)
 * @buff: buffer to store the read data
 * @len:  number of bytes required to read
 */
ssize_t mfdf_prio_gets(int fd, int prio, char *buff, size_t len)
{
        if(prio != KEEP_PRIO && mfdf_set_priority(fd, prio))
                return -1;

        return read(fd, buff, len);
}
