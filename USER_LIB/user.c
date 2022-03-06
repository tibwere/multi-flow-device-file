#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include "user.h"

/**
 * Printf-like version of the write on the multi-flow device file
 *
 * @fd:     file descriptor
 * @format: format string (as in printf)
 * @...:    arguments va_list
 */
ssize_t mfdf_printf(int fd, const char *restrict format, ...)
{
        ssize_t ret;
        char buff[4096];

        memset(buff, 0x0, 4096);

        va_list args;
        va_start(args, format);
        vsnprintf(buff, 4096, format, args);
        ret = write(fd,buff,strlen(buff));
        va_end(args);
        return ret;
}
