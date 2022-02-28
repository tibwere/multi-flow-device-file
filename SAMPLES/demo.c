#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <mfdf/user.h>

int main()
{
        char buff[4096];
        int ret, fd;

        memset(buff, 0x0, 4096);

        if((fd = mfdf_open("/dev/mf", MFDF_READ_WRITE)) == -1) {
                fprintf(stderr, "Opening error (errcode: %d)\n", errno);
                return 1;
        }

        if (mfdf_printf(fd, "Hi there, I'm using a multi flow device file with file descriptor no. %d\n", fd) == -1) {
                fprintf(stderr, "Write error (errcode: %d)\n", errno);
                return 1;
        }

        if ((ret = mfdf_gets(fd, buff, 4096)) == -1) {
                fprintf(stderr, "Read error (errcode: %d)\n", errno);
                return 1;
        }

        printf("This is what I read: \"%s\" (len: %d)\n", buff, ret);
        return 0;
}
