#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <mfdf/user.h>

#include "common.h"

#define DEMO_DEV "/dev/demo-mfdf"

int main()
{
        char buff[4096];
        int ret, fd, major;

        memset(buff, 0x0, 4096);
        major = get_major_number();


        if((fd = init_test_environment(DEMO_DEV, major, 0)) == -1) {
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

        // remove trailing newline
        buff[strcspn(buff, "\n")] = '\0';

        printf("This is what I read: \"%s\" (len: %d)\n", buff, ret);
        unlink(DEMO_DEV);
        return 0;
}
