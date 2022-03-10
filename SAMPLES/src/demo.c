#include <stdio.h>     // for printf
#include <string.h>    // for memset
#include <unistd.h>    // for unlink
#include <errno.h>     // for errno
#include <mfdf/user.h> // for mfdf_printf/read

#include "common.h"    // for init_test_environment and get_major_number

#define DEMO_DEV "/dev/demo-mfdf"

int main()
{
        char buff[4096];
        int ret, fd, major;

        memset(buff, 0x0, 4096);
        // get major number from /sys
        major = get_major_number();


        // creates a node that can be driven by the driver
        // and opens it via mfdf_open
        if((fd = init_test_environment(DEMO_DEV, major, 0)) == -1) {
                fprintf(stderr, "Opening error (errcode: %d)\n", errno);
                return 1;
        }

        // 'printf-like' writes a presentation string
        // to the previously selected stream (default: LOW)
        if (mfdf_printf(fd, "Hi there, I'm using a multi flow device file with file descriptor no. %d", fd) == -1) {
                fprintf(stderr, "Write error (errcode: %d)\n", errno);
                return 1;
        }

        // it reads what is written on the same flow in which
        // the writing took place previously
        if ((ret = mfdf_read(fd, buff, 4096)) == -1) {
                fprintf(stderr, "Read error (errcode: %d)\n", errno);
                return 1;
        }

        printf("This is what I read: \"%s\" (len: %d)\n", buff, ret);

        // delete the node used for the demo
        unlink(DEMO_DEV);
        return 0;
}
