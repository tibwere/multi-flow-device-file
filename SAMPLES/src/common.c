#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/sysmacros.h>
#include <sys/stat.h>
#include <mfdf/user.h>

#include "common.h"

int get_major_number(void)
{
        int fd;
        char buff[16];

        if((fd = open(MAJOR_SYS, O_RDONLY)) == -1)
                return -1;

        if(read(fd, buff, 16) == -1)
                return -1;

        close(fd);

        return strtol(buff, NULL, 10);
}


int init_test_environment(const char * name, int major, int minor)
{
        if(mknod(name, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH | S_IFCHR, makedev(major, minor)))
                return -1;

        return mfdf_open(name, O_RDWR);
}
