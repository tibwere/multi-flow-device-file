#include <stdio.h>
#include <stdlib.h>
#include <sys/sysmacros.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <mfdf/user.h>


#define TEST_DEV "/dev/test-md"
#define MAJOR_SYS "/sys/module/mfdf/parameters/major"
#define TABLE_ROW "%-40s %-20s [M: %3d, m: %3d]\n"
#define TABLE_HDR "%-40s %-20s %s\n"
#define OUTCOME_LEN 30
#define ROW_LEN 78


struct test_case {
        const char *name;
        int (*test_fn) (int);
};


/********************************************************************
 ************************* START TEST CASES *************************
 ********************************************************************/
int test_non_blocking_read_no_data(int fd)
{
        int ret;
        char buff[16];

        mfdf_set_read_modality(fd, NON_BLOCK);
        ret = mfdf_gets_low(fd, buff, 16);
        mfdf_close(fd);

        return (ret == 0);
}


int test_blocking_read_no_data(int fd)
{
        int ret;
        char buff[16];

        mfdf_set_timeout(fd, 3);
        ret = mfdf_gets_low(fd, buff, 16);
        mfdf_close(fd);

        return (ret == -1 && errno == ETIME);
}

static struct test_case test_cases[] = {
        {"Blocking read with no input", test_blocking_read_no_data},
        {"Non-blocking read with no input", test_non_blocking_read_no_data},
};
#define NUMBER_OF_TEST_CASES (2)
/********************************************************************
 ************************** END TEST CASES **************************
 ********************************************************************/


int get_major_number(void)
{
        int fd;
        char buff[16];

        if((fd = open(MAJOR_SYS, O_RDONLY)) == -1)
                return -1;

        if(read(fd, buff, 16) == -1)
                return -1;

        return strtol(buff, NULL, 10);
}


int init_test_environment(int major, int minor)
{
        if(mknod(TEST_DEV, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH | S_IFCHR, makedev(major, minor)))
                return -1;

        return mfdf_open(TEST_DEV, MFDF_READ_ONLY);
}


void do_test(int major, int minor)
{
        int ret, fd;
        char outcome[OUTCOME_LEN];
        struct test_case *the_test_case = &(test_cases[minor]);

        if((fd = init_test_environment(major, minor)) == -1) {
                fprintf(stderr, "Environment setup failed (M: %d, m: %d, err: %d)\n", major, minor, errno);
                return;
        }

        ret = (the_test_case->test_fn)(fd);
        unlink(TEST_DEV);

        switch(ret) {
                case -1:
                        snprintf(outcome, OUTCOME_LEN, "ERROR (errcode: %d)", errno);
                        break;
                case 0:
                        snprintf(outcome, OUTCOME_LEN, "FAIL");
                        break;
                case 1:
                        snprintf(outcome, OUTCOME_LEN, "SUCCESS");
                        break;
        }

        printf(TABLE_ROW, the_test_case->name, outcome, major, minor);
}


int main()
{
        int i, major;

        major = get_major_number();
        printf("Major number detected from %s is: %d\n\n", MAJOR_SYS, major);

        printf(TABLE_HDR, "TEST NAME", "OUTCOME", "DEVICE DETAILS");
        for(i=0; i<ROW_LEN; ++i)
                putchar('-');
        putchar('\n');

        for(i=0; i<NUMBER_OF_TEST_CASES; ++i)
                do_test(major, i);
}
