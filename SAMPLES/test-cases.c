#include <stdio.h>
#include <stdlib.h>
#include <sys/sysmacros.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <mfdf/user.h>


#define TEST_DEV "/dev/test-md"
#define MAJOR_SYS "/sys/module/mfdf/parameters/major"
#define STANDING_BYTES_SYS "/sys/kernel/mfdf/standing_bytes"
#define TABLE_ROW "%-40s %-20s [M: %3d, m: %2d]\n"
#define TABLE_HDR "%-40s %-20s %s\n"
#define OUTCOME_LEN 30
#define ROW_LEN 78
#define STANDING_BYTES_ROW_LEN 14

struct test_case {
        const char *name;
        int (*test_fn) (int, int);
};


/********************************************************************
 ************************* START TEST CASES *************************
 ********************************************************************/

int test_standing_bytes(int fd, int minor)
{
        int sysfd, lret, hret, standing_high, standing_low;
        char buff[16];

        lret = mfdf_printf_low(fd, "MESSAGGIO");
        hret = mfdf_printf_high(fd, "MESSAGGIO");

        if((sysfd = open(STANDING_BYTES_SYS, O_RDONLY)) == -1)
                return -1;

        if(lseek(sysfd, STANDING_BYTES_ROW_LEN * minor, SEEK_SET) == -1)
                return -1;

        if(read(sysfd, buff, 16) == -1)
                return -1;

        /* n.b. File format "%3d %4d %4d\n" */
        standing_low = strtol(buff + 3, NULL, 10);
        standing_high = strtol(buff + 8, NULL, 10);

        // Cleanup buffer
        mfdf_gets_low(fd, buff, 16);
        mfdf_gets_high(fd, buff, 16);

        close(fd);
        close(sysfd);

        return (lret == standing_low && hret == standing_high);
}

int test_write_less_read_more_low(int fd, __attribute__ ((unused)) int minor)
{
        int wret, rret;
        char buff[128];

        memset(buff, 0x0, 128);

        wret = mfdf_printf_low(fd, "MESSAGGIO");
        rret = mfdf_gets_low(fd, buff, 128);

        mfdf_close(fd);

        return (wret == strlen("MESSAGGIO") && rret == strlen("MESSAGGIO") && strcmp(buff, "MESSAGGIO") == 0);
}


int test_write_less_read_more_high(int fd, __attribute__ ((unused)) int minor)
{
        int wret, rret;
        char buff[128];

        memset(buff, 0x0, 128);

        wret = mfdf_printf_high(fd, "MESSAGGIO");
        rret = mfdf_gets_high(fd, buff, 128);

        mfdf_close(fd);

        return (wret == strlen("MESSAGGIO") && rret == strlen("MESSAGGIO") && strcmp(buff, "MESSAGGIO") == 0);
}


int test_non_blocking_read_no_data(int fd, __attribute__ ((unused)) int minor)
{
        int ret;
        char buff[16];

        mfdf_set_read_modality(fd, NON_BLOCK);
        ret = mfdf_gets_low(fd, buff, 16);
        mfdf_close(fd);

        return (ret == 0);
}


int test_blocking_read_no_data(int fd, __attribute__ ((unused)) int minor)
{
        int ret;
        char buff[16];

        mfdf_set_timeout(fd, 2);
        ret = mfdf_gets_low(fd, buff, 16);
        mfdf_close(fd);

        return (ret == -1 && errno == ETIME);
}

/* This array MUST be NULL terminated */
static struct test_case test_cases[] = {
        {"Blocking read with no input", test_blocking_read_no_data},
        {"Non-blocking read with no input", test_non_blocking_read_no_data},
        {"Write less byte than read ones (LOW)", test_write_less_read_more_low},
        {"Write less byte than read ones (HIGH)", test_write_less_read_more_high},
        {"Standing bytes", test_standing_bytes},
        {NULL, NULL}
};
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

        close(fd);

        return strtol(buff, NULL, 10);
}


int init_test_environment(int major, int minor)
{
        if(mknod(TEST_DEV, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH | S_IFCHR, makedev(major, minor)))
                return -1;

        return mfdf_open(TEST_DEV, MFDF_READ_WRITE);
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

        ret = (the_test_case->test_fn)(fd, minor);
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

        for(i=0; (test_cases[i].name != NULL && test_cases[i].test_fn != NULL); ++i)
                do_test(major, i);
}
