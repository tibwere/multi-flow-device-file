#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <mfdf/user.h>

#include "common.h"

#define TEST_DEV "/dev/test-mfdf"
#define STANDING_BYTES_SYS "/sys/kernel/mfdf/standing_bytes"
#define STANDING_THREADS_SYS "/sys/kernel/mfdf/standing_threads"
#define TABLE_ROW "%2d) [M: %3d, m: %2d]      %-40s %-20s\n"
#define TABLE_HDR "    %-20s %-40s %-20s\n"
#define OUTCOME_LEN 30
#define ROW_LEN 81
#define STANDING_ROW_LEN 14
#define WAIT_TIME 3
// #define SHOW_RESULTS

struct test_case {
        const char *name;
        int (*test_fn) (int, int);
};

struct thread_args {
        int fd;
        int prio;
};


void *read_worker(void *argptr)
{
        struct thread_args *targs;
        char buff[16];

        targs = (struct thread_args *)argptr;

        if(targs->prio == LOW_PRIO)
                mfdf_gets_low(targs->fd, buff, 16);
        else
                mfdf_gets_high(targs->fd, buff, 16);

        free(targs);
        return NULL;
}


/********************************************************************
 ************************* START TEST CASES *************************
 ********************************************************************/
int test_standing_threads(int fd, int minor)
{
        int i, j, sysfd, standing_high, standing_low, ret;
        pthread_t ids[10];
        struct thread_args *args;
        char buff[80];

        memset(buff, 0x41, 80); // buff = "AA[...]AA"

        for(i=0; i<5; ++i) {
                for(j=0; j<2; ++j) {
                        if((args = malloc(sizeof(struct thread_args))) == NULL)
                                return -1;

                        args->fd = fd;
                        args->prio = j;

                        if((ret = pthread_create(&(ids[2*i + j]), NULL, read_worker, (void *)args) > 0) > 0) {
                                errno = ret; // See manpage "Return value" section
                                return -1;
                        }
                }
        }

        sleep(WAIT_TIME);

        if((sysfd = open(STANDING_THREADS_SYS, O_RDONLY)) == -1)
                return -1;

        if(lseek(sysfd, STANDING_ROW_LEN * minor, SEEK_SET) == -1)
                return -1;

        if(read(sysfd, buff, 16) == -1)
                return -1;

        /* n.b. File format "%3d %4d %4d\n" */
        standing_low = strtol(buff + 3, NULL, 10);
        standing_high = strtol(buff + 8, NULL, 10);

        // Unlock threads
        mfdf_printf_low(fd, buff);
        mfdf_printf_high(fd, buff);

        for(i=0; i<10; ++i){
                if((ret = pthread_join(ids[i], NULL)) > 0) {
                        errno = ret;
                        return -1;
                }
        }

        close(fd);
        close(sysfd);

#ifdef SHOW_RESULTS
        printf("STANDING LOW  [expected: 5 -> actual: %d]\n", standing_low);
        printf("STANDING HIGH [expected: 5 -> actual: %d]\n", standing_high);
#endif

        return (standing_low == 5 && standing_high == 5);
}

int test_standing_bytes(int fd, int minor)
{
        int sysfd, lret, hret, standing_high, standing_low;
        char buff[16];

        lret = mfdf_printf_low(fd, "MESSAGE");
        hret = mfdf_printf_high(fd, "MESSAGE");

        if((sysfd = open(STANDING_BYTES_SYS, O_RDONLY)) == -1)
                return -1;

        if(lseek(sysfd, STANDING_ROW_LEN * minor, SEEK_SET) == -1)
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

#ifdef SHOW_RESULTS
        printf("STANDING LOW   [expected: 7 (strlen(\"MESSAGE\") = %d) -> actual: %d]\n", lret, standing_low);
        printf("STANDING HIGH  [expected: 7 (strlen(\"MESSAGE\") = %d) -> actual: %d]\n", hret, standing_high);
#endif

        return (lret == standing_low && hret == standing_high);
}

int test_write_less_read_more_low(int fd, __attribute__ ((unused)) int minor)
{
        int wret, rret;
        char buff[128];

        memset(buff, 0x0, 128);

        wret = mfdf_printf_low(fd, "MESSAGE");
        rret = mfdf_gets_low(fd, buff, 128);

        mfdf_close(fd);

#ifdef SHOW_RESULTS
        printf("WRITTEN BYTES   [expected: 7 (strlen(\"MESSAGE\") = %ld) -> actual: %d]\n", strlen("MESSAGE"), wret);
        printf("READ BYTES      [expected: 7 (strlen(\"MESSAGE\") = %ld) -> actual: %d]\n", strlen("MESSAGE"), rret);
        printf("COMPARE STRINGS [expected: 0 (EQUALS) -> actual: %d]\n", strcmp(buff, "MESSAGE"));
#endif

        return (wret == strlen("MESSAGE") && rret == strlen("MESSAGE") && strcmp(buff, "MESSAGE") == 0);
}


int test_write_less_read_more_high(int fd, __attribute__ ((unused)) int minor)
{
        int wret, rret;
        char buff[128];

        memset(buff, 0x0, 128);

        wret = mfdf_printf_high(fd, "MESSAGE");
        rret = mfdf_gets_high(fd, buff, 128);

        mfdf_close(fd);

#ifdef SHOW_RESULTS
        printf("WRITTEN BYTES   [expected: 7 (strlen(\"MESSAGE\") = %ld) -> actual: %d]\n", strlen("MESSAGE"), wret);
        printf("READ BYTES      [expected: 7 (strlen(\"MESSAGE\") = %ld) -> actual: %d]\n", strlen("MESSAGE"), rret);
        printf("COMPARE STRINGS [expected: 0 (EQUALS) -> actual: %d]\n", strcmp(buff, "MESSAGE"));
#endif

        return (wret == strlen("MESSAGE") && rret == strlen("MESSAGE") && strcmp(buff, "MESSAGE") == 0);
}


int test_non_blocking_write_no_space(int fd, __attribute__ ((unused)) int minor)
{
        int first_ret, second_ret;
        char buff[4096];

        memset(buff, 0x41, 4096); // buff = "AA[...]AA"

        mfdf_set_write_modality(fd, NON_BLOCK);
        first_ret = write(fd, buff, 4096);
        second_ret = write(fd, "This shouldn't be written to the device", strlen("This shouldn't be written to the device"));

        mfdf_gets_low(fd, buff, 4096);
        mfdf_close(fd);

#ifdef SHOW_RESULTS
        printf("FIRST WRITE  [expected: 4096 -> actual: %d]\n", first_ret);
        printf("SECOND WRITE [expected: 0 -> actual: %d]\n", second_ret);
#endif
        return (first_ret == 4096 && second_ret == 0);
}


int test_blocking_write_no_space(int fd, __attribute__ ((unused)) int minor)
{
        int first_ret, second_ret;
        char buff[4096];

        memset(buff, 0x41, 4096); // buff = "AA[...]AA"

        mfdf_set_timeout(fd, WAIT_TIME);
        first_ret = write(fd, buff, 4096);
        second_ret = write(fd, "This shouldn't be written to the device", strlen("This shouldn't be written to the device"));

        mfdf_gets_low(fd, buff, 4096);
        mfdf_close(fd);

#ifdef SHOW_RESULTS
        printf("FIRST WRITE  [expected: 4096 -> actual: %d]\n", first_ret);
        printf("SECOND WRITE [expected: -1 -> actual: %d]\n", second_ret);
        printf("ERRNO        [expected: %d -> actual: %d]\n", ETIME, second_ret);
#endif

        return (first_ret == 4096 && second_ret == -1 && errno == ETIME);
}


int test_non_blocking_read_no_data(int fd, __attribute__ ((unused)) int minor)
{
        int ret;
        char buff[16];

        mfdf_set_read_modality(fd, NON_BLOCK);
        ret = mfdf_gets_low(fd, buff, 16);
        mfdf_close(fd);

#ifdef SHOW_RESULTS
        printf("READ BYTES [expected: 0 -> actual: %d]\n", ret);
#endif

        return (ret == 0);
}


int test_blocking_read_no_data(int fd, __attribute__ ((unused)) int minor)
{
        int ret;
        char buff[16];

        mfdf_set_timeout(fd, WAIT_TIME);
        ret = mfdf_gets_low(fd, buff, 16);
        mfdf_close(fd);

#ifdef SHOW_RESULTS
        printf("READ BYTES [expected: -> -1 actual: %d]\n", ret);
        printf("ERRNO      [expected: %d -> actual: %d]\n", ETIME, errno);
#endif

        return (ret == -1 && errno == ETIME);
}

/* This array MUST be NULL terminated */
static struct test_case test_cases[] = {
        {"Blocking read with no input", test_blocking_read_no_data},
        {"Non-blocking read with no input", test_non_blocking_read_no_data},
        {"Blocking write with no space", test_blocking_write_no_space},
        {"Non-blocking write with no space", test_non_blocking_write_no_space},
        {"Write less byte than read ones (LOW)", test_write_less_read_more_low},
        {"Write less byte than read ones (HIGH)", test_write_less_read_more_high},
        {"Standing bytes", test_standing_bytes},
        {"Standing threads", test_standing_threads},
        {NULL, NULL}
};
/********************************************************************
 ************************** END TEST CASES **************************
 ********************************************************************/


void do_test(int major, int minor)
{
        int ret, fd;
        char outcome[OUTCOME_LEN];
        struct test_case *the_test_case = &(test_cases[minor]);

        if((fd = init_test_environment(TEST_DEV, major, minor)) == -1) {
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

        printf(TABLE_ROW, minor+1, major, minor, the_test_case->name, outcome);
}


int main()
{
        int i, major;

        major = get_major_number();
        printf("Major number detected from %s is: %d\n\n", MAJOR_SYS, major);

        printf(TABLE_HDR, "DEVICE DETAILS", "TEST NAME", "OUTCOME");
        for(i=0; i<ROW_LEN; ++i)
                putchar('-');
        putchar('\n');

        for(i=0; (test_cases[i].name != NULL && test_cases[i].test_fn != NULL); ++i)
                do_test(major, i);
}
