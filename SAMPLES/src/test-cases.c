#include <mfdf/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <mfdf/user.h>

#include "common.h"


#define GREEN "\033[0;32m"
#define RESET "\033[0m"
#define RED "\033[0;31m"
#define YELLOW "\033[0;33m"

#define SIZE (8192)
#define TEST_DEV "/dev/test-mfdf"
#define STANDING_BYTES_SYS "/sys/kernel/mfdf/standing_bytes"
#define STANDING_THREADS_SYS "/sys/kernel/mfdf/standing_threads"
#define TABLE_ROW "%2d) [M: %3d, m: %2d]      %-40s %-20s\n"
#define TABLE_HDR "    %-20s %-40s %-20s\n"
#define OUTCOME_LEN 30
#define ROW_LEN 81
#define STANDING_ROW_LEN 14
#define WAIT_TIME 3
#define NON_BLOCK_VALID_ERRNO ((errno == EBUSY) || (errno == ENODEV) || (errno == EAGAIN) || (errno == ENOMEM))

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
        mfdf_set_priority(targs->fd, targs->prio);
        mfdf_read(targs->fd, buff, 16);
        free(targs);
        return NULL;
}


/********************************************************************
 ************************* START TEST CASES *************************
 ********************************************************************/
int test_immutable_major_from_sys(__attribute__ ((unused)) int fd, __attribute__ ((unused)) int minor)
{
        int ret, sys_fd;
        mode_t original_mode, new_mode;
        original_mode = 0440;
        new_mode = 0660;

        if(chmod(MAJOR_SYS, new_mode) == -1)
                return -1;

        if((sys_fd = open(MAJOR_SYS, O_WRONLY)) == -1)
                return -1;

        ret = write(sys_fd, "1", 1);

        close(sys_fd);

        if(chmod(MAJOR_SYS, original_mode) == -1)
                return -1;

#ifdef VERBOSE
        printf("WRITE RETURN VALUE [expected: -1 -> actual: %d]\n", ret);
        printf("ERRNO              [expected: %d (EIO) -> actual: %d]\n", EIO, errno);
#endif

        return (ret == -1 && errno == EIO);
}


int test_subsequent_low_writes(int fd, __attribute__ ((unused)) int minor)
{
        int i, cmp;
        char buff[SIZE];
        char temp_buff[16];
        char expected_buff[SIZE];

        memset(expected_buff, 0x0, SIZE);
        for (i=0; i<10; ++i) {
                memset(temp_buff, 0x0, 16);
                snprintf(temp_buff, 16, "Message %d", i);
                mfdf_write(fd, temp_buff, strlen(temp_buff));
                strcat(expected_buff, temp_buff);
        }

        sleep(WAIT_TIME);

        memset(buff, 0x0, SIZE);
        mfdf_read(fd, buff, SIZE);

        cmp = strcmp(expected_buff, buff);

#ifdef VERBOSE
        printf("COMPARING STRINGS [expected: 0 (equals) -> actual: %d]\n", cmp);
#endif

        return cmp == 0;
}


int __test_standing_threads(int fd, int minor, int prio)
{
        int i, sysfd, standing, ret;
        pthread_t ids[5];
        struct thread_args *args;
        char buff[128];

        memset(buff, 0x41, 128); // buff = "AA[...]AA"

        for(i=0; i<5; ++i) {
                if((args = malloc(sizeof(struct thread_args))) == NULL)
                        return -1;

                args->fd = fd;
                args->prio = prio;

                if((ret = pthread_create(&(ids[i]), NULL, read_worker, (void *)args) > 0) > 0) {
                        errno = ret; // See manpage "Return value" section
                        return -1;
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
        if (prio == LOW_PRIO)
                standing = strtol(buff + 3, NULL, 10);
        else
                standing = strtol(buff + 8, NULL, 10);

        // Unlock threads
        mfdf_set_priority(fd, prio);
        mfdf_write(fd, buff, 80);

        for(i=0; i<5; ++i){
                if((ret = pthread_join(ids[i], NULL)) > 0) {
                        errno = ret;
                        return -1;
                }
        }

        close(sysfd);

#ifdef VERBOSE
        printf("STANDING [expected: 5 -> actual: %d]\n", standing);
#endif

        return (standing == 5);
}


int test_standing_threads_low(int fd, int minor)
{
        return __test_standing_threads(fd, minor, LOW_PRIO);
}


int test_standing_threads_high(int fd, int minor)
{
        return __test_standing_threads(fd, minor, HIGH_PRIO);
}


int __test_standing_bytes(int fd, int minor, int prio)
{
        int sysfd, ret, standing;
        char buff[16];

        mfdf_set_priority(fd, prio);
        ret = mfdf_printf(fd, "MESSAGE");

        if((sysfd = open(STANDING_BYTES_SYS, O_RDONLY)) == -1)
                return -1;

        if(lseek(sysfd, STANDING_ROW_LEN * minor, SEEK_SET) == -1)
                return -1;

        if(read(sysfd, buff, 16) == -1)
                return -1;

        /* n.b. File format "%3d %4d %4d\n" */
        if (prio == LOW_PRIO)
                standing = strtol(buff + 3, NULL, 10);
        else
                standing = strtol(buff + 8, NULL, 10);

        // Cleanup
        mfdf_read(fd, buff, 16);
        close(sysfd);

#ifdef VERBOSE
        printf("STANDING [expected: 7 (strlen(\"MESSAGE\") = %d) -> actual: %d]\n", ret, standing);
#endif

        return (ret == standing);
}


int test_standing_bytes_low(int fd, int minor)
{
        return __test_standing_bytes(fd, minor, LOW_PRIO);
}


int test_standing_bytes_high(int fd, int minor)
{
        return __test_standing_bytes(fd, minor, HIGH_PRIO);
}


int __test_write_less_read_more(int fd, int prio)
{
        int wret, rret;
        char buff[128];

        memset(buff, 0x0, 128);

        mfdf_set_priority(fd, prio);
        wret = mfdf_printf(fd, "MESSAGE");
        rret = mfdf_read(fd, buff, 128);


#ifdef VERBOSE
        printf("WRITTEN BYTES   [expected: 7 (strlen(\"MESSAGE\") = %ld) -> actual: %d]\n", strlen("MESSAGE"), wret);
        printf("READ BYTES      [expected: 7 (strlen(\"MESSAGE\") = %ld) -> actual: %d]\n", strlen("MESSAGE"), rret);
        printf("COMPARE STRINGS [expected: 0 (EQUALS) -> actual: %d]\n", strcmp(buff, "MESSAGE"));
#endif

        return (wret == strlen("MESSAGE") && rret == strlen("MESSAGE") && strcmp(buff, "MESSAGE") == 0);
}


int test_write_less_read_more_low(int fd, __attribute__ ((unused)) int minor)
{
        return __test_write_less_read_more(fd, LOW_PRIO);
}


int test_write_less_read_more_high(int fd, __attribute__ ((unused)) int minor)
{
        return __test_write_less_read_more(fd, HIGH_PRIO);
}




int __test_non_blocking_write_no_space(int fd, int prio)
{
        int first_ret, second_ret;
        char buff[SIZE];

        memset(buff, 0x41, SIZE); // buff = "AA[...]AA"

        mfdf_set_priority(fd, prio);
        mfdf_set_write_modality(fd, NON_BLOCK);
        first_ret = mfdf_write(fd, buff, SIZE);
        second_ret = mfdf_write(fd, "This shouldn't be written to the device", strlen("This shouldn't be written to the device"));

        mfdf_read(fd, buff, SIZE);

#ifdef VERBOSE
        printf("FIRST WRITE  [expected: SIZE -> actual: %d]\n", first_ret);
        printf("SECOND WRITE [expected: -1 -> actual: %d]\n", second_ret);
        printf("ERRNO        [expected: %d (EAGAIN), %d (ENOMEM), %d (ENODEV) or %d (EBUSY) -> actual: %d]\n", EAGAIN, ENOMEM, ENODEV, EBUSY, errno);
#endif
        return ((first_ret == SIZE) && (second_ret == -1) && NON_BLOCK_VALID_ERRNO);
}


int test_non_blocking_write_no_space_low(int fd, __attribute__ ((unused)) int minor)
{
        return __test_non_blocking_write_no_space(fd, LOW_PRIO);
}


int test_non_blocking_write_no_space_high(int fd, __attribute__ ((unused)) int minor)
{
        return __test_non_blocking_write_no_space(fd, HIGH_PRIO);
}


int __test_blocking_write_no_space(int fd, int prio)
{
        int first_ret, second_ret;
        char buff[SIZE];

        memset(buff, 0x41, SIZE); // buff = "AA[...]AA"

        mfdf_set_priority(fd, prio);
        mfdf_set_timeout(fd, WAIT_TIME);
        first_ret = mfdf_write(fd, buff, SIZE);
        second_ret = mfdf_write(fd, "This shouldn't be written to the device", strlen("This shouldn't be written to the device"));

        mfdf_read(fd, buff, SIZE);

#ifdef VERBOSE
        printf("FIRST WRITE  [expected: SIZE -> actual: %d]\n", first_ret);
        printf("SECOND WRITE [expected: -1 -> actual: %d]\n", second_ret);
        printf("ERRNO        [expected: %d (ETIME) -> actual: %d]\n", ETIME, errno);
#endif

        return (first_ret == SIZE && second_ret == -1 && errno == ETIME);
}

int test_blocking_write_no_space_low(int fd, __attribute__ ((unused)) int minor)
{
        return __test_blocking_write_no_space(fd, LOW_PRIO);
}


int test_blocking_write_no_space_high(int fd, __attribute__ ((unused)) int minor)
{
        return __test_blocking_write_no_space(fd, HIGH_PRIO);
}


int __test_non_blocking_read_no_data(int fd, int prio)
{
        int ret;
        char buff[16];

        mfdf_set_priority(fd, prio);
        mfdf_set_read_modality(fd, NON_BLOCK);
        ret = mfdf_read(fd, buff, 16);

#ifdef VERBOSE
        printf("READ BYTES [expected: -1 -> actual: %d]\n", ret);
        printf("ERRNO      [expected: %d (EAGAIN), %d (ENOMEM), %d (ENODEV) or %d (EBUSY) -> actual: %d]\n", EAGAIN, ENOMEM, ENODEV, EBUSY, errno);
#endif

        return ((ret == -1) && NON_BLOCK_VALID_ERRNO);
}


int test_non_blocking_read_no_data_low(int fd, __attribute__ ((unused)) int minor)
{
        return __test_non_blocking_read_no_data(fd, LOW_PRIO);
}


int test_non_blocking_read_no_data_high(int fd, __attribute__ ((unused)) int minor)
{
        return __test_non_blocking_read_no_data(fd, HIGH_PRIO);
}


int __test_blocking_read_no_data(int fd, int prio)
{
        int ret;
        char buff[16];

        mfdf_set_priority(fd, prio);
        mfdf_set_timeout(fd, WAIT_TIME);
        ret = mfdf_read(fd, buff, 16);

#ifdef VERBOSE
        printf("READ BYTES [expected: -1 -> actual: %d]\n", ret);
        printf("ERRNO      [expected: %d (ETIME) -> actual: %d]\n", ETIME, errno);
#endif

        return (ret == -1 && errno == ETIME);
}


int test_blocking_read_no_data_low(int fd, __attribute__ ((unused)) int minor)
{
        return __test_blocking_read_no_data(fd, LOW_PRIO);
}


int test_blocking_read_no_data_high(int fd, __attribute__ ((unused)) int minor)
{
        return __test_blocking_read_no_data(fd, HIGH_PRIO);
}


/* This array MUST be NULL terminated */
static struct test_case test_cases[] = {
        {"Blocking read with no data (LOW)",            test_blocking_read_no_data_low},
        {"Blocking read with no data (HIGH)",           test_blocking_read_no_data_high},
        {"Non-blocking read with no data (LOW)",        test_non_blocking_read_no_data_low},
        {"Non-blocking read with no data (HIGH)",       test_non_blocking_read_no_data_high},
        {"Blocking write with no space (LOW)",          test_blocking_write_no_space_low},
        {"Blocking write with no space (HIGH)",         test_blocking_write_no_space_high},
        {"Non-blocking write with no space (LOW)",      test_non_blocking_write_no_space_low},
        {"Non-blocking write with no space (HIGH)",     test_non_blocking_write_no_space_high},
        {"Write less byte than read ones (LOW)",        test_write_less_read_more_low},
        {"Write less byte than read ones (HIGH)",       test_write_less_read_more_high},
        {"Standing bytes (LOW)",                        test_standing_bytes_low},
        {"Standing bytes (HIGH)",                       test_standing_bytes_high},
        {"Standing threads (LOW)",                      test_standing_threads_low},
        {"Standing threads (HIGH)",                     test_standing_threads_high},
        {"Subsequent writes on low priority",           test_subsequent_low_writes},
        {"Immutable major from /sys pseudo file",       test_immutable_major_from_sys},
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

        mfdf_close(fd);
        unlink(TEST_DEV);

        switch(ret) {
                case -1:
                        snprintf(outcome, OUTCOME_LEN, YELLOW "ERROR (errcode: %d)" RESET, errno);
                        break;
                case 0:
                        snprintf(outcome, OUTCOME_LEN, RED "FAIL" RESET);
                        break;
                case 1:
                        snprintf(outcome, OUTCOME_LEN, GREEN "SUCCESS" RESET);
                        break;
        }

        printf(TABLE_ROW, minor+1, major, minor, the_test_case->name, outcome);

#ifdef VERBOSE
        printf("\n\n");
#endif
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
