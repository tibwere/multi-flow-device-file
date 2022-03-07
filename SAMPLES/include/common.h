#ifndef __H_MFDF_SAMPLE_COMMON__
#define __H_MFDF_SAMPLE_COMMON__

#define MAJOR_SYS "/sys/module/mfdf/parameters/major"
#define DEMO_DEV "/dev/demo-mfdf"
#define TEST_DEV "/dev/test-mfdf"

int get_major_number(void);
int init_test_environment(const char *, int, int);

#endif // !__H_MFDF_SAMPLE_COMMON__
