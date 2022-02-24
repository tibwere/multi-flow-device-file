#ifndef __MFDF_H__
#define __MFDF_H__

#include <fcntl.h>
#include <sys/ioctl.h>

#define LOW_PRIO (0)
#define HIGH_PRIO (1)
#define KEEP_PRIO (2)
#define SET_PRIO_CMD (0)
#define NON_BLOCK (0)
#define BLOCK (1)
#define SET_READ_MODALITY_CMD (1)
#define MFDF_READ_ONLY (O_RDONLY)
#define MFDF_WRITE_ONLY (O_WRONLY)
#define MFDF_READ_WRITE (O_RDWR)

ssize_t mfdf_prio_printf(int, int, const char *restrict, ...);
ssize_t mfdf_prio_gets(int, int, char *, size_t);

#define mfdf_open(path, flags) open(path, flags)
#define mfdf_close(fd) close(fd)
#define mfdf_set_priority(fd,level) ioctl(fd, SET_PRIO_CMD, level)
#define mfdf_set_read_modality(fd,modality) ioctl(fd, SET_READ_MODALITY_CMD, modality)

#define mfdf_printf(fd, format,...) mfdf_prio_printf(fd, KEEP_PRIO, format, ##__VA_ARGS__)
#define mfdf_printf_low(fd, format,...) mfdf_prio_printf(fd, LOW_PRIO, format, ##__VA_ARGS__)
#define mfdf_printf_high(fd, format,...) mfdf_prio_printf(fd, HIGH_PRIO, format, ##__VA_ARGS__)

#define mfdf_gets(fd, buff, len) mfdf_prio_gets(fd, KEEP_PRIO, buff, len)
#define mfdf_gets_low(fd, buff, len) mfdf_prio_gets(fd, LOW_PRIO, buff, len)
#define mfdf_gets_high(fd, buff, len) mfdf_prio_gets(fd, HIGH_PRIO, buff, len)

#endif // !__MFDF_H__
