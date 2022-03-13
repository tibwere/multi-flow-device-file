#ifndef __MFDF_H__
#define __MFDF_H__

#include <fcntl.h>
#include <sys/ioctl.h>
#include <mfdf/ioctl.h>

/*
 * For more details:
 *      - install the user library with
 *              # make install
 *
 *      - visit the manpage with:
 *              $ man mfdf_user.h
 */

#define MFDF_MAX_FLOW_SIZE (8192)

ssize_t mfdf_printf(int, const char *restrict, ...);

#define mfdf_open(path, flags)                  open(path, flags)
#define mfdf_close(fd)                          close(fd)
#define mfdf_set_priority(fd, level)            ioctl(fd, MFDF_IOCTL_SET_PRIO, level)
#define mfdf_set_read_modality(fd, modality)    ioctl(fd, MFDF_IOCTL_SET_RMOD, modality)
#define mfdf_set_write_modality(fd, modality)   ioctl(fd, MFDF_IOCTL_SET_WMOD, modality)
#define mfdf_set_timeout(fd, timeout)           ioctl(fd, MFDF_IOCTL_SET_TOUT, timeout)
#define mfdf_read(fd, buff, size)               read(fd, buff, size)
#define mfdf_write(fd, buff, size)              write(fd, buff, size)

#endif // !__MFDF_H__
