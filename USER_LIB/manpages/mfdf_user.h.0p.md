---
title: mfdf/user.h
section: 0P
---

# NAME
mfdf/user.h - Operations available for multi flow device files

# SYNOPSIS
\#include <mfdf/user.h>

# DESCRIPTION
Below is a brief description of what is in the mfdf/user.h library:

- Constants

        - KEEP_PRIO:       to be used in the invocation of mfdf_prio_printf to not change the currently active stream
        - MFDF_READ_ONLY:  to be used to open device file in read-only mode (equiv. O_RDONLY)
        - MFDF_WRITE_ONLY: to be used to open device file in read-only mode (equiv. O_WRONLY)
        - MFDF_READ_WRITE: to be used to open device file in read-only mode (equiv. O_RDWR)

- Functions

        - ssize_t mfdf_prio_printf(int fd, int prio, const char *restrict fmt, ...): it writes in printf-like mode on the file associated with the descriptor fd after setting the priority
        - ssize_t mfdf_prio_gets(int fd, int prio, char *buff, size_t len):          reads at most len bytes from the device and stores what is read in buff after setting the priority

- Facilities macros:

        - mfdf_open(path, flags):               equivalent to open(path, flags)
        - mfdf_close(fd):                       equivalent to close(fd)
        - mfdf_set_priority(fd,level):          equivalent to ioctl(fd, MFDF_IOCTL_SET_PRIO, level)
        - mfdf_set_read_modality(fd,modality):  equivalent to ioctl(fd, MFDF_IOCTL_SET_RMOD, modality)
        - mfdf_set_write_modality(fd,modality): equivalent to ioctl(fd, MFDF_IOCTL_SET_WMOD, modality)
        - mfdf_printf(fd, format,...):          equivalent to mfdf_prio_printf(fd, KEEP_PRIO, format, ##__VA_ARGS__)
        - mfdf_printf_low(fd, format,...):      equivalent to mfdf_prio_printf(fd, LOW_PRIO, format, ##__VA_ARGS__)
        - mfdf_printf_high(fd, format,...):     equivalent to mfdf_prio_printf(fd, HIGH_PRIO, format, ##__VA_ARGS__)
        - mfdf_gets(fd, buff, len):             equivalent to mfdf_prio_gets(fd, KEEP_PRIO, buff, len)
        - mfdf_gets_low(fd, buff, len):         equivalent to mfdf_prio_gets(fd, LOW_PRIO, buff, len)
        - mfdf_gets_high(fd, buff, len):        equivalent to mfdf_prio_gets(fd, HIGH_PRIO, buff, len)

# AUTHORS
Simone Tiberi <simone.tiberi.98@gmail.com>

# SEE ALSO
<sys/ioctl.h>, <stdio.h>, <fcntl.h>, <unistd.h>
