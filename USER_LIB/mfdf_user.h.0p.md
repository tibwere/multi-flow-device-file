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

        - MFDF_MAX_FLOW_SIZE                                            maximum number of bytes writable in a stream
        - ssize_t mfdf_printf(int fd, const char *restrict fmt, ...):   it writes in printf-like mode on the file associated with the descriptor fd

        - mfdf_open(path, flags):                                       equivalent to open(path, flags)
        - mfdf_close(fd):                                               equivalent to close(fd)
        - mfdf_set_priority(fd, level):                                 equivalent to ioctl(fd, MFDF_IOCTL_SET_PRIO, level)
        - mfdf_set_read_modality(fd, modality):                         equivalent to ioctl(fd, MFDF_IOCTL_SET_RMOD, modality)
        - mfdf_set_write_modality(fd, modality):                        equivalent to ioctl(fd, MFDF_IOCTL_SET_WMOD, modality)
        - mfdf_set_timeout(fd, timeout):                                equivalent to ioctl(fd, MFDF_IOCTL_SET_TOUT, timeout)
        - mfdf_read(fd, buff, len):                                     equivalent to read(fd, buff, len);
        - mfdf_write(fd, buff, len):                                    equivalent to write(fd, buff, len);

# AUTHORS
Simone Tiberi <simone.tiberi.98@gmail.com>

# SEE ALSO
<sys/ioctl.h>, <stdio.h>, <fcntl.h>, <unistd.h>
