#ifndef __H_IOCTL__
#define __H_IOCTL__

#include <linux/ioctl.h>

#define MFDF_IOCTL_MAGIC    (0x29)
#define MFDF_IOCTL_SET_PRIO _IOW(MFDF_IOCTL_MAGIC, 0, int)
#define MFDF_IOCTL_SET_RMOD _IOW(MFDF_IOCTL_MAGIC, 1, int)
#define MFDF_IOCTL_SET_WMOD _IOW(MFDF_IOCTL_MAGIC, 2, int)
#define MFDF_IOCTL_SET_TOUT _IOW(MFDF_IOCTL_MAGIC, 3, int)

#define LOW_PRIO  (0)
#define HIGH_PRIO (1)

#define BLOCK     (0)
#define NON_BLOCK (1)

#define DEFAULT_TOUT (0x29314)

#endif // !__H_IOCTL__
