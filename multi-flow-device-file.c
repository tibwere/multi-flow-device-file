#define EXPORT_SYMTAB
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/tty.h>
#include <linux/version.h>
#include <linux/string.h>


/* Module informations */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Simone Tiberi <simone.tiberi.98@gmail.com>");
MODULE_DESCRIPTION("Multi flow device file");


#define MIN(a,b) (((a)<(b))?(a):(b))
#define MODNAME "[SOA-PROJECT]"     // Module name, useful for debug printk
#define DEVICE_NAME "multi-flow"    // Device name, useful for debug printk
#define MINORS (128)                // Number of minors available
#define BUFSIZE (PAGE_SIZE)         // Size of buffer

// IOCTL stuff
#define SET_PRIO_CMD (0)
#define LOW_PRIO (0)
#define HIGH_PRIO (1)

/* Macro for the retrieve of major and minor code from session */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
    #define get_major(session)      MAJOR(session->f_inode->i_rdev)
    #define get_minor(session)      MINOR(session->f_inode->i_rdev)
#else
    #define get_major(session)      MAJOR(session->f_dentry->d_inode->i_rdev)
    #define get_minor(session)      MINOR(session->f_dentry->d_inode->i_rdev)
#endif


/* Major number for the driver obtained from the subsystem */
int major;
module_param(major, int, 0660);


/* Basic metadata for representing the device */
struct data_flow {
    char *buffer;
    int read_offset;
    int write_offset;
};

struct device_state {
    struct mutex synchronizer;
    struct data_flow flows[2];
    struct data_flow *active_flow;
} devs[MINORS];

#define ACTIVE_BUFFER(dev) dev->active_flow->buffer
#define ACTIVE_RD_OFF(dev) dev->active_flow->read_offset
#define ACTIVE_WR_OFF(dev) dev->active_flow->write_offset

/* Prototypes of driver operations */
static int mfdf_open(struct inode *, struct file *);
static int mfdf_release(struct inode *, struct file *);
static ssize_t mfdf_write(struct file *, const char __user *, size_t, loff_t *);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35))
   static long mfdf_ioctl(struct file *, unsigned int, unsigned long);
#else
    static long mfdf_ioctl(struct file *, unsigned int, unsigned long);
#endif
static int init_devices(void);


static int mfdf_open(struct inode *inode, struct file *file)
{
    printk("%s Thread %d has called an open on %s device [MAJOR: %d, minor: %d]", MODNAME, current->pid, DEVICE_NAME ,get_major(file), get_minor(file));
    return 0;
}


static int mfdf_release(struct inode *inode, struct file *file)
{
    printk("%s Thread %d has called a release on %s device [MAJOR: %d, minor: %d]", MODNAME, current->pid, DEVICE_NAME ,get_major(file), get_minor(file));
    return 0;
}


static ssize_t mfdf_write(struct file * filp, const char __user * buff, size_t len, loff_t *off)
{
    int minor, residual;
    size_t to_end_length, from_start_length;
    struct device_state *the_device;
    printk("%s Thread %d has called a write on %s device [MAJOR: %d, minor: %d]", MODNAME, current->pid, DEVICE_NAME ,get_major(filp), get_minor(filp));

    minor = get_minor(filp);
    the_device = devs + minor;

    mutex_lock(&(the_device->synchronizer));
    to_end_length = MIN(len, BUFSIZE - ACTIVE_WR_OFF(the_device));
    residual = copy_from_user(ACTIVE_BUFFER(the_device) + ACTIVE_WR_OFF(the_device), buff, to_end_length);
    ACTIVE_WR_OFF(the_device) += (to_end_length - residual);
    if (unlikely(residual) != 0) {
        mutex_unlock(&(the_device->synchronizer));
        return (len - residual);
    }

    from_start_length = MIN((len - to_end_length), ACTIVE_RD_OFF(the_device));
    if (from_start_length > 0) {
        residual = copy_from_user(ACTIVE_BUFFER(the_device), buff + to_end_length, from_start_length);
        ACTIVE_WR_OFF(the_device) = (from_start_length - residual);
        if (unlikely(residual) != 0) {
            mutex_unlock(&(the_device->synchronizer));
            return (len-residual);
        }

    }
    mutex_unlock(&(the_device->synchronizer));

    return to_end_length + from_start_length;
}


static ssize_t mfdf_read(struct file *filp, char *buff, size_t len, loff_t *off)
{
    int minor, residual;
    size_t to_end_length, from_start_length;
    struct device_state *the_device;

    printk("%s Thread %d has called a read on %s device [MAJOR: %d, minor: %d]", MODNAME, current->pid, DEVICE_NAME ,get_major(filp), get_minor(filp));

    minor = get_minor(filp);
    the_device = devs + minor;

    mutex_lock(&(the_device->synchronizer));

    if(ACTIVE_WR_OFF(the_device) >= ACTIVE_RD_OFF(the_device)) {
        to_end_length = MIN(len, (ACTIVE_WR_OFF(the_device) - ACTIVE_RD_OFF(the_device)));
        from_start_length = 0;
    } else {
        to_end_length = MIN(len, (BUFSIZE - ACTIVE_RD_OFF(the_device)));
        from_start_length = MIN(len - to_end_length, ACTIVE_WR_OFF(the_device));
    }

    residual = copy_to_user(buff, ACTIVE_BUFFER(the_device) + ACTIVE_RD_OFF(the_device), to_end_length);
    ACTIVE_RD_OFF(the_device) += (to_end_length-residual);
    if (unlikely(residual) != 0) {
        mutex_unlock(&(the_device->synchronizer));
        return (len-residual);
    }

    if (from_start_length > 0) {
        residual = copy_to_user(buff + to_end_length, ACTIVE_BUFFER(the_device), from_start_length);
        ACTIVE_RD_OFF(the_device) = (from_start_length-residual);
        if (unlikely(residual) != 0) {
            mutex_unlock(&(the_device->synchronizer));
            return (len-residual);
        }

    }
    mutex_unlock(&(the_device->synchronizer));

    return to_end_length + from_start_length;
}


#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35))
   static int mfdf_ioctl(struct inode *inode, struct file *filp, unsigned int cmd, unsigned long arg)
#else
    static long mfdf_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
#endif
{
    struct device_state *the_device;
    int minor;

    minor = get_minor(filp);
    the_device = devs + minor;

    switch (cmd) {
        case SET_PRIO_CMD:
            if (arg != HIGH_PRIO && arg != LOW_PRIO)
                return -EINVAL;

            mutex_lock(&(the_device->synchronizer));
            printk("%s Thread %d used an ioctl on %s device [MAJOR: %d, minor: %d] to change priority to %s",
                   MODNAME, current->pid, DEVICE_NAME ,get_major(filp), get_minor(filp), (arg == HIGH_PRIO) ? "HIGH" : "LOW");
            the_device->active_flow = &(the_device->flows[arg]);
            mutex_unlock(&(the_device->synchronizer));
            return 0;
        default:
            return -EINVAL;
    }
}


/* Driver for multi-flow-device-file */
static struct file_operations fops = {
    .owner          = THIS_MODULE,
    .open           = mfdf_open,
    .release        = mfdf_release,
    .write          = mfdf_write,
    .read           = mfdf_read,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35))
   .ioctl          = mfdf_ioctl
#else
    .unlocked_ioctl = mfdf_ioctl
#endif
};


/*
 * Initialize devices metadata and return the number of devices initialized
 */
static int init_devices(void) {
    int i;

    memset(devs, 0x0, MINORS * sizeof(struct device_state));

    for (i=0; i<MINORS; ++i) {
        mutex_init(&(devs[i].synchronizer));

        devs[i].flows[LOW_PRIO].buffer = (char *)get_zeroed_page(GFP_KERNEL);
        if (unlikely(devs[i].flows[LOW_PRIO].buffer == NULL))
            break;

        devs[i].flows[HIGH_PRIO].buffer = (char *)get_zeroed_page(GFP_KERNEL);
        if(unlikely(devs[i].flows[HIGH_PRIO].buffer == NULL)) {
            free_page((unsigned long)devs[i].flows[LOW_PRIO].buffer);
            break;
        }

        // default flow is low priority
        devs[i].active_flow = &(devs[i].flows[LOW_PRIO]);
    }

    if (likely(i == MINORS))
        return 0;

    for(i-=1; i>=0; --i) {
        free_page((unsigned long)devs[i].flows[LOW_PRIO].buffer);
        free_page((unsigned long)devs[i].flows[HIGH_PRIO].buffer);
    }

    return -1;
}


int mfdf_initialize(void)
{
    if(init_devices() == -1)
        return -ENOMEM;

    major = __register_chrdev(0, 0, MINORS, DEVICE_NAME, &fops);
    if (major < 0) {
        printk("Registering multi-flow device file failed\n");
        return major;
    }

    printk(KERN_INFO "Multi flow device file registered (MAJOR number: %d)\n", major);
    return 0;
}


void mfdf_cleanup(void)
{
    int i;
    for(i=0; i<MINORS;++i) {
        free_page((unsigned long)devs[i].flows[LOW_PRIO].buffer);
        free_page((unsigned long)devs[i].flows[HIGH_PRIO].buffer);
    }

    unregister_chrdev(major, DEVICE_NAME);
    printk(KERN_INFO "Multi flow device file unregistered (MAJOR number: %d)\n", major);
}

module_init(mfdf_initialize);
module_exit(mfdf_cleanup);
