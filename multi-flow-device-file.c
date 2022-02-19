#define EXPORT_SYMTAB
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/tty.h>
#include <linux/version.h>

/* Module informations */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Simone Tiberi <simone.tiberi.98@gmail.com>");
MODULE_DESCRIPTION("Multi flow device file");

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MODNAME "[SOA-PROJECT]"     // Module name, useful for debug printk
#define DEVICE_NAME "multi-flow"    // Device name, useful for debug printk
#define MINORS (128)                // Number of minors available
#define BUFSIZE (10)         // Size of buffer

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
struct device_state {
    struct mutex synchronizer;
    char *data;
    int read_offset;
    int write_offset;
} devs[MINORS];

/* Prototypes of driver operations */
static int mfdf_open(struct inode *, struct file *);
static int mfdf_release(struct inode *, struct file *);
static ssize_t mfdf_write(struct file *, const char __user *, size_t, loff_t *);
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
    to_end_length = MIN(len, BUFSIZE - (the_device->write_offset));
    residual = copy_from_user(the_device->data + the_device->write_offset, buff, to_end_length);
    if (unlikely(residual) != 0) {
        mutex_unlock(&(the_device->synchronizer));
        printk("%s Write operation requested by %d on %s device failed", MODNAME, current->pid, DEVICE_NAME);
        return -EBADFD;
    }

    printk("%s First part of write operation requested by %d on %s device succeded (from %d to %ld)",
           MODNAME, current->pid, DEVICE_NAME, the_device->write_offset, the_device->write_offset + to_end_length);
    the_device->write_offset += to_end_length;

    from_start_length = MIN((len - to_end_length), the_device->read_offset);
    if (from_start_length > 0) {
        residual = copy_from_user(the_device->data, buff + to_end_length, from_start_length);
        if (unlikely(residual) != 0) {
            mutex_unlock(&(the_device->synchronizer));
            printk("%s Write operation requested by %d on %s device failed", MODNAME, current->pid, DEVICE_NAME);
            return -EBADFD;
        }

        printk("%s Second part of write operation requested by %d on %s device succeded (from 0 to %ld)",
               MODNAME, current->pid, DEVICE_NAME, from_start_length);
        the_device->write_offset = from_start_length;
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

    if(the_device->write_offset >= the_device->read_offset) {
        to_end_length = MIN(len, (the_device->write_offset - the_device->read_offset));
        from_start_length = 0;
    } else {
        to_end_length = MIN(len, (BUFSIZE - the_device->read_offset));
        from_start_length = MIN(len - to_end_length, the_device->write_offset);
    }

    residual = copy_to_user(buff, the_device->data + the_device->read_offset, to_end_length);
    if (unlikely(residual) != 0) {
        mutex_unlock(&(the_device->synchronizer));
        printk("%s Read operation requested by %d on %s device failed", MODNAME, current->pid, DEVICE_NAME);
        return -EBADFD;
    }

    printk("%s First part of read operation requested by %d on %s device succeded (from %d to %ld)",
           MODNAME, current->pid, DEVICE_NAME, the_device->read_offset, the_device->read_offset + to_end_length);
    the_device->read_offset += to_end_length;

    if (from_start_length > 0) {
        residual = copy_to_user(buff + to_end_length, the_device->data, from_start_length);
        if (unlikely(residual) != 0) {
            mutex_unlock(&(the_device->synchronizer));
            printk("%s Read operation requested by %d on %s device failed", MODNAME, current->pid, DEVICE_NAME);
            return -EBADFD;
        }

        printk("%s Second part of read operation requested by %d on %s device succeded (from 0 to %ld)",
               MODNAME, current->pid, DEVICE_NAME, from_start_length);
        the_device->read_offset = from_start_length;
    }
    mutex_unlock(&(the_device->synchronizer));

    return to_end_length + from_start_length;
}

/* Driver for multi-flow-device-file */
static struct file_operations fops = {
    .owner   = THIS_MODULE,
    .open    = mfdf_open,
    .release = mfdf_release,
    .write   = mfdf_write,
    .read    = mfdf_read
};

/*
 * Initialize devices metadata and return the number of devices initialized
 */
static int init_devices(void) {
    int index;
    for (index=0; index<MINORS; ++index) {
        mutex_init(&(devs[index].synchronizer));
        devs[index].read_offset = 0;
        devs[index].write_offset = 0;
        devs[index].data = (char *)get_zeroed_page(GFP_KERNEL);
        if (unlikely(devs[index].data == NULL)) break;
    }

    return index;
}

int init_module(void)
{
    int last_index = init_devices();
    if (unlikely(last_index != MINORS)) {
        for (; last_index >= 0; --last_index)
            free_page((unsigned long)devs[last_index].data);
        return -ENOMEM;
    }

    major = __register_chrdev(0, 0, MINORS, DEVICE_NAME, &fops);
    if (major < 0) {
        printk("Registering multi-flow device file failed\n");
        return major;
    }

    printk(KERN_INFO "Multi flow device file registered (MAJOR number: %d)\n", major);
    return 0;
}

void cleanup_module(void)
{
    int i;
    for(i=0; i<MINORS;++i)
        free_page((unsigned long)devs[i].data);

    unregister_chrdev(major, DEVICE_NAME);
    printk(KERN_INFO "Multi flow device file unregistered (MAJOR number: %d)\n", major);
}
