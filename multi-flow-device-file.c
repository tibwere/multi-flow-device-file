#define EXPORT_SYMTAB
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/tty.h>
#include <linux/version.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Simone Tiberi <simone.tiberi.98@gmail.com>");
MODULE_DESCRIPTION("Multi flow device file");

#define MODNAME "[SOA-PROJECT]"
#define DEVICE_NAME "multi-flow"

/* Macro for the retrieve of major and minor code */
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

/* Prototypes of driver operations */
static int mfdf_open(struct inode *, struct file *);
static int mfdf_release(struct inode *, struct file *);
static ssize_t mfdf_write(struct file *, const char __user *, size_t, loff_t *);

static int mfdf_open(struct inode *inode, struct file *file)
{
    printk("%s Thread %d has called an open on %s device [MAJOR: %d, minor: %d]", MODNAME, current->pid, DEVICE_NAME ,get_major(file), get_minor(file));
    return 0;
}

static int mfdf_release(struct inode *inode, struct file *file)
{
    printk("%s Thread %d has called an release on %s device [MAJOR: %d, minor: %d]", MODNAME, current->pid, DEVICE_NAME ,get_major(file), get_minor(file));
    return 0;
}

static ssize_t mfdf_write(struct file * filp, const char __user * buff, size_t len, loff_t *off) 
{
    printk("%s Thread %d has called an write on %s device [MAJOR: %d, minor: %d]", MODNAME, current->pid, DEVICE_NAME ,get_major(filp), get_minor(filp));
    return len;
}

/* Driver for multi-flow-device-file */
static struct file_operations fops = {
    .owner   = THIS_MODULE,
    .open    = mfdf_open,
    .release = mfdf_release,
    .write   = mfdf_write
};

int init_module(void)
{
    major = __register_chrdev(0, 0, 128, DEVICE_NAME, &fops);
    if (major < 0) {
        printk("Registering multi-flow device file failed\n");
        return major;
    }

    printk(KERN_INFO "Multi flow device file registered (MAJOR number: %d)\n", major);
    return 0;
}

void cleanup_module(void)
{
    unregister_chrdev(major, DEVICE_NAME);
    printk(KERN_INFO "Multi flow device file unregistered (MAJOR number: %d)\n", major);
}
