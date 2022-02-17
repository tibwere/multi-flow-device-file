#define EXPORT_SYMTAB
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/tty.h>
#include <linux/version.h>
#include <linux/signal_types.h>
#include <linux/syscalls.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Simone Tiberi email: simone.tiberi.98@gmail.com");

#define MODNAME "[SOA-PROJECT]"
#define DEVICE "multi-flow"

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
static int procctl_open(struct inode *, struct file *);
static int procctl_release(struct inode *, struct file *);
static ssize_t procctl_write(struct file *, const char __user *, size_t, loff_t *);

static int procctl_open(struct inode *inode, struct file *file)
{
    printk("%s Thread %d has called an open on %s device [MAJOR: %d, minor: %d]", MODNAME, current->pid, DEVICE ,get_major(file), get_minor(file));
    return 0;
}

static int procctl_release(struct inode *inode, struct file *file)
{
    printk("%s Thread %d has called an release on %s device [MAJOR: %d, minor: %d]", MODNAME, current->pid, DEVICE ,get_major(file), get_minor(file));
    return 0;
}

static ssize_t procctl_write(struct file * filp, const char __user * buff, size_t len, loff_t *off) 
{
    printk("%s Thread %d has called an write on %s device [MAJOR: %d, minor: %d]", MODNAME, current->pid, DEVICE ,get_major(filp), get_minor(filp));
    return len;
}

/* Driver for multi-flow-device-file */
static struct file_operations fops = {
    .owner   = THIS_MODULE,
    .open    = procctl_open,
    .release = procctl_release,
    .write   = procctl_write
};

int init_module(void)
{
    major = register_chrdev(0, DEVICE, &fops);
 
    if (major < 0) {
        printk("Registering process controller device failed\n");
        return major;
    }

    printk(KERN_INFO "Process controller device registered, it is assigned major number %d\n", major);
    return 0;
}

void cleanup_module(void)
{
    unregister_chrdev(major, DEVICE);
    printk(KERN_INFO "Process controller device unregistered, it was assigned major number %d\n", major);
}
