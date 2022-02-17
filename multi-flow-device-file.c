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

#define MODNAME "[SOA-PROJECT]"   // Module name, useful for debug printk
#define DEVICE_NAME "multi-flow"  // Device name, useful for debug printk
#define MINORS (128)              // Number of minors available

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
  int valid_offset;
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
  int residual;
  int minor = get_minor(filp);
  struct device_state *the_device = devs + minor;

  printk("%s Thread %d has called a write on %s device [MAJOR: %d, minor: %d]", MODNAME, current->pid, DEVICE_NAME ,get_major(filp), get_minor(filp));

  mutex_lock(&(the_device->synchronizer));

  if (*off > PAGE_SIZE) { // if offset is invalid return error (errno: ENOSPC)
    mutex_unlock(&(the_device->synchronizer));
    return -ENOSPC;
  }

  if((PAGE_SIZE - *off) < len) // if length is greater than available space, adjust it
    len = PAGE_SIZE - *off;

  // Write data and update offset
  residual = copy_from_user(&(the_device->data[*off]),buff,len);
  *off += (len - residual);
  the_device->valid_offset = *off;

  mutex_unlock(&(the_device->synchronizer));

  return len - residual;
}

static ssize_t mfdf_read(struct file *filp, char *buff, size_t len, loff_t *off)
{
  int residual;
  int minor = get_minor(filp);
  struct device_state *the_device = devs + minor;

  printk("%s Thread %d has called a read on %s device [MAJOR: %d, minor: %d]", MODNAME, current->pid, DEVICE_NAME ,get_major(filp), get_minor(filp));

  mutex_lock(&(the_device->synchronizer));

  if(*off > the_device->valid_offset) {
 	 mutex_unlock(&(the_device->synchronizer));
	 return 0;
  }
  if((the_device->valid_offset - *off) < len)
    len = the_device->valid_offset - *off;

  residual = copy_to_user(buff,&(the_device->data[*off]),len);

  *off += (len - residual);
  mutex_unlock(&(the_device->synchronizer));

  return len - residual;
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
  int i;
  for (i=0; i<MINORS; ++i) {
    mutex_init(&(devs[i].synchronizer));
    devs[i].data = (char *)get_zeroed_page(GFP_KERNEL);
    if (devs[i].data == NULL) break;
  }

  return i;
}

int init_module(void)
{
  int tot = init_devices();
  if (tot != MINORS) {
    for(; tot>=0; --tot)
      free_page((unsigned long)devs[tot].data);
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
  for(i=0; i<MINORS;++i) {
    free_page((unsigned long)devs[i].data);
  }
  unregister_chrdev(major, DEVICE_NAME);
  printk(KERN_INFO "Multi flow device file unregistered (MAJOR number: %d)\n", major);
}
