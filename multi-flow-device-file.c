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
#include <linux/slab.h>


/* Module informations */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Simone Tiberi <simone.tiberi.98@gmail.com>");
MODULE_DESCRIPTION("Multi flow device file");


/* "Constants" macros */
#define MODNAME "[SOA-PROJECT]"     // Module name, useful for debug printk
#define DEVICE_NAME "multi-flow"    // Device name, useful for debug printk
#define MINORS (128)                // Number of minors available
#define BUFSIZE (PAGE_SIZE)         // Size of buffer

#define SET_PRIO_CMD (0)
#define LOW_PRIO (0)
#define HIGH_PRIO (1)
#define BLOCK (0)
#define NON_BLOCK (1)


/* Global variables/module parameters */
int major;
module_param(major, int, 0660);


/* Data structures */
struct data_flow {
    struct mutex mu;
    char *buffer;
    int read_offset;
    int write_offset;
    int standing_bytes;
};

struct device_state {
    struct data_flow flows[2];
    struct workqueue_struct *queue;
} devs[MINORS];

struct work_metadata {
    int major;
    int minor;
    struct data_flow *active_flow;
    char buff[BUFSIZE];
    size_t len;
    struct work_struct the_work;
};

struct session_metadata {
    struct data_flow *active_flow;
    int modality;
    int timeout;
};


/* "Code" macros */
#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
    #define get_major(session)      MAJOR(session->f_inode->i_rdev)
    #define get_minor(session)      MINOR(session->f_inode->i_rdev)
#else
    #define get_major(session)      MAJOR(session->f_dentry->d_inode->i_rdev)
    #define get_minor(session)      MINOR(session->f_dentry->d_inode->i_rdev)
#endif

#define get_writable_space(flow) (BUFSIZE - flow->standing_bytes)
#define update_standing_bytes_write(flow, len) flow->standing_bytes = MIN(flow->standing_bytes + len, BUFSIZE)
#define update_standing_bytes_read(flow, len) flow->standing_bytes = MAX(flow->standing_bytes - len, 0)

#define get_active_flow(filp) __atomic_load_n(&(((struct session_metadata *)filp->private_data)->active_flow), __ATOMIC_SEQ_CST)
#define set_active_flow(filp, newflow) __atomic_store_n(&(((struct session_metadata *)filp->private_data)->active_flow), newflow, __ATOMIC_SEQ_CST)
#define is_high_active(filp, dev) (get_active_flow(filp) == &(dev->flows[HIGH_PRIO]))


/* Prototypes */
static int mfdf_open(struct inode *, struct file *);
static int mfdf_release(struct inode *, struct file *);
static ssize_t mfdf_write(struct file *, const char __user *, size_t, loff_t *);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35))
   static long mfdf_ioctl(struct file *, unsigned int, unsigned long);
#else
    static long mfdf_ioctl(struct file *, unsigned int, unsigned long);
#endif
static int init_devices(void);
static void write_on_buffer(unsigned long);
static void __always_inline __do_write_on_buffer_unlocked(struct data_flow *, const char *, size_t);
static int __always_inline __deferred_write(struct file *, struct device_state *, const char __user *, size_t);
static int __always_inline __syncronous_write(struct data_flow *, const char __user *, size_t);


static void write_on_buffer(unsigned long data)
{
    struct work_metadata *the_task = (struct work_metadata *)container_of((void*)data,struct work_metadata,the_work);
    printk("%s kworker %d handle a write operation on the low priority flow of %s device [MAJOR: %d, minor: %d]",
           MODNAME, current->pid, DEVICE_NAME, the_task->major, the_task->minor);

    mutex_lock(&(the_task->active_flow->mu));
    __do_write_on_buffer_unlocked(the_task->active_flow, the_task->buff, the_task->len);
    mutex_unlock(&(the_task->active_flow->mu));

    kfree(the_task);

    module_put(THIS_MODULE);
}

static void __always_inline __do_write_on_buffer_unlocked(struct data_flow *flow, const char *buff, size_t len)
{
    size_t to_end_length, from_start_length;

    to_end_length = MIN(len, BUFSIZE - flow->write_offset);
    memcpy(flow->buffer + flow->write_offset, buff, to_end_length);
    flow->write_offset += to_end_length;

    from_start_length = MIN((len - to_end_length), flow->read_offset);
    if (from_start_length > 0) {
        memcpy(flow->buffer, buff + to_end_length, from_start_length);
        flow->write_offset = from_start_length;
    }
}

static int mfdf_open(struct inode *inode, struct file *filp)
{
    struct device_state *the_device;
    printk("%s Thread %d has called an open on %s device [MAJOR: %d, minor: %d]",
           MODNAME, current->pid, DEVICE_NAME, get_major(filp), get_minor(filp));

    the_device = devs + get_minor(filp);

    filp->private_data = (struct session_metadata *)kzalloc(sizeof(struct session_metadata), GFP_KERNEL);
    if (unlikely(filp->private_data == NULL))
        return -ENOMEM;

    // Default active flow is the low priority one
    ((struct session_metadata *)filp->private_data)->active_flow = &(the_device->flows[LOW_PRIO]);
    ((struct session_metadata *)filp->private_data)->modality = BLOCK;
    ((struct session_metadata *)filp->private_data)->timeout = 0;

    return 0;
}

static int mfdf_release(struct inode *inode, struct file *filp)
{
    printk("%s Thread %d has called a release on %s device [MAJOR: %d, minor: %d]",
           MODNAME, current->pid, DEVICE_NAME, get_major(filp), get_minor(filp));

    kfree(filp->private_data);
    return 0;
}

static int __always_inline __syncronous_write(struct data_flow *flow, const char __user *user_buffer, size_t len)
{
    char *kernel_buffer;
    if((kernel_buffer = (char *)kzalloc(BUFSIZE, GFP_KERNEL)) == NULL)
        return -ENOMEM;

    if(copy_from_user(kernel_buffer, user_buffer, len) != 0)
        return -ENOMEM;

    __do_write_on_buffer_unlocked(flow, kernel_buffer, len);
    kfree(kernel_buffer);
    return 0;
}

static int __always_inline __deferred_write(struct file *filp, struct device_state *dev, const char __user *buff, size_t len)
{
    struct work_metadata *the_task;

    if(!try_module_get(THIS_MODULE))
        return -ENODEV;

    the_task = (struct work_metadata *)kzalloc(sizeof(struct work_metadata), GFP_KERNEL);
    if(unlikely(the_task == NULL))
        return -ENOMEM;

    the_task->major = get_major(filp);
    the_task->minor = get_minor(filp);
    the_task->active_flow = get_active_flow(filp);
    the_task->len = len;
    if (copy_from_user(the_task->buff, buff, len) != 0) {
        kfree(the_task);
        return -ENOMEM;
    }

    __INIT_WORK(&(the_task->the_work),(void*)write_on_buffer,(unsigned long)(&(the_task->the_work)));
    queue_work(dev->queue, &the_task->the_work);

    return 0;
}

static ssize_t mfdf_write(struct file * filp, const char __user *buff, size_t len, loff_t *off)
{
    int write_operation_retval, retval;
    struct device_state *the_device;
    struct data_flow *active_flow;

    printk("%s Thread %d has called a write on %s device [MAJOR: %d, minor: %d]",
           MODNAME, current->pid, DEVICE_NAME, get_major(filp), get_minor(filp));

    the_device = devs + get_minor(filp);
    active_flow = get_active_flow(filp);

    mutex_lock(&(active_flow->mu));

    retval = MIN(get_writable_space(active_flow), len);
    update_standing_bytes_write(active_flow, len);

    if(is_high_active(filp, the_device)) {
        if((write_operation_retval = __syncronous_write(active_flow, buff, len)) != 0)
            retval = write_operation_retval;
    } else {
        if((write_operation_retval = __deferred_write(filp, the_device, buff, len)) != 0)
            retval = write_operation_retval;
    }

    mutex_unlock(&(active_flow->mu));
    return retval;
}

static ssize_t mfdf_read(struct file *filp, char *buff, size_t len, loff_t *off)
{
    int residual;
    size_t to_end_length, from_start_length;
    struct device_state *the_device;
    struct data_flow *active_flow;

    printk("%s Thread %d has called a read on %s device [MAJOR: %d, minor: %d]",
           MODNAME, current->pid, DEVICE_NAME ,get_major(filp), get_minor(filp));

    the_device = devs + get_minor(filp);
    active_flow = get_active_flow(filp);

    mutex_lock(&(active_flow->mu));
    update_standing_bytes_read(active_flow, len);

    if(active_flow->write_offset >= active_flow->read_offset) {
        to_end_length = MIN(len, (active_flow->write_offset - active_flow->read_offset));
        from_start_length = 0;
    } else {
        to_end_length = MIN(len, (BUFSIZE - active_flow->read_offset));
        from_start_length = MIN((len - to_end_length), active_flow->write_offset);
    }

    residual = copy_to_user(buff, active_flow->buffer + active_flow->read_offset, to_end_length);
    active_flow->read_offset += (to_end_length-residual);
    if (unlikely(residual) != 0) {
        mutex_unlock(&(active_flow->mu));
        return (len-residual);
    }

    if (from_start_length > 0) {
        residual = copy_to_user(buff + to_end_length, active_flow->buffer, from_start_length);
        active_flow->read_offset = (from_start_length-residual);
        if (unlikely(residual) != 0) {
            mutex_unlock(&(active_flow->mu));
            return (len-residual);
        }

    }
    mutex_unlock(&(active_flow->mu));

    return to_end_length + from_start_length;
}


#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35))
   static int mfdf_ioctl(struct inode *inode, struct file *filp, unsigned int cmd, unsigned long arg)
#else
    static long mfdf_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
#endif
{
    struct device_state *the_device = devs + get_minor(filp);

    switch (cmd) {
        case SET_PRIO_CMD:
            if (arg != HIGH_PRIO && arg != LOW_PRIO)
                return -EINVAL;

            printk("%s Thread %d used an ioctl on %s device [MAJOR: %d, minor: %d] to change priority to %s",
                   MODNAME, current->pid, DEVICE_NAME ,get_major(filp), get_minor(filp), (arg == HIGH_PRIO) ? "HIGH" : "LOW");

            set_active_flow(filp, &(the_device->flows[arg]));
            return 0;
        default:
            return -EINVAL;
    }
}


/* Driver for multi-flow-device-file */
static struct file_operations fops = {
    .owner          = THIS_MODULE,
    .open           = mfdf_open,
    .write          = mfdf_write,
    .read           = mfdf_read,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35))
   .ioctl           = mfdf_ioctl,
#else
    .unlocked_ioctl = mfdf_ioctl,
#endif
    .release        = mfdf_release,
};


/*
 * Initialize devices metadata and return the number of devices initialized
 */
static int init_devices(void) {
    int i;
    char wq_name[64];

    memset(devs, 0x0, MINORS * sizeof(struct device_state));

    for (i=0; i<MINORS; ++i) {
        mutex_init(&(devs[i].flows[LOW_PRIO].mu));
        mutex_init(&(devs[i].flows[HIGH_PRIO].mu));

        devs[i].flows[LOW_PRIO].buffer = (char *)get_zeroed_page(GFP_KERNEL);
        if (unlikely(devs[i].flows[LOW_PRIO].buffer == NULL))
            break;

        devs[i].flows[HIGH_PRIO].buffer = (char *)get_zeroed_page(GFP_KERNEL);
        if(unlikely(devs[i].flows[HIGH_PRIO].buffer == NULL)) {
            free_page((unsigned long)devs[i].flows[LOW_PRIO].buffer);
            break;
        }

        /* N.B. other fields initialization is not necessary due to previout memset */

        memset(wq_name, 0x0, 64);
        snprintf(wq_name, 64, "mfdf-wq-%d-%d", major, i);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36))
        devs[i].queue = alloc_ordered_workqueue(wq_name, 0);
#else
        devs[i].queue = create_singlethread_workqueue(wq_name);
#endif
        if(unlikely(devs[i].queue == NULL)) {
            free_page((unsigned long)devs[i].flows[LOW_PRIO].buffer);
            free_page((unsigned long)devs[i].flows[HIGH_PRIO].buffer);
            break;
        }
    }

    if (likely(i == MINORS))
        return 0;

    for(i-=1; i>=0; --i) {
        free_page((unsigned long)devs[i].flows[LOW_PRIO].buffer);
        free_page((unsigned long)devs[i].flows[HIGH_PRIO].buffer);
        destroy_workqueue(devs[i].queue);
    }

    return -1;
}


int mfdf_initialize(void)
{
    major = __register_chrdev(0, 0, MINORS, DEVICE_NAME, &fops);
    if (major < 0) {
        printk("Registering multi-flow device file failed\n");
        return major;
    }

    if(init_devices() == -1) {
        unregister_chrdev(major, DEVICE_NAME);
        return -ENOMEM;
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
        destroy_workqueue(devs[i].queue);
    }

    unregister_chrdev(major, DEVICE_NAME);
    printk(KERN_INFO "Multi flow device file unregistered (MAJOR number: %d)\n", major);
}

module_init(mfdf_initialize);
module_exit(mfdf_cleanup);
