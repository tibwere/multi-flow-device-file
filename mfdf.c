#define EXPORT_SYMTAB
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/version.h>
#include <linux/string.h>
#include <linux/slab.h>

#include "include/ioctl.h"
#include "include/core.h"


/* Module informations */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Simone Tiberi <simone.tiberi.98@gmail.com>");
MODULE_DESCRIPTION("Multi flow device file");

/* Global variables/parameters */
int major;
int enable[MINORS] = {[0 ... (MINORS-1)] = 1};

module_param(major, int, 0440);
module_param_array(enable, int, NULL, 0660);

struct device_state devs[MINORS];
static struct kobject *mfdf_sys_kobj;


/* MIN and MAX utility macros */
#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

/*
 * Retrieve major and minor number from the session according to
 * the version of linux in use
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
#define get_major(session)      MAJOR(session->f_inode->i_rdev)
#define get_minor(session)      MINOR(session->f_inode->i_rdev)
#else
#define get_major(session)      MAJOR(session->f_dentry->d_inode->i_rdev)
#define get_minor(session)      MINOR(session->f_dentry->d_inode->i_rdev)
#endif


static int __always_inline __available_bytes(struct data_flow *flow, int type)
{
        int available_for_read;

        if (flow->off[WOFF] >= flow->off[ROFF])
                available_for_read = flow->off[WOFF] - flow->off[ROFF];
        else
                available_for_read =  (BUFSIZE - flow->off[ROFF]) + flow->off[WOFF];

        return (type == 0) ? available_for_read : BUFSIZE - available_for_read;
}

#define available_bytes_for_read(flow) __available_bytes(flow, 0)
#define available_bytes_for_write(flow) __available_bytes(flow, 1)


static int __always_inline __check_if_bytes_are_available(struct data_flow *flow, int type)
{
        int ret;
        mutex_lock(&(flow->mu));
        ret = (__available_bytes(flow, type) > 0);
        mutex_unlock(&(flow->mu));

        return ret;
}

#define check_if_bytes_are_available_for_read(flow) __check_if_bytes_are_available(flow, 0)
#define check_if_bytes_are_available_for_write(flow) __check_if_bytes_are_available(flow, 1)


static ssize_t sb_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
        int ret, i, high_av, low_av;

        for(i=0, ret=0; i<MINORS; ++i) {
                mutex_lock(&(devs[i].flows[LOW_PRIO].mu));
                low_av = available_bytes_for_read(&(devs[i].flows[LOW_PRIO]));
                mutex_unlock(&(devs[i].flows[LOW_PRIO].mu));

                mutex_lock(&(devs[i].flows[HIGH_PRIO].mu));
                high_av = available_bytes_for_read(&(devs[i].flows[HIGH_PRIO]));
                mutex_unlock(&(devs[i].flows[HIGH_PRIO].mu));

                ret += sprintf(buf + ret, "%3d %4d %4d\n", i, low_av, high_av);
        }

        return ret;
}


static ssize_t sb_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
        return -EACCES;
}


static ssize_t st_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
        int ret, i;
        struct data_flow *lowf, *highf;

        for(i=0, ret=0; i<MINORS; ++i) {
                lowf = &(devs[i].flows[LOW_PRIO]);
                highf = &(devs[i].flows[HIGH_PRIO]);
                ret += sprintf(buf + ret, "%3d %4d %4d\n",
                               i, atomic_read(&(lowf->pending_threads)),
                               atomic_read(&(highf->pending_threads)));
        }

        return ret;
}


static ssize_t st_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
        return -EACCES;
}


static void  __do_effective_write(struct data_flow *flow, const char *buff, size_t len)
{
        size_t to_end_length, from_start_length;

        if(flow->off[WOFF] >= flow->off[ROFF]) {
                to_end_length = MIN(len, (BUFSIZE - flow->off[WOFF]));
                from_start_length = MIN(len - to_end_length, flow->off[ROFF]);
        } else {
                to_end_length = MIN(len, (flow->off[ROFF] - flow->off[WOFF]));
                from_start_length = 0;
        }

        memcpy(flow->buffer + flow->off[WOFF], buff, to_end_length);
        flow->off[WOFF] += to_end_length;

        if (from_start_length > 0) {
                memcpy(flow->buffer, buff + to_end_length, from_start_length);
                flow->off[WOFF] = from_start_length;
        }

        flow->pending_bytes -= (from_start_length + to_end_length);
}


static void write_on_buffer(unsigned long data)
{
        struct work_metadata *the_task = (struct work_metadata *)container_of((void*)data,struct work_metadata,the_work);
        pr_info("%s kworker %d handle a write operation on the low priority flow of %s device [MAJOR: %d, minor: %d]",
               MODNAME, current->pid, DEVICE_NAME, the_task->major, the_task->minor);

        mutex_lock(&(the_task->active_flow->mu));
        __do_effective_write(the_task->active_flow, the_task->buff, the_task->len);
        mutex_unlock(&(the_task->active_flow->mu));

        wake_up_interruptible(&(the_task->active_flow->pending_requests));

        kfree(the_task);

        module_put(THIS_MODULE);
}


#define init_modality(filp) \
        do { \
                ((struct session_metadata *)filp->private_data)->READ_MODALITY = 0x0; \
                ((struct session_metadata *)filp->private_data)->WRITE_MODALITY = 0x0; \
        } while(0)

static int mfdf_open(struct inode *inode, struct file *filp)
{
        int minor;
        struct device_state *the_device;
        pr_info("%s thread %d has called an open on %s device [MAJOR: %d, minor: %d]",
               MODNAME, current->pid, DEVICE_NAME, get_major(filp), get_minor(filp));

        minor = get_minor(filp);
        the_device = devs + minor;
        if (!enable[minor])
                return -EAGAIN;

        filp->private_data = (struct session_metadata *)kzalloc(sizeof(struct session_metadata), GFP_KERNEL);
        if (unlikely(filp->private_data == NULL))
                return -ENOMEM;

        // Default active flow is the low priority one
        set_active_flow(filp, LOW_PRIO);
        init_modality(filp);
        set_timeout(filp, DEFAULT_TOUT);

        return 0;
}


static int mfdf_release(struct inode *inode, struct file *filp)
{
        pr_info("%s thread %d has called a release on %s device [MAJOR: %d, minor: %d]",
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

        __do_effective_write(flow, kernel_buffer, len);
        kfree(kernel_buffer);
        return 0;
}


static int  __deferred_write(struct file *filp, struct device_state *dev, const char __user *buff, size_t len)
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
        int write_operation_retval, retval, wait_return_value;
        struct device_state *the_device;
        struct data_flow *active_flow;

        pr_info("%s thread %d has called a write on %s device [MAJOR: %d, minor: %d]",
               MODNAME, current->pid, DEVICE_NAME, get_major(filp), get_minor(filp));

        the_device = devs + get_minor(filp);
        active_flow = get_active_flow(filp);

        if (is_block_write(filp)) {
                mutex_lock(&(active_flow->mu));
        } else {
                if (!mutex_trylock(&(active_flow->mu)))
                        return -EBUSY;
        }

retry:
        if((available_bytes_for_write(active_flow) == 0) && is_block_write(filp)) {
                mutex_unlock(&(active_flow->mu));
                pr_info("%s thread %d waits until %ld bytes are ready to be written to %s device [MAJOR: %d, minor: %d]",
                       MODNAME, current->pid, len, DEVICE_NAME , get_major(filp), get_minor(filp));

                atomic_inc(&(active_flow->pending_threads));
                wait_return_value = wait_event_interruptible_timeout(
                                active_flow->pending_requests,
                                check_if_bytes_are_available_for_write(active_flow),
                                get_timeout(filp)
                        );
                atomic_dec(&(active_flow->pending_threads));

                mutex_lock(&(active_flow->mu));
                if(wait_return_value == 0) {
                        mutex_unlock(&(active_flow->mu));
                        return -ETIME;
                } else if(wait_return_value == -ERESTARTSYS || available_bytes_for_write(active_flow) == 0) {
                        goto retry;
                }
        }

        retval = MIN(available_bytes_for_write(active_flow) - active_flow->pending_bytes, len);

        if(is_high_active(filp)) {
                if((write_operation_retval = __syncronous_write(active_flow, buff, len)) != 0)
                        retval = write_operation_retval;
        } else {
                if((write_operation_retval = __deferred_write(filp, the_device, buff, len)) != 0)
                        retval = write_operation_retval;
        }

        mutex_unlock(&(active_flow->mu));
        wake_up_interruptible(&(active_flow->pending_requests));

        return retval;
}


static int __do_effective_read(struct data_flow *flow, char __user *buff, size_t len, int *total)
{
        int residual, from_start_len, to_end_len;

        if(flow->off[WOFF] >= flow->off[ROFF]) {
                to_end_len = MIN(len, (flow->off[WOFF] - flow->off[ROFF]));
                from_start_len = 0;
        } else {
                to_end_len = MIN(len, (BUFSIZE - flow->off[ROFF]));
                from_start_len = MIN(len - to_end_len, flow->off[WOFF]);
        }

        residual = copy_to_user(buff, flow->buffer + flow->off[ROFF], to_end_len);
        flow->off[ROFF] += (to_end_len - residual);
        if (unlikely(residual) != 0) {
                *total = (len - residual);
                return -1;
        }

        if (from_start_len > 0) {
                residual = copy_to_user(buff + to_end_len, flow->buffer, from_start_len);
                flow->off[ROFF] = (from_start_len - residual);
                if (unlikely(residual) != 0) {
                        *total = (len - residual);
                        return -1;
                }
        }

        return 0;
}


static ssize_t mfdf_read(struct file *filp, char __user *buff, size_t len, loff_t *off)
{
        int read_bytes, retval, wait_return_value;
        struct device_state *the_device;
        struct data_flow *active_flow;

        pr_info("%s thread %d has called a read on %s device [MAJOR: %d, minor: %d]",
               MODNAME, current->pid, DEVICE_NAME ,get_major(filp), get_minor(filp));

        the_device = devs + get_minor(filp);
        active_flow = get_active_flow(filp);

        if (is_block_read(filp)) {
                mutex_lock(&(active_flow->mu));
        } else {
                if (!mutex_trylock(&(active_flow->mu)))
                        return -EBUSY;
        }

retry:
        if((available_bytes_for_read(active_flow) == 0) && is_block_read(filp)) {
                mutex_unlock(&(active_flow->mu));
                pr_info("%s thread %d waits until %ld bytes are ready to be read from %s device [MAJOR: %d, minor: %d]",
                       MODNAME, current->pid, len, DEVICE_NAME ,get_major(filp), get_minor(filp));

                atomic_inc(&(active_flow->pending_threads));
                wait_return_value = wait_event_interruptible_timeout(
                                active_flow->pending_requests,
                                check_if_bytes_are_available_for_read(active_flow),
                                get_timeout(filp)
                        );
                atomic_dec(&(active_flow->pending_threads));

                mutex_lock(&(active_flow->mu));

                if(wait_return_value == 0) {
                        mutex_unlock(&(active_flow->mu));
                        return -ETIME;
                } else if(wait_return_value == -ERESTARTSYS || available_bytes_for_read(active_flow) == 0) {
                        goto retry;
                }
        }

        retval = MIN(available_bytes_for_read(active_flow), len);

        if(__do_effective_read(active_flow, buff, len, &read_bytes) != 0)
                retval = read_bytes;

        mutex_unlock(&(active_flow->mu));
        wake_up_interruptible(&(active_flow->pending_requests));

        return retval;
}


#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35))
static int mfdf_ioctl(struct inode *inode, struct file *filp, unsigned int cmd, unsigned long arg)
#else
static long mfdf_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
#endif
{
        switch (cmd) {
                case MFDF_IOCTL_SET_PRIO:
                        if (arg != HIGH_PRIO && arg != LOW_PRIO)
                                return -EINVAL;

                        pr_info("%s thread %d used an ioctl on %s device [MAJOR: %d, minor: %d] to change priority to %s",
                               MODNAME, current->pid, DEVICE_NAME ,get_major(filp), get_minor(filp), (arg == HIGH_PRIO) ? "HIGH" : "LOW");

                        set_active_flow(filp, arg);
                        return 0;
                case MFDF_IOCTL_SET_RMOD:
                        if (arg != BLOCK && arg != NON_BLOCK)
                                return -EINVAL;

                        pr_info("%s thread %d used an ioctl on %s device [MAJOR: %d, minor: %d] to change read modality to %s",
                               MODNAME, current->pid, DEVICE_NAME ,get_major(filp), get_minor(filp), (arg == BLOCK) ? "BLOCK" : "NON-BLOCK");

                        set_read_modality(filp, arg);
                        return 0;
                case MFDF_IOCTL_SET_WMOD:
                        if (arg != BLOCK && arg != NON_BLOCK)
                                return -EINVAL;

                        pr_info("%s thread %d used an ioctl on %s device [MAJOR: %d, minor: %d] to change write modality to %s",
                               MODNAME, current->pid, DEVICE_NAME ,get_major(filp), get_minor(filp), (arg == BLOCK) ? "BLOCK" : "NON-BLOCK");

                        set_write_modality(filp, arg);
                        return 0;
                case MFDF_IOCTL_SET_TOUT:
                        pr_info("%s thread %d used an ioctl on %s device [MAJOR: %d, minor: %d] to set timeout for blocking operations to %ld",
                               MODNAME, current->pid, DEVICE_NAME ,get_major(filp), get_minor(filp), arg);

                        set_timeout(filp, arg);
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
        .ioctl           = mfdf_ioctl,
#else
        .unlocked_ioctl = mfdf_ioctl,
#endif
};

/* Attribute for standing bytes */
static struct kobj_attribute sb_attr = __ATTR(standing_bytes, 0440, sb_show, sb_store);

/* Attribute for standing threads */
static struct kobj_attribute st_attr = __ATTR(standing_threads, 0440, st_show, st_store);

/* The group of attributes is useful for creating and deleting them all at once */
static struct attribute *attrs[] = {
	&sb_attr.attr,
	&st_attr.attr,
	NULL,	/* need to NULL terminate the list of attributes */
};

/*
 * Since the group is unnamed, the files associated with the attributes
 * will be created directly under the directory associated with the kobject
 */
static struct attribute_group attr_group = {
	.attrs = attrs,
};

#define init_waitqueues(idx) \
        do { \
                init_waitqueue_head(&(devs[idx].flows[LOW_PRIO].pending_requests)); \
                init_waitqueue_head(&(devs[idx].flows[HIGH_PRIO].pending_requests)); \
        } while(0)

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

                init_waitqueues(i);

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


static int __init mfdf_initialize(void)
{
        major = __register_chrdev(0, 0, MINORS, DEVICE_NAME, &fops);
        if (major < 0) {
                pr_info("%s registering multi-flow device file failed\n", MODNAME);
                return major;
        }

        if(init_devices() == -1) {
                unregister_chrdev(major, DEVICE_NAME);
                return -ENOMEM;
        }

        mfdf_sys_kobj = kobject_create_and_add(SYS_KOBJ_NAME, kernel_kobj);
	if(!mfdf_sys_kobj)
		return -ENOMEM;

	if(sysfs_create_group(mfdf_sys_kobj, &attr_group))
		kobject_put(mfdf_sys_kobj);

        pr_info("%s multi flow device file registered (MAJOR number: %d)\n", MODNAME, major);
        return 0;
}


static void __exit mfdf_cleanup(void)
{
        int i;
        for(i=0; i<MINORS;++i) {
                free_page((unsigned long)devs[i].flows[LOW_PRIO].buffer);
                free_page((unsigned long)devs[i].flows[HIGH_PRIO].buffer);
                destroy_workqueue(devs[i].queue);
        }

        unregister_chrdev(major, DEVICE_NAME);
        kobject_put(mfdf_sys_kobj);
        pr_info("%s multi flow device file unregistered (MAJOR number: %d)\n", MODNAME, major);
}


module_init(mfdf_initialize);
module_exit(mfdf_cleanup);
