#define EXPORT_SYMTAB
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/version.h>
#include <linux/slab.h>

#include "include/ioctl.h"
#include "include/core.h"


/* Major number associated with the device */
int major;
/* Flag to enable the granularity of the minor number */
int enable[MINORS] = {[0 ... (MINORS-1)] = 1};
/* Array of struct device_state to keep track of the state of devices */
static struct device_state devs[MINORS];


/* MIN utility macro */
#define MIN(a,b) (((a)<(b))?(a):(b))

/**
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


/**
 * Function responsible for evaluating the space available
 * for writing by discriminating whether the HIGH or LOW
 * stream is active
 *
 * @flow: current flow
 */
static int __always_inline writable_bytes(struct data_flow *flow)
{
        if (flow->prio_level == HIGH_PRIO)
                return BUFSIZE - flow->valid_bytes;
        else
                return BUFSIZE - flow->valid_bytes - flow->pending_bytes;
}


/**
 * Function invoked by wait_event_interruptible_timeout
 * to check space availability.
 *
 * The lock is released only if the check fails.
 *
 * THIS FUNCTION IS PRACTICALLY IDENTICAL TO THE OTHER ONE
 * (is_it_possible_to_read) BUT TO MAKE THE EXECUTION AS
 * EFFICIENT AS POSSIBLE, IT WAS PREFERRED TO REPLY CODE
 * INSTEAD OF USING AN IF NOT EASILY PREDICTABLE EVERY TIME.
 *
 * @flow: current flow
 */
static int __always_inline is_it_possible_to_write(struct data_flow *flow)
{
        mutex_lock(&(flow->mu));
        if(unlikely(writable_bytes(flow) == 0)) {
                mutex_unlock(&(flow->mu));
                return 0;
        }

        return 1;
}


/**
 * Function invoked by wait_event_interruptible_timeout
 * to check data availability.
 *
 * The lock is released only if the check fails.
 *
 * THIS FUNCTION IS PRACTICALLY IDENTICAL TO THE OTHER ONE
 * (is_it_possible_to_write) BUT TO MAKE THE EXECUTION AS
 * EFFICIENT AS POSSIBLE, IT WAS PREFERRED TO REPLY CODE
 * INSTEAD OF USING AN IF NOT EASILY PREDICTABLE EVERY TIME.
 *
 * @flow: current flow
 */
static int __always_inline is_it_possible_to_read(struct data_flow *flow)
{
        mutex_lock(&(flow->mu));
        if(unlikely(flow->valid_bytes == 0)) {
                mutex_unlock(&(flow->mu));
                return 0;
        }

        return 1;
}


/* Format of each line within the files in /sys/kernel/mfdf */
#define SYS_FMT_LINE "%3d %4d %4d\n"

/**
 * Function responsible for showing the standing bytes
 * being read from the pseudofile in /sys
 *
 * @kobj: kernel object (/sys/kernel/mfdf)
 * @attr: kernel attribute (/sys/kernel/mfdf/standing_bytes)
 * @buff: buffer in which to store the requested data
 */
static ssize_t sb_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
        int ret, i, high_av, low_av;

        for(i=0, ret=0; i<MINORS; ++i) {
                mutex_lock(&(devs[i].flows[LOW_PRIO].mu));
                low_av = devs[i].flows[LOW_PRIO].valid_bytes;
                mutex_unlock(&(devs[i].flows[LOW_PRIO].mu));

                mutex_lock(&(devs[i].flows[HIGH_PRIO].mu));
                high_av = devs[i].flows[HIGH_PRIO].valid_bytes;
                mutex_unlock(&(devs[i].flows[HIGH_PRIO].mu));

                ret += sprintf(buf + ret, SYS_FMT_LINE, i, low_av, high_av);
        }

        return ret;
}


/**
 * Function responsible for showing the standing threads
 * being read from the pseudofile in /sys
 *
 * @kobj: kernel object (/sys/kernel/mfdf)
 * @attr: kernel attribute (/sys/kernel/mfdf/standing_threads)
 * @buff: buffer in which to store the requested data
 */
static ssize_t st_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
        int ret, i;
        struct data_flow *lowf, *highf;

        for(i=0, ret=0; i<MINORS; ++i) {
                lowf = &(devs[i].flows[LOW_PRIO]);
                highf = &(devs[i].flows[HIGH_PRIO]);
                ret += sprintf(buf + ret, SYS_FMT_LINE,
                               i, atomic_read(&(lowf->pending_threads)),
                               atomic_read(&(highf->pending_threads)));
        }

        return ret;
}


/**
 * Makes it impossible to read read-only parameters
 * exposed via pseudofile in /sys/kernel/mfdf
 */
static ssize_t forbidden_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
        return -EACCES;
}



/**
 * Last layer of writing invoked:
 *      - directly from mfdf_write in the synchronous case
 *      - from the write_on_buffer, executed by the kworker, in the asynchronous case
 *
 * @new_data: new data segment
 * @flow:     current flow
 */
static void __always_inline do_the_linkage(struct data_segment *new_data, struct data_flow *flow)
{
        struct list_head *curr, *tail;

        curr = &(new_data->links);
        tail = &(flow->tail);

        curr->prev = tail->prev;
        curr->next = tail;

        tail->prev->next = curr;
        tail->prev = curr;

        flow->valid_bytes += new_data->size;
}


/**
 * Function executed by the kworker to invoke the deferred write
 * on the buffer associated with the current stream
 *
 * @data: pointer to work_metadata struct
 */
static void deferred_write(unsigned long data)
{
        struct work_metadata *the_task = (struct work_metadata *)container_of((void*)data,struct work_metadata,the_work);
        pr_debug("%s kworker %d handle a write operation on the low priority flow of %s device [MAJOR: %d, minor: %d]",
               MODNAME, current->pid, DEVICE_NAME, the_task->major, the_task->minor);

        mutex_lock(&(the_task->active_flow->mu));
        do_the_linkage(the_task->new_data, the_task->active_flow);
        the_task->active_flow->pending_bytes -= the_task->new_data->size;
        mutex_unlock(&(the_task->active_flow->mu));

        wake_up_interruptible(&(the_task->active_flow->pending_requests));

        kfree(the_task);

        module_put(THIS_MODULE);
}


/**
 * File operation: open
 *
 * @inode: metadata associated to file
 * @filp:  pointed by the entry of FDT
 */
static int mfdf_open(struct inode *inode, struct file *filp)
{
        int minor;
        pr_debug("%s thread %d has called an open on %s device [MAJOR: %d, minor: %d]",
               MODNAME, current->pid, DEVICE_NAME, get_major(filp), get_minor(filp));

        minor = get_minor(filp);
        if (!enable[minor])
                return -EAGAIN;

        filp->private_data = (struct session_metadata *)kzalloc(sizeof(struct session_metadata), GFP_KERNEL);
        if (unlikely(filp->private_data == NULL))
                return -ENOMEM;

        // Default active flow is the low priority one
        set_active_flow(filp, LOW_PRIO);
        session_metadata_field_value(filp, READ_MODALITY) = 0x0;
        session_metadata_field_value(filp, WRITE_MODALITY) = 0x0;
        set_timeout(filp, DEFAULT_TOUT);

        return 0;
}


/**
 * File operation: release
 *
 * @inode: metadata associated to file
 * @filp:  pointed by the entry of FDT
 */
static int mfdf_release(struct inode *inode, struct file *filp)
{
        pr_debug("%s thread %d has called a release on %s device [MAJOR: %d, minor: %d]",
               MODNAME, current->pid, DEVICE_NAME, get_major(filp), get_minor(filp));

        kfree(filp->private_data);
        return 0;
}


/**
 * Second function of the chain of invocations for writing on low priority flow.
 * Prepare the metadata needed by the kworker by packing them in a special structure
 *
 * @flow:  current flow
 * @queue: "single threaded" work queue in which to append the deferred write
 * @filp:  pointed by the entry of FDT
 * @buff:  user buffer containing the data to be written
 * @len:   length required to write
 */
static int trigger_deferred_work(struct data_flow *flow, struct data_segment *new_data, struct file *filp, gfp_t flags)
{
        struct work_metadata *the_task;
        struct workqueue_struct *queue;
        int retval;

        if(!try_module_get(THIS_MODULE)) {
                kfree(new_data->buffer);
                kfree(new_data);
                return -ENODEV;
        }

        queue = devs[get_minor(filp)].queue;

        the_task = (struct work_metadata *)kzalloc(sizeof(struct work_metadata), flags);
        if(unlikely(the_task == NULL)) {
                kfree(new_data->buffer);
                kfree(new_data);
                return -ENOMEM;
        }

        the_task->major = get_major(filp);
        the_task->minor = get_minor(filp);
        the_task->active_flow = flow;
        the_task->new_data = new_data;

        retval = new_data->size;

        __INIT_WORK(&(the_task->the_work),(void*)deferred_write,(unsigned long)(&(the_task->the_work)));
        queue_work(queue, &the_task->the_work);

        return retval;
}


/**
 * File operation: write
 *
 * @filp:  pointed by the entry of FDT
 * @buff:  user buffer containing the data to be written
 * @len:   length required to write
 * @off:   offset to write to [DON'T CARE]
 */
static ssize_t mfdf_write(struct file *filp, const char __user *buff, size_t len, loff_t *off)
{
        int residual, retval;
        struct data_flow *active_flow;
        struct data_segment *the_data;
        gfp_t flags;

        pr_debug("%s thread %d has called a write on %s device [MAJOR: %d, minor: %d]",
               MODNAME, current->pid, DEVICE_NAME, get_major(filp), get_minor(filp));

        if (unlikely(len == 0))
                return 0;

        active_flow = get_active_flow(filp);
        flags = (is_block_write(filp)) ? GFP_KERNEL : GFP_ATOMIC;

        the_data = (struct data_segment *)kzalloc(sizeof(struct data_segment), flags);
        if (unlikely(the_data == NULL))
                return -ENOMEM;

        the_data->buffer = (char *)kzalloc(len, flags);
        if (unlikely(the_data->buffer == NULL)) {
                kfree(the_data);
                return -ENOMEM;
        }

        residual = copy_from_user(the_data->buffer, buff, len);


        if (is_block_write(filp)) {
                mutex_lock(&(active_flow->mu));
        } else {
                if (!mutex_trylock(&(active_flow->mu)))
                        return -EBUSY;
        }

        if((writable_bytes(active_flow) == 0) && is_block_write(filp)) {
                mutex_unlock(&(active_flow->mu));
                pr_debug("%s thread %d is waiting for space available for writing on the device %s [MAJOR: %d, minor: %d]",
                       MODNAME, current->pid, DEVICE_NAME , get_major(filp), get_minor(filp));

                atomic_inc(&(active_flow->pending_threads));
                retval = wait_event_interruptible_timeout(
                                active_flow->pending_requests,
                                is_it_possible_to_write(active_flow),
                                get_timeout(filp)
                        );
                atomic_dec(&(active_flow->pending_threads));

                if(retval == 0) {
                        mutex_unlock(&(active_flow->mu));
                        pr_debug("%s timer has expired for thread %d and it is not possible to write to the device %s [MAJOR: %d, minor: %d]",
                                 MODNAME, current->pid, DEVICE_NAME, get_major(filp), get_minor(filp));
                        return -ETIME;
                } else if(retval == -ERESTARTSYS) {
                        mutex_unlock(&(active_flow->mu));
                        pr_debug("%s thread %d was hit with a signal while waiting for available space on device %s [MAJOR: %d, minor: %d]",
                                 MODNAME, current->pid, DEVICE_NAME, get_major(filp), get_minor(filp));
                        return -EINTR;
                }
        }

        if (unlikely(writable_bytes(active_flow) == 0)) {
                kfree(the_data->buffer);
                kfree(the_data);

                retval = -EAGAIN;
                goto out;
        }

        the_data->size = MIN(len - residual, writable_bytes(active_flow));
        if (active_flow->prio_level == HIGH_PRIO) {
                do_the_linkage(the_data, active_flow);
                retval = the_data->size;
        } else {
                retval = trigger_deferred_work(active_flow, the_data, filp, flags);
                if (retval > 0)
                        active_flow->pending_bytes += retval;
        }

out:
        mutex_unlock(&(active_flow->mu));
        wake_up_interruptible(&(active_flow->pending_requests));

        return retval;
}


/**
 * Second layer of the reading invoked directly by the mfdf_read
 *
 * @flow: current flow
 * @buff: user buffer containing the data to be written
 * @len:  size required
 */
static int do_effective_read(struct data_flow *flow, char __user *buff, size_t len, int is_block)
{
        int residual;
        size_t read_bytes, current_readable_bytes, current_read_len;
        struct data_segment *curr;
        struct list_head *head;

        read_bytes = 0;

        head = &(flow->head);
        while ((head->next != &(flow->tail)) && (len > read_bytes)) {
                curr = (struct data_segment *)container_of((void *)head->next, struct data_segment, links);
                current_readable_bytes = curr->size - curr->off;
                current_read_len = MIN(len - read_bytes, current_readable_bytes);

                residual = copy_to_user(buff + read_bytes, &(curr->buffer[curr->off]), current_read_len);
                read_bytes += (current_read_len - residual);
                curr->off += (current_read_len - residual);

                if (curr->off == curr->size) {
                        head->next = head->next->next;
                        head->next->prev = head;

                        kfree(curr->buffer);
                        kfree(curr);
                }
        }

        flow->valid_bytes -= read_bytes;

        return read_bytes;
}


/**
 * File operation: read
 *
 * @filp:  pointed by the entry of FDT
 * @buff:  user buffer in which to write the read data
 * @len:   length required to read
 * @off:   offset to read to [DON'T CARE]
 */
static ssize_t mfdf_read(struct file *filp, char __user *buff, size_t len, loff_t *off)
{
        int retval;
        struct data_flow *active_flow;

        pr_debug("%s thread %d has called a read on %s device [MAJOR: %d, minor: %d]",
               MODNAME, current->pid, DEVICE_NAME ,get_major(filp), get_minor(filp));

        if (unlikely(len == 0))
                return 0;

        active_flow = get_active_flow(filp);

        if (is_block_read(filp)) {
                mutex_lock(&(active_flow->mu));
        } else {
                if (!mutex_trylock(&(active_flow->mu)))
                        return -EBUSY;
        }

        if ((active_flow->valid_bytes == 0) && is_block_read(filp)) {
                mutex_unlock(&(active_flow->mu));
                pr_debug("%s thread %d is waiting for bytes to read from device %s [MAJOR: %d, minor: %d]",
                       MODNAME, current->pid, DEVICE_NAME , get_major(filp), get_minor(filp));

                atomic_inc(&(active_flow->pending_threads));
                retval = wait_event_interruptible_timeout(
                                active_flow->pending_requests,
                                is_it_possible_to_read(active_flow),
                                get_timeout(filp)
                        );
                atomic_dec(&(active_flow->pending_threads));

                if(retval == 0) {
                        mutex_unlock(&(active_flow->mu));
                        pr_debug("%s timer has expired for thread %d and it is not possible to read from the device %s [MAJOR: %d, minor: %d]",
                                 MODNAME, current->pid, DEVICE_NAME, get_major(filp), get_minor(filp));
                        return -ETIME;
                } else if(retval == -ERESTARTSYS) {
                        mutex_unlock(&(active_flow->mu));
                        pr_debug("%s thread %d was hit with a signal while waiting for bytes to read on device %s [MAJOR: %d, minor: %d]",
                                 MODNAME, current->pid, DEVICE_NAME, get_major(filp), get_minor(filp));
                        return -EINTR;
                }
        }

        if (unlikely(active_flow->valid_bytes == 0))
                retval = -EAGAIN;
        else
                retval = do_effective_read(active_flow, buff, len, is_block_read(filp));

        mutex_unlock(&(active_flow->mu));
        wake_up_interruptible(&(active_flow->pending_requests));

        return retval;
}


/**
 * File operation: ioctl (up to v.2.6.35) unlocked_ioctl (from v 2.6.35)
 *
 * @inode: metadata associated to file (up to v.2.6.35)
 * @filp:  pointed by the entry of FDT
 * @cmd:   command required
 * @arg:   argument of command
 */
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

                        pr_debug("%s thread %d used an ioctl on %s device [MAJOR: %d, minor: %d] to change priority to %s",
                               MODNAME, current->pid, DEVICE_NAME ,get_major(filp), get_minor(filp), (arg == HIGH_PRIO) ? "HIGH" : "LOW");

                        set_active_flow(filp, arg);
                        return 0;
                case MFDF_IOCTL_SET_RMOD:
                        if (arg != BLOCK && arg != NON_BLOCK)
                                return -EINVAL;

                        pr_debug("%s thread %d used an ioctl on %s device [MAJOR: %d, minor: %d] to change read modality to %s",
                               MODNAME, current->pid, DEVICE_NAME ,get_major(filp), get_minor(filp), (arg == BLOCK) ? "BLOCK" : "NON-BLOCK");

                        set_read_modality(filp, arg);
                        return 0;
                case MFDF_IOCTL_SET_WMOD:
                        if (arg != BLOCK && arg != NON_BLOCK)
                                return -EINVAL;

                        pr_debug("%s thread %d used an ioctl on %s device [MAJOR: %d, minor: %d] to change write modality to %s",
                               MODNAME, current->pid, DEVICE_NAME ,get_major(filp), get_minor(filp), (arg == BLOCK) ? "BLOCK" : "NON-BLOCK");

                        set_write_modality(filp, arg);
                        return 0;
                case MFDF_IOCTL_SET_TOUT:
                        if (arg > MAX_JIFFIES)
                                return -EINVAL;

                        pr_debug("%s thread %d used an ioctl on %s device [MAJOR: %d, minor: %d] to set timeout for blocking operations to %ld",
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


/* Object in sys for handling read-only parameters */
static struct kobject *mfdf_sys_kobj;

/* Attribute for standing bytes */
static struct kobj_attribute sb_attr = __ATTR(standing_bytes, 0440, sb_show, forbidden_store);

/* Attribute for standing threads */
static struct kobj_attribute st_attr = __ATTR(standing_threads, 0440, st_show, forbidden_store);

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


/**
 * Operations for major param (WRITE IS FORBIDDEN)
 */
static struct kernel_param_ops major_ops = {
	.get	= &param_get_int,
	.set	= NULL,
};


/**
 * Array initialization of struct device_state devs
 */
static int init_devices(void) {
        int i, j;
        char wq_name[64];

        for (i=0; i<MINORS; ++i) {

                for (j=0; j<2; ++j) {
                        devs[i].flows[j].prio_level = j;
                        mutex_init(&(devs[i].flows[j].mu));
                        init_waitqueue_head(&(devs[i].flows[j].pending_requests));

                        devs[i].flows[j].head.next = &(devs[i].flows[j].tail);
                        devs[i].flows[j].tail.prev = &(devs[i].flows[j].head);
                }

                memset(wq_name, 0x0, 64);
                snprintf(wq_name, 64, "mfdf-wq-%03d", i);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36))
                devs[i].queue = alloc_ordered_workqueue(wq_name, 0);
#else
                devs[i].queue = create_singlethread_workqueue(wq_name);
#endif
                if(unlikely(devs[i].queue == NULL))
                        break;

        }

        if (likely(i == MINORS))
                return 0;

        for(i-=1; i>=0; --i)
                destroy_workqueue(devs[i].queue);

        return -1;
}


/**
 * Module init function
 */
static int __init mfdf_initialize(void)
{
        if(init_devices() == -1)
                return -ENOMEM;

        major = __register_chrdev(0, 0, MINORS, DEVICE_NAME, &fops);
        if (major < 0) {
                pr_debug("%s registering multi-flow device file failed\n", MODNAME);
                return major;
        }


        mfdf_sys_kobj = kobject_create_and_add(SYS_KOBJ_NAME, kernel_kobj);
	if(!mfdf_sys_kobj)
		return -ENOMEM;

	if(sysfs_create_group(mfdf_sys_kobj, &attr_group))
		kobject_put(mfdf_sys_kobj);

        pr_debug("%s multi flow device file registered (MAJOR number: %d)\n", MODNAME, major);
        return 0;
}


static void cleanup_device(int minor)
{
        int i;
        struct device_state *current_device;
        struct list_head *head;
        struct data_segment *current_segment;

        current_device = devs + minor;
        destroy_workqueue(devs[minor].queue);

        for (i=0; i<2; ++i) {
                head = &(devs[minor].flows[i].head);
                while (head->next != &(devs[minor].flows[i].tail)) {
                        current_segment = (struct data_segment *)container_of((void *)head->next, struct data_segment, links);
                        head->next = head->next->next;

                        kfree(current_segment->buffer);
                        kfree(current_segment);
                }
        }
}


/**
 * Module cleanup function
 */
static void __exit mfdf_cleanup(void)
{
        int i;
        for(i=0; i<MINORS;++i)
                cleanup_device(i);

        __unregister_chrdev(major, 0, MINORS, DEVICE_NAME);
        kobject_put(mfdf_sys_kobj);
        pr_debug("%s multi flow device file unregistered (MAJOR number: %d)\n", MODNAME, major);
}

/* Things related to module management */
module_param_cb(major, &major_ops, &major, 0440);
module_param_array(enable, int, NULL, 0660);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Simone Tiberi <simone.tiberi.98@gmail.com>");
MODULE_DESCRIPTION("Multi flow device file");

module_init(mfdf_initialize);
module_exit(mfdf_cleanup);
