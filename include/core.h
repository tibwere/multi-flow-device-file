#ifndef __H_CORE__
#define __H_CORE__

#include <linux/kconfig.h> // for CONFIG_HZ constant

/* "Constants" macros */
#define MODNAME "[MFDF]"         // Module name, useful for debug printk
#define DEVICE_NAME "multi-flow" // Device name, useful for debug printk
#define MINORS (128)             // Number of minors available
#define BUFSIZE (PAGE_SIZE)      // Size of buffer


/*
 * This structure represents the single stream (HIGH or LOW)
 * associated with the i-th device file (with 0 <= i <= 127).
 * It contains metadata such as the buffer, the offsets,
 * the mutex for the atomicity of the operations
 * and some fields for the management of the deferred work
 */
struct data_flow {
        struct mutex mu;
        struct wait_queue_head pending_requests;
        char   *buffer;
        int    off[2];
        int    pending_bytes;
};

/* Indexes of the off array belonging to the data_flow struct */
#define ROFF (0)
#define WOFF (1)


/*
 * This structure represents the state of the i-th multi-flow device.
 * Inside, there is an array of two elements each of which represents
 * one of the available flows (HIGH and LOW) and a workqueue for
 * managing the deferred work in the low priority flow
 */
struct device_state {
        struct data_flow        flows[2];
        struct workqueue_struct *queue;
};


/*
 * This structure contains all the metadata necessary for the management
 * of the deferred work
 */
struct work_metadata {
        int                major;
        int                minor;
        struct data_flow   *active_flow;
        char               buff[BUFSIZE];
        size_t             len;
        struct work_struct the_work;
};


/*
 * This structure contains all the metadata necessary to manage the session.
 * These are represented by atomic fields to avoid the explicit use of a mutex.
 * In particular, to optimize the memory, the ": size" construct was used to ensure
 * that the actual footprint of the structure remains minimal
 */
struct session_metadata {
        atomic_t idx;
        atomic_t timeout;
        volatile unsigned char READ_MODALITY : 1;
        volatile unsigned char WRITE_MODALITY : 1;
};

#define DEFAULT_TOUT (5)

/*
 * Utility macros to "easily" access the fields of the session_metadata struct
 * starting from the private_data field of the struct file
 */
#define __session_metadata_addr(filp, field) &(((struct session_metadata *)filp->private_data)->field)
#define get_active_flow(filp) &(devs[get_minor(filp)].flows[atomic_read(__session_metadata_addr(filp, idx))])
#define set_active_flow(filp, new) atomic_set(__session_metadata_addr(filp, idx), new)
#define is_high_active(filp) (atomic_read(__session_metadata_addr(filp, idx)) == HIGH_PRIO)
#define is_block_read(filp) (((struct session_metadata *)filp->private_data)->READ_MODALITY == BLOCK)
#define is_block_write(filp) (((struct session_metadata *)filp->private_data)->WRITE_MODALITY == BLOCK)
#define set_read_modality(filp, new) ((struct session_metadata *)filp->private_data)->READ_MODALITY = new
#define set_write_modality(filp, new) ((struct session_metadata *)filp->private_data)->WRITE_MODALITY = new
#define get_timeout(filp) atomic_read(__session_metadata_addr(filp, timeout)) * CONFIG_HZ
#define set_timeout(filp, new) atomic_set(__session_metadata_addr(filp,timeout), new)


#endif // !__H_CORE__
