#ifndef __H_CORE__
#define __H_CORE__

#include <linux/kconfig.h> // for CONFIG_HZ constant

/* "Constants" macros */
#define MODNAME "MFDF:"                         // Module name, useful for printk
#define DEVICE_NAME "multi-flow"                // Device name, useful for printk
#define MINORS (128)                            // Number of minors available
#define BUFSIZE (2*PAGE_SIZE)                   // Size of each data flow
#define SYS_KOBJ_NAME "mfdf"                    // Kernel object name (directory in /sys)
#define MAX_SECONDS (ULONG_MAX / CONFIG_HZ)     // Maximum number of seconds that can be set with the ioctl


/**
 * This structure represents the single stream (HIGH or LOW)
 * associated with the i-th device file (with 0 <= i <= 127).
 * It contains metadata such as the boundaries of the data,
 * the priority level, the mutex for the atomicity of the
 * operations and some fields for the management of the
 * deferred work
 */
struct data_flow {
        int                     prio_level;
        struct mutex            mu;
        struct wait_queue_head  pending_requests;
        struct list_head        head;
        struct list_head        tail;
        size_t                  valid_bytes;
        int                     pending_bytes;
        atomic_t                pending_threads;
};


/**
 * This structure represents the state of the i-th multi-flow device.
 * Inside, there is an array of two elements, each of which represents
 * one of the available flows (HIGH and LOW) and a workqueue for
 * managing the deferred work in the low priority flow
 */
struct device_state {
        struct data_flow        flows[2];
        struct workqueue_struct *queue;
};


/**
 * This structure represents the single data chunk written by
 * a write operation. It contains the actual buffer, the current
 * reading index, the total size (the buffer could theoretically
 * contain more data but are not considered in any case) and
 * finally a list_head field for the connectiona
 */
struct data_segment {
        char             *buffer;
        size_t           size;
        off_t            off;
        struct list_head links;
};


/**
 * This structure contains all the metadata necessary for the management
 * of the deferred work
 */
struct work_metadata {
        int                 major;
        int                 minor;
        struct data_flow    *active_flow;
        struct data_segment *new_data;
        struct work_struct  the_work;
};


/**
 * This structure contains all the metadata necessary to manage the session.
 * These are represented by atomic fields to avoid the explicit use of a mutex.
 * In particular, to optimize the memory, the ": size" construct was used to ensure
 * that the actual footprint of the structure remains minimal
 */
struct session_metadata {
        atomic_t idx;
        atomic_long_t timeout;
        volatile unsigned char READ_MODALITY : 1;
        volatile unsigned char WRITE_MODALITY : 1;
};



/**
 * Macro used to retrieve the address of the field <field> starting
 * from the pointer to a struct file
 */
#define session_metadata_field_addr(filp, field) \
        &(((struct session_metadata *)(filp)->private_data)->field)


/**
 * Macro used to retrieve the value of the field <field> starting
 * from the pointer to a struct file
 */
#define session_metadata_field_value(filp, field) \
        (((struct session_metadata *)(filp)->private_data)->field)


/**
 * Gets the address of the currently active stream
 * by atomically reading the index <idx>
 */
#define get_active_flow(filp) \
        &(devs[get_minor(filp)].flows[atomic_read(session_metadata_field_addr((filp), idx))])


/**
 * Sets the index (HIGH_PRIO or LOW_PRIO) of the currently active stream
 */
#define set_active_flow(filp, new_idx) \
        atomic_set(session_metadata_field_addr((filp), idx), (new_idx))


/**
 * Check if the reading is currently blocking
 */
#define is_block_read(filp) \
        (session_metadata_field_value((filp),READ_MODALITY) == BLOCK)


/**
 * Check if the writing is currently blocking
 */
#define is_block_write(filp) \
        (session_metadata_field_value((filp),WRITE_MODALITY) == BLOCK)


/**
 * Set the writing mode (BLOCK vs NON_BLOCK)
 */
#define set_read_modality(filp, new_mod) \
        session_metadata_field_value((filp), READ_MODALITY) = (new_mod)


/**
 * Set the writing mode (BLOCK vs NON_BLOCK)
 */
#define set_write_modality(filp, new_mod) \
        session_metadata_field_value((filp),WRITE_MODALITY) = (new_mod)


/**
 * Gets the currently set value of the timeout
 * n.b. direct casting is possible according to what is reported
 * in https://www.kernel.org/doc/Documentation/atomic_t.txt
 */
#define get_timeout(filp) \
        (((unsigned long)atomic_long_read(session_metadata_field_addr((filp), timeout))) * CONFIG_HZ)


/**
 * Sets the value of the timeout
 */
#define set_timeout(filp, new_val) \
        atomic_long_set(session_metadata_field_addr((filp),timeout), (new_val))


#endif // !__H_CORE__
