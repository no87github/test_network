/**
 * Copyright (C) 2005, Trend Micro Incorporated. All Rights Reserved. This
 * program is an unpublished copyrighted work which is proprietary to Trend
 * Micro Incorporated and contains confidential information that is not to be
 * reproduced or disclosed to any other person or entity without prior written
 * consent from Trend Micro, Inc. in each and every instance.
 *
 * WARNING: Unauthorized reproduction of this program as well as unauthorized
 * preparation of derivative works based upon the program or distribution of
 * copies by sale, rental, lease or lending are violations of federal copyright
 * laws and state trade secret laws, punishable by civil and criminal
 * penalties.
 */

#ifndef TPOOL_H
#define TPOOL_H

#include <unistd.h>

__BEGIN_DECLS

struct tpool;
struct tpool_stats;
struct tpool_attr;

struct tpool_stats
{
    size_t total_threads; /* the total number of threads */
    size_t idle_threads; /* the number of idle threads */
    size_t active_threads; /* the number of active threads */
    size_t peak_threads; /* the number of peak threads */
    size_t pending_tasks; /* the number of pending tasks */
    size_t peak_tasks; /* the number of peak tasks */
};

struct tpool_attr
{
    /* The thread_min specifies the minimum number of threads to be created in the thread pool.
     * The value of min should be larger than zero.
     */
    size_t thread_min;

    /* The thread_max specifies the maximum number of threads to be created in the thread pool.
     * The value of max should be larger than one.
     */
    size_t thread_max;

    /* The thread_stack_size defines the minimum stack size (in bytes)
     * allocated for the created threads stack.
     * If the stack_size is set to zero, a default stack size will be used.
     * Otherwise, the stack_size can't be less than PTHREAD_STACK_MIN or
     * exceeds a system-imposed limit.
     */
    size_t thread_stack_size;

    /* The overload evaluator function is used to determine how many worker threads to be increased. */
    int (*overload_evaluator)(const struct tpool_stats *stats);

    /* The underload evaluator function is used to determine how many worker threads to be decreased. */
    int (*underload_evaluator)(const struct tpool_stats *stats);

    /* The task_queue_size defines the maximum number of tasks to be queued */
    size_t task_queue_size;

    /* The task_unit_size defines the size of each task to be queued */
    size_t task_unit_size;
   
    /* The task_handler function is used to handle a task */
    void (*task_handler)(void *task, size_t tasklen);

    /* The task_sweeper function is used to sweep a task remains in the task queue */
    void (*task_sweeper)(void *task, size_t tasklen);
};

/**
 * The function returns a pointer to the newly created thread pool, or a NULL value if the thread pool could not be created.
 */
extern struct tpool *tpool_init(const struct tpool_attr *attr);

/**
 * Destroy the thread pool, and cause all threads in it to cease and desist.
 */
extern int tpool_destroy(struct tpool *tpool, int timeout, int (*timeout_routine)(void));

/**
 * tpool_attr_init initializes the thread pool attributes object attr and fills it with default values for the attributes.
 */
extern int tpool_attr_init(struct tpool_attr *attr);

/**
 * tpool_attr_destroy destroys a thread tpool attribute object, which must not be reused until it is reinitialized.
 * tpool_attr_destroy does nothing in the thread pool implementation.
 */
extern int tpool_attr_destroy(struct tpool_attr *attr);

extern int tpool_attr_setthreadmin(struct tpool_attr *attr, size_t thread_min);
extern int tpool_attr_getthreadmin(const struct tpool_attr *attr, size_t *thread_min);

extern int tpool_attr_setthreadmax(struct tpool_attr *attr, size_t thread_max);
extern int tpool_attr_getthreadmax(const struct tpool_attr *attr, size_t *thread_max);

extern int tpool_attr_setthreadstacksize(struct tpool_attr *attr, size_t thread_stack_size);
extern int tpool_attr_getthreadstacksize(const struct tpool_attr *attr, size_t *thread_stack_size);

extern int tpool_attr_setoverloadevaluator(struct tpool_attr *attr, int (*overload_evaluator)(const struct tpool_stats *stats));
extern int tpool_attr_getoverloadevaluator(const struct tpool_attr *attr, int (**overload_evaluator)(const struct tpool_stats *stats));

extern int tpool_attr_setunderloadevaluator(struct tpool_attr *attr, int (*underload_evaluator)(const struct tpool_stats *stats));
extern int tpool_attr_getunderloadevaluator(const struct tpool_attr *attr, int (**underload_evaluator)(const struct tpool_stats *stats));

extern int tpool_attr_settaskqueuesize(struct tpool_attr *attr, size_t task_unit_size);
extern int tpool_attr_gettaskqueuesize(const struct tpool_attr *attr, size_t *task_unit_size);

extern int tpool_attr_settaskhandler(struct tpool_attr *attr, void (*task_handler)(void *task, size_t tasklen));
extern int tpool_attr_gettaskhandler(const struct tpool_attr *attr, void (**task_handler)(void *task, size_t tasklen));

extern int tpool_attr_settasksweeper(struct tpool_attr *attr, void (*task_sweeper)(void *task, size_t tasklen));
extern int tpool_attr_gettasksweeper(const struct tpool_attr *attr, void (**task_sweeper)(void *task, size_t tasklen));

/**
 * tpool_stats returns the statistics information of the thread pool.
 */
extern int tpool_stats(struct tpool *tpool, struct tpool_stats *stats);

/**
 * tpool_enqueue enqueues a task to the thread pool's task queue.
 */
extern int tpool_enqueue(struct tpool *tpool, void *task, size_t *tasklen);
extern int tpool_tryenqueue(struct tpool *tpool, void *task, size_t *tasklen);
extern int tpool_timedenqueue(struct tpool *tpool, void *task, size_t *tasklen, const struct timespec *abstime);

__END_DECLS

#endif /* TPOOL_H */
