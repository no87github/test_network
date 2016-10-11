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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <limits.h> /* INT_MAX */
#include <time.h>
#include <tpool.h>
#include "list.h"
#include "log.h"

/****************************************************************************/
/* MACRO DECLARATIONS                                                       */
/****************************************************************************/

#define TPOOL_STATS(tpool, format, args...) \
        do { \
            LOGDEBUG( \
                "threads(min=%zu,max=%zu,total=%zu,idle=%zu,active=%zu,peak=%zu) tasks(pending=%zu,peak=%zu): " format, \
                tpool->attr.thread_min, \
                tpool->attr.thread_max, \
                tpool->stats.total_threads, \
                tpool->stats.idle_threads, \
                tpool->stats.active_threads, \
                tpool->stats.peak_threads, \
                tpool->stats.pending_tasks, \
                tpool->stats.peak_tasks, \
                ##args); \
        } while (0);

#define DEFAULT_TPOOL_ATTR_THREAD_MIN           (0)
#define DEFAULT_TPOOL_ATTR_THREAD_MAX           (INT_MAX)
#define DEFAULT_TPOOL_ATTR_THREAD_STACK_SIZE    (0)
#define DEFAULT_TPOOL_ATTR_TASK_QUEUE_SIZE      (0x20)
#define DEFAULT_TPOOL_ATTR_TASK_UNIT_SIZE       (sizeof(void *))

#define TPOOL_STATE_INVALID     (0)
#define TPOOL_STATE_READY       (1)
#define TPOOL_STATE_EXIT        (2)

#define THREAD_STATE_INVALID    (0)
#define THREAD_STATE_READY      (1)
#define THREAD_STATE_IDLE       (2)
#define THREAD_STATE_ACTIVE     (3)
#define THREAD_STATE_EXIT       (4)

#define MONITOR_THREAD_EVENT_TIMEOUT (5)

/****************************************************************************/
/* STRUCTURE DECLARATIONS                                                   */
/****************************************************************************/

struct tpool_task_queue
{
    pthread_cond_t can_push;
    pthread_cond_t can_pop;
    void *data;
    size_t front; /* points to the first element */
    size_t last;  /* points to the last element */
};

struct tpool_monitor_thread
{
    struct tpool *tpool;
    pthread_t tid;
    pthread_cond_t init_cond;
    pthread_cond_t event_cond;
    int state;
};

struct tpool_worker_thread
{
    struct list_head list;
    struct tpool *tpool; /* pointed to the thread pool */
    pthread_t tid; /* the thread's identifier */
    pthread_cond_t init_cond; /* a condition variable that is used to wait for thread initialization */
    pthread_cond_t event_cond; /* a condition variable for receiving events */
    int state;
    void *task;
    time_t creation_time; /* the creation time */
    time_t last_access_time; /* last access time */
    size_t access_count;
};

struct tpool
{
    pthread_attr_t thread_attr; /* the thread attribute */
    pthread_mutex_t mutex; /* a global mutex of the thread pool */
    pthread_cond_t exit_cond; /* a condition variable that is used to wait for thread termination */
    int state;
    struct tpool_task_queue task_queue;
    struct tpool_attr attr;
    struct tpool_stats stats;
    struct tpool_monitor_thread *monitor_thread;
    struct list_head idle_thread_list; /* the list head of idle worker threads */
    struct list_head active_thread_list; /* the list head of active worker threads */
};


/****************************************************************************/
/* FUNCTION DECLARATIONS                                                    */
/****************************************************************************/

static int add_worker_threads(struct tpool *tpool, int number);

static int remove_worker_threads(struct tpool *tpool, int number);

static struct tpool_monitor_thread *create_monitor_thread(struct tpool *tpool, void *(*startup_routine)(struct tpool_monitor_thread *));

static void *monitor_thread_startup(struct tpool_monitor_thread *monitor_thread);

static void monitor_thread_cleanup(struct tpool_monitor_thread *monitor_thread);

static struct tpool_worker_thread *create_worker_thread(struct tpool *tpool, void *(*startup_routine)(struct tpool_worker_thread *));

static void *worker_thread_startup(struct tpool_worker_thread *worker_thread);

static void worker_thread_cleanup(struct tpool_worker_thread *worker_thread);


/****************************************************************************/
/* FUNCTION DEFINITIONS                                                     */
/****************************************************************************/

struct tpool *
tpool_init(
    const struct tpool_attr *attr)
{
    int ret;
    struct tpool_attr default_attr;
    struct tpool *tpool = NULL;

    LOGDEBUG("%s: CHECKPOINT", __FUNCTION__);

    if (attr == NULL)
    {
        (void)tpool_attr_init(&default_attr);
        attr = &default_attr;
    }
    assert(attr != NULL);

    /* Check the validity range: min >= 0, max > 0 */
    if ((attr->thread_max == 0) || (attr->thread_max < attr->thread_min))
    {
        errno = EINVAL;
        LOGERROR("Cannot represent values between the minimum and the maximum: min=%zu, max=%zu",
                 attr->thread_min,
                 attr->thread_max);
        goto error;
    }

    if (attr->task_queue_size == 0)
    {
        errno = EINVAL;
        LOGERROR("The task queue size must be greater than zero: task_queue_size=%zu",
                 attr->task_queue_size);
        goto error;
    }

    if (attr->task_unit_size == 0)
    {
        errno = EINVAL;
        LOGERROR("The task unit size must be greater then zero: task_unit_size=%zu",
                 attr->task_unit_size);
        goto error;
    }

    LOGINFO("tpool_init: thread_min=%zu", attr->thread_min);
    LOGINFO("tpool_init: thread_max=%zu", attr->thread_max);
    LOGINFO("tpool_init: thread_stack_size=%zu", attr->thread_stack_size);
    LOGINFO("tpool_init: overload_evaluator()=%p", attr->overload_evaluator);
    LOGINFO("tpool_init: underload_evaluator()=%p", attr->underload_evaluator);
    LOGINFO("tpool_init: task_queue_size=%zu", attr->task_queue_size);
    LOGINFO("tpool_init: task_unit_size=%zu", attr->task_unit_size);
    LOGINFO("tpool_init: task_handler()=%p", attr->task_handler);
    LOGINFO("tpool_init: task_sweeper()=%p", attr->task_sweeper);

    /***************
     * THREAD POOL *
     ***************/
    if ((tpool = malloc(sizeof(struct tpool))) == NULL)
    {
        LOGERROR("Failed to create thread pool: %m");
        goto error;
    }

    (void)memset(tpool, '\0', sizeof(struct tpool));

    ret = pthread_mutex_init(&tpool->mutex, NULL);
    assert(ret == 0);

    ret = pthread_cond_init(&tpool->exit_cond, NULL);
    assert(ret == 0);

    tpool->state = TPOOL_STATE_READY;

    /*************************
     * THREAD POOL ATTRIBUTE *
     *************************/
    (void)memcpy(&tpool->attr, attr, sizeof(struct tpool_attr));

    assert(tpool->attr.thread_min == attr->thread_min);
    assert(tpool->attr.thread_max == attr->thread_max);
    assert(tpool->attr.thread_stack_size == attr->thread_stack_size);
    assert(tpool->attr.overload_evaluator == attr->overload_evaluator);
    assert(tpool->attr.underload_evaluator == attr->underload_evaluator);
    assert(tpool->attr.task_queue_size == attr->task_queue_size);
    assert(tpool->attr.task_unit_size == attr->task_unit_size);
    assert(tpool->attr.task_handler == attr->task_handler);
    assert(tpool->attr.task_sweeper == attr->task_sweeper);

    /**************************
     * THREAD POOL TASK QUEUE *
     **************************/
    assert(tpool->attr.task_queue_size != 0);
    assert(tpool->attr.task_unit_size != 0);

    tpool->task_queue.data = calloc(tpool->attr.task_queue_size, tpool->attr.task_unit_size);
    if (tpool->task_queue.data == NULL)
    {
        LOGERROR("Failed to create a task queue: %m");
        goto error;
    }

    ret = pthread_cond_init(&tpool->task_queue.can_push, NULL);
    assert(ret == 0);

    ret = pthread_cond_init(&tpool->task_queue.can_pop, NULL);
    assert(ret == 0);

    tpool->task_queue.front = 0;
    tpool->task_queue.last = 0;

    /********************
     * THREAD ATTRIBUTE *
     ********************/
    /* Initializes attr with all the default pthread attributes */
    if (pthread_attr_init(&tpool->thread_attr) != 0)
    {
        LOGERROR("pthread_attr_init(): %m");
        goto error;
    }

    if (tpool->attr.thread_stack_size != 0)
    {
        if (pthread_attr_setstacksize(&tpool->thread_attr, tpool->attr.thread_stack_size) != 0)
        {
            errno = EINVAL;
            LOGERROR("pthread_attr_setstacksize() with stack_size=%zu: %m",
                     tpool->attr.thread_stack_size);
            goto error;
        }
    }

    if (pthread_attr_getstacksize(&tpool->thread_attr, &tpool->attr.thread_stack_size) != 0)
    {
        LOGERROR("pthread_attr_getstacksize(): %m");
        goto error;
    }

    if (pthread_attr_setdetachstate(&tpool->thread_attr, PTHREAD_CREATE_DETACHED) != 0)
    {
        LOGERROR("pthread_attr_setdetachstate() with detachstate=%u: %m",
                 PTHREAD_CREATE_DETACHED);
        goto error;
    }

    /*********************
     * THREAD POOL STATS *
     *********************/
    tpool->stats.total_threads = 0;
    tpool->stats.idle_threads = 0;
    tpool->stats.active_threads = 0;
    tpool->stats.peak_threads = 0;
    tpool->stats.pending_tasks = 0;
    tpool->stats.peak_tasks = 0;

    /*************************************
     * MONITOR THREAD AND WORKER THREADS *
     *************************************/
    INIT_LIST_HEAD(&tpool->idle_thread_list);

    INIT_LIST_HEAD(&tpool->active_thread_list);

    ret = pthread_mutex_lock(&tpool->mutex);
    assert(ret == 0);

    LOGDEBUG("Starting the monitor thread");
    tpool->monitor_thread = create_monitor_thread(tpool, monitor_thread_startup);
    if (tpool->monitor_thread == NULL)
    {
        LOGERROR("Failed to create the monitor thread");
        goto error;
    }

    ret = pthread_mutex_unlock(&tpool->mutex);
    assert(ret == 0);

    return tpool;

error:
    /* Destroy the thread pool, and cause all threads in it to cease and desist */
    if (tpool != NULL)
    {
        (void)tpool_destroy(tpool, -1, NULL);
        tpool = NULL;
    }

    return NULL;
}

int
tpool_destroy(
    struct tpool *tpool,
    int timeout,
    int (*timeout_routine)(void))
{
    int ret = 0;
    struct tpool_task_queue *task_queue = NULL;

    LOGDEBUG("%s: CHECKPOINT", __FUNCTION__);

    if (tpool == NULL)
    {
        LOGDEBUG("The pointer pointed to a thread pool is NULL");
        return EINVAL;
    }
    assert(tpool != NULL);

    ret = pthread_mutex_lock(&tpool->mutex);
    assert(ret == 0);

    tpool->state = TPOOL_STATE_EXIT;

    /**
     * STAGE #1: Stop monitor thread
     */
    LOGINFO("Waiting for the monitor thread to be stopped");
    tpool->monitor_thread->state = THREAD_STATE_EXIT;
    (void)pthread_cond_signal(&tpool->monitor_thread->event_cond);
    (void)pthread_cond_wait(&tpool->exit_cond, &tpool->mutex);

    /**
     * STAGE #2: Stop worker threads
     */
    (void)pthread_cond_broadcast(&tpool->task_queue.can_pop);

    if (timeout >= 0)
        TPOOL_STATS(tpool, "Waiting up to %d second(s) for worker threads to be stopped", timeout);

    while ((tpool->stats.active_threads > 0) && (timeout >= 0))
    {
        struct timespec abstime;

        abstime.tv_sec = time(NULL) + timeout;
        abstime.tv_nsec = 0;
        ret = pthread_cond_timedwait(&tpool->exit_cond, &tpool->mutex, &abstime);
        if ((ret == ETIMEDOUT) && (tpool->stats.total_threads > 0))
        {
            struct list_head *pos = NULL;

            LOGDEBUG("The timeout has occurred: timeout=%d", timeout);

            if (timeout_routine != NULL)
            {
                ret = timeout_routine();
                LOGDEBUG("timeout_routine: ret=%d", ret);
            }

            list_for_each(pos, &tpool->active_thread_list)
            {
                struct tpool_worker_thread *worker_thread = NULL;
                worker_thread = list_entry(pos, struct tpool_worker_thread, list);

                if (worker_thread == NULL)
                    continue;

                TPOOL_STATS(tpool, "Terminating active thread: %p",
                            (void *)worker_thread->tid);
                (void)pthread_cancel(worker_thread->tid);
            }

            break;
        }
    }

    TPOOL_STATS(tpool, "Waiting for worker threads completion");
    while (tpool->stats.total_threads > 0)
    {
        struct timespec abstime;

        abstime.tv_sec = time(NULL) + 1;
        abstime.tv_nsec = 0;
        (void)pthread_cond_timedwait(&tpool->exit_cond, &tpool->mutex, &abstime);
    }

    /**
     * STAGE #3: Call task sweeper
     */
    task_queue = &tpool->task_queue;
    if (task_queue->data != NULL)
    {
        size_t task_queue_size = tpool->attr.task_queue_size;
        size_t task_unit_size = tpool->attr.task_unit_size;
        void (*task_sweeper)(void *, size_t) = tpool->attr.task_sweeper;

        while (tpool->stats.pending_tasks > 0)
        {
            /* Remove a task from the front of the task queue */
            void *task = ((char *)task_queue->data + (task_queue->front * task_unit_size));
            assert(((char *)task >= (char *)task_queue->data) && ((char *)task <= ((char *)task_queue->data + (task_queue_size - 1) * task_unit_size)));

            task_queue->front = (task_queue->front + 1) % task_queue_size;
            --(tpool->stats.pending_tasks);

            if (task_sweeper == NULL)
                continue;

            task_sweeper(task, task_unit_size);
        }

        free(task_queue->data);
        task_queue->data = NULL;
    }

    ret = pthread_mutex_unlock(&tpool->mutex);
    assert(ret == 0);

    if (tpool != NULL)
    {
        free(tpool);
        tpool = NULL;
    }

    return 0;
}

int
tpool_attr_init(
    struct tpool_attr *attr)
{
    LOGDEBUG("%s: CHECKPOINT", __FUNCTION__);

    if (attr == NULL)
    {
        LOGDEBUG("The pointer pointed to a thread pool attribute is NULL");
        return EINVAL;
    }

    attr->thread_min = DEFAULT_TPOOL_ATTR_THREAD_MIN;
    attr->thread_max = DEFAULT_TPOOL_ATTR_THREAD_MAX;
    attr->thread_stack_size = DEFAULT_TPOOL_ATTR_THREAD_STACK_SIZE;
    attr->overload_evaluator = NULL;
    attr->underload_evaluator = NULL;
    attr->task_queue_size = DEFAULT_TPOOL_ATTR_TASK_QUEUE_SIZE;
    attr->task_unit_size = DEFAULT_TPOOL_ATTR_TASK_UNIT_SIZE;
    attr->task_handler = NULL;
    attr->task_sweeper = NULL;

    return 0;
}

int
tpool_attr_setthreadmin(
    struct tpool_attr *attr,
    size_t thread_min)
{
    LOGDEBUG("%s: CHECKPOINT", __FUNCTION__);

    if (attr == NULL)
    {
        LOGDEBUG("The pointer pointed to a thread pool attribute is NULL");
        return EINVAL;
    }

    attr->thread_min = thread_min;

    return 0;
}

int
tpool_attr_getthreadmin(
    const struct tpool_attr *attr,
    size_t *thread_min)
{
    LOGDEBUG("%s: CHECKPOINT", __FUNCTION__);

    if (attr == NULL)
    {
        LOGDEBUG("The pointer pointed to a thread pool attribute is NULL");
        return EINVAL;
    }

    if (thread_min != NULL)
        (*thread_min) = attr->thread_min;

    return 0;
}

int
tpool_attr_setthreadmax(
    struct tpool_attr *attr,
    size_t thread_max)
{
    LOGDEBUG("%s: CHECKPOINT", __FUNCTION__);

    if (attr == NULL)
    {
        LOGDEBUG("The pointer pointed to a thread pool attribute is NULL");
        return EINVAL;
    }

    attr->thread_max = thread_max;

    return 0;
}

int
tpool_attr_getthreadmax(
    const struct tpool_attr *attr,
    size_t *thread_max)
{
    LOGDEBUG("%s: CHECKPOINT", __FUNCTION__);

    if (attr == NULL)
    {
        LOGDEBUG("The pointer pointed to a thread pool attribute is NULL");
        return EINVAL;
    }

    if (thread_max != NULL)
        (*thread_max) = attr->thread_max;

    return 0;
}

int
tpool_attr_setthreadstacksize(
    struct tpool_attr *attr,
    size_t thread_stack_size)
{
    LOGDEBUG("%s: CHECKPOINT", __FUNCTION__);

    if (attr == NULL)
    {
        LOGDEBUG("The pointer pointed to a thread pool attribute is NULL");
        return EINVAL;
    }

    attr->thread_stack_size = thread_stack_size;

    return 0;
}

int
tpool_attr_getthreadstacksize(
    const struct tpool_attr *attr,
    size_t *thread_stack_size)
{
    LOGDEBUG("%s: CHECKPOINT", __FUNCTION__);

    if (attr == NULL)
    {
        LOGDEBUG("The pointer pointed to a thread pool attribute is NULL");
        return EINVAL;
    }

    if (thread_stack_size != NULL)
        (*thread_stack_size) = attr->thread_stack_size;

    return 0;
}

int
tpool_attr_setoverloadevaluator(
    struct tpool_attr *attr,
    int (*overload_evaluator)(const struct tpool_stats *stats))
{
    LOGDEBUG("%s: CHECKPOINT", __FUNCTION__);

    if (attr == NULL)
    {
        LOGDEBUG("The pointer pointed to a thread pool attribute is NULL");
        return EINVAL;
    }

    attr->overload_evaluator = overload_evaluator;

    return 0;
}

int
tpool_attr_getoverloadevaluator(
    const struct tpool_attr *attr,
    int (**overload_evaluator)(const struct tpool_stats *stats))
{
    LOGDEBUG("%s: CHECKPOINT", __FUNCTION__);

    if (attr == NULL)
    {
        LOGDEBUG("The pointer pointed to a thread pool attribute is NULL");
        return EINVAL;
    }

    if (overload_evaluator != NULL)
        (*overload_evaluator) = attr->overload_evaluator;

    return 0;
}

int
tpool_attr_setunderloadevaluator(
    struct tpool_attr *attr,
    int (*underload_evaluator)(const struct tpool_stats *stats))
{
    LOGDEBUG("%s: CHECKPOINT", __FUNCTION__);

    if (attr == NULL)
    {
        LOGDEBUG("The pointer pointed to a thread pool attribute is NULL");
        return EINVAL;
    }

    attr->underload_evaluator = underload_evaluator;

    return 0;
}

int
tpool_attr_getunderloadevaluator(
    const struct tpool_attr *attr,
    int (**underload_evaluator)(const struct tpool_stats *stats))
{
    LOGDEBUG("%s: CHECKPOINT", __FUNCTION__);

    if (attr == NULL)
    {
        LOGDEBUG("The pointer pointed to a thread pool attribute is NULL");
        return EINVAL;
    }

    if (underload_evaluator != NULL)
        (*underload_evaluator) = attr->underload_evaluator;

    return 0;
}

int
tpool_attr_settaskqueuesizea(
    struct tpool_attr *attr,
    size_t task_unit_size)
{
    LOGDEBUG("%s: CHECKPOINT", __FUNCTION__);

    if (attr == NULL)
    {
        LOGDEBUG("The pointer pointed to a thread pool attribute is NULL");
        return EINVAL;
    }

    attr->task_unit_size = task_unit_size;

    return 0;
}

int
tpool_attr_gettaskqueuesize(
    const struct tpool_attr *attr,
    size_t *task_unit_size)
{
    LOGDEBUG("%s: CHECKPOINT", __FUNCTION__);

    if (attr == NULL)
    {
        LOGDEBUG("The pointer pointed to a thread pool attribute is NULL");
        return EINVAL;
    }

    if (task_unit_size != NULL)
        (*task_unit_size) = attr->task_unit_size;

    return 0;
}

int
tpool_attr_settaskhandler(
    struct tpool_attr *attr,
    void (*task_handler)(void *task, size_t tasklen))
{
    LOGDEBUG("%s: CHECKPOINT", __FUNCTION__);

    if (attr == NULL)
    {
        LOGDEBUG("The pointer pointed to a thread pool attribute is NULL");
        return EINVAL;
    }

    attr->task_handler = task_handler;

    return 0;
}

int
tpool_attr_gettaskhandler(
    const struct tpool_attr *attr,
    void (**task_handler)(void *task, size_t tasklen))
{
    LOGDEBUG("%s: CHECKPOINT", __FUNCTION__);

    if (attr == NULL)
    {
        LOGDEBUG("The pointer pointed to a thread pool attribute is NULL");
        return EINVAL;
    }

    if (task_handler != NULL)
        (*task_handler) = attr->task_handler;

    return 0;
}

int
tpool_attr_settasksweeper(
    struct tpool_attr *attr,
    void (*task_sweeper)(void *task, size_t tasklen))
{
    LOGDEBUG("%s: CHECKPOINT", __FUNCTION__);

    if (attr == NULL)
    {
        LOGDEBUG("The pointer pointed to a thread pool attribute is NULL");
        return EINVAL;
    }

    attr->task_sweeper = task_sweeper;

    return 0;
}

int
tpool_attr_gettasksweeper(
    const struct tpool_attr *attr,
    void (**task_sweeper)(void *task, size_t tasklen))
{
    LOGDEBUG("%s: CHECKPOINT", __FUNCTION__);

    if (attr == NULL)
    {
        LOGDEBUG("The pointer pointed to a thread pool attribute is NULL");
        return EINVAL;
    }

    if (task_sweeper != NULL)
        (*task_sweeper) = attr->task_sweeper;

    return 0;
}

int
tpool_stats(
    struct tpool *tpool,
    struct tpool_stats *stats)
{
    int ret = 0;

    if (tpool == NULL)
    {
        LOGDEBUG("The pointer pointed to a thread pool is NULL");
        return EINVAL;
    }
    assert(tpool != NULL);

    if (stats == NULL)
    {
        LOGDEBUG("The pointer pointed to a thread pool stats is NULL");
        return EINVAL;
    }

    ret = pthread_mutex_lock(&tpool->mutex);
    if (ret != 0)
    {
        LOGERROR("pthread_mutex_lock() failed: ret=%d", ret);
        return ret;
    }

    (void)memcpy(stats, &tpool->stats, sizeof(struct tpool_stats));

    ret = pthread_mutex_unlock(&tpool->mutex);
    if (ret != 0)
    {
        LOGERROR("pthread_mutex_unlock() failed: ret=%d", ret);
        return ret;
    }

    return 0;
}

int
tpool_enqueue(
    struct tpool *tpool,
    void *task,
    size_t *tasklen)
{
    int ret = 0;
    struct tpool_monitor_thread *monitor_thread = NULL;
    struct tpool_task_queue *task_queue = NULL;
    size_t task_queue_size = 0;
    size_t task_unit_size = 0;

    if (tpool == NULL)
    {
        LOGERROR("The pointer pointed to a thread pool is NULL");
        return EINVAL;
    }
    assert(tpool != NULL);

    monitor_thread = tpool->monitor_thread;
    if (monitor_thread == NULL)
    {
        LOGERROR("The monitor thread is pointed to a NULL value");
        return EINVAL;
    }
    assert(monitor_thread != NULL);

    ret = pthread_mutex_lock(&tpool->mutex);
    if (ret != 0)
    {
        LOGERROR("pthread_mutex_lock() failed: ret=%d", ret);
        return ret;
    }

    if (tpool->state != TPOOL_STATE_READY)
        goto leave;

    task_queue = &tpool->task_queue;
    task_queue_size = tpool->attr.task_queue_size;
    task_unit_size = tpool->attr.task_unit_size;

    if ((monitor_thread->state == THREAD_STATE_IDLE) &&
        (tpool->stats.idle_threads == 0) &&
        (tpool->stats.total_threads < tpool->attr.thread_max) &&
        (tpool->stats.pending_tasks > 0 ))
    {
        /**
         * After detecting the burst, the calling thread must notify the burst
         * condition to the monitor thread so that it can handle the situation
         * in time.
         */ 

        TPOOL_STATS(tpool, "Notify the burst condition to the monitor thread");
        (void)pthread_cond_signal(&tpool->monitor_thread->event_cond);
    }

    /* To check if the task queue is full */
    while (tpool->stats.pending_tasks == task_queue_size)
    {
        ret = pthread_cond_wait(&task_queue->can_push, &tpool->mutex);
        if (ret != 0)
        {
            if (ret == EINTR)
                continue;

            LOGERROR("pthread_cond_wait() failed: ret=%d", ret);
            goto leave;
        }
    }

    { /* Add a task onto the end of the task queue */
        char *p = (char *)task_queue->data + (task_queue->last * task_unit_size);
        assert((p >= (char *)task_queue->data) && (p <= ((char *)task_queue->data + (task_queue_size - 1) * task_unit_size)));
        (*tasklen) = ((task_unit_size) < (*tasklen)) ? (task_unit_size) : (*tasklen);
        (void)memcpy(p, (char *)task, (*tasklen));

        task_queue->last = (task_queue->last + 1) % task_queue_size;
        ++(tpool->stats.pending_tasks);
        if (tpool->stats.pending_tasks > tpool->stats.peak_tasks)
            tpool->stats.peak_tasks = tpool->stats.pending_tasks;

        (void)pthread_cond_signal(&task_queue->can_pop);
    }

leave:
    ret = pthread_mutex_unlock(&tpool->mutex);
    if (ret != 0)
    {
        LOGERROR("pthread_mutex_unlock() failed: ret=%d", ret);
        return ret;
    }

    return 0;
}

/**
 * NOTE. Before calling the add_worker_threads function, the tpool->mutex must be locked by the caller.
 */
static int
add_worker_threads(
    struct tpool *tpool,
    int number)
{
    int i = 0;

    LOGDEBUG("%s: CHECKPOINT", __FUNCTION__);

    assert(tpool != NULL);

    for (i = 0; i < number; ++i)
    {
        struct tpool_worker_thread *worker_thread = NULL;

        if (tpool->stats.total_threads >= tpool->attr.thread_max)
            break;

        worker_thread = create_worker_thread(tpool, worker_thread_startup);
        if (worker_thread == NULL)
        {
            LOGWARN("Failed to allocate memory for a worker thread\n");
            break;
        }
    }

    return i;
}

static int
remove_worker_threads(
    struct tpool *tpool,
    int number)
{
    int i = 0;
    struct list_head *pos = NULL;
    struct list_head *tmp = NULL;

    LOGDEBUG("%s: CHECKPOINT", __FUNCTION__);

    assert(tpool != NULL);

    i = 0;
    list_for_each_safe(pos, tmp, &tpool->idle_thread_list)
    {
        struct tpool_worker_thread *worker_thread = NULL;

        if ((i >= number) || (tpool->stats.total_threads <= tpool->attr.thread_min))
            break;

        worker_thread = list_entry(pos, struct tpool_worker_thread, list);

        list_del_init(&worker_thread->list);

        LOGDEBUG("Sending a cancellation request to the idle worker thread: %p", (void *)worker_thread->tid);

        worker_thread->state = THREAD_STATE_EXIT;

        ++i;
    }

    (void)pthread_cond_broadcast(&tpool->task_queue.can_pop);

    return i;
}

static struct tpool_monitor_thread *
create_monitor_thread(
    struct tpool *tpool,
    void *(*startup_routine)(struct tpool_monitor_thread *))
{
    int ret = 0;
    struct tpool_monitor_thread *monitor_thread = NULL;

    LOGDEBUG("%s: CHECKPOINT", __FUNCTION__);

    assert(tpool != NULL);

    if (startup_routine == NULL)
    {
        errno = EINVAL;
        LOGERROR("The pointer pointed to startup_routine is NULL");
        return NULL;
    }

    if ((monitor_thread = malloc(sizeof(struct tpool_monitor_thread))) == NULL)
    {
        LOGERROR("Unable to allocate memory for tpool_monitor_thread: %m");
        goto error;
    }

    (void)memset(monitor_thread, '\0', sizeof(struct tpool_monitor_thread));

    /* thread pool */
    monitor_thread->tpool = tpool;

    /* tid */
    monitor_thread->tid = 0;

    /* Initializes a condition variable using default attributes */
    ret = pthread_cond_init(&monitor_thread->init_cond, NULL);
    assert(ret == 0);

    /* Initializes a condition variable using default attributes */
    ret = pthread_cond_init(&monitor_thread->event_cond, NULL);
    assert(ret == 0);

    /* state */
    monitor_thread->state = THREAD_STATE_READY;

    if (pthread_create(&monitor_thread->tid, &tpool->thread_attr, (void *(*)(void *))startup_routine, monitor_thread) != 0)
    {
        LOGERROR("pthread_create(): unable to create monitor thread: %m");
        goto error;
    }

    if (monitor_thread->state == THREAD_STATE_READY)
    {
        (void)pthread_cond_wait(&monitor_thread->init_cond, &tpool->mutex);
        assert(monitor_thread->state != THREAD_STATE_READY);
    }

    return monitor_thread;

error:
    if (monitor_thread != NULL)
    {
        if (monitor_thread->tid != 0)
        {
            (void)pthread_cancel(monitor_thread->tid);
        }

        free(monitor_thread);
        monitor_thread = NULL;
    }

    return NULL;
}

static void *
monitor_thread_startup(
    struct tpool_monitor_thread *monitor_thread)
{
    int ret = 0;
    int oldtype = 0;
    struct tpool *tpool = NULL;
    struct timespec timeout;
    int reset_timeout = 0;

    LOGDEBUG("%s: CHECKPOINT", __FUNCTION__);

    assert(monitor_thread != NULL);

    tpool = monitor_thread->tpool;
    assert(tpool != NULL);

    ret = pthread_mutex_lock(&tpool->mutex);
    assert(ret == 0);

/****************************************************************************/
    LOGDEBUG("Installing a cleanup handler for the monitor thread: %p", (void *)monitor_thread->tid);
    ret = pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, &oldtype);
    assert(ret == 0);
    pthread_cleanup_push((void (*)(void *))monitor_thread_cleanup, (void *)monitor_thread);
/****************************************************************************/
    (void)pthread_cond_signal(&monitor_thread->init_cond);
/****************************************************************************/

    assert(monitor_thread->state == THREAD_STATE_READY);
    monitor_thread->state = THREAD_STATE_ACTIVE;

    /* The total number of threads should be zero */
    assert(tpool->stats.total_threads == 0);

    /* Create and start up to tpool->attr.thread_min threads in the thread pool */
    if (add_worker_threads(tpool, tpool->attr.thread_min) != tpool->attr.thread_min)
    {
        LOGERROR("Failed to create %zu worker threads", tpool->attr.thread_min);
        goto leave;
    }

    LOGINFO("The monitor thread has started: %p", (void *)monitor_thread->tid);

    reset_timeout = 1;
    while (1)
    {
        if (tpool->state == TPOOL_STATE_EXIT)
            goto leave;

        if (monitor_thread->state == THREAD_STATE_EXIT)
            goto leave;

        if (reset_timeout)
        {
            (void)memset(&timeout, 0, sizeof(timeout));
            timeout.tv_sec = time(NULL) + MONITOR_THREAD_EVENT_TIMEOUT;
            timeout.tv_nsec = 0;
            reset_timeout = 0;
        }

        assert(monitor_thread->state != THREAD_STATE_EXIT);
        monitor_thread->state = THREAD_STATE_IDLE;

        //LOGDEBUG("Enter pthread_cond_timedwait: %p", (void *)monitor_thread->tid);
        ret = pthread_cond_timedwait(&monitor_thread->event_cond, &tpool->mutex, &timeout);
        //LOGDEBUG("Leave pthread_cond_timedwait: %p", (void *)monitor_thread->tid);

        if (tpool->state == TPOOL_STATE_EXIT)
        {
            LOGINFO("Monitor thread exit: TPOOL_STATE_EXIT");
            goto leave;
        }

        if (monitor_thread->state == THREAD_STATE_EXIT)
        {
            LOGINFO("Monitor thread exit: THREAD_STATE_EXIT");
            goto leave;
        }

        assert(monitor_thread->state != THREAD_STATE_EXIT);
        monitor_thread->state = THREAD_STATE_ACTIVE;

        if (tpool->stats.total_threads < tpool->attr.thread_min)
        {
            reset_timeout = 1;
            continue;
        }

        if (ret == ETIMEDOUT)
        {
            reset_timeout = 1;
        }

        /**
         * overload evaluation function
         */
        if (tpool->attr.overload_evaluator != NULL)
        {
            int increment;

            increment = tpool->attr.overload_evaluator(&tpool->stats);
            if (increment > 0)
            {
                TPOOL_STATS(tpool, "The thread pool is overloaded");

                ret = add_worker_threads(tpool, increment);
                if (ret != increment)
                {
                    LOGWARN("Only %u of %u requested threads are added to the thread pool\n", ret, increment);
                }
            }
        }

        /**
         * underload evaluation function
         */
        if (tpool->attr.underload_evaluator != NULL)
        {
            int decrement = 0;

            decrement = tpool->attr.underload_evaluator(&tpool->stats);
            if (decrement > 0)
            {
                TPOOL_STATS(tpool, "The thread pool is underloaded");

                ret = remove_worker_threads(tpool, decrement);
                if (ret != decrement)
                {
                    LOGWARN("Only %u of %u requested threads are removed from the thread pool\n", ret, decrement);
                }
            }
        }

        //TPOOL_STATS(tpool, "monitor_thread");
    }
leave:
    LOGDEBUG("The monitor thread has stopped: %p", (void *)monitor_thread->tid);
    ret = pthread_mutex_unlock(&tpool->mutex);
    assert(ret == 0);

/****************************************************************************/
    LOGDEBUG("The monitor thread's cleanup handler is being called");
    pthread_cleanup_pop(1);
    ret = pthread_setcanceltype(oldtype, NULL);
    assert(ret == 0);
/****************************************************************************/

    return 0;
}

static void
monitor_thread_cleanup(
    struct tpool_monitor_thread *monitor_thread)
{
    int ret = 0;
    struct tpool *tpool = NULL;

    LOGDEBUG("%s: CHECKPOINT", __FUNCTION__);

    assert(monitor_thread != NULL);

    tpool = monitor_thread->tpool;
    assert(tpool != NULL);

    ret = pthread_mutex_lock(&tpool->mutex);
    assert(ret == 0);

    /* To restart the thread that are waiting on the condition variable exit_cond. i.e. tpool_destroy() */
    (void)pthread_cond_signal(&tpool->exit_cond);

    monitor_thread->state = THREAD_STATE_INVALID;

    ret = pthread_mutex_unlock(&tpool->mutex);
    assert(ret == 0);

    if (monitor_thread != NULL)
    {
        free(monitor_thread);
        monitor_thread = NULL;
    }
}

static struct tpool_worker_thread *
create_worker_thread(
    struct tpool *tpool,
    void *(*startup_routine)(struct tpool_worker_thread *))
{
    int ret = 0;
    struct tpool_worker_thread *worker_thread = NULL;

    LOGDEBUG("%s: CHECKPOINT", __FUNCTION__);

    assert(tpool != NULL);

    if (startup_routine == NULL)
    {
        errno = EINVAL;
        LOGERROR("The pointer pointed to startup_routine is NULL");
        return NULL;
    }

    if ((worker_thread = malloc(sizeof(struct tpool_worker_thread))) == NULL)
    {
        LOGERROR("Unable to allocate memory for tpool_worker_thread: %m");
        goto error;
    }

    (void)memset(worker_thread, '\0', sizeof(struct tpool_worker_thread));

    /* list */
    INIT_LIST_HEAD(&worker_thread->list);

    /* thread pool */
    worker_thread->tpool = tpool;

    /* tid */
    worker_thread->tid = 0;

    /* Initializes a condition variable using default attributes */
    ret = pthread_cond_init(&worker_thread->init_cond, NULL);
    assert(ret == 0);

    /* Initializes a condition variable using default attributes */
    ret = pthread_cond_init(&worker_thread->event_cond, NULL);
    assert(ret == 0);

    /* state */
    worker_thread->state = THREAD_STATE_READY;

    /* task */
    worker_thread->task = NULL;

    /* creation time */
    (void)time(&worker_thread->creation_time);

    /* last access time */
    worker_thread->last_access_time = 0;

    /* access count */
    worker_thread->access_count = 0;

    if (pthread_create(&worker_thread->tid, &tpool->thread_attr, (void *(*)(void *))startup_routine, worker_thread) != 0)
    {
        LOGERROR("pthread_create(): unable to create worker thread: %m");
        goto error;
    }

    if (worker_thread->state == THREAD_STATE_READY)
    {
        (void)pthread_cond_wait(&worker_thread->init_cond, &tpool->mutex);
        assert(worker_thread->state != THREAD_STATE_READY);
    }

    return worker_thread;

error:
    if (worker_thread != NULL)
    {
        if (worker_thread->tid != 0)
        {
            (void)pthread_cancel(worker_thread->tid);
        }

        free(worker_thread);
        worker_thread = NULL;
    }

    return NULL;
}

static void *
worker_thread_startup(
    struct tpool_worker_thread *worker_thread)
{
    int ret = 0;
    int oldtype = 0;
    struct tpool *tpool = NULL;
    struct tpool_task_queue *task_queue = NULL;
    size_t task_queue_size = 0;
    size_t task_unit_size = 0;
    void (*task_handler)(void *, size_t) = NULL;
    void *task = NULL;

    LOGDEBUG("%s: CHECKPOINT", __FUNCTION__);

    assert(worker_thread != NULL);

    tpool = worker_thread->tpool;
    assert(tpool != NULL);

    task_queue = &tpool->task_queue;
    assert(task_queue != NULL);

    ret = pthread_mutex_lock(&tpool->mutex);
    assert(ret == 0);

/****************************************************************************/
    LOGDEBUG("Installing a cleanup handler for the worker thread: %p", (void *)worker_thread->tid);
    ret = pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, &oldtype);
    assert(ret == 0);
    pthread_cleanup_push((void (*)(void *))worker_thread_cleanup, (void *)worker_thread);
/****************************************************************************/
    (void)pthread_cond_signal(&worker_thread->init_cond);
/****************************************************************************/

    /* The task_queue_size should not be a zero value */
    task_queue_size = tpool->attr.task_queue_size;
    assert(task_queue_size > 0);

    /* The task_unit_size should not be a zero value */
    task_unit_size = tpool->attr.task_unit_size;
    assert(task_unit_size > 0);

    /* The task_handler could be a NULL pointer */
    task_handler = tpool->attr.task_handler;

    worker_thread->task = malloc(task_unit_size);
    if (worker_thread->task == NULL) 
    {
        LOGWARN("Failed to allocate memory for a task\n");
        goto leave;
    }
    task = worker_thread->task;
    assert(task != NULL);

    assert(worker_thread->state == THREAD_STATE_READY);
    worker_thread->state = THREAD_STATE_IDLE;

    list_add_tail(&worker_thread->list, &tpool->idle_thread_list);

    ++(tpool->stats.idle_threads);
    ++(tpool->stats.total_threads);
    if (tpool->stats.total_threads > tpool->stats.peak_threads)
        tpool->stats.peak_threads = tpool->stats.total_threads;

    assert(tpool->stats.total_threads == (tpool->stats.idle_threads + tpool->stats.active_threads));

    TPOOL_STATS(tpool, "A worker thread has been added to the thread pool");

    LOGDEBUG("The worker thread has started: %p", (void *)worker_thread->tid);

    while (1)
    {
        if (tpool->state == TPOOL_STATE_EXIT)
            goto leave;

        if (worker_thread->state == THREAD_STATE_EXIT)
            goto leave;

        while (tpool->stats.pending_tasks == 0)
        {
            ret = pthread_cond_wait(&task_queue->can_pop, &tpool->mutex);

            if (tpool->state == TPOOL_STATE_EXIT)
                goto leave;

            if (worker_thread->state == THREAD_STATE_EXIT)
                goto leave;

            if (ret != 0)
            {
                if (ret == EINTR)
                    continue;

                LOGERROR("pthread_cond_wait() failed: ret=%d", ret);
                goto leave;
            }
        }

        { /* Remove a task from the front of the task queue */
            char *p = (char *)task_queue->data + (task_queue->front * task_unit_size);
            assert((p >= (char *)task_queue->data) && (p <= ((char *)task_queue->data + (task_queue_size - 1) * task_unit_size)));
            (void)memcpy(task, p, task_unit_size);

            task_queue->front = (task_queue->front + 1) % task_queue_size;
            --(tpool->stats.pending_tasks);

            (void)pthread_cond_signal(&task_queue->can_push);
        }

        { /* Switch the worker thread from idle_list to active_list */
            worker_thread->state = THREAD_STATE_ACTIVE;

            --(tpool->stats.idle_threads);
            ++(tpool->stats.active_threads);

            list_del_init(&worker_thread->list);
            list_add_tail(&worker_thread->list, &tpool->active_thread_list);

            TPOOL_STATS(tpool, "The worker thread is starting a task");
        }

        pthread_mutex_unlock(&tpool->mutex);
        
        if (task_handler != NULL)
        {
            //LOGDEBUG("Enter the task_handler: func=%p, task=%p", task_handler, task);

            /* Run the task */
            task_handler(task, task_unit_size);
 
            //LOGDEBUG("Leave the task_handler: func=%p, task=%p", task_handler, task);
        }

        pthread_mutex_lock(&tpool->mutex);

        { /* Switch the worker thread from active_list to idle_list */
            list_del_init(&worker_thread->list);
            list_add_tail(&worker_thread->list, &tpool->idle_thread_list);

            --(tpool->stats.active_threads);
            ++(tpool->stats.idle_threads);

            worker_thread->state = THREAD_STATE_IDLE;

            TPOOL_STATS(tpool, "The worker thread has finished the task");
        }
    }

leave:
    LOGDEBUG("The worker thread has stopped: %p", (void *)worker_thread->tid);
    ret = pthread_mutex_unlock(&tpool->mutex);
    assert(ret == 0);

/****************************************************************************/
    LOGDEBUG("The worker thread's cleanup handler is being called");
    pthread_cleanup_pop(1);
    ret = pthread_setcanceltype(oldtype, NULL);
    assert(ret == 0);
/****************************************************************************/

    return 0;
}

static void
worker_thread_cleanup(
   struct tpool_worker_thread *worker_thread)
{
    int ret = 0;
    struct tpool *tpool = NULL;

    LOGDEBUG("%s: CHECKPOINT", __FUNCTION__);

    assert(worker_thread != NULL);

    tpool = worker_thread->tpool;
    assert(tpool != NULL);

    ret = pthread_mutex_lock(&tpool->mutex);
    assert(ret == 0);

    list_del_init(&worker_thread->list);

    if (worker_thread->state == THREAD_STATE_ACTIVE)
    {
        --(tpool->stats.active_threads);
        --(tpool->stats.total_threads);
    }
    else if ((worker_thread->state == THREAD_STATE_IDLE) || (worker_thread->state == THREAD_STATE_EXIT))
    {
        --(tpool->stats.idle_threads);
        --(tpool->stats.total_threads);
    }
    else
    {
        LOGERROR("The worker thread's state is invalid: state=%d", worker_thread->state);
    }

    assert(tpool->stats.total_threads == (tpool->stats.idle_threads + tpool->stats.active_threads));

    if (worker_thread->task != NULL)
    {
        free(worker_thread->task);
        worker_thread->task = NULL;
    }

    TPOOL_STATS(tpool, "A worker thread has been removed from the thread pool");

    /* To restart the thread that are waiting on the condition variable exit_cond. i.e. tpool_destroy() */
    (void)pthread_cond_signal(&tpool->exit_cond);

    worker_thread->state = THREAD_STATE_INVALID;

    ret = pthread_mutex_unlock(&tpool->mutex);
    assert(ret == 0);

    if (worker_thread != NULL)
    {
        free(worker_thread);
        worker_thread = NULL;
    }
}
