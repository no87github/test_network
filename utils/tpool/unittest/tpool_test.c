#include <assert.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <tpool.h>

#define min(a, b) ((a)<(b)?(a):(b))

#define TPOOL_THREAD_MIN (10)
#define TPOOL_THREAD_MAX (1024)
#define TPOOL_THREAD_HIGH_WATERMARK (50)
#define TPOOL_THREAD_LOW_WATERMARK (20)
#define TPOOL_TASK_QUEUE_SIZE (150)

static volatile unsigned int sessions = 0;

struct tpool *tpool = NULL;
struct tpool_attr tpool_attr;

time_t start_time;

void
log_stats(
    const struct tpool_stats *stats,
    char *suffix)
{
    time_t t;

    time(&t);
    printf("%lu: threads(min=%zu,max=%zu,total=%zu,idle=%zu,active=%zu,peak=%zu) tasks(pending=%zu,peak=%zu) sessions(total=%u): %s\n",
           t - start_time,
           tpool_attr.thread_min,
           tpool_attr.thread_max,
           stats->total_threads,
           stats->idle_threads,
           stats->active_threads,
           stats->peak_threads,
           stats->pending_tasks,
           stats->peak_tasks,
           sessions,
           suffix);
}

static void
task_handler(
    void *task,
    size_t tasklen)
{
    //int *data = (int *)task;

    if (++sessions % 1000 == 0)
    {
        struct tpool_stats stats;

        tpool_stats(tpool, &stats);

        log_stats(&stats, "task_handler");
    }

    //usleep(200000);
    sleep(20);
}

static int
overload_evaluator(
    const struct tpool_stats *stats)
{
    int increment = 0;

    //printf("%s: CHECKPOINT\n", __FUNCTION__);

    if (stats == NULL)
    {
        errno = EINVAL;
        fprintf(stderr, "The pointer pointed to a thread pool stats is NULL\n");
        return -1;
    }

    if (stats->idle_threads < TPOOL_THREAD_LOW_WATERMARK)
    {
        increment = min((TPOOL_THREAD_MAX - stats->total_threads), 
                        (stats->pending_tasks + TPOOL_THREAD_LOW_WATERMARK - stats->idle_threads));

        if (increment < 0)
            increment = 0;
    }

    if (increment > 0)
        log_stats(stats, "overload");
    
    return increment;
}

static int
underload_evaluator(
    const struct tpool_stats *stats)
{
    int decrement = 0;

    //printf("%s: CHECKPOINT\n", __FUNCTION__);

    if (stats == NULL)
    {
        errno = EINVAL;
        fprintf(stderr, "The pointer pointed to a thread pool stats is NULL\n");
        return -1;
    }

    if (stats->idle_threads > TPOOL_THREAD_HIGH_WATERMARK)
    {
        decrement = (stats->idle_threads - TPOOL_THREAD_HIGH_WATERMARK) / 2 + 1;

        /**
         * (30 - 15) / 2 + 1 = 8, 30 - 8 = 22
         * (22 - 15) / 2 + 1 = 4, 22 - 4 = 18
         * (18 - 15) / 2 + 1 = 2, 18 - 2 = 16
         * (16 - 15) / 2 + 1 = 1, 16 - 1 = 15
         */
    }
    else if ((TPOOL_THREAD_HIGH_WATERMARK >= stats->idle_threads) && (stats->idle_threads > TPOOL_THREAD_LOW_WATERMARK))
    {
        decrement = 1;
    }

    if (decrement > 0)
        log_stats(stats, "underload");

    return decrement;
}

int main()
{
    int i;
    int ret = 0;

    tpool_attr_init(&tpool_attr);

    tpool_attr.thread_min = TPOOL_THREAD_MIN;
    tpool_attr.thread_max = TPOOL_THREAD_MAX;
    tpool_attr.thread_stack_size = 524288;

    ret = tpool_attr_setoverloadevaluator(&tpool_attr, overload_evaluator);
    assert(ret == 0);

    ret = tpool_attr_setunderloadevaluator(&tpool_attr, underload_evaluator);
    assert(ret == 0);

    tpool_attr.task_queue_size = TPOOL_TASK_QUEUE_SIZE;
    tpool_attr.task_unit_size = sizeof(int);
    tpool_attr.task_handler = task_handler;
    tpool_attr.task_sweeper = NULL;

    tpool = tpool_init(&tpool_attr);
    if (tpool == NULL)
    {
        fprintf(stderr, "Failed to initialize thread pool\n");
        return EXIT_FAILURE;
    }

    sleep(2);

    time(&start_time);

//    while (1)
    {
        for (i = 0; i < 1000; ++i)
        {
            static int task = 0;
            size_t tasklen = 0;

            usleep((random()%10));
            ++task;
            tasklen = sizeof(task);
            tpool_enqueue(tpool, &task, &tasklen);
        }

        //sleep(100);
    }

    tpool_destroy(tpool, 10, NULL);

    return EXIT_SUCCESS;
}
