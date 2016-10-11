/*
 * Copyright (C) 2005, Trend Micro Incorporated.  All Rights Reserved.
 * This program is an unpublished copyrighted work which is
 * proprietary to Trend Micro Incorporated and contains confidential
 * information that is not to be reproduced or disclosed to any other
 * person or entity without prior written consent from Trend Micro,
 * Inc. in each and every instance.
 *
 * WARNING: Unauthorized reproduction of this program as well as
 * unauthorized preparation of derivative works based upon the program
 * or distribution of copies by sale, rental, lease or lending are
 * violations of federal copyright laws and state trade secret laws,
 * punishable by civil and criminal penalties.
 */

/**
 * @file semaphore.c Session control functions used by all scan
 * engine.
 *
 * @author John Lee <john_lee@trend.com.tw>
 */

#include <errno.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>

#include "phoenix_ipc_key.h"

#define SCAN_MAX_SESSION (8)

#ifdef _SEM_SEMUN_UNDEFINED
union semun
{
    int val;
    struct semid_ds *buf;
    unsigned short int *array;
    struct seminfo *__buf;
};
#endif

int scan_enter_sc ()
{
    int sid, r;
    struct sembuf sop;
    sid = semget (SCAN_SEM_KEY, 0, 0);
    if (sid < 0)
    {
        union semun arg;
        if (errno != ENOENT) return errno;
        /* create & set value */
        sid = semget (SCAN_SEM_KEY, 1, IPC_CREAT | IPC_EXCL | 0600);
        if (sid < 0) return errno;
        arg.val = SCAN_MAX_SESSION;
        r = semctl (sid, 0, SETVAL, arg);
        if (r < 0) return errno;
    }
    sop.sem_num = 0; sop.sem_op = -1; sop.sem_flg = SEM_UNDO;
    while ((r = semop (sid, &sop, 1)) < 0 && errno == EINTR);
    return r ? errno : 0;
}

int scan_leave_sc ()
{
    int sid, r;
    struct sembuf sop;
    sid = semget (SCAN_SEM_KEY, 0, 0);
    if (sid < 0) return errno;
    sop.sem_num = 0; sop.sem_op = 1; sop.sem_flg = SEM_UNDO;
    while ((r = semop (sid, &sop, 1)) < 0 && errno == EINTR);
    return r ? errno : 0;
}
