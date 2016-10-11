/*
 * Copyright (C) 2005, Trend Micro Incorporated. All Rights Reserved. This program is an unpublished
 * copyrighted work which is proprietary to Trend Micro Incorporated and contains confidential
 * information that is not to be reproduced or disclosed to any other person or entity without prior
 * written consent from Trend Micro, Inc. in each and every instance.
 *
 * WARNING: Unauthorized reproduction of this program as well as unauthorized preparation of
 * derivative works based upon the program or distribution of copies by sale, rental, lease or
 * lending are violations of federal copyright laws and state trade secret laws, punishable by civil
 * and criminal penalties.
 */

/*
 * v_sem.h
 *
 * Description: header file of the semaphore with timeout control for virus scan module 
 * Author: HY Cheng
 *
 * #001 Aug 11, 2005 HY Cheng Initial implementation.
 */
 
#ifndef _VIRUS_SEMAPHORE_H
#define _VIRUS_SEMAPHORE_H

#include <pthread.h>

/* struct for concurrent scanning control */
typedef struct vscan_semaphore_st {
	pthread_cond_t scan_cond;	          /*condition variable for scanning */
	pthread_mutex_t scan_mutex;               /*mutex for scanning */
	int scan_num;	                          /*the number of concurrent virus scanning  */
	int max_scan_num;                         /*max number of concurrent virus  scan  */
} vscan_semaphore_t;

/*
 * vsem_init: initialize the vsem object
 * Paramemters:
 *      vsem: IN : pointer to vsem object
 *      value: IN : the value of max concurrency 
 * Return:
 *      0 if successful; -1 if error
 */
int vsem_init(vscan_semaphore_t * vsem, int value);

/*
 * vsem_wait: wait  the vsem object
 * Paramemters:
 *      vsem: IN : pointer to vsem object
 * Return:
 *      0 if successful; -1 if error
 */
int vsem_wait(vscan_semaphore_t * vsem, struct timespec *tmTimeout);

/*
 * vsem_post: post the vsem object
 * Paramemters:
 *      vsem: IN : pointer to vsem object
 * Return:
 *      0 if successful; -1 if error
 */
int vsem_post(vscan_semaphore_t * vsem);

/*
 * vsem_init: destroy  the vsem object
 * Paramemters:
 *      vsem: IN : pointer to vsem object
 * Return:
 *      0 if successful; -1 if error
 */
int vsem_destroy(vscan_semaphore_t * vsem);

#ifdef __cplusplus
}				/* extern "C" */
#endif


#endif
