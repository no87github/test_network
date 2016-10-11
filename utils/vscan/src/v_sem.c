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
 * v_sem.c
 *
 * Description: source file of the semaphore with timeout control for virus scan module 
 * Author: HY Cheng
 *
 * #001 Aug 11, 2005 HY Cheng Initial implementation.
 */
#include <stdio.h>
#include <errno.h>
#include "v_common.h"
#include "v_sem.h"

/*****************************************************/
/*                   EXPORT FUNCTION                                              */
/*****************************************************/
int vsem_init(vscan_semaphore_t * vsem, int value)
{
	if (pthread_cond_init(&vsem->scan_cond, NULL) != 0)
		LOGERROR("Failed to pthread_cond_init");
    
	if (pthread_mutex_init(&vsem->scan_mutex, NULL) != 0)
		LOGERROR("Failed to pthread_mutex_init");
    
	vsem->scan_num = 0;
	vsem->max_scan_num = value;
    
	return 0;
}

int vsem_wait(vscan_semaphore_t * vsem, struct timespec *tmTimeout)
{
	/*if the scanning jobs exceeds g_max_scan_num, then wait */
	if (pthread_mutex_lock(&vsem->scan_mutex) != 0)
		LOGERROR("Failed to pthread_mutex_lock");
    
	while (vsem->scan_num >= vsem->max_scan_num) 
    {
		int status;
        
		status = pthread_cond_timedwait(&vsem->scan_cond,  &vsem->scan_mutex, tmTimeout);

		/*When condition variable wait timeout, return VR_TIMEOUT */
		if (status == ETIMEDOUT) 
        {
			if (pthread_mutex_unlock(&vsem->scan_mutex) != 0)
				LOGERROR("Failed to pthread_mutex_unlock");
			return status;
		}

		/*When being interrupted by signal, contine to wait */
		if (status == EINTR)
			continue;

		/*other error */
		if (status != 0) 
        {
			LOGERROR("Failed to wait condition variable");
			if (pthread_mutex_unlock(&vsem->scan_mutex) != 0)
				LOGERROR("Failed to pthread_mutex_unlock");
			return status;
		}
	}
    
	vsem->scan_num++;
    
	if (pthread_mutex_unlock(&vsem->scan_mutex) != 0)
		LOGERROR("Failed to pthread_mutex_unlock");

	return 0;
}

int vsem_post(vscan_semaphore_t * vsem)
{
	/*wake up the waiting scan thread */
	if (pthread_mutex_lock(&vsem->scan_mutex) != 0)
		LOGERROR("Failed to pthread_mutex_lock");

	vsem->scan_num--;

	if (pthread_cond_signal(&vsem->scan_cond) != 0)
		LOGERROR("Failed to pthread_cond_signal");

	if (pthread_mutex_unlock(&vsem->scan_mutex) != 0)
		LOGERROR("Failed to pthread_mutex_unlock");
	return 0;
}

int vsem_destroy(vscan_semaphore_t * vsem)
{
	if (pthread_cond_destroy(&vsem->scan_cond) != 0)
		LOGERROR("Failed to pthread_cond_destroy");
    
	if (pthread_mutex_destroy(&vsem->scan_mutex) != 0)
		LOGERROR("Failed to pthread_mutex_destroy");
    
	vsem->scan_num = -1;
	vsem->max_scan_num = -1;
	return 0;
}
