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
 * v_handle.h
 *
 * Description: header file for the internal vscan handle struct.
 * Author: HY Cheng
 *
 * #001 Aug 11, 2005 HY Cheng Initial implementation.
 */
 
#ifndef VSCAN_HANDLE_H
#define VSCAN_HANDLE_H

#include <pthread.h>
#include "vscan_def.h"
#include "tmvs.h"


typedef struct VscanHandle_st
{
   VSCTYPE vsc;             /*virus scan context,defined in VSAPI*/
   vscan_config_t config;   /*scan configuration*/
   pthread_rwlock_t rwlock; /*read/write lock for configuration change*/
}VscanHandle_t;

void v_handle_invariant(const VscanHandle *handle);


#endif

