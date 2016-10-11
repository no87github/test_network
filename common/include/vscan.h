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
 * vscan.h
 *
 * Description: header file for virus scan module in ISGL.
 * Author: HY Cheng
 *
 * #001 Aug 11, 2005 HY Cheng Initial implementation.
 */

#ifndef VSCAN_H
#define VSCAN_H

#include <tmvs.h>
#include <v_result.h>
#include <tmdebug.h>
#include <vscan_def.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * vscan_init(): initialize virus scan engine
 * Parameters:
 *      config: IN : config setting for vscan
 *      log: IN : log handle pointer
 * Return:
 *      On success, VscanHandle is returned.
 *      On error, NULL is returned.
 */
VscanHandle *  vscan_init(vscan_config_t * config);


/*
 * vscan_fini(): terminate virus scan engine
 * Parameters:
 *      vsh: IN : vscan handle
 * Return:
 *      VSCAN_SUCCESS if successful; < 0 if error
 */
int  vscan_fini(VscanHandle *vsh);


/*
 * vscan_scan_mem(): scan memory for virus
 * Parameters:
 *      vsh: IN : vscan handle
 *      data: IN : the input data
 *      n: IN : length of the input data
 *      name: IN : real name of the input data
 *      virus_result: OUT : output the virus result
 *      scan_result: OUT : output the scan result statistics
 * Return:
 *      VSCAN_ERROR_INTERNAL : error
 *      VSCAN_SUCCESS: success
 */
int  vscan_scan_mem(const VscanHandle *vsh,
                    VSCTYPE* pthread_vsc,
                    unsigned int *patse_reload_indicator,
                    char *data, 
                    size_t n,
                    char *name, 
                    VirusResult *virus_result,
                    vscan_result_t *scan_result, 
#ifdef USE_ATSE
                    scan_evae_result_t *evae_result
#endif
                    );

/*
 * vscan_scan_fd(): scan file descriptor for virus
 * Parameters:
 *      vsh: IN : vscan handle
 *      fd: IN : the input file descriptor
 *      n: IN : Optional, length of the input data, could be zero
 *      name: IN : Optional, real name of the input data, could be zero
 *      virus_result: OUT : output the virus result
 *      scan_result: OUT : output the scan result statistics
 * Return:
 *      VSCAN_ERROR_INTERNAL : error
 *      VSCAN_SUCCESS: success
 */
int vscan_scan_fd(const VscanHandle * handle,
               VSCTYPE* pthread_vsc,
               unsigned int *patse_reload_indicator,
               int fd,
               size_t n, 
               char *name,
               VirusResult * virus_result,
               vscan_result_t *scan_result, 
#ifdef USE_ATSE
               scan_evae_result_t *evae_result
#endif
               );

/*
 * vscan_reload_pattern(): reload virus pattern at runtime
 * Parameters:
 *      ptnlist: IN : the list of  virus pattern's path and basename
 * Return:
 *      VSCAN_SUCCESS if successful; < 0 if error
 */
int  vscan_reload_pattern(pattern_list *ptnlist);


/*
 * vscan_create_handle: create scan handle for each protocol
 * Paramemters:
 *      protocol: IN : scan configuration of protocol
 * Return:
 *      vsh if successful
 *      NULL if error
 */
VscanHandle * vscan_create_handle(protocol_config_t protocol);


/*
 * vscan_delete_handle: delete scan handle
 * Parameters:
 *      vsh: IN : vscan handle
 * Return: 
 *      VSCAN_SUCCESS if sucessful; < 0 if error
 */
int  vscan_delete_handle(VscanHandle *vsh);


/*
 * vscan_set_config: set up configuration of protocol at runtime
 * Parameters:
 *      vsh: IN : vscan handle
 *      protocol: IN : scan configuration of protocol
 * Return:
 *      VSCAN_SUCCESS if sucessful; < 0 if error
 */
int  vscan_set_config(const VscanHandle *vsh, const protocol_config_t *protocol); 

/*
 * vscan_reload_engine: reload the vsapi engine
 * Parameters:
 *      new_engine_path : IN : new vsapi engine path
 *      ptnlist: IN : the list of  virus pattern's path and basename
 * Return:
 *      VSCAN_SUCCESS if sucessful; < 0 if error
 */
int  vscan_reload_engine (const char *new_engine_path, pattern_list * ptnlist);

/*
 * vscan_get_version: get the infomation about vsapi engine
 * Parameters:
 *      engine_info : IN : the structure for the infomation about vsapi engine
 * Return:
 *      VSCAN_SUCCESS if sucessful; < 0 if error
 */
int vscan_get_version(const VscanHandle * vsh, vscan_version_t *version);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* VSCAN_H */
