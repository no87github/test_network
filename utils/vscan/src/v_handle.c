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
 * v_handle.c
 *
 * Description: source file for the internal vscan handle struct.
 * Author: HY Cheng
 *
 * #001 Aug 11, 2005 HY Cheng Initial implementation.
 */
 
#include <assert.h>
#include "v_handle.h"

#define IS_BOOL(var) (var == 0 || var == 1)

void v_handle_invariant(const VscanHandle *handle)
{
    VscanHandle_t *vsh = NULL; 
    vsh = (VscanHandle_t *)handle;
    
    assert(vsh != NULL);
    
    assert(vsh->vsc != VSCTYPE_INVALID);
     
    /****************************/
    /*  validate common config  */
    /****************************/
    assert(vsh->config.common.tmppath != NULL);
    assert(vsh->config.common.ptnpath != NULL);
    assert(vsh->config.common.ptnfile != NULL);
    assert(vsh->config.common.spyptnfile != NULL);
    assert(vsh->config.common.max_scan_num >= 0);
    
    /****************************/
    /* validate protocol config */
    /****************************/
    
    /* enable flag*/
    assert(IS_BOOL(vsh->config.protocol.virus_enable));
    assert(IS_BOOL(vsh->config.protocol.compress_enable));
    assert(IS_BOOL(vsh->config.protocol.spyware_enable));
    assert(IS_BOOL(vsh->config.protocol.bot_enable));
    
    /* limit */
    assert(vsh->config.protocol.max_scan_loop >= 0);           
    assert(vsh->config.protocol.decompress_layer >=0 && vsh->config.protocol.decompress_layer <= 20);        	      
    assert(vsh->config.protocol.extract_file_size_limit >= 0); 
    assert(vsh->config.protocol.extract_file_count_limit >= 0); /*0 => no limit*/
    assert(vsh->config.protocol.extract_file_ratio_limit >= 0); /*0 => no limit*/
    assert(vsh->config.protocol.detection_level >= 0 && vsh->config.protocol.detection_level <= 4);
    
    /* scan flag */
    assert(IS_BOOL(vsh->config.protocol.intelli_scan));              
    assert(IS_BOOL(vsh->config.protocol.process_all_file));          
    assert(IS_BOOL(vsh->config.protocol.process_all_file_in_arc)); 
    
    /*include extension name list*/
    assert(vsh->config.protocol.ext_include != NULL);
    
    /*grey area*/
    assert(IS_BOOL(vsh->config.protocol.scan_spyware));
    assert(IS_BOOL(vsh->config.protocol.scan_adware));
    assert(IS_BOOL(vsh->config.protocol.scan_dialer));
    assert(IS_BOOL(vsh->config.protocol.scan_hacktool));
    assert(IS_BOOL(vsh->config.protocol.scan_joke));
    assert(IS_BOOL(vsh->config.protocol.scan_remoteaccess));
    assert(IS_BOOL(vsh->config.protocol.scan_passwdcrack));
    assert(IS_BOOL(vsh->config.protocol.scan_others));
    
    /*spyware exclude list*/
    assert(vsh->config.protocol.spyware_exclude != NULL); 
    
}

