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
 * v_node.h
 *
 * Description: header file for the internal vscan node struct.
 * Author: HY Cheng
 *
 * #001 Aug 11, 2005 HY Cheng Initial implementation.
 */
 
#ifndef VSCAN_NODE_H
#define VSCAN_NODE_H

#include "v_handle.h"
#include "v_eng_reload.h"

/*
* struct for tracking the vsh(s)
*/
typedef struct vsh_node_st 
{
    VscanHandle_t *vsh;
    struct vsh_node_st *next;
} vsh_node_t;

vsh_node_t *create_vsh_node_list();
void delete_vsh_node_list(vsh_node_t * node_list, vscan_func_table_t *func_table);
vsh_node_t *new_vsh_node();
void delete_vsh_node(vsh_node_t * node);
int append_vsh_node(vsh_node_t * node_list, vsh_node_t * node);


#endif
