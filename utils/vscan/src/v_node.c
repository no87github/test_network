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
 * Description: source file for the internal vscan node struct.
 * Author: HY Cheng
 *
 * #001 Aug 11, 2005 HY Cheng Initial implementation.
 */
 
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "v_common.h"
#include "v_node.h"

//static const pthread_rwlock_t g_rwlock_initializer = PTHREAD_RWLOCK_WRITER_NONRECURSIVE_INITIALIZER_NP;
 
vsh_node_t *new_vsh_node()
{
    int ret = -1;
    vsh_node_t *node = NULL;
    
    node = (vsh_node_t *)malloc(sizeof(vsh_node_t));
    if (node == NULL)
    {
        LOGERROR("Failed to allocate memory for vsh_node");
        goto leave;
    }
    
    memset(node, 0, sizeof(vsh_node_t));
    
    node->vsh = (VscanHandle_t *)malloc(sizeof(VscanHandle_t));
    if (node->vsh == NULL)
    {
        LOGERROR("Failed to allocate memory for VscanHandle");
        goto leave;
    }
    
    memset(node->vsh, 0, sizeof(VscanHandle_t));
    
    /* We have to assign all read/write locks with the value of PTHREAD_RWLOCK_INITIALIZER
     * because Linux's pthread implementation has the following behavior:
     * - The kind value of PTHREAD_RWLOCK_INITIALIZER is PTHREAD_RWLOCK_PREFER_WRITER_NP.
     * - The kind value initialized by pthread_rwlock_init() is PTHREAD_RWLOCK_PREFER_READER_NP.
     */
    //assert(sizeof(node->vsh->rwlock) == sizeof(g_rwlock_initializer));
    //memcpy(&node->vsh->rwlock, &g_rwlock_initializer, sizeof(g_rwlock_initializer));
    
    {
       pthread_rwlockattr_t attr;
       pthread_rwlockattr_init(&attr);
       pthread_rwlockattr_setkind_np(&attr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);

       pthread_rwlock_init(&node->vsh->rwlock, &attr);

       pthread_rwlockattr_destroy(&attr);
    }
    

    ret = 0;
    
leave:
    if (ret != 0)
    {
        if (node != NULL)
        {
            if (node->vsh != NULL)
            {
                xfree(node->vsh);
                node->vsh = NULL;
            }
            xfree(node);
            node = NULL;
        }
    }
    return node;
}

void delete_vsh_node(vsh_node_t * node)
{
    if (node != NULL)
    {
        if (node->vsh != NULL)
        {
            (void)pthread_rwlock_destroy(&node->vsh->rwlock);
            xfree(node->vsh);
            node->vsh = NULL;
        }
        xfree(node);
        node = NULL;
    }
}

int append_vsh_node(vsh_node_t * node_list, vsh_node_t * node)
{
    vsh_node_t *p = node_list;
    
    while (p) 
    {
        if (p->next == NULL) 
        {
            p->next = node;
            break;
        }
        p = p->next;
    }
    return 0;
}

vsh_node_t *create_vsh_node_list()
{
    vsh_node_t *node = NULL;
    
    if ((node = (vsh_node_t *)malloc(sizeof(vsh_node_t))) == NULL)
        return NULL;
    
    memset(node, 0, sizeof(vsh_node_t));/*dummy node */
    
    return node;
}

void delete_vsh_node_list(vsh_node_t * node_list, vscan_func_table_t *func_table)
{
    int en = 0;
    vsh_node_t *list = NULL;

    if (node_list == NULL || func_table == NULL)
    {
        errno = EINVAL;
        LOGERROR("node_list=%p, func_table=%p", node_list, func_table);
        return;
    }

    list = node_list->next;
    xfree(node_list); /*free the dummy node */
    
    /*free remaining nodes */
    while (list) 
    {
        vsh_node_t *p = list;
        list = list->next;
        if ((en = (*func_table->VSQuit)(p->vsh->vsc)) != 0)
        {
            LOGERROR("VSQuit(): %d", en);
            /* skip the error */
        }
        
        delete_vsh_node(p);
        p = NULL;
    }
}

