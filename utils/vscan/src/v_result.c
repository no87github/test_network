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
 * v_result.c
 *
 * Description: source file of the virus result struct for virus scan module 
 * Author: HY Cheng
 *
 * #001 Aug 11, 2005 HY Cheng Initial implementation.
 */
 
#include <locale.h>
#include <libintl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include "list.h"
#include "v_common.h"
#include "v_result.h"

/*****************************************************/
/*                EXPORT FUNCTION                    */
/*****************************************************/

int has_virus(vscan_result_t *scan_result)
{
    if(scan_result->virus_count > 0)
        return 1;
    return 0;
}

int has_spyware(vscan_result_t *scan_result)
{
    if(scan_result->spyware_count > 0)
        return 1;
    return 0;
}

int has_bot(vscan_result_t *scan_result)
{
    if(scan_result->bot_count > 0)
        return 1;
    return 0;
}

int has_limit(vscan_result_t *scan_result)
{
    if (scan_result->err_compressdeep_count == 0 && 
        scan_result->err_filesize_count == 0 && 
        scan_result->err_filecount_count == 0 &&  
        scan_result->err_fileratio_count == 0 &&  
        scan_result->err_max_scan_loop == 0 &&
        scan_result->err_unhandle_count == 0)
    {
        return 0;
    }
    
    return 1;
}

int has_malware(vscan_result_t *scan_result)
{
    if (has_virus(scan_result) || has_spyware(scan_result) || has_bot(scan_result))
        return 1;
    
    return 0;
}

int virus_only(vscan_result_t *scan_result) 
{
    if ((has_virus(scan_result) != 0) &&
        (has_spyware(scan_result) == 0) && 
        (has_bot(scan_result) == 0) && 
        (has_limit(scan_result) == 0))
    return 1;
    
    return 0;
}

int spyware_only(vscan_result_t *scan_result)
{
    if ((has_virus(scan_result) == 0) && 
        (has_spyware(scan_result) != 0) && 
        (has_bot(scan_result) == 0) && 
        (has_limit(scan_result) == 0))
    return 1;
    
    return 0;
}

int bot_only(vscan_result_t *scan_result)
{
    if ((has_virus(scan_result) == 0) && 
        (has_spyware(scan_result) == 0) && 
        (has_bot(scan_result) != 0) && 
        (has_limit(scan_result) == 0))
    return 1;
    
    return 0;
}

int limit_only(vscan_result_t *scan_result)
{
    if ((has_virus(scan_result) == 0) &&
        (has_spyware(scan_result) == 0) &&
        (has_bot(scan_result) == 0) &&
        (has_limit(scan_result) != 0))
    return 1;

    return 0;
}

int all_virus_clean(vscan_result_t *scan_result)
{
    if (scan_result->virus_count == scan_result->clean_ok_count)
        return 1;
    
    return 0;
}

void vscan_rsult_to_debuglog(vscan_result_t *scan_result)
{
    LOGDEBUG("+++ vscan result +++");
    LOGDEBUG("      scan_cb_count=%d",scan_result->scan_cb_count);
    LOGDEBUG("      no_virus_count=%d",scan_result->no_virus_count);
    LOGDEBUG("      virus_count=%d",scan_result->virus_count);
    LOGDEBUG("      spyware_count=%d",scan_result->spyware_count);
    LOGDEBUG("      bot_count=%d",scan_result->bot_count);
    LOGDEBUG("      clean_ok_count=%d",scan_result->clean_ok_count);
    LOGDEBUG("      clean_err_count=%d",scan_result->clean_err_count);
    LOGDEBUG("      err_compressdeep_count=%d",scan_result->err_compressdeep_count);
    LOGDEBUG("      err_filesize_count=%d",scan_result->err_filesize_count);
    LOGDEBUG("      err_filecount_count=%d",scan_result->err_filecount_count);
    LOGDEBUG("      err_fileratio_count=%d",scan_result->err_fileratio_count);
    LOGDEBUG("      err_unhandle_count=%d",scan_result->err_unhandle_count);
    LOGDEBUG("      err_max_scan_loop=%d",scan_result->err_max_scan_loop);
    LOGDEBUG("--- vscan result ---");
}

VirusResult *VirusResult_new()
{
	VirusResult *vr = NULL;
    
	if((vr = malloc(sizeof(VirusResult))) == NULL)
        return NULL;
    
    memset(vr, 0, sizeof(VirusResult));
    
    vr->filename = NULL;
    vr->virusname = NULL;
    vr->majortype = NULL;
    vr->minortype = NULL;
    vr->clean_result = C_NO_CLEAN;
    vr->action.reason = R_INVALID;
    vr->action.action = A_INVALID;
    vr->action.result = AR_SUCCESS;
    vr->next = NULL;
    
	return vr;
}


void VirusResult_free(VirusResult * first_vr)
{
	VirusResult *vr = NULL;
	VirusResult *tmp_vr = NULL;

	if (first_vr == NULL)
		return;
    
	vr = first_vr;
    
	while (vr)
    {
	    xfree(vr->filename);
	    xfree(vr->virusname);
		xfree(vr->majortype);
        xfree(vr->minortype);
		tmp_vr = vr;
		vr = vr->next;
		xfree(tmp_vr);
	}
}

int VirusResult_appendSubVirus(VirusResult * attached_vr,
			       VirusResult * assign_vr)
{
	VirusResult *vr = NULL;
    
	if (attached_vr == NULL || assign_vr == NULL)
		return -1;
    
	vr = attached_vr;
	while (vr) {
		if (vr->next == NULL) {
			vr->next = assign_vr;	
			break;
		} else
			vr = vr->next;
	}

	return 0;
}

#ifdef USE_ATSE
/*
pwd_node_t *password_node_new() {
   pwd_node_t *p;
   p = malloc(sizeof(scan_evae_result_node_t));
   if(p==NULL) {
      return NULL;
   }
   memset(p, 0, sizeof(*p));
   return p;
}

void password_node_del(pwd_node_t *p) {
   if(p==NULL) {
      return NULL;
   }
   if (p->pwd) xfree(p->pwd);
   free(p);
   return;
}
*/
scan_evae_result_node_t *scan_evae_result_node_new() {
    scan_evae_result_node_t *p;

    p = malloc(sizeof(scan_evae_result_node_t));
    if(p==NULL) {
        return NULL;
    }
    memset(p, 0, sizeof(*p));
    return p;
}

void scan_evae_result_node_del(scan_evae_result_node_t *p) {
   //pwd_node_t *pn;

   if(p==NULL) {
      return;
   }

   if (p->file_name) xfree(p->file_name);
/*
   {  
      struct list_head *iter, *iter_next;
      list_for_each_safe(iter, iter_next, &p->pwd_list_head) {
         pn = list_entry(iter, pwd_node_t, list_node);
         list_del(iter);
         password_node_del(pn);
      }
   }
*/
   free(p);
   return;
}

scan_evae_result_t *scan_evae_result_new()
{
    scan_evae_result_t *er = NULL;

    if((er = malloc(sizeof(scan_evae_result_t))) == NULL)
        return NULL;

    memset(er, 0, sizeof(scan_evae_result_t));
    list_head_init(&er->list_head);

    return er;
}

void scan_evae_result_free(scan_evae_result_t *er) {
    scan_evae_result_node_t *en;

    if(er==NULL) {
        return;
    }

    {  
        struct list_head *iter, *iter_next;
        list_for_each_safe(iter, iter_next, &er->list_head) {
            en = list_entry(iter, scan_evae_result_node_t, list_node);
            list_del(iter);
            scan_evae_result_node_del(en);
        }
    }

    xfree(er);
}

#endif
