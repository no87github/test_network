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
 * vscan.c
 *
 * Description: source file for virus scan module in ISGL.
 * Author: HY Cheng
 *
 * #001 Aug 11, 2005 HY Cheng Initial implementation.
 */

#include "list.h"
#include <stdio.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/time.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <ctype.h>
#include <vscan.h>
#include <vstd2category.h>
#include <msg_utils.h>
#include <sk_string.h>
#include <sk_io.h>
#include <tmsyslog.h>
#include "v_common.h"
#include "v_handle.h"
#include "v_eng_reload.h"
#include "v_node.h"

#define SHA1_FMT_5            "%02X%02X%02X%02X%02X"
#define SHA1_FMT              SHA1_FMT_5 SHA1_FMT_5 SHA1_FMT_5 SHA1_FMT_5
#define SHA1_TUPLE_1(sha1, n) ((((unsigned char*) (sha1))[n]) & 0xff)
#define SHA1_TUPLE_4(sha1, n) SHA1_TUPLE_1(sha1, n), SHA1_TUPLE_1(sha1, n + 1), SHA1_TUPLE_1(sha1, n + 2), SHA1_TUPLE_1(sha1, n + 3)
#define SHA1_TUPLE(sha1)      SHA1_TUPLE_4(sha1, 0), SHA1_TUPLE_4(sha1, 4), SHA1_TUPLE_4(sha1, 8), SHA1_TUPLE_4(sha1, 12), SHA1_TUPLE_4(sha1, 16)

/*****************************************************/
/*                   DATA STRUCTURE                  */
/*****************************************************/
/* Enum for scan type */
enum 
{
	SCAN_IN_MEMORY = 0,
    SCAN_IN_FILED = 2
};

/* callback data for vscan_pfcb*/
typedef struct vscan_callback_data_st 
{
    protocol_config_t *protocol;      /* protocol setting */
	vscan_result_t *scan_result;      /* keep the statistics of virus scanning */
	int do_clean;                     /* flag to do clean */
	VirusResult *virus_result;        /* linked list of infected virus result */
    vscan_func_table_t *func_table;   /* function table for vsapi */
#ifdef USE_ATSE
    scan_evae_result_t *evae_result;
#endif
}vscan_callback_data;

/* 
* struct for different resource(file/memory)
*/
typedef struct vscan_resource_st
{
	int type;		                /*resource type */
	char *name;		                /*real name */
	char *file;		                /*file name */
	unsigned char *data;	        /*begin address of memory buffer */
	size_t n;		                /*size of memory buffer */
    int fd;                         /*file descriptor */
}vscan_resource_t;                                                                                    


/*****************************************************/
/*                 GLOBAL  VARIABLE                  */
/*****************************************************/

static const char ModuleName[] = "vscan";

static pthread_mutex_t thread_safe_mutex = PTHREAD_MUTEX_INITIALIZER; /*virus thread-safe protection mutex. */
static pthread_mutex_t local_vsh_mutex = PTHREAD_MUTEX_INITIALIZER; /*protect the local vsh*/ 
//static const pthread_rwlock_t g_rwlock_initializer = PTHREAD_RWLOCK_WRITER_NONRECURSIVE_INITIALIZER_NP; 
static VscanHandle_t *g_vsh = NULL; /* global vsh */ 
static vsh_node_t *g_vsh_list = NULL;  /* vsh list for each protocol*/ 
static pthread_rwlock_t g_rwlock_pattern = PTHREAD_RWLOCK_WRITER_NONRECURSIVE_INITIALIZER_NP; /* to control the pattern reload*/
static void *g_vsapi_handle = NULL; /* vsapi engine handle */
static pthread_rwlock_t g_rwlock_engine = PTHREAD_RWLOCK_WRITER_NONRECURSIVE_INITIALIZER_NP; /* to control the engine reload*/
static vscan_func_table_t g_func_table; /* vsapi function table */

extern int queue_size;
extern unsigned int *pg_atse_reload_indicator;
extern VSCTYPE** ppg_thread_vsc;

/*****************************************************/
/*                  MACRO DEFINITION                 */
/*****************************************************/

#define MAX_MINOR_TYPE_LIST_SIZE (512)

/*****************************************************/
/*                   STATIC FUNCTION                 */
/*****************************************************/


__inline__ static vscan_func_table_t *get_func_table() {
    if(pthread_rwlock_rdlock(&g_rwlock_engine) != 0)
        LOGERROR("Failed to pthread_rwlock_rdlock");
    return &g_func_table;
}

__inline__ static int release_func_table() {
    if(pthread_rwlock_unlock(&g_rwlock_engine) != 0)
        LOGERROR("Failed to pthread_rwlock_unlock");
    return 0;
}

static VirusResult *get_last_virusresult(VirusResult * virus_result) {
	VirusResult *vr = NULL;
    
	vr = virus_result;
	while (vr) {
		if (vr->next == NULL)
			return vr;
		vr = vr->next;
	}
    
	return NULL;
}

/* create virus scanning handle,    sharing configuration, 
*                                           pattern, 
*                                           runtime option.
*/
static int create_thread_vsc(VSCTYPE * dst_vsc, VSCTYPE src_vsc, vscan_func_table_t *func_table) {
   int ret = -1;
   int en = 0;

   /*Share source VSC configuration */
   pthread_mutex_lock(&local_vsh_mutex); /*because the VSInit/VSReadVirusPattern/VSQuit isn't thread safe, use mutext to protect*/
   if((en = (*func_table->VSInit)(0, (char *) ModuleName, src_vsc, dst_vsc)) != 0) {
		LOGERROR("Failed to VSInit, en = %d", en);
		goto leave;
	}
    
	/*Share source VSC pattern */
	if((en = (*func_table->VSReadVirusPattern)(*dst_vsc, src_vsc, NULL, NULL)) != 0) {
		LOGERROR("Failed to VSReadVirusPattern, en = %d", en);
		goto leave;
	}
      
    ret = 0;

leave:
    pthread_mutex_unlock(&local_vsh_mutex);

	return ret;
}


void delete_thread_vsc(VSCTYPE * vsc, vscan_func_table_t *func_table)
{
    int en = 0;
    
    pthread_mutex_lock(&local_vsh_mutex);
    if((en = (*func_table->VSQuit)(*vsc)) != 0) {
       LOGERROR("Failed to VSQuit, en = %d", en);
	   goto leave;
    }
  
    *vsc = VSCTYPE_INVALID;
   
leave:
    pthread_mutex_unlock(&local_vsh_mutex);
    
}

static int set_long_virusname(VSCTYPE vsc, char* virusname, char **long_virusname, vscan_func_table_t *func_table) {
    int en; 
    VSVirusNameProp ln;
    char buf[16+1];

    ln.name_buffer_size = sizeof(buf);
    ln.name_buffer = buf;

    en = (*(func_table->VSGetVirusPropertyByName))(vsc, virusname, VSVPN_LONG_VIRNAME, NULL, &ln);
    if (en != 1) {
        if (en != BUFFER_TOO_SHORT_ERR) {  
            LOGERROR("Failed to VSGetVirusPropertyByName");
            return -1;
        }

        ln.name_buffer = malloc(ln.name_buffer_size);
        if (ln.name_buffer == NULL) { 
            LOGERROR("Failed to malloc");
            return -1;
        }

        en = (*(func_table->VSGetVirusPropertyByName))(vsc, virusname, VSVPN_LONG_VIRNAME, NULL, &ln);
        if (en != 1) {
            LOGERROR("Failed to VSGetVirusPropertyByName");
            return -1;
        }
    }

    *long_virusname = strdup(ln.name_buffer);

    if (ln.name_buffer != buf) {
        xfree(ln.name_buffer); 
    }

    if(*long_virusname == NULL) {
        LOGERROR("Failed to strdup");
        return -1;
    }

    return 0;
}

static int set_major_type(VSCTYPE vsc, char *virusname, char **majortype, vscan_func_table_t *func_table) {
    VSVirusTypeProp VP;

    if ((*func_table->VSGetVirusPropertyByName)(vsc, virusname, VSVPN_QUERY_MAJOR, NULL, (void *) &VP) < 0) {
        LOGERROR("Failed to VSGetVirusPropertyByName");
        return -1;
    }

    *majortype = strdup(VP.vp_Name);

    return 0;
}

static int set_minor_type(VSCTYPE vsc, char *virusname, char **minorrtype, vscan_func_table_t *func_table) {
    int ret = -1;
    int rc = 0;
    VSVirusTypeProp VP;
    VSVirusTypeProp* pVP = NULL;
    VSVirusTypePropArray VPA;
    char text_[MAX_MINOR_TYPE_LIST_SIZE] = {0};
    sk_string_t text;
    char *minor_type_buffer = NULL;

    sk_string_create(&text, text_, sizeof(text_));

    VPA.pVP = &VP;
    VPA.count = 1;
    rc = (*func_table->VSGetVirusPropertyByName)(vsc, virusname, VSVPN_QUERY_MINOR, NULL, (void*)&VPA);
    if (rc >= 1) {
        int i = 0;

        if((pVP = (VSVirusTypeProp*)malloc(sizeof(VSVirusTypeProp)*rc)) == NULL) {
            LOGERROR("Failed to malloc");
            goto leave;
        }
        VPA.pVP = pVP;
        VPA.count = rc;
        if((rc = (*func_table->VSGetVirusPropertyByName)(vsc, virusname, VSVPN_QUERY_MINOR, NULL, (void*)&VPA)) == 0) {
            LOGINFO("No minor types");
            ret = 0;
            goto leave;
        }

        for ( i = 0 ; i < rc ; i++ ) {
            if(sk_string_append_string_urlenc(&text,VPA.pVP[i].vp_Name) != 0) {
                LOGERROR("Failed to sk_string_append_string_urlenc");
                goto leave;
            }
            if(i < (rc - 1)) {
                if(sk_string_append_string(&text,",") != 0) {
                    LOGERROR("Failed to sk_string_append_string");
                    goto leave;
                } 
            }
        }
    }

    minor_type_buffer = (char *)sk_string_get_content(&text);

    if (minor_type_buffer != NULL) {
        if((*minorrtype = strdup(minor_type_buffer)) == NULL) {
            LOGERROR("Failed to strdup");
            goto leave;
        }
    } else {
        *minorrtype = NULL;
    }

    ret = 0;

leave:

    if(NULL != pVP)
        xfree(pVP);

    sk_string_destroy(&text);

    return ret;
}

static VirusResult *append_virus_result(VirusResult *virus_result_list, VirusResult *virus_result) {
    VirusResult *vr = NULL;
    int newed = 0;

    /* set new result */
    if (virus_result_list->virusname == NULL) {	/* not yet touched */
        vr = virus_result_list;
    } else {
        vr = VirusResult_new();
        if(!vr){
            LOGERROR("Failed to VirusResult_new()");
            return NULL;
        }
        newed = 1;
    }
    vr->filename = virus_result->filename;
    vr->virusname = virus_result->virusname;
    vr->majortype = virus_result->majortype;
    vr->minortype = virus_result->minortype;
    vr->system_clean = virus_result->system_clean;
    vr->virus_maybe = virus_result->virus_maybe;
    vr->action.reason = virus_result->action.reason;
    vr->detection_level = virus_result->detection_level;
    if (newed) {
        VirusResult_appendSubVirus(virus_result_list,vr);
    }       

    return vr;
}

#define OFFSETOF(s,m)                   ((char*)&((s*)0)->m - (char*)0)
#define MIN_EXTENDSIZE(last_member)     ((OFFSETOF(VIRINFO_EX, last_member) - sizeof(VIRINFO)) + sizeof(((VIRINFO_EX*)0)->last_member))

static int scan_callback_func(VSCTYPE vsc, VSPFCB *pf, int *action) {
    VIRINFO_EX *pvirinfo = NULL;
    vscan_callback_data *pcbdata = NULL;
    VirusResult *curr_vr = NULL;

    LOGDEBUG("[VSCAN] ==>scan_callback_func");    

    pvirinfo = (VIRINFO_EX *) (pf->pfcb_Info);
    pcbdata = (vscan_callback_data *) pf->pfcb_Para;

    pcbdata->scan_result->scan_cb_count++;

    if (pf->pfcb_status == 0) {
        /* no virus found */
        pcbdata->scan_result->no_virus_count++;
    } else if (pf->pfcb_status > 0) {
        VirusResult vr = {0};

        if((vr.filename = strdup(pf->pfcb_FileName)) == NULL)
        {
            LOGERROR("Failed to strdup");
            goto free;
        }

        if(set_long_virusname(vsc, pvirinfo->vi_VirusName, &vr.virusname, pcbdata->func_table) != 0)
        {
            LOGERROR("Failed to set_long_virusname");
            goto free; 
        }

        if(set_major_type(vsc,pvirinfo->vi_VirusName,&vr.majortype,pcbdata->func_table)!= 0) 
        {
            LOGERROR("Failed to set_major_type");
            goto free;
        }

        if(set_minor_type(vsc,pvirinfo->vi_VirusName,&vr.minortype,pcbdata->func_table)!= 0) 
        {
            LOGERROR("Failed to set_minor_type");
            goto free;
        }
        if(strstr(vr.minortype,"SystemClean") == NULL)
        {
            vr.system_clean = 0;
        } else {
            vr.system_clean = 1;
        }
        if (pvirinfo->vi_VirusFlag & Virus_Maybe)
            vr.virus_maybe = 1;
        else
            vr.virus_maybe = 0;
        {
           int min_extendsize = MIN_EXTENDSIZE(vi_atse_rule_aggressive_level);
           if (min_extendsize <= pvirinfo->vi_ExtendSize) {
              vr.detection_level = pvirinfo->vi_atse_rule_aggressive_level;
           }
        }
           if(strcasecmp(vr.majortype,"spyware") == 0)
        {
            if(pcbdata->protocol->spyware_enable == 1)
            {
                pcbdata->scan_result->spyware_count++;
                vr.action.reason = R_SPYWARE;
                if(NULL == (curr_vr = append_virus_result(pcbdata->virus_result, &vr)))
                {
                    LOGERROR("Failed to append_virus_result");
                    goto free;
                }
                else
                    goto leave;

            }
        } else if(strcasecmp(vr.majortype,"packer") == 0) {
            if(pcbdata->protocol->bot_enable == 1)
            {
                pcbdata->scan_result->bot_count++;
                vr.action.reason = R_BOT;
                if(NULL == (curr_vr = append_virus_result(pcbdata->virus_result, &vr)))
                {
                    LOGERROR("Failed to append_virus_result");
                    goto free;
                }
                else
                    goto leave;
            }
        } else {
            if(pcbdata->protocol->virus_enable == 1) {
                pcbdata->scan_result->virus_count++;
                vr.action.reason = R_VIRUS_FIRST;
                if(NULL == (curr_vr = append_virus_result(pcbdata->virus_result, &vr))) {
                    LOGERROR("Failed to append_virus_result");
                    goto free;
                } else {
                    /*set clean action */
                    if (pcbdata->do_clean == 1)
                        *action = VC_ACT_CLEAN;

                    goto leave;

                }
            }
        }
free:              
        if(vr.filename)
            xfree(vr.filename);
        if(vr.virusname)
            xfree(vr.virusname);
        if(vr.majortype)
            xfree(vr.majortype);
        if(vr.minortype)
            xfree(vr.minortype);	           
    } else if (pf->pfcb_status == MAXDECOM_ERR) {
        /* this is for compress_deep */
        pcbdata->scan_result->err_compressdeep_count++;
        LOGINFO("vscan_pfcb:MAXDECOM_ERR");
    } else if (pf->pfcb_status == EXTRACT_TOO_BIG_ERR) {
        /* this is for extraction limit violated */
        pcbdata->scan_result->err_filesize_count++;
        LOGINFO("vscan_pfcb:EXTRACT_TOO_BIG_ERR");
    } else if(pf->pfcb_status == ZIP_FILE_COUNT_ERR) {
        /* this is for file count limit of archive file violated */
        pcbdata->scan_result->err_filecount_count++;
        LOGINFO("vscan_pfcb:ZIP_FILE_COUNT_ERR");
    } else if(pf->pfcb_status == ZIP_RATIO_ERR) {
        /* this is for file ratio limit of archive file violated */
        pcbdata->scan_result->err_fileratio_count++;
        LOGINFO("vscan_pfcb:ZIP_RATIO_ERR");
    } else {	/* something error, may be unhandled file format, corrupted file format, 
           password protected compress file or office file... */
        pcbdata->scan_result->err_unhandle_count++;
        LOGINFO("vscan_pfcb:Unhandled file, ret:%d", pf->pfcb_status);
    }

leave:   
#ifdef USE_ATSE
    {
        scan_evae_result_t *er = pcbdata->evae_result;
        if(er->curr_en!=NULL) {
            scan_evae_result_node_t *en = er->curr_en;
            if(0>pf->pfcb_status) {
                en->ret_code = pf->pfcb_status;
                if(en->vr!=NULL) {
                    LOGERROR("evae_result_t already has VirusResult,er:%p,vr:%p", en, en->vr);
                }
            }
            en->vr = curr_vr;
        } else {	/* No scan_evae_result with same layer found */
            if (0 <= pf->pfcb_status) {
                LOGDEBUG("Can't find valid scan_evae_result_node_t with this virus, layer:%d, name:%s, status:%d", pf->pfcb_CompressLayer, pf->pfcb_FileName, pf->pfcb_status);
            } else {
                LOGERROR("Can't find valid scan_evae_result_node_t with this virus, layer:%d, name:%s, status:%d", pf->pfcb_CompressLayer, pf->pfcb_FileName, pf->pfcb_status);
            }
        }
    }
#endif
    LOGDEBUG("[VSCAN] <==scan_callback_func");
    return VSCAN_SUCCESS;
}

static int action_callback(VSCTYPE vsc, VSPFCB *pf, int *action) {
    vscan_callback_data *pcbdata = (vscan_callback_data *) pf->pfcb_Para;
    LOGDEBUG("[VSCAN] ==>action_callback");    

    if (*action == VC_ACT_CLEAN) {
        VirusResult *vr = NULL;
        vr = get_last_virusresult(pcbdata->virus_result);
        if(!vr) {
            LOGERROR("Failed in get_last_virusresult()");
            return VSCAN_ERROR_INTERNAL;
        }
        if (pf->pfcb_status != 0) {
            /* clean fail */
            vr->clean_result = C_CLEAN_FAIL;
            vr->action.reason = R_VIRUS_SECOND;
            pcbdata->scan_result->clean_err_count++;
            LOGWARN("Failed to clean %s in %s",vr->virusname, pf->pfcb_FileName);
        } else {
            /* clean success */
            vr->clean_result = C_CLEAN_SUCCESS;
            pcbdata->scan_result->clean_ok_count++;
            LOGWARN("Succeeded to clean %s in %s",vr->virusname, pf->pfcb_FileName);
        }
    }

    LOGDEBUG("[VSCAN] <==action_callback");    
    return VSCAN_SUCCESS;
}

static int error_callback(VSCTYPE vsc, VSPFCB *pfcb) {
	tmDebugWrite (NULL, TMDEBUG_LEVEL_ERROR, "[VSCAN] vscan_pfcb:error callback");
	return VSCAN_ERROR_INTERNAL;
}

/* 
*  callback function for vsapi process file
*/
static int PASCAL vscan_pfcb(VSCTYPE vsc, VSPFCB * pf, int mode, int *action) {
	if (mode == 1) {
        /********************************************/
		/* VSAPI mode 1 callback: after scan        */
        /********************************************/
        return scan_callback_func(vsc, pf, action);
		
	} else if (mode == 2) {
        /********************************************/
		/* VSAPI mode 2 callback: after take action */
        /********************************************/
		return action_callback(vsc, pf, action);     
	} else {
		/* something wrong */
		return error_callback(vsc, pf);
	}
}

#ifdef USE_ATSE
union VSAFIU {
    VSAFI_LAYER_BGN         lb;
    VSAFI_LAYER_END         le;
    VSAFI_BASIC             b;
    VSAFI_PE_SECTION        s;
    VSAFI_PE_SEC_ENTROPY    e;
    VSAFI_PE_PACK           p;
    VSAFI_PE_TRAP           t;
    VSAFI_PTN               r;
    VSAFI_SHA1              sh;
    VSAFI_PE_EXPORT_INFO    pe_export;
    //VSAFI_PASSWORD          pwd;
};


static int PASCAL evae_afi_cb(VSCTYPE vsc, const VSAFIH* _h, void* para) {
    const VSAFIH* h = _h;
    vscan_callback_data *pcbdata = (vscan_callback_data *) para;
    scan_evae_result_t *er = pcbdata->evae_result;
     LOGDEBUG("Begin evae_afi_cb!");

    if(er->error_count!=0) {
       LOGDEBUG("er->error_count!=0 quit evae_afi_cb!");
        return 0;
    }

    for(; h!=NULL; h=h->pNext) {
        union VSAFIU *u = (union VSAFIU*)h;
        if(h->ulStatus==AFI_BLOCK_INVALID) {
            continue;
        }
        switch(h->ulID) {
            case AFI_LAYER_BGN_ID:
                { // add child
                    scan_evae_result_node_t *en;
                    LOGDEBUG("Enter AFI_LAYER_BGN_ID!");

                    en = scan_evae_result_node_new();
                    if(en == NULL) {
                        er->error_count++;
                        LOGERROR("[%p][%d]+ scan_evae_result_node_new() failed", er, er->layer);
                        return 0;
                    }

                    if(h->ulStatus!=AFI_BLOCK_VALID) {
                        LOGERROR("[%p][%d]+ Status=%u", er, er->layer, h->ulStatus);
                        en->file_name = strdup("");
                    } else {
                       LOGDEBUG("[%p][%d]+ Name=%s DT=%u/%u Size=%u, Status=%u", er, er->layer, u->lb.pFileName, u->lb.ulDataType, u->lb.ulSubType, u->lb.ulFileSize, h->ulStatus);
                       en->isStore = (u->lb.ulFileFlag&AFI_STORED_FLAG)?1:0;
                       en->file_size = u->lb.ulFileSize;
                       en->file_type = u->lb.ulDataType;
                       en->file_sub_type = u->lb.ulSubType;
                       if(u->lb.ulFileNameType == AFI_ANSI_FILE_NAME || u->lb.ulFileNameType==AFI_UTF8_FILE_NAME) {
                          en->file_name = strdup(u->lb.pFileName);
                       } else {
                          LOGDEBUG("[%p][%d] FileNameType=%u", er, er->layer, u->lb.ulFileNameType);
                          en->file_name = strdup("");
                       }
                    }

                    en->layer = er->layer;
                    list_add_tail(&en->list_node, &er->list_head);
                    er->curr_en = en;
                    er->layer++;
                }
                break;
            case AFI_LAYER_END_ID:
                // pop current
                er->layer--;
                if(er->layer>0) {
                    struct list_head *iter;
                    scan_evae_result_node_t *en = NULL;
                    list_for_each_prev(iter, &er->list_head) {
                        en = list_entry(iter, scan_evae_result_node_t, list_node);
                        if(en->layer==er->layer-1) {
                            break;
                        }
                    }
                    if(en!=NULL) {
                        er->curr_en = en;
                    } else {
                        LOGERROR("BUG [%p][%d]- Next=0x%p", er, er->layer, h->pNext);
                        er->curr_en = NULL;
                    }
                } else if(er->layer==0) {
                    er->curr_en = NULL;
                } else {
                    LOGERROR("BUG [%p][%d]- Next=0x%p", er, er->layer, h->pNext);
                }
                LOGDEBUG("[%p][%d]- Next=0x%p", er, er->layer, h->pNext);
                break;
            case AFI_SHA1_ID:
                {
                    if(er->layer > 0) {
                        scan_evae_result_node_t *en = er->curr_en;

                        if(en == NULL) {
                            LOGERROR("BUG [%p][%d] sha1 - Next=0x%p", er, er->layer, h->pNext);
                        } else {
                            if(h->ulStatus!=AFI_BLOCK_VALID) {
                                LOGERROR("[%p][%d] sha1 Status=%u", er, er->layer, h->ulStatus);
                            } else {
                               memcpy(en->sha1, u->sh.sha1, 20);
                               LOGDEBUG("[%p][%d] sha1=" SHA1_FMT, er, er->layer, SHA1_TUPLE(u->sh.sha1));
                            }
                        }
                    } else {
                        LOGERROR("BUG [%p][%d] sha1 - Next=0x%p", er, er->layer, h->pNext);
                    }
                }
                break;
                /*  This part is not tested yet!
            case AFI_PASSWORD_ID:
                {
                   if(er->layer > 0) {
                      scan_evae_result_node_t *en = er->curr_en;
                      if(en == NULL) {
                         LOGERROR("BUG [%p][%d] password - Next=0x%p", er, er->layer, h->pNext);
                      } else {
                         if(h->ulStatus!=AFI_BLOCK_VALID) {
                            LOGERROR("[%p][%d] password Status=%u", er, er->layer, h->ulStatus);
                         } else {
                            VSAFI_PS* ps;
                            int key_num = 0;
                            pwd_node_t *pn = NULL;
                            for (ps=u->pwd.ps; ps!= NULL; ps=ps->next) {
                               if(0 == ps->size)
                                  continue;
                               pn = password_node_new();
                               if(NULL == pn){
                                  LOGERROR("[%p][%d]+ password_node_new() failed", er, er->layer);
                               }
                               pn->pwd_size = ps->size;
                               pn->pwd = (char*)calloc(1, (pn->pwd_size+1));
                               memcpy(pn->pwd, ps->data, pn->pwd_size);
                               list_add_tail(&pn->list_node, &en->pwd_list_head);
                            }
                         }
                      }
                   } else {
                      LOGERROR("BUG [%p][%d] password - Next=0x%p", er, er->layer, h->pNext);
                   }
                }
                break;
                */
            case AFI_PE_EXPORT_INFO_ID:
                {
                   if(er->layer > 0) {
                      scan_evae_result_node_t *en = er->curr_en;
                      if(en == NULL) {
                         LOGERROR("BUG [%p][%d] pe_export_info - Next=0x%p", er, er->layer, h->pNext);
                      } else {
                         if(h->ulStatus!=AFI_BLOCK_VALID) {
                            LOGERROR("[%p][%d] pe_export_info Status=%u", er, er->layer, h->ulStatus);
                         } else {
                            en->pe_flags = u->pe_export.flags;
                            LOGDEBUG("[%p][%d] pe_export_info= 0x%08x" , er, er->layer, en->pe_flags);
                         }
                      }
                   } else {
                      LOGERROR("BUG [%p][%d] pe_export_info - Next=0x%p", er, er->layer, h->pNext);
                   }
                }
                break;
            default:
                break;
        }
    }
    return 0;
}
#endif

static int set_common_config(VSCTYPE vsc, common_config_t *common, vscan_func_table_t *func_table) {
	int en = 0;
    
	/* sets path of temporary files */
	if ((en = (*func_table->VSSetTempPath)(vsc, common->tmppath)) != 0) {
		LOGERROR("Failed to VSSetTempPath,%s",common->tmppath);
		return -1;
	}
    
	/* sets path of pattern file */
	if ((en = (*func_table->VSSetPatternPath)(vsc, common->ptnpath)) != 0) {
		LOGERROR("Failed to VSSetPatternPath,%s",common->ptnpath);
		return -1;
	}
    
	/* cleans zip flag */
	(*func_table->VSSetCleanZipFlag)(vsc, 1);
    
	/* sets smart decompress enable/disable flag */
	if ((en = (*func_table->VSSetSmartDecompressFlag)(vsc, 0)) < 0) {
		LOGERROR("Failed to VSSetSmartDecompressFlag,%d",en);
		return -1;
	}
    
	/* sets process file callback function */
	if ((en = (*func_table->VSSetProcessFileCallBackFunc)(vsc, vscan_pfcb)) != 0) {
		LOGERROR("Failed to VSSetProcessFileCallBackFunc");
		return -1;
	}
    
#ifdef USE_ATSE
    if ((en = (*func_table->VSSetAdvFileInfoCallBackFunc)(vsc, &evae_afi_cb)) != 0) {
		LOGERROR("Failed to VSSetAdvFileInfoCallBackFunc");
		return -1;
    }
    if ((en = (*func_table->VSSetConfig)(vsc, VSCFG_AFI_LAYER_FLAG, 1, NULL)) != 0) {
		LOGERROR("Failed to VSSetConfig(%d)", VSCFG_AFI_LAYER_FLAG);
		return -1;
    };
    if ((en = (*func_table->VSSetConfig)(vsc, VSCFG_AFI_SHA1_FLAG, 1, NULL)) != 0) {
		LOGERROR("Failed to VSSetConfig(%d)", VSCFG_AFI_SHA1_FLAG);
		return -1;
    };
    if ((en = (*func_table->VSSetConfig)(vsc, VSCFG_AFI_PE_EXPORT_INFO_FLAG, 1, NULL)) != 0) {
		LOGERROR("Failed to VSSetConfig(%d)", VSCFG_AFI_PE_EXPORT_INFO_FLAG);
		return -1;
    };
#endif

	return 0;
}

static int update_spyware_exclusion_list(VSCTYPE vsc, protocol_config_t *protocol, vscan_func_table_t *func_table) {
    int ret = -1;
    int err_code = 0;
    char *exclusion_list[MU_MAX_ENTRY_NUM] = {0};
    int num = 0;
    int i;

    LOGDEBUG("protocol->spyware_exclude=\"%s\"", protocol->spyware_exclude);
    
    if(protocol->spyware_exclude[0]=='\0')
        return 0;
    
    for (i = 0; i < MU_MAX_ENTRY_NUM; ++i)
        exclusion_list[i] = NULL;

    if ((num = mu_read_line_from_file(protocol->spyware_exclude, exclusion_list, MU_MAX_ENTRY_NUM)) < 0) {
        LOGERROR("Failed to mu_read_line_from_file");
        goto leave;
    }
    
    if((*func_table->VSClearSpywareExcludeNameTable)(vsc) != 0) {
        LOGERROR("Failed to VSClearSpywareExcludeNameTable(vsc)");
        goto leave;
    }
    
    for (i = 0; i < num; ++i) {
        char *spyware_name = exclusion_list[i];

        if ((spyware_name == NULL) || (strlen(spyware_name) == 0))
            continue;
        
        if ((err_code = (*func_table->VSAddSpywareExcludeName)(vsc, spyware_name)) <= 0) {
            LOGERROR("VSAddSpywareExcludeName(): spyware_name=\"%s\", err_code=%d", spyware_name, err_code);
            continue;
        }
            
        LOGINFO("spyware_exclude_list[%d]=%s", i, spyware_name);
    }

    ret = 0;

leave:
    for (i = 0; i < num; ++i) {
        if (exclusion_list[i] == NULL)
            continue;

        xfree(exclusion_list[i]);
        exclusion_list[i] = NULL;
    }
    return ret;
}


static int set_protocol_config(VSCTYPE vsc, protocol_config_t *protocol, vscan_func_table_t *func_table) {
	int en = 0;
	VULONG NewValue = 0;
	VULONG OldValue = 0;
  
  LOGDEBUG("[Vscan] ==> set_protocol_config : extract_file_size_limit(%zd), decompress_layer(%zd), extract_file_count_limit(%zd),\n extract_file_ratio_limit(%zd), intelli_scan(%d), process_all_file(%d), process_all_file_in_arc(%d)",
         protocol->extract_file_size_limit,protocol->decompress_layer,protocol->extract_file_count_limit,
         protocol->extract_file_ratio_limit,protocol->intelli_scan,protocol->process_all_file,protocol->process_all_file_in_arc);
    
	/* sets extract file size limit */
	if((en = (*func_table->VSSetExtractFileSizeLimit)(vsc,protocol->extract_file_size_limit)) != 0) {
		LOGERROR("[Vscan] <== Failed to VSSetExtractFileSizeLimit, en = %d",en);
		return -1;
	}
    
	/* sets decompress layer */
	if((en = (*func_table->VSSetDecompressLayer)(vsc, protocol->decompress_layer)) < 0) {
		LOGERROR("[Vscan] <== Failed to VSSetDecompressLayer, en = %d",en);
		return -1;
	}
    
    /* sets the maximum amount of files to be decompressed*/
    if((en = (*func_table->VSSetExtractFileCountLimit)(vsc, protocol->extract_file_count_limit,&OldValue)) != 0) {
		LOGERROR("[Vscan] <== Failed to VSSetExtractFileCountLimit, en = %d",en);
		return -1;
	}
    
    /*sets the decompress ratio limit of the file*/
    if((en = (*func_table->VSSetExtractFileRatioLimit)(vsc, protocol->extract_file_ratio_limit,&OldValue)) != 0) {
		LOGERROR("[Vscan] <== Failed to VSSetExtractFileRatioLimit, en = %d",en);
		return -1;
	}
    
	/* sets IntelliScan flag */
	if((en = (*func_table->VSSetActiveScanFlag)(vsc, protocol->intelli_scan)) == PARA_ERR) {
		LOGERROR("[Vscan] <== Failed to VSSetActiveScanFlag, en = %d",en);
		return -1;
	}
    
	/* sets process all file flag */
	if((en = (*func_table->VSSetProcessAllFileFlag)(vsc,protocol->process_all_file)) ==PARA_ERR) {
		LOGERROR("[Vscan] <== Failed to VSSetProcessAllFileFlag, en = %d",en);
		return -1;
	}
    
	/* sets process all file in arc flag */
	if((en = (*func_table->VSSetProcessAllFileInArcFlag)(vsc,protocol->process_all_file_in_arc)) == PARA_ERR) {
		LOGERROR("[Vscan] <== Failed to VSSetProcessAllFileInArcFlag, en = %d",en);
		return -1;
	}
    
    /* set grey area flag */
	if(protocol->scan_spyware == 1)
		NewValue |= VSGREY_SPYWARE;
	if(protocol->scan_adware == 1)
		NewValue |= VSGREY_ADWARE;
	if(protocol->scan_dialer == 1)
		NewValue |= VSGREY_DIALER;
	if(protocol->scan_hacktool == 1)
		NewValue |= VSGREY_HACKTOOL;
	if(protocol->scan_joke == 1)
		NewValue |= VSGREY_JOKE;
	if(protocol->scan_remoteaccess == 1)
		NewValue |= VSGREY_REMOTEACCESS;
	if(protocol->scan_passwdcrack == 1)
		NewValue |= VSGREY_PASSWDCRACK;
    if(protocol->scan_others == 1)
        NewValue |= VSGREY_OTHERS;
    
	if((en = (*func_table->VSSetConfig)(vsc, VSCFG_GREY_FLAG, NewValue, &OldValue)) != 0) {
        LOGERROR("[Vscan] <== Failed to VSSetConfig, en = %d",en);
		return -1;
    }
    
    /*set mail trap flag*/
    if((en = (*func_table->VSSetConfig)(vsc, VSCFG_MAILTRAP_FLAG, protocol->bot_enable, NULL)) != 0) {
        LOGERROR("[Vscan] <== Failed to VSSetConfig, en = %d",en);
        return -1;
    }
    /*set Detection Level*/
    if((en = (*func_table->VSSetConfig)(vsc, VSCFG_ATSE_AGGRESSIVE_LEVEL, protocol->detection_level, NULL)) != 0) {
        LOGERROR("[Vscan] <== Failed to VSSetConfig, en = %d",en);
        return -1;
    }
    
    if(update_spyware_exclusion_list(vsc, protocol, func_table) != 0) {
        LOGERROR("[Vscan] <== Failed to update_spyware_exclusion_list");
        return -1;
    }
    
    LOGDEBUG("[Vscan] <== (0) = set_protocol_config");
	return 0;
}

/* set vscan setting */
static int set_vscan_config(VSCTYPE vsc, vscan_config_t *config, vscan_func_table_t *func_table)
{
	if (set_common_config(vsc, &(config->common),func_table) != 0)
		return -1;
	if (set_protocol_config(vsc, &(config->protocol),func_table) != 0)
		return -1;
	return 0;
    
}

static int show_load_pattern_error(int error_code) {
    switch(error_code) {
    case -1:
        LOGERROR("Corrupt pattern structure in OldSession.");
        break;
    case -2:
        LOGERROR("No pattern structure in OldSession.");
        break;
    case -3:
        LOGERROR("Invalid pattern file.");
        break;
    case -4:
        LOGERROR("Pattern not found.");
        break;
    case -83:
        LOGERROR("The pattern found does not contain the new pattern file structure.");
        break;
    case READ_ERR:
        LOGERROR("Read error.");
        break;
    case NO_MEM_ERR:
        LOGERROR("Out of memory.");
        break;
    case PARA_ERR:
        LOGERROR("Invalid parameter(s).");
        break;
    default:
        /*do nothing*/
        break;
    }
    return 0;
}

static int write_def_ext_to_file(VSCTYPE vsc, char *filename,vscan_func_table_t *func_table) {
    char *def_ext = NULL;
    VULONG def_ext_size = 0; 
    int fd = -1;
    
    if((fd = creat(filename, 0644)) < 0) {
        LOGERROR("Failed to open, error code = %d", errno);
        goto leave;
    }
    
    if((*func_table->VSGetDefaultExtListSize)(vsc, &def_ext_size) == PARA_ERR) {
       LOGERROR("Failed to VSGetDefaultExtListSize"); 
       goto leave;
    }
   
    if((def_ext = (char*)malloc(def_ext_size + 1)) == NULL) {
       LOGERROR("Failed to malloc"); 
	   goto leave;
    }
   
    if((*func_table->VSGetDefaultExtList)(vsc, def_ext) == PARA_ERR) {
       LOGERROR("Failed to VSGetDefaultExtList");  
       goto leave;
    }
    
    def_ext[def_ext_size] = '\0';
      
    if(sk_io_write(fd, def_ext, strlen(def_ext) + 1) != 0) {
       LOGERROR("Failed to sk_io_write" );  
       goto leave; 
    }
    
leave:

    if(fd != -1)
        close(fd);
    
    xfree(def_ext);
    
    return 0;
}

static const char *get_category_mem(VSCTYPE vsc, char *data, size_t n, vscan_func_table_t *func_table) {
   VSDTYPE dt;
   int dtype; 
   const char *file_category = NULL;
   
   dtype = (*func_table->VSResourceDataType)(vsc,
                                             data,
                                             VS_RT_MEM, 
                                             0,
                                             n, 
                                             &dt);

    
   if (dtype < 0) {
        if (dtype != -2) {
            LOGERROR("Failed to VSResourceDataType, errno=%d", dtype);
        }
       goto leave;
   }
    
   file_category = vstd2category(dtype);
    
leave:

    return file_category;
}

static const char *get_category_fd(VSCTYPE vsc, VSHANDLE *handle, vscan_func_table_t *func_table) {
    int dtype;
    const char *file_category = NULL;
    dtype = (*func_table->VSDataTypeFD)(vsc, handle);
                               
    if (dtype < 0) {
        if (dtype != -2) {
            LOGERROR("Failed to VSDataTypeFD, errno=%d", dtype);
        }
        goto leave;
    }
    
    file_category = vstd2category(dtype);
    
leave:

    return file_category;
}

/*virus scanning in memory*/
static int memory_scan(VSCTYPE vsc,
            protocol_config_t *protocol,
            unsigned char *data, 
            size_t n, 
            char *name,
            VirusResult * virus_result,
            vscan_result_t *scan_result,
#ifdef USE_ATSE
            scan_evae_result_t *evae_result,
#endif
            vscan_func_table_t *func_table) {
    int en = 0;
	vscan_callback_data cbdata;
	RESOURCE res;
    const char *file_category = NULL;
    
    memset(&cbdata, 0, sizeof(cbdata));
    memset(scan_result, 0, sizeof(vscan_result_t));

    /* check if the compress enable flag is set */
    file_category = get_category_mem(vsc, (char*) data, n, func_table);
    LOGINFO("[VSCAN] file_category = %s", file_category ? file_category : "null");
    if(file_category && strcasecmp(file_category,VSTD2CATEGORY_ARCHIVE) == 0) {
        /* if compress enable flag is false, exit immediately */
        if(protocol->compress_enable == 0) {
        	 LOGDEBUG("[VSCAN] compress disable return");
           return VSCAN_SUCCESS;
        }
    }
    
	/* initializes resource */
	memset(&res, 0, sizeof(RESOURCE));
    
	res.r_File = (char *) data;
	res.r_Name = name;
	res.r_Type = VS_RT_MEM;
	res.r_Handle = 0;
    
	/* open resource */
	if ((en = (*func_table->VSOpenResource)(res.r_File, res.r_Type, VS_READ, 0, n, &res.r_Handle)) != 0) {
		LOGERROR("Cannot be able to open resource, en = %d", en);
		return VSCAN_ERROR_INTERNAL;
	}
    
	/* Because VSAPI has a bug, we must have this assignment. */
	res.r_File = name;
    
	/* fill callback data */
    cbdata.protocol = protocol;
	cbdata.do_clean = 0;
	cbdata.virus_result = virus_result;
    cbdata.scan_result = scan_result;
    memset(cbdata.scan_result, 0 , sizeof(vscan_result_t));
    cbdata.func_table = func_table;
#ifdef USE_ATSE
    cbdata.evae_result = evae_result;
#endif
    
	/* starts to scan */
    en = (*func_table->VSScanResource)(vsc, &res, &cbdata);
    LOGINFO("(%d) = VSScanResource", en);
    
	/* releases resource */
	(*func_table->VSCloseResource)(res.r_Handle);
    
	/*check the scan result */
	if (en < 0 && en != SKIP_ERR && en != BREAK_ERR) {
		LOGERROR("Scan Engine Scan File Resource, en = %d", en);
		return VSCAN_ERROR_INTERNAL;
	}
    
	return VSCAN_SUCCESS;
}

/*virus scanning in file descriptor*/
static int file_descriptor_scan(VSCTYPE vsc,
            protocol_config_t *protocol,
            int fd,
            char * name,
            VirusResult * virus_result,
            vscan_result_t *scan_result,
#ifdef USE_ATSE
            scan_evae_result_t *evae_result,
#endif
            vscan_func_table_t *func_table) {
    int en = 0;
    vscan_callback_data cbdata;
    RESOURCE res;
    const char *file_category = NULL;

    memset(&cbdata, 0, sizeof(cbdata));
    /* initializes resource */
    memset(&res, 0, sizeof(RESOURCE));

    res.r_File = (char *)fd; // #NOTE: dangerous casting; workaround for VSAPI;
    res.r_Name = name;
    res.r_Type = VS_RT_FILED;
    res.r_Handle = 0;

    /* open resource */
    if ((en = (*func_table->VSOpenResource)(res.r_File, res.r_Type, VS_READ, 0, 0, &res.r_Handle)) != 0) {
        LOGERROR("Cannot be able to open resource, fd:%d, en = %d", fd, en);
        return VSCAN_ERROR_INTERNAL;
    }

    /* check if the compress enable flag is set */
    file_category = get_category_fd(vsc, res.r_Handle, func_table);
    LOGDEBUG("[VSCAN] file_category = %s", file_category ? file_category : "null");
    if(file_category && strcasecmp(file_category,VSTD2CATEGORY_ARCHIVE) == 0) {
        /* if compress enable flag is false, exit immediately */
        if(protocol->compress_enable == 0) {
            LOGDEBUG("[VSCAN] compress disable return");
            (*func_table->VSCloseResource)(res.r_Handle);
            return VSCAN_SUCCESS;
        }
    }

    /* Because VSAPI has a bug, we must have this assignment. */
    res.r_File = name;

    /* fill callback data */
    cbdata.protocol = protocol;
    cbdata.do_clean = 0;
    cbdata.virus_result = virus_result;
    cbdata.scan_result = scan_result;
    memset(cbdata.scan_result, 0 , sizeof(vscan_result_t));
    cbdata.func_table = func_table;
#ifdef USE_ATSE
    cbdata.evae_result = evae_result;
#endif

    /* starts to scan */
    en = (*func_table->VSScanResource)(vsc, &res, &cbdata);
    LOGINFO("(%d) = VSScanResource", en);

    /* releases resource */
    (*func_table->VSCloseResource)(res.r_Handle);

    /*check the scan result */
    if (en < 0 && en != SKIP_ERR && en != BREAK_ERR) {
        LOGERROR("Scan Engine Scan File Resource, en = %d", en);
        return VSCAN_ERROR_INTERNAL;
    }

    return VSCAN_SUCCESS;
}

static void format_pattern_version(char *version_string, VULONG ptn_ver) {
	/* internalver:  R R R R R V V V B B in decimal*/
	int build_number   =ptn_ver%100;
	int version_number =(ptn_ver/100)%1000;
	int roll_number    =ptn_ver/100000;

	snprintf(version_string, VSCAN_MAX_PATTERN_VERSION_SIZE, "%d.%03d.%02d", roll_number, version_number, build_number);
}

static int get_version(VscanHandle_t *vsh, vscan_version_t *version, vscan_func_table_t *func_table) {
    char*  base_name;
    int    master_pattern;
    VULONG pattern_version;
    char version_string[VSCAN_MAX_PATTERN_VERSION_SIZE] = {0};

    if (vsh == NULL || version == NULL || func_table == NULL) {
        LOGERROR("Invalid argument");
        return -1;
    }

    (void)memset(version, 0, sizeof(vscan_version_t));

    { /* Get VSAPI Version */
        VSVERSION eng_ver = {0};
        int ret;

        if ((ret = (*(func_table->VSGetVersion))(&eng_ver)) != 0)
        {
            LOGERROR("Failed to VSGetVersion(): %d", ret);
            return -1;
        }

        version->vsapi_engine_major = eng_ver.major;
        version->vsapi_engine_minor = eng_ver.minor;
        version->vsapi_engine_revision = eng_ver.revision;
        version->vsapi_engine_build = eng_ver.build;

        ret = snprintf(version->vsapi_engine, sizeof(version->vsapi_engine),
                "%u.%u.%u.%u",
                version->vsapi_engine_major,
                version->vsapi_engine_minor,
                version->vsapi_engine_revision,
                version->vsapi_engine_build);

        // refering to old_read_vsapi_version() in src/trend/update/lib/query_version.c
        if(eng_ver.minor < 10 && eng_ver.minor >= 0 ) {
            ret = snprintf(version->vsapi_engine_for_au, sizeof(version->vsapi_engine_for_au),
                    "%u.%u%02d.%u",
                    version->vsapi_engine_major,
                    version->vsapi_engine_minor,
                    0,
                    version->vsapi_engine_build);
        } else if(eng_ver.minor >= 10 && eng_ver.minor < 100 ){
            ret = snprintf(version->vsapi_engine_for_au, sizeof(version->vsapi_engine_for_au),
                    "%u.%02u%u.%u",
                    version->vsapi_engine_major,
                    version->vsapi_engine_minor,
                    version->vsapi_engine_revision,
                    version->vsapi_engine_build);
        } else if(eng_ver.minor >= 100 && eng_ver.minor < 1000 ) {
            ret = snprintf(version->vsapi_engine_for_au, sizeof(version->vsapi_engine_for_au),
                    "%u.%03u.%u",
                    version->vsapi_engine_major,
                    version->vsapi_engine_minor,
                    version->vsapi_engine_build);
        } else {
           LOGERROR("Invalid Engine Minor Version : (%u)", version->vsapi_engine_minor);
           return -1;
        }
    }

    if ((*(func_table->VSGetPatternProperty))(vsh->vsc, VSPP_EXIST_MASTER_PTN, 0, &master_pattern) < 0) {
        LOGERROR("Failed to VSGetPatternProperty(%s)", "the vsc does not include a master pattern");
        return -1;
    } 

    /* get virus pattern version */
    base_name = "lpt$vpn.";
    if((*(func_table->VSGetPatternProperty))(vsh->vsc, VSPP_VERSION, (void*)base_name, (void*)&pattern_version) < 0) {
        LOGERROR("Failed to VSGetPatternProperty");
        return -1;
    } 
    if (pattern_version != 0) {
        format_pattern_version(version_string, pattern_version);
        memcpy(version->virus_pattern,
                version_string, 
                ((strlen(version_string) + 1) <= VSCAN_MAX_PATTERN_VERSION_SIZE)?(strlen(version_string) + 1):VSCAN_MAX_PATTERN_VERSION_SIZE);
    } 

    /* get spyware pattern version */
    base_name = "ssaptn.";
    if((*(func_table->VSGetPatternProperty))(vsh->vsc, VSPP_VERSION, (void*)base_name, (void*)&pattern_version) < 0) {
        LOGERROR("Failed to VSGetPatternProperty");
        return -1;
    }
    if (pattern_version != 0) {
        format_pattern_version(version_string, pattern_version);
        memcpy(version->spyware_pattern,
                version_string, 
                ((strlen(version_string) + 1) <= VSCAN_MAX_PATTERN_VERSION_SIZE)?strlen(version_string) + 1:VSCAN_MAX_PATTERN_VERSION_SIZE);
    }     

    /* get tmwhite pattern version */
    base_name = "tmwhite.";
    if((*(func_table->VSGetPatternProperty))(vsh->vsc, VSPP_VERSION, (void*)base_name, (void*)&pattern_version) < 0)
    {
        LOGERROR("Failed to VSGetPatternProperty");
        return -1;
    }
    if (pattern_version != 0) {
        format_pattern_version(version_string, pattern_version);
        memcpy(version->tmwhite_pattern,
                version_string, 
                ((strlen(version_string) + 1) <= VSCAN_MAX_PATTERN_VERSION_SIZE)?strlen(version_string) + 1:VSCAN_MAX_PATTERN_VERSION_SIZE);
    }  

    /* get tmblack pattern version */
    base_name = "tmblack.";
    if((*(func_table->VSGetPatternProperty))(vsh->vsc, VSPP_VERSION, (void*)base_name, (void*)&pattern_version) < 0) {
        LOGERROR("Failed to VSGetPatternProperty");
        return -1;
    }
    if (pattern_version != 0) {
        format_pattern_version(version_string, pattern_version);
        memcpy(version->tmblack_pattern,
                version_string, 
                ((strlen(version_string) + 1)<= VSCAN_MAX_PATTERN_VERSION_SIZE)?strlen(version_string) + 1:VSCAN_MAX_PATTERN_VERSION_SIZE);
    }

    return 0;
}

static int dump_version(vscan_version_t *version) {
    if (version == NULL) {
        LOGERROR("Invalid argument");
        return -1;
    }

    LOGINFO("vsapi_engine: %s", version->vsapi_engine);
    LOGINFO("virus_pattern: %s", version->virus_pattern);
    LOGINFO("spyware_pattern: %s", version->spyware_pattern);
    LOGINFO("tmwhite_pattern: %s", version->tmwhite_pattern);
    LOGINFO("tmblack_pattern: %s", version->tmblack_pattern);
    
    return 0;
}

/*
 * virus scanning management, including concurrent scanning, pattern reload.
 */
static int virus_scan_controller(VscanHandle_t *vsh,
                      VSCTYPE* pthread_vsc,
                      unsigned int *patse_reload_indicator,
                      vscan_resource_t *res_info,
                      VirusResult *virus_result,
                      vscan_result_t *scan_result,
#ifdef USE_ATSE
                      scan_evae_result_t *evae_result,
#endif
                      vscan_func_table_t *func_table) {
    int ret = -1;

    LOGDEBUG("[Vscan] virus_enable(%d), compress_enable(%d), spyware_enable(%d), bot_enable(%d)", 
            vsh->config.protocol.virus_enable, vsh->config.protocol.compress_enable,
            vsh->config.protocol.spyware_enable, vsh->config.protocol.bot_enable);

    /* check if {virus, spyware, bot} enable flag is disabled*/
    if(vsh->config.protocol.virus_enable == 0 &&
            vsh->config.protocol.spyware_enable == 0 &&
            vsh->config.protocol.bot_enable == 0) {
        LOGDEBUG("Dont enter virus scanning");
        return 0;
    }

    if(*patse_reload_indicator){
       LOGDEBUG("Re-Create thread vsc, thead_vsc=0x%08x , indicator (addr:value)=(%p:%d)",*pthread_vsc, patse_reload_indicator, *patse_reload_indicator);
       *patse_reload_indicator = 0;  
       if(VSCTYPE_INVALID != *pthread_vsc) {  
          delete_thread_vsc(pthread_vsc, func_table);
       }
       /*copy vsh to local_vsh,including configuration, pattern, runtime option */
       if (create_thread_vsc(pthread_vsc, vsh->vsc,func_table) != 0) {
          LOGERROR("Failed to copy virus handle");
          ret = VSCAN_ERROR_INTERNAL;
          goto leave;
       }
    }

    /*According to resource type to take different scan,(memory/file) */
    if (res_info->type == SCAN_IN_MEMORY) {
        LOGDEBUG("memory_scan");
        ret = memory_scan(*pthread_vsc,
                &(vsh->config.protocol),
                res_info->data,
                res_info->n,
                res_info->name,
                virus_result,
                scan_result,
#ifdef USE_ATSE
                evae_result,
#endif
                func_table);
    } else {
        LOGDEBUG("file_descriptor_scan");
        ret = file_descriptor_scan(*pthread_vsc,
                &(vsh->config.protocol),
                res_info->fd,
                res_info->name,
                virus_result,
                scan_result,
#ifdef USE_ATSE
                evae_result,
#endif
                func_table);
    }

    vscan_rsult_to_debuglog(scan_result);

    /*free resource of local_vsh */
    //delete_thread_vsc(&local_vsc,func_table);

    ret = 0;
leave:

    return ret;
}

static int read_vscan_pattern(VscanHandle_t *vsh, vscan_config_t *config, vscan_func_table_t *func_table) {
    int en = 0;

    /* reads virus pattern*/
    if (strlen(config->common.ptnfile) > 0) {     
        if ((en = (*func_table->VSReadVirusPattern)(vsh->vsc, 0, config->common.ptnfile, 0)) != 0)
        {
            LOGERROR("Failed to VSReadVirusPattern() ,%d", en);
            show_load_pattern_error(en);
            return -1;
        }
    }

    /* reads spyware pattern*/
    if (strlen(config->common.spyptnfile) > 0) {
        if ((en = (*func_table->VSReadVirusPattern)(vsh->vsc, 0, config->common.spyptnfile, 0)) != 0)
        {
            LOGERROR("Failed to VSReadVirusPattern(),%d", en);
            show_load_pattern_error(en);
            return -1;
        }
    }

    /* reads tmblack pattern*/
    if (strlen(config->common.tmblack) > 0) {
        if ((en = (*func_table->VSReadVirusPattern)(vsh->vsc, 0, config->common.tmblack, 0)) != 0) {
            LOGERROR("Failed to VSReadVirusPattern(),%d", en);
            show_load_pattern_error(en);
            return -1;
        }
    }

    /* reads tmwhite pattern*/
    if (strlen(config->common.tmwhite) > 0) {
        if ((en = (*func_table->VSReadVirusPattern)(vsh->vsc, 0, config->common.tmwhite, 0)) != 0) {
            LOGERROR("Failed to VSReadVirusPattern(),%d", en);
            show_load_pattern_error(en);
            return -1;
        }
    }

    return 0;
}

static int reload_pattern(pattern_list * ptnlist, vscan_func_table_t *old_func_table, vscan_func_table_t *new_func_table) {
    int en = 0;
    pattern_list *p = NULL;
    vsh_node_t *vl = NULL; 

    LOGDEBUG("[Vscan] <== reload_pattern");

    /*initialize g_vsh */
    if((*old_func_table->VSQuit)(g_vsh->vsc) != 0) {
        LOGERROR("Failed to VSQuit");
        return -1;
    }
    if((en = (*new_func_table->VSInit)(0, (char *) ModuleName, 0, &(g_vsh->vsc))) != 0) {
        LOGERROR("Failed to VSInit, en = %d", en);
        return -1; 
    }

    /* set VSAPI setting for g_vsh */
    if (set_vscan_config(g_vsh->vsc, &(g_vsh->config),new_func_table) != 0) {
        LOGERROR("Failed to set_vscan_config");
        return -1;
    }

    /*reload  new pattern(s) for g_vsh */ 
    p = ptnlist;
    while (p) {

        /* set pattern path */
        if((*new_func_table->VSSetPatternPath)(g_vsh->vsc, p->ptnpath) != 0) {
            LOGERROR("Failed to VSSetPatternPath"); 
            return -1;
        }

        /*read new pattern */
        if((en = (*new_func_table->VSReadVirusPattern)(g_vsh->vsc, 0, p->ptnfile_base, NULL))!= 0)
        {
            LOGERROR("Failed to VSReadVirusPattern,%d",en);
            show_load_pattern_error(en);
            return -1;
        }
        p = p->next;
    }

    vl = g_vsh_list->next; /*the first node is dummy */

    while (vl) {
        if((*old_func_table->VSQuit)(vl->vsh->vsc) != 0) {
            LOGERROR("Failed to VSQuit");
            return -1;
        }

        if ((en = (*new_func_table->VSInit)(0, (char *) ModuleName, VSCTYPE_INVALID,&(vl->vsh->vsc))) != 0) {
            LOGERROR("Failed to VSInit, en = %d", en);
            return -1;
        }

        if (set_vscan_config(vl->vsh->vsc, &(vl->vsh->config),new_func_table) != 0) {
            LOGERROR("Failed to set_vscan_config");
            return -1;
        }

        if ((en = (*new_func_table->VSReadVirusPattern)(vl->vsh->vsc, g_vsh->vsc, NULL, NULL)) != 0) {
            LOGERROR("Failed to VSReadVirusPattern, %d",en);   
            show_load_pattern_error(en);
            return -1;
        }

        p = ptnlist;

        while (p) { 
            /* set pattern path */
            if((*new_func_table->VSSetPatternPath)(vl->vsh->vsc, p->ptnpath) != 0) {
                LOGERROR("Failed to VSSetPatternPath"); 
                return -1;
            }

            /*read new pattern */
            if((en = (*new_func_table->VSReadVirusPattern)(vl->vsh->vsc, 0, p->ptnfile_base, NULL))!= 0) {
                LOGERROR("Failed to VSReadVirusPattern,%d",en); 
                show_load_pattern_error(en);
                return -1;
            }
            p = p->next;
        }

        vl = vl->next;
    }

    /* write VSAPI file extension list to file */
    if(write_def_ext_to_file(g_vsh->vsc, g_vsh->config.common.vsapi_def_file_ext, new_func_table) != 0) {
        LOGERROR("Failed to write_def_ext_to_file");
        return -1; 
    }

    LOGDEBUG("[Vscan] ==> reload_pattern");
    return 0;
}

static VscanHandle_t * scan_engine_staticinit(vscan_config_t *config, vscan_func_table_t *func_table) {
    int en = 0;
    static volatile sig_atomic_t init = 0;
    VscanHandle_t *vsh = NULL;
    vscan_version_t version;
    
    LOGDEBUG("[Vscan] ==> scan_engine_staticinit");
    
    if(init == 1) /* if vscan module has been initialzied, just return g_vsh */
        return g_vsh;
    
	if ((en = (*func_table->VSInit)(0, (char *) ModuleName, 0,&(g_vsh->vsc))) != 0) {
		LOGERROR("Failed to VSInit, en = %d", en);
		goto leave;
	}
	
    /* set the vscan configuration */
	if (set_vscan_config(g_vsh->vsc, config, func_table) != 0) {
        LOGERROR("Failed to set_vscan_config");
		goto leave;
	}
    
	LOGINFO("init: max scan num=%u", config->common.max_scan_num);
    
    /* read {virus,spyware,tmblack,tmwhite} pattern */
    if(read_vscan_pattern(g_vsh, config, func_table) != 0) {
        LOGERROR("Failed to read_vscan_pattern");
        goto leave;
    }
    
    if(get_version(g_vsh, &version, func_table) != 0) {
        LOGERROR("Failed to get_version");
        goto leave;
    }
    
    if(dump_version(&version) != 0) {
        LOGERROR("Failed to dump_version");
        goto leave;
    }
    
    /* write VSAPI file extension list to file */
    if(write_def_ext_to_file(g_vsh->vsc, g_vsh->config.common.vsapi_def_file_ext, func_table) != 0) {
        LOGERROR("Failed to write_def_ext_to_file");
        goto leave;
    }
    
    vsh = g_vsh;
    
    init = 1;
    
leave:

    LOGDEBUG("[Vscan] <== scan_engine_staticinit");
    return vsh;
}



/*****************************************************/
/*                   EXPORT FUNCTION                 */
/*****************************************************/

VscanHandle *vscan_init(vscan_config_t * config) {
    vscan_func_table_t *func_table = NULL;
    VscanHandle *vsh = NULL;

    if(pthread_mutex_lock(&thread_safe_mutex) != 0)
        LOGERROR("Failed to pthread_mutex_lock");

    if(g_vsh == NULL) {
        if((g_vsh = (VscanHandle_t *)malloc(sizeof(VscanHandle_t))) == NULL) {
            LOGERROR("Failed to malloc");
            goto leave;
        }

        memset(g_vsh,0,sizeof(VscanHandle_t));

        /*initialize read/write lock for config change */
        /* We have to assign all read/write locks with the value of PTHREAD_RWLOCK_INITIALIZER
         * because Linux's pthread implementation has the following behavior:
         * - The kind value of PTHREAD_RWLOCK_INITIALIZER is PTHREAD_RWLOCK_PREFER_WRITER_NP.
         * - The kind value initialized by pthread_rwlock_init() is PTHREAD_RWLOCK_PREFER_READER_NP.
         */
        //assert(sizeof(g_vsh->rwlock) == sizeof(g_rwlock_initializer));
        //memcpy(&g_vsh->rwlock, &g_rwlock_initializer, sizeof(g_rwlock_initializer));
        
        {
           pthread_rwlockattr_t attr;
           pthread_rwlockattr_init(&attr);
           pthread_rwlockattr_setkind_np(&attr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);

           pthread_rwlock_init(&g_vsh->rwlock, &attr);

           pthread_rwlockattr_destroy(&attr);
        }
        
        /*fill config field of g_vsh */
        memcpy(&(g_vsh->config), config, sizeof(vscan_config_t));
    }

    if(g_vsh_list == NULL) {
        if((g_vsh_list = create_vsh_node_list()) == NULL) {
            LOGERROR("Failed to create_vsh_node_list");
            goto leave;
        }
    }

    /*load the vsapi library*/
    if((g_vsapi_handle = mu_library_loader_open(VSAPI_LIBNAME_STR)) == NULL) {
        LOGERROR("Failed to mu_library_loader_open");
        goto leave;
    }

    /*compose the function pointer table*/
    if(vsapi_compose_func_table(g_vsapi_handle, &g_func_table) != 0) {
        LOGERROR("Failed to compose_func_table");
        goto leave;
    }

    func_table = get_func_table();

    vsh = (VscanHandle *)scan_engine_staticinit(config,func_table);

    (void)release_func_table();

leave:

    /* unlocks pthread-safe mutex */
    if (pthread_mutex_unlock(&thread_safe_mutex) != 0)
        LOGERROR("Failed to pthread_mutex_unlock");

    return vsh;
}

int vscan_fini(VscanHandle * handle) {
    VscanHandle_t *vsh = NULL;
    vscan_func_table_t *func_table = NULL;
    
	v_handle_invariant(handle);
    
	if (handle == NULL) {
		LOGERROR("Invalid arguments");
		return VSCAN_ERROR_INTERNAL;
	}
    
    vsh = (VscanHandle_t *)handle;
    
	if (pthread_mutex_lock(&thread_safe_mutex) != 0)
		LOGERROR("Failed to pthread_mutex_lock");
    
    func_table = get_func_table();
    
	(*func_table->VSQuit)(vsh->vsc);

	vsh->vsc = VSCTYPE_INVALID;
    
    /*free all resource(vsh,synchronous object,etc)*/
    
	delete_vsh_node_list(g_vsh_list, func_table);
    
    if(pthread_rwlock_destroy(&(vsh->rwlock)) != 0)
        LOGERROR("Failed to pthread_rwlock_destroy");
    
    xfree(vsh);
    
    (void)release_func_table();
    
    /*unload the vsapi library*/
    if(mu_library_loader_close(g_vsapi_handle) != 0) {
        LOGERROR("Failed to mu_library_loader_close");
    }
    
    if(pthread_mutex_unlock(&thread_safe_mutex) != 0)
		LOGERROR("Failed to pthread_mutex_unlock");
    
	return VSCAN_SUCCESS;
    
}

int vscan_scan_mem(const VscanHandle * handle,
               VSCTYPE* pthread_vsc,
               unsigned int *patse_reload_indicator,
               char *data,
               size_t n, 
               char *name, 
               VirusResult * virus_result,
               vscan_result_t *scan_result, 
#ifdef USE_ATSE
               scan_evae_result_t *evae_result
#endif
               ) {

    int ret = VSCAN_ERROR_INTERNAL;
    vscan_resource_t res_info = {
        SCAN_IN_MEMORY,
        name,
        NULL,
        (unsigned char*) data,
        n,
        0
    };
    vscan_func_table_t *func_table = NULL;

	v_handle_invariant(handle);
	assert(data != NULL);
	assert(virus_result != NULL);
	
	LOGDEBUG("[VScan] ==> vscan_scan_mem");
    
	if (handle == NULL || data == NULL || virus_result == NULL) {
		LOGERROR("Invalid arguments");
		return VSCAN_ERROR_INTERNAL;
	}
    
    VscanHandle_t *vsh = (VscanHandle_t *)handle;
    
	/* acquire reader lock for pattern reload */
	if(pthread_rwlock_rdlock(&g_rwlock_pattern) != 0)
        LOGERROR("Failed to pthread_rwlock_rdlock");
    
	/* acquire reader lock for config change */
	if(pthread_rwlock_rdlock(&(vsh->rwlock)) != 0)
        LOGERROR("Failed to pthread_rwlock_rdlock");
    
    func_table = get_func_table();
    
    ret = virus_scan_controller(vsh,
            pthread_vsc,
            patse_reload_indicator,
            &res_info, 
            virus_result,
            scan_result, 
#ifdef USE_ATSE
            evae_result,
#endif
            func_table);

    (void)release_func_table();

    /*unlock reader/writer lock for configuration change */
    if(pthread_rwlock_unlock(&(vsh->rwlock)) != 0)
        LOGERROR("Failed to pthread_rwlock_unlock");

    /*unlock reader/writer lock for pattern reload */
    if(pthread_rwlock_unlock(&g_rwlock_pattern) != 0)
        LOGERROR("Failed to pthread_rwlock_unlock");

    v_handle_invariant(handle);

    LOGDEBUG("[VScan] <== (%d) = vscan_scan_mem", ret);  
    return ret;
}

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
               ) {
    
	int ret = VSCAN_ERROR_INTERNAL;
	vscan_resource_t res_info = {
		SCAN_IN_FILED,
		name,
		name,
		NULL,
		n,
        fd
	};
    vscan_func_table_t *func_table = NULL;

	v_handle_invariant(handle);
	assert(fd >= 0);
	assert(virus_result != NULL);
	
	LOGDEBUG("[VScan] ==> vscan_scan_fd");
    
	if (handle == NULL || fd < 0 || virus_result == NULL) {
		LOGERROR("Invalid arguments");
		return VSCAN_ERROR_INTERNAL;
	}
    
    VscanHandle_t *vsh = (VscanHandle_t *)handle;
    
	/* acquire reader lock for pattern reload */
	if(pthread_rwlock_rdlock(&g_rwlock_pattern) != 0)
        LOGERROR("Failed to pthread_rwlock_rdlock");
    
	/* acquire reader lock for config change */
	if(pthread_rwlock_rdlock(&(vsh->rwlock)) != 0)
        LOGERROR("Failed to pthread_rwlock_rdlock");
    
    func_table = get_func_table();
    
    ret = virus_scan_controller(vsh,
            pthread_vsc,
            patse_reload_indicator,
            &res_info, 
            virus_result,
            scan_result, 
#ifdef USE_ATSE
            evae_result,
#endif
            func_table);

    (void)release_func_table();

    /*unlock reader/writer lock for configuration change */
    if(pthread_rwlock_unlock(&(vsh->rwlock)) != 0)
        LOGERROR("Failed to pthread_rwlock_unlock");

    /*unlock reader/writer lock for pattern reload */
    if(pthread_rwlock_unlock(&g_rwlock_pattern) != 0)
        LOGERROR("Failed to pthread_rwlock_unlock");

    v_handle_invariant(handle);

    LOGDEBUG("[VScan] <== (%d) = vscan_scan_fd", ret);  
    return ret;
}


VscanHandle * vscan_create_handle(protocol_config_t protocol) {
    int en = 0;
    static int id = 0;
    vscan_func_table_t *func_table = NULL;
    vsh_node_t *node = NULL;
    VscanHandle_t *vsh = NULL;

    LOGDEBUG("[Vscan] ==> vscan_create_handle");

    assert(g_vsh != NULL);

    if(g_vsh == NULL) {
        LOGERROR("Invalid arguments");
        return NULL;
    }

    if(pthread_mutex_lock(&thread_safe_mutex) != 0)
        LOGERROR("Failed to pthread_mutex_lock");

    func_table = get_func_table();

    /*new a node */
    if((node = new_vsh_node()) == NULL) {
        LOGERROR("Failed to new_vsh_node");
        goto leave;
    }

    /*initialize vsc */
    if((en = (*func_table->VSInit)(id, (char *) ModuleName, 0, &(node->vsh->vsc)) != 0)) {
        LOGERROR("Failed to VSInit, ret = %d", en);
        goto leave;
    }
    id++;

    /*fill config field of vsh */
    memcpy(&node->vsh->config.common, &g_vsh->config.common,sizeof(common_config_t));
    memcpy(&node->vsh->config.protocol, &protocol,sizeof(protocol_config_t));
    /*set config */
    if((en = set_vscan_config(node->vsh->vsc, &(node->vsh->config), func_table)) != 0) {
        LOGERROR("Failed to set_vscan_config");
        goto leave;
    }

    /* read {virus,spyware,tmblack,tmwhite} pattern */
    if(read_vscan_pattern(node->vsh, &(node->vsh->config), func_table) != 0) {
        LOGERROR("Failed to VSReadVirusPattern, ret = %d", en);
        goto leave;
    }

    /*insert node to g_vsh_list */
    if(append_vsh_node(g_vsh_list, node) == -1) {
        LOGERROR("Failed to append_vsh_node");
        goto leave;
    }

    vsh = node->vsh;

leave:   

    if(NULL == vsh) {
        if(NULL != node) {
            delete_vsh_node(node);
        }
    }
    (void)release_func_table();

    if(pthread_mutex_unlock(&thread_safe_mutex) != 0)
        LOGERROR("Failed to pthread_mutex_unlock");

    LOGDEBUG("[Vscan] <== vscan_create_handle");    
    return (VscanHandle *)vsh;
}

int vscan_delete_handle(VscanHandle * handle) {
    int ret = VSCAN_ERROR_INTERNAL;
    VscanHandle_t *vsh = NULL;
    
	v_handle_invariant(handle);
    
	if(handle == NULL) {
		LOGERROR("Invalid arguments");
		return VSCAN_ERROR_INTERNAL;
	}
 
    vsh = (VscanHandle_t *)handle;
    
    if(pthread_mutex_lock(&thread_safe_mutex) != 0)
		LOGERROR("Failed to pthread_mutex_lock");
    
	/* dummy function */
    
    if(pthread_mutex_unlock(&thread_safe_mutex) != 0)
            LOGERROR("Failed to pthread_mutex_unlock");

    ret =  VSCAN_SUCCESS;    
    
	return ret;
}

int vscan_set_config(const VscanHandle * handle, const protocol_config_t *protocol) {
    int ret = VSCAN_ERROR_INTERNAL;
    vscan_func_table_t *func_table = NULL;
    
    LOGDEBUG("[Vscan] <== vscan_set_config");
    
	v_handle_invariant(handle);
    assert(protocol != NULL);
    
	if(handle == NULL || protocol == NULL) {
		LOGERROR("Invalid arguments");
		return VSCAN_ERROR_INTERNAL;
	}
    
    VscanHandle_t *vsh = (VscanHandle_t *)handle;
    
	if(pthread_mutex_lock(&thread_safe_mutex) != 0)
		LOGERROR("Failed to pthread_mutex_lock");
    
	/*acquire write lock */
	if(pthread_rwlock_wrlock(&(vsh->rwlock)) != 0)
        LOGERROR("Failed to pthread_rwlock_wrlock");
    
    func_table = get_func_table();
    
	/*fill config field of vsh */
	memcpy(&vsh->config.protocol, protocol,sizeof(protocol_config_t));
    
	/*set config for vsh */
	if (set_protocol_config(vsh->vsc, &(vsh->config.protocol), func_table) == -1) {
        LOGERROR("Failed to set_protocol_config");
        goto leave;
	}
    
    ret = VSCAN_SUCCESS;
    { //Set the reload flag for each scanning threads.
       int i=0;
       LOGDEBUG("----------- vscan_set_config ----- Set reload flag"); 
       for(i=0;i<queue_size;i++) {
          *(pg_atse_reload_indicator+i) = i+1;
       }
    }

    
leave:

    (void)release_func_table();

	if(pthread_rwlock_unlock(&(vsh->rwlock)) != 0)
        LOGERROR("Failed to pthread_rwlock_unlock");
    
	if(pthread_mutex_unlock(&thread_safe_mutex) != 0)
		LOGERROR("Failed to pthread_mutex_unlock");
    
   LOGDEBUG("[Vscan] ==> vscan_set_config"); 
	return ret;
}

int vscan_reload_pattern(pattern_list * ptnlist) {
    int ret = VSCAN_ERROR_INTERNAL;
    vscan_func_table_t *func_table = NULL;

	/*validate arguments */
	assert(ptnlist != NULL);
    
	if (ptnlist == NULL) {
		LOGERROR("Invalid arguments");
		return VSCAN_ERROR_INTERNAL;
	}
    
	if (pthread_mutex_lock(&thread_safe_mutex) != 0)
		LOGERROR("Failed to pthread_mutex_lock");
    
	/*acquire writer lock */
	if(pthread_rwlock_wrlock(&g_rwlock_pattern) != 0)
        LOGERROR("Failed to pthread_rwlock_wrlock");
    
	LOGINFO("++++++++++++++ vscan_reload_pattern  ++++++++++++");
    
    func_table = get_func_table();
    
	/*reload virus pattern */
	if(reload_pattern(ptnlist, func_table, func_table) != 0) {
		ret = VSCAN_ERROR_INTERNAL;
        LOGERROR("Failed to reload_pattern");
        goto leave;
	}
    
	LOGINFO("-------------- vscan_reload_pattern  -------------");
    
    ret = VSCAN_SUCCESS;
    { //Set the reload flag for each scanning threads.
       int i=0;
       LOGDEBUG("--------- vscan_reload_pattern ----- Set reload flag"); 
       for(i=0;i<queue_size;i++) {
          *(pg_atse_reload_indicator+i) = i+1;
       }
    }

    
leave:

    (void)release_func_table();

    if(pthread_rwlock_unlock(&g_rwlock_pattern) != 0)
         LOGERROR("Failed to pthread_rwlock_unlock");
    
    if(pthread_mutex_unlock(&thread_safe_mutex) != 0)
	     LOGERROR("Failed to pthread_mutex_unlock");
    
	return ret;
}


int vscan_reload_engine(const char *new_engine_path, pattern_list * ptnlist) {
    int ret = VSCAN_ERROR_INTERNAL;
    void *new_vsapi_handle = NULL;
    vscan_func_table_t new_func_table;
    vscan_version_t version;

    assert(new_engine_path != NULL);
    assert(ptnlist != NULL);

    if(new_engine_path == NULL || ptnlist == NULL) {
        LOGERROR("Invalid arguments");
        return VSCAN_ERROR_INTERNAL;
    }

    if(pthread_mutex_lock(&thread_safe_mutex) != 0)
        LOGERROR("Failed to pthread_mutex_lock");

    /*load the vsapi library*/
    if((new_vsapi_handle = mu_library_loader_open(new_engine_path)) == NULL) {
        LOGERROR("Failed to mu_library_loader_open");
        goto failure;
    }
    /*acquaire the write lock for engine reload*/
    if(pthread_rwlock_wrlock(&g_rwlock_engine) != 0) {
        LOGERROR("Failed to pthread_rwlock_wrlock");
        goto failure;
    }

    LOGINFO("++++++++++++ vscan_reload_engine +++++++++++");

    LOGDEBUG("++++ vsapi_compose_func_table ++++");
    /*resolve all symbols, and compose the function pointer table*/
    if(vsapi_compose_func_table(new_vsapi_handle, &new_func_table) != 0) {
        LOGERROR("Failed to compose_func_table");
        goto leave;
    }
    LOGDEBUG("---- vsapi_compose_func_table ----");

    /*reload the patterns*/
    LOGDEBUG("++++ reload_pattern ++++");
    if(reload_pattern(ptnlist, &g_func_table, &new_func_table) != 0) {
        LOGERROR("Failed to reload_pattern");
        goto leave;
    }
    LOGDEBUG("---- reload_pattern ----");

    /* get new version */
    LOGDEBUG("++++ get_version ++++");
    if(get_version(g_vsh, &version, &new_func_table) != 0) {
        LOGERROR("Failed to get_version");
        goto leave;
    }
    LOGDEBUG("---- get_version ----");

    /* show new version */
    LOGDEBUG("++++ dump_version ++++");
    if(dump_version(&version) != 0) {
        LOGERROR("Failed to dump_version");
        goto leave;
    }
    LOGDEBUG("---- dump_version ----");


    { //Set the reload flag for each scanning threads.
       int i=0;
       LOGDEBUG("-------- vscan_reload_engine ----- Set reload flag"); 
       for(i=0;i<queue_size;i++) {
          *(pg_atse_reload_indicator+i) = i+1;
          if( *(ppg_thread_vsc[i]) != VSCTYPE_INVALID ) {
             LOGDEBUG("- vscan_reload_engine -delete_thread_vsc(%d)",i);
             delete_thread_vsc(ppg_thread_vsc[i], &g_func_table);
             *(ppg_thread_vsc[i]) = VSCTYPE_INVALID;
          }
       }
    }

    /* unload the vsapi library */
    LOGDEBUG("++++ mu_library_loader_close ++++");
    if(mu_library_loader_close(g_vsapi_handle) != 0) {
        LOGERROR("Failed to mu_library_loader_close");
        goto leave;
    }
    LOGDEBUG("---- mu_library_loader_close ----");

    /* replace the old {handle, func_table} with the new one */
    g_vsapi_handle = new_vsapi_handle;
    new_vsapi_handle = NULL;
    memcpy(&g_func_table,&new_func_table,sizeof(vscan_func_table_t));

    LOGINFO("----------- vscan_reload_engine -----------");

    ret = VSCAN_SUCCESS;

leave:

    if(pthread_rwlock_unlock(&g_rwlock_engine) != 0)
        LOGERROR("Failed to pthread_rwlock_unlock");

failure:
    if(NULL != new_vsapi_handle)
        mu_library_loader_close(new_vsapi_handle);
    if(pthread_mutex_unlock(&thread_safe_mutex) != 0)
        LOGERROR("Failed to pthread_mutex_lock");

    return ret;
}


int vscan_get_version(const VscanHandle * handle, vscan_version_t *version) {
    int ret = VSCAN_ERROR_INTERNAL;
    VscanHandle_t *vsh = NULL; 
    vscan_func_table_t *func_table = NULL;

    v_handle_invariant(handle);
    assert(version != NULL);

    if(handle == NULL || version == NULL) {
        LOGERROR("Invalid arguments");
        return VSCAN_ERROR_INTERNAL;
    }

    vsh = (VscanHandle_t *)handle;

    if(pthread_rwlock_rdlock(&g_rwlock_pattern) != 0)
        LOGERROR("Failed to pthread_rwlock_rdlock");

    if(pthread_rwlock_rdlock(&(vsh->rwlock)) != 0)
        LOGERROR("Failed to pthread_rwlock_rdlock");

    func_table = get_func_table();

    if(get_version(vsh, version, func_table) != 0) {
        LOGERROR("Failed to get_engine_info");
        goto leave;
    }

    ret = VSCAN_SUCCESS;

leave:

    (void)release_func_table();

    if(pthread_rwlock_unlock(&(vsh->rwlock)) != 0)
        LOGERROR("Failed to pthread_rwlock_unlock");

    if(pthread_rwlock_unlock(&g_rwlock_pattern) != 0)
        LOGERROR("Failed to pthread_mutex_unlock");

    return ret;
}


