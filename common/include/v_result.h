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
* v_result.h
*
* Description: header file of the virus result struct for virus scan module 
* Author: HY Cheng
*
* #001 Aug 11, 2005 HY Cheng Initial implementation.
*/

#ifndef V_RESULT_H
#define V_RESULT_H

#include <string.h>

/* Enum of scan reason */
enum
{
	R_INVALID = -1,
	R_NO_MALWARE,
	R_VIRUS_FIRST,
	R_VIRUS_SECOND,
	R_SPYWARE,
	R_BOT,
	R_MACRO,
	R_ERROR
};

/* Enum of scan action */
enum 
{
	A_INVALID = -1,
	A_CLEAN,
	A_STAMP,
	A_QUARANTINE_EUQ,
    A_PASS,
	A_DELETE,
	A_QUARANTINE,
	A_QUARANTINE_RSET,
	A_BLOCK,
	A_BLOCK_RSET,
};

/* Enum of action result*/
enum
{
  AR_FAILURE = -1,
  AR_SUCCESS = 0
};

typedef struct vscan_action_st
{
	int reason; /* action reason */
	int action; /* action to take */
    int result; /* action result */
}vscan_action_t;

/* struct of scan result statistics */
typedef struct vscan_result_st
{
	int scan_cb_count;                    /*the count of scan callback*/
	int no_virus_count;                   /*the count of no malware*/
	int virus_count;                      /*the count of virus*/
	int spyware_count;                    /*the count of spyware*/
	int bot_count;                        /*the count of bot*/
    int clean_ok_count;                   /*the count of successful clean , NOTE: only for virus with clean taken*/
	int clean_err_count;                  /*the count of failed clean , NOTE: only for virus with clean taken*/
	int err_compressdeep_count;           /*the count of vsapi limitation : comressed archive file is too deep*/
	int err_filesize_count;               /*the count of vsapi limitation : too big file size in archive file*/
	int err_filecount_count;              /*the count of vsapi limitation : too many files in archive file */
	int err_fileratio_count;              /*the count of vsapi limitation : the compress ratio is too big*/
	int err_unhandle_count;               /*the count of vsapi limitation : other errors that vsapi can't handle */
	int err_max_scan_loop;                /*the count of max scan loop, for multiple infection issue */
}vscan_result_t;

typedef enum clean_result_st
{
	C_NO_CLEAN = 0,
	C_CLEAN_SUCCESS,
	C_CLEAN_FAIL
}clean_result_t;

typedef struct VirusResult_st
{
	char *filename;                   /*infected filename*/
	char *virusname;                  /*infected virusname(long format)*/
	char *majortype;                  /*major type of virus*/
	char *minortype;                  /*minor type(malware)of virus*/
    int virus_maybe;                  /*is detected by heuristic or not */
    int system_clean;
    int detection_level;
	clean_result_t  clean_result;     /*clean result*/
    vscan_action_t action;            /*action status */
	struct VirusResult_st *next;
}VirusResult;

#ifdef USE_ATSE

/*
typedef struct pwd_node_st {
   struct list_head list_node;
   char* pwd;
   unsigned long pwd_size;
} pwd_node_t;
*/
typedef struct scan_evae_result_node_st {
    struct list_head list_node;
    char *file_name;
    long file_size;
    unsigned short file_type;
    unsigned short file_sub_type;
    unsigned char sha1[20];
    int layer;
    int pe_flags;
    //struct list_head pwd_list_head;

    int isStore;
    int ret_code;                      /*pfcb_status */
    VirusResult *vr;
} scan_evae_result_node_t;
typedef struct scan_evae_result_st
{
    struct list_head list_head;
    scan_evae_result_node_t *curr_en;
    int layer;
    int error_count;
} scan_evae_result_t;
#endif

/* helper macros for major type checking */
#define IS_VIRUS(vr) (vr && vr->majortype && strcasecmp(vr->majortype,"spyware") != 0 && strcasecmp(vr->majortype,"packer") != 0) 
#define IS_SPYWARE(vr) (vr && vr->majortype && strcasecmp(vr->majortype,"spyware") == 0) 	
#define IS_BOT(vr) (vr && vr->majortype && strcasecmp(vr->majortype,"packer") == 0)

/* helper macros for action checking */
#define IS_BLOCK_ACTION(action) (action == A_BLOCK || action == A_BLOCK_RSET)
#define IS_QUARANTINE_ACTION(action) (action == A_QUARANTINE || action == A_QUARANTINE_RSET)   
#define IS_RSET_ACTION(action) (action == A_BLOCK_RSET || action == A_QUARANTINE_RSET)  

#ifdef __cplusplus
extern "C" {
#endif

    /*
     * helper functions for vscan result
     */
    int has_virus(vscan_result_t *scan_result);
    int has_spyware(vscan_result_t *scan_result);
    int has_bot(vscan_result_t *scan_result);
    int has_limit(vscan_result_t *scan_result);
    int has_malware(vscan_result_t *scan_result);
    int virus_only(vscan_result_t *scan_result);
    int spyware_only(vscan_result_t *scan_result);
    int bot_only(vscan_result_t *scan_result);
    int limit_only(vscan_result_t *scan_result);
    int all_virus_clean(vscan_result_t *scan_result);
    
    /*
     * write the vscan result to debug log 
     */
    void vscan_rsult_to_debuglog(vscan_result_t *scan_result);

    /*
     * create virus result 
     */
    VirusResult *VirusResult_new();

    /*
     * destroty virus result 
     */
    void VirusResult_free(VirusResult *first_vr);

    /*
     * append assign_vr to the next pointer of attached_vr 
     */
    int VirusResult_appendSubVirus(VirusResult *attached_vr, VirusResult *assign_vr);

#ifdef USE_ATSE
    scan_evae_result_node_t *scan_evae_result_node_new();
    void scan_evae_result_node_del(scan_evae_result_node_t *en);
    scan_evae_result_t *scan_evae_result_new();
    void scan_evae_result_free(scan_evae_result_t *er);
#endif

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
