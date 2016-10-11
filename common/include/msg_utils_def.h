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
* msg_utils_def.h
*
* Description: header file of data structures for message related module
* Author: HY Cheng
*
* #001 Aug 11, 2005 HY Cheng Initial implementation.
*/

#ifndef MSG_UTILS_DEF_H
#define MSG_UTILS_DEF_H

#include <vscan_def.h>
//#include <spam_def.h>
//#include <em_filter.h>

#define MU_MAX_EXPRESSION_SIZE (1024)
#define MU_MAX_ENTRY_NUM (100)
#define MU_MAX_STRING_SIZE (128)
#define MU_MAX_PREFIX_SIZE (256)
#define MU_MAX_RAW_ADDRESS_LENGTH (1024)
#define MU_MAX_ADDRESS_LENGTH (512)
#define MU_MAX_PATH_SIZE (256)
#define MU_MAX_IPV4_LENGTH (16)
#define MU_MAX_CHARSET (64)
#define MU_MAX_KK_EXCEPT (2048)

#if 0
typedef struct mail_address_st
{
    char address[MU_MAX_ADDRESS_LENGTH];
    struct mail_address_st *next;
} mail_address_t;

typedef struct 
{
    int first_action;
    int snd_action;
    int spy_action;
    int bot_action;
    int err_action;
}virus_action_t;

typedef struct
{
    int show_risk_detected_subject;
    int show_risk_detected_message;
    int show_risk_free_message;
}vscan_inline_t;

typedef struct 
{
   /* spyware */
   int vscan_spy_notify_administrator;
   int vscan_spy_notify_sender;
   int vscan_spy_notify_recipient;
   /* bottrap */
   int vscan_bot_notify_administrator; 
   int vscan_bot_notify_sender;
   int vscan_bot_notify_recipient;
   /* phishing */
   int phi_notify_administrator;
   int phi_notify_recipient;
   /* content filtering */
   int cf_notify_administrator;
   int cf_notify_sender;
   int cf_notify_recipient;
}mail_nv_notify_t;
 
typedef struct 
{
   int vscan_notify_administrator; 
   int vscan_notify_sender;
   int vscan_notify_recipient;
}mail_v_notify_t;

#define EMGR_MAX_CATEGORY_LIST_SIZE (256)
struct emgr_filter_setting
{
    /* SIZE */
    struct em_filter_size_attr size_attr;
    /* HEADER */
    struct em_filter_content_attr header_attr;
    char header_expr_file[PATH_MAX];
    char header_expr_file_default[PATH_MAX];
    /* BODY */
    struct em_filter_content_attr body_attr;
    char body_expr_file[PATH_MAX];
    char body_expr_file_default[PATH_MAX];
    /* ATTACHMENT */
    struct em_filter_attachment_attr attachment_attr;
    char attachment_expr_file[PATH_MAX];
    char attachment_expr_file_default[PATH_MAX];
    /* FILE CATEGORY */
    char category_list[EMGR_MAX_CATEGORY_LIST_SIZE];
};

struct OPP_filter_setting
{
    /* HEADER */
    struct em_filter_content_attr header_attr;
    char header_expr_file[PATH_MAX];
    char header_expr_file_default[PATH_MAX];
    /* BODY */
    struct em_filter_content_attr body_attr;
    char body_expr_file[PATH_MAX];
    char body_expr_file_default[PATH_MAX];
    /* ATTACHMENT */
    struct em_filter_attachment_attr attachment_attr;
    char attachment_expr_file[PATH_MAX];
    char attachment_expr_file_default[PATH_MAX];
};

typedef struct
{
    int  emgr_enable;
    int  OPP_enable;
    struct emgr_filter_setting emgr_filter;
    struct OPP_filter_setting OPP_filter;
    int  emgr_action;
    int  OPP_action;
    int  enable_size_filter;
    int  delete_triggered_attachment;
}emgr_setting_t;

typedef struct 
{
    int  spam_enable;
    spam_protocol_config protocol;
    char spam_prefix[MU_MAX_PREFIX_SIZE];
    int  spam_action;
    int  phishing_enable;
    char phishing_prefix[MU_MAX_PREFIX_SIZE];
    int  phishing_action;
}spam_setting_t;

typedef struct 
{
    protocol_config_t protocol;
    int vscan_timeout;
    virus_action_t action;
    mail_v_notify_t notify;
    vscan_inline_t inline_notification;
}vscan_setting_t;

typedef struct
{
    unsigned int trickling_enable;
    unsigned int trickling_interval;
}trickle_config_t;

typedef struct
{
    trickle_config_t trickle;
    unsigned int dlm_timeout;
    unsigned int pass_large_file;
    mail_nv_notify_t notify;
    int proxy_mode;
}proxy_common_setting_t;

typedef struct
{
    int file_error_action;
    int parse_error_action;
}proxy_action_setting_t;

typedef struct
{
    int  enable_kk;
    int  RBL_only;
    char kk_exception_list[MU_MAX_KK_EXCEPT];
    char RBL_action[MU_MAX_STRING_SIZE];
    unsigned int RBL_error_code;
    char QIL_action[MU_MAX_STRING_SIZE];
    unsigned int QIL_error_code;
    char activation_code[MU_MAX_STRING_SIZE];
}kelkea_setting_t;

typedef struct
{
    unsigned int std_valid;
//    unsigned int eps_valid;
}license_setting_t;
#endif
#endif
