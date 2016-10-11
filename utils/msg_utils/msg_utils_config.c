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
* msg_utils_config.c
*
* Description: source file of  reading configuration for message related modules
* Author: HY Cheng
*
* #001 Aug 11, 2005 HY Cheng Initial implementation.
*/

#include "list.h"
#include <assert.h>
#include <unistd.h>
#include <stdio.h> 
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <config_def.h>
#include <msg_utils.h>
#include <v_result.h>
#include "msg_utils_common.h"

#ifndef PROJECT_RUNTIME_PATH
#warning "PROJECT_RUNTIME_PATH not defined"
#endif
#define SYSTEM_CONFIG_FILE PROJECT_RUNTIME_PATH "/etc/igsa.conf"

/*****************************************************/
/*                  STATIC FNUCTION                  */
/*****************************************************/

#define IS_CLEAN(action) (action && strcasecmp(action,"clean") == 0)
#define IS_QUARANTINE(action) (action && strcasecmp(action,"quarantine") == 0) 
#define IS_QUARANTINE_RSET(action) (action && strcasecmp(action,"quarantine_rset") == 0) 
#define IS_QUARANTINE_EUQ(action) (action && strcasecmp(action,"quarantine_euq") == 0) 
#define IS_DELETE(action) (action && strcasecmp(action,"delete") == 0)
#define IS_PASS(action) (action && strcasecmp(action,"pass") == 0)
#define IS_BLOCK(action) (action && strcasecmp(action,"block") == 0)
#define IS_BLOCK_RSET(action) (action && strcasecmp(action,"block_rset") == 0)
#define IS_STAMP(action) (action && strcasecmp(action,"stamp") == 0)


inline static int action_to_int(const char *p)
{
    int action = A_INVALID;
    
    if(IS_CLEAN(p))
        action = A_CLEAN;
    else if(IS_QUARANTINE(p))
        action = A_QUARANTINE;
    else if(IS_QUARANTINE_RSET(p))
        action = A_QUARANTINE_RSET;
    else if(IS_QUARANTINE_EUQ(p))
        action = A_QUARANTINE_EUQ;
    else if(IS_DELETE(p))
        action = A_DELETE; 
    else if(IS_PASS(p))
        action = A_PASS; 
    else if(IS_BLOCK(p))
        action = A_BLOCK;
    else if(IS_BLOCK_RSET(p))
        action = A_BLOCK_RSET;
    else if(IS_STAMP(p))
        action = A_STAMP;
    
    return action;
}

static int str2int(const char *p, long *retval) 
{ 
    char *nptr = NULL; 
    long val = 0; 
    
    if (p == NULL) 
        return -1; 
    
    errno = 0; 
    val = strtol(p, &nptr, 10); 
    if ((((val == LONG_MIN) || (val == LONG_MAX)) && (errno == ERANGE)) || (*nptr != '\0') || (nptr == p)) 
        return -1; 
    
    if (retval != NULL) 
        *retval = val; 
    
    return 0; 
} 

const char *
get_param_number(const char *module,
                 const char *param,
                 unsigned int *retval,
                 glcfg_t glcfg)
{
    long val;
    const char *glcfg_value;
    
    glcfg_value = glcfg_get_param_value(glcfg, module, param, NULL);
    if (glcfg_value == NULL)
    {
        LOGERROR("glcfg_get_param_value(): module=%s, param=%s", module, param);
        return NULL;
    }
    
    if(str2int(glcfg_value,&val) == -1)
    {
        LOGERROR("str2int(%s): module=%s, param=%s", glcfg_value, module, param);
        return NULL;
    }
    
    if (val < 0)
    {
        LOGERROR("The value (%ld) is less than zero: module=%s, param=%s\n", val, module, param);
        return NULL;
    }
    
    if (retval != NULL)
        (*retval) = (unsigned int)val;
    
    return glcfg_value;
}
#if 0
static int read_trickling_config(glcfg_t glcfg, char *module, proxy_common_setting_t *common_setting)
{
    const char *p = NULL;
    unsigned int val;
    
    /*get the enable flag of trickling*/
    if((p = get_param_number(module,"trickling_enable",&val,glcfg)) == NULL)
    {
        LOGERROR("Failed to get_param_number");
        return -1;
    }
    common_setting->trickle.trickling_enable = (int)val;
    LOGDEBUG("        %s:trickle->trickling_enable=%d", module, common_setting->trickle.trickling_enable);
    
    /*get the interval of trickling*/
    if((p = get_param_number(module,"trickling_interval",&val,glcfg)) == NULL)
    {
        LOGERROR("Failed to get_param_number");
        return -1;
    }
    common_setting->trickle.trickling_interval = (int)val;
    LOGDEBUG("        %s:trickle->trickling_interval=%d", module, common_setting->trickle.trickling_interval);
    
    return 0;
}

static int read_dlm_config(glcfg_t glcfg, char *module, proxy_common_setting_t *common_setting)
{
    const char *p = NULL;
    unsigned int val;
    
    if((p = get_param_number(module,"dlm_timeout",&val,glcfg)) == NULL)
    {
        LOGERROR("Failed to get_param_number");
        return -1;
    }
    common_setting->dlm_timeout = (int)val;
    LOGDEBUG("        %s:dlm_timeout=%d", module, common_setting->dlm_timeout);
    
    return 0;
}

static int read_passlargefile_config(glcfg_t glcfg, char *module, proxy_common_setting_t *common_setting)
{
    const char *p = NULL;
    unsigned int val;
    
    if((p = get_param_number(module,"pass_large_files",&val,glcfg)) == NULL)
    {
        LOGERROR("Failed to get_param_number");
        return -1;
    }
    common_setting->pass_large_file = (int)val;
    LOGDEBUG("        %s:pass_large_file=%d", module, common_setting->pass_large_file);
    
    return 0;
}

static int read_nv_notify(glcfg_t glcfg, char *module, proxy_common_setting_t *common_setting)
{
    const char *p = NULL;
    unsigned int val = 0;
    
    if((p = get_param_number(module, "vscan_spy_notify_administrator", &val,glcfg)) == NULL)
    {
        LOGERROR("Failed to get_param_number");
        return -1;
    }
    common_setting->notify.vscan_spy_notify_administrator = val;
    LOGDEBUG("        %s:notify->vscan_spy_notify_administrator=%d", module, common_setting->notify.vscan_spy_notify_administrator);
    
    if((p = get_param_number(module, "vscan_spy_notify_sender", &val,glcfg)) == NULL)
    {
        LOGERROR("Failed to get_param_number");
        return -1;
    }
    common_setting->notify.vscan_spy_notify_sender = val;
    LOGDEBUG("        %s:notify->vscan_spy_notify_sender=%d", module, common_setting->notify.vscan_spy_notify_sender);
    
    if((p = get_param_number(module, "vscan_spy_notify_recipient", &val,glcfg)) == NULL)
    {
        LOGERROR("Failed to get_param_number");
        return -1;
    }
    common_setting->notify.vscan_spy_notify_recipient = val;
    LOGDEBUG("        %s:notify->vscan_spy_notify_recipient=%d", module, common_setting->notify.vscan_spy_notify_recipient);
    
    if((p = get_param_number(module, "vscan_bot_notify_administrator", &val,glcfg)) == NULL)
    {
        LOGERROR("Failed to get_param_number");
        return -1;
    }
    common_setting->notify.vscan_bot_notify_administrator = val;
    LOGDEBUG("        %s:notify->vscan_bot_notify_administrator=%d", module, common_setting->notify.vscan_bot_notify_administrator);
    
    if((p = get_param_number(module, "vscan_bot_notify_sender", &val,glcfg)) == NULL)
    {
        LOGERROR("Failed to get_param_number");
        return -1;
    }
    common_setting->notify.vscan_bot_notify_sender = val;
    LOGDEBUG("        %s:notify->vscan_bot_notify_sender=%d", module, common_setting->notify.vscan_bot_notify_sender);
    
    if((p = get_param_number(module, "vscan_bot_notify_recipient", &val,glcfg)) == NULL)
    {
        LOGERROR("Failed to get_param_number");
        return -1;
    }
    common_setting->notify.vscan_bot_notify_recipient = val;
    LOGDEBUG("        %s:notify->vscan_bot_notify_recipient=%d", module, common_setting->notify.vscan_bot_notify_recipient);
    
    if((p = get_param_number(module, "phi_notify_administrator", &val,glcfg)) == NULL)
    {
        LOGERROR("Failed to get_param_number");
        return -1;
    }
    common_setting->notify.phi_notify_administrator = val;
    LOGDEBUG("        %s:notify->phi_notify_administrator=%d", module, common_setting->notify.phi_notify_administrator);
    
    if((p = get_param_number(module, "phi_notify_recipient", &val,glcfg)) == NULL)
    {
        LOGERROR("Failed to get_param_number");
        return -1;
    }
    common_setting->notify.phi_notify_recipient = val;
    LOGDEBUG("        %s:notify->phi_notify_recipient=%d", module, common_setting->notify.phi_notify_recipient);
    
    if((p = get_param_number(module, "cf_notify_administrator", &val,glcfg)) == NULL)
    {
        LOGERROR("Failed to get_param_number");
        return -1;
    }
    common_setting->notify.cf_notify_administrator = val;
    LOGDEBUG("        %s:notify->cf_notify_administrator=%d", module, common_setting->notify.cf_notify_administrator);
    
    if((p = get_param_number(module, "cf_notify_sender", &val,glcfg)) == NULL)
    {
        LOGERROR("Failed to get_param_number");
        return -1;
    }
    common_setting->notify.cf_notify_sender = val;
    LOGDEBUG("        %s:notify->cf_notify_sender=%d", module, common_setting->notify.cf_notify_sender);
    
    if((p = get_param_number(module, "cf_notify_recipient", &val,glcfg)) == NULL)
    {
        LOGERROR("Failed to get_param_number");
        return -1;
    }
    common_setting->notify.cf_notify_recipient = val;
    LOGDEBUG("        %s:notify->cf_notify_recipient=%d", module, common_setting->notify.cf_notify_recipient);
    
    return 0;
}

static int read_vscan_action(glcfg_t glcfg, char *module, virus_action_t *action)
{
    const char *p = NULL;
    /*1st action*/
    if((p = glcfg_get_param_value(glcfg,module,"vscan_action_1st",NULL)) == NULL)
    {
        LOGERROR("Failed to glcfg_get_param_value");
        return -1;
    }
    action->first_action = action_to_int(p);
    LOGDEBUG("        %s:vscan_action_1st=%s (%d)", module, p, action->first_action);
   
    /*2nd action*/
    if((p = glcfg_get_param_value(glcfg,module,"vscan_action_2nd",NULL)) == NULL)
    {
        LOGERROR("Failed to glcfg_get_param_value");
        return -1;
    }
    action->snd_action = action_to_int(p);
    LOGDEBUG("        %s:vscan_action_2nd=%s (%d)", module, p, action->snd_action);

    /*spy action*/
    if((p = glcfg_get_param_value(glcfg,module,"vscan_action_spy",NULL)) == NULL)
    {
        LOGERROR("Failed to glcfg_get_param_value");
        return -1;
    }
    action->spy_action = action_to_int(p);
    LOGDEBUG("        %s:vscan_action_spy=%s (%d)", module, p, action->spy_action);
    
    /*bot action*/
    if((p = glcfg_get_param_value(glcfg,module,"vscan_action_bot",NULL)) == NULL)
    {
        LOGERROR("Failed to glcfg_get_param_value");
        return -1;
    }
    action->bot_action = action_to_int(p);
    LOGDEBUG("        %s:vscan_action_bot=%s (%d)", module, p, action->bot_action);

    /*error action*/
    if((p = glcfg_get_param_value(glcfg,module,"vscan_action_err",NULL)) == NULL)
    {
        LOGERROR("Failed to glcfg_get_param_value");
        return -1;
    }
    action->err_action = action_to_int(p);
    LOGDEBUG("        %s:vscan_action_err=%s (%d)", module, p, action->err_action);

    return 0;
}

static int read_vscan_inline(glcfg_t glcfg, char *module, vscan_inline_t *inline_notification)
{
    const char *p = NULL;
    unsigned int val = 0;
    
    if((p = get_param_number(module, "vscan_show_risk_detected_subject", &val,glcfg)) == NULL)
    {
        LOGERROR("Failed to get_param_number");
        return -1;
    }
    inline_notification->show_risk_detected_subject = val;
    LOGDEBUG("        %s:inline_notification->show_risk_detected_subject=%d", module, inline_notification->show_risk_detected_subject);

    if((p = get_param_number(module, "vscan_show_risk_detected_message", &val,glcfg)) == NULL)
    {
        LOGERROR("Failed to get_param_number");
        return -1;
    }
    inline_notification->show_risk_detected_message = val;
    LOGDEBUG("        %s:inline_notification->show_risk_detected_message=%d", module, inline_notification->show_risk_detected_message);
    
    if((p = get_param_number(module, "vscan_show_risk_free_message", &val,glcfg)) == NULL)
    {
        LOGERROR("Failed to get_param_number");
        return -1;
    }
    inline_notification->show_risk_free_message = val;
    LOGDEBUG("        %s:inline_notification->show_risk_free_message=%d", module, inline_notification->show_risk_free_message);
    
    return 0;
}

static int read_vscan_notify(glcfg_t glcfg, char *module, mail_v_notify_t *v_notify)
{
    const char *p = NULL;
    unsigned int val = 0;
    
    if((p = get_param_number(module, "vscan_notify_administrator", &val,glcfg)) == NULL)
    {
        LOGERROR("Failed to get_param_number");
        return -1;
    }
    v_notify->vscan_notify_administrator = val;
    LOGDEBUG("        %s:vscan_notify_administrator=%d", module, v_notify->vscan_notify_administrator);
    
    if((p = get_param_number(module, "vscan_notify_sender", &val,glcfg)) == NULL)
    {
        LOGERROR("Failed to get_param_number");
        return -1;
    }
    v_notify->vscan_notify_sender = val;
    LOGDEBUG("        %s:vscan_notify_sender=%d", module, v_notify->vscan_notify_sender);
    
    if((p = get_param_number(module, "vscan_notify_recipient", &val,glcfg)) == NULL)
    {
        LOGERROR("Failed to get_param_number");
        return -1;
    }
    v_notify->vscan_notify_recipient = val;
    LOGDEBUG("        %s:vscan_notify_recipient=%d", module, v_notify->vscan_notify_recipient);
    
    return 0;
}

static int
read_emgr_filter_setting(
    glcfg_t glcfg,
    const char *module,
    struct emgr_filter_setting *config)
{ 
    int ret = -1;
    const char *param = NULL;
    const char *value = NULL;

    LOGDEBUG("Enter %s(): glcfg=%p, module=\"%s\", config=%p",
             __FUNCTION__, glcfg, module, config);

    if (glcfg == NULL || module == NULL || config == NULL)
    {
        LOGERROR("Invalid argument");
        goto leave;
    }

    { /* Size Filter */
        /* size_attr */
        if (em_filter_size_attr_init(&config->size_attr) != 0)
        {
            LOGERROR("em_filter_size_attr_init()");
            goto leave;
        }

        /* compare */
        param = "compare";
        if ((value = get_param_number(module, param, &config->size_attr.compare, glcfg)) == NULL)
        {
            LOGERROR("get_param_number(): module=\"%s\", param=\"%s\"", module, param);
            goto leave;
        }

        /* size_threshold */
        param = "size_threshold";
        if ((value = get_param_number(module, param, &config->size_attr.threshold, glcfg)) == NULL)
        {
            LOGERROR("get_param_number(): module=\"%s\", param=\"%s\"", module, param);
            goto leave;
        }
    }

    { /* Header Filter */
        /* header_attr */
        if (em_filter_header_attr_init(&config->header_attr) != 0)
        {
            LOGERROR("em_filter_header_attr_init()");
            goto leave;
        }

        /* subject_case_sensitive */
        param = "subject_case_sensitive";
        if ((value = get_param_number(module, param, &config->header_attr.expr_case_sensitive, glcfg)) == NULL)
        {
            LOGERROR("get_param_number(): module=\"%s\", param=\"%s\"", module, param);
            goto leave;
        }

        /* header_expr_file */
        param = "subject_expr_file";
        if ((value = glcfg_get_param_value(glcfg, module, param, NULL)) == NULL)
        {
            LOGERROR("glcfg_get_param_value(): module=\"%s\", param=\"%s\"", module, param);
            goto leave;
        }
        snprintf(config->header_expr_file, sizeof(config->header_expr_file), "%s", value);
        LOGDEBUG("        %s: config->header_expr_file=\"%s\"", module, config->header_expr_file);

        /* header_expr_file_default */
        param = "subject_expr_file_default";
        if ((value = glcfg_get_param_value(glcfg, module, param, NULL)) == NULL)
        {
            LOGERROR("glcfg_get_param_value(): module=\"%s\", param=\"%s\"", module, param);
            goto leave;
        }
        snprintf(config->header_expr_file_default, sizeof(config->header_expr_file_default), "%s", value);
        LOGDEBUG("        %s: config->header_expr_file_default=\"%s\"", module, config->header_expr_file_default);
    }

    { /* Body Filter */
        /* body_attr */
        if (em_filter_body_attr_init(&config->body_attr) != 0)
        {
            LOGERROR("em_filter_body_attr_init()");
            goto leave;
        }

        /* msgbody_case_sensitive */
        param = "msgbody_case_sensitive";
        if ((value = get_param_number(module, param, &config->body_attr.expr_case_sensitive, glcfg)) == NULL)
        {
            LOGERROR("get_param_number(): module=\"%s\", param=\"%s\"", module, param);
            goto leave;
        }

        /* body_expr_file */
        param = "msgbody_expr_file";
        if ((value = glcfg_get_param_value(glcfg, module, param, NULL)) == NULL)
        {
            LOGERROR("glcfg_get_param_value(): module=\"%s\", param=\"%s\"", module, param);
            goto leave;
        }
        snprintf(config->body_expr_file, sizeof(config->body_expr_file), "%s", value);
        LOGDEBUG("        %s: config->body_expr_file=\"%s\"", module, config->body_expr_file);

        /* body_expr_file_default */
        param = "msgbody_expr_file_default";
        if ((value = glcfg_get_param_value(glcfg, module, param, NULL)) == NULL)
        {
            LOGERROR("glcfg_get_param_value(): module=\"%s\", param=\"%s\"", module, param);
            goto leave;
        }
        snprintf(config->body_expr_file_default, sizeof(config->body_expr_file_default), "%s", value);
        LOGDEBUG("        %s: config->body_expr_file_default=\"%s\"", module, config->body_expr_file_default);
    }
    
    { /* Attachment Filter */
        /* attachment_attr */
        if (em_filter_attachment_attr_init(&config->attachment_attr) != 0)
        {
            LOGERROR("em_filter_attachment_attr_init()");
            goto leave;
        }

        /* attachment_expr_file */
        param = "attachment_expr_file";
        if ((value = glcfg_get_param_value(glcfg, module, param, NULL)) == NULL)
        {
            LOGERROR("glcfg_get_param_value(): module=\"%s\", param=\"%s\"", module, param);
            goto leave;
        }
        snprintf(config->attachment_expr_file, sizeof(config->attachment_expr_file), "%s", value);
        LOGDEBUG("        %s: config->attachment_expr_file=\"%s\"", module, config->attachment_expr_file);

        /* attachment_expr_file_default */
        param = "attachment_expr_file_default";
        if ((value = glcfg_get_param_value(glcfg, module, param, NULL)) == NULL)
        {
            LOGERROR("glcfg_get_param_value(): module=\"%s\", param=\"%s\"", module, param);
            goto leave;
        }
        snprintf(config->attachment_expr_file_default, sizeof(config->attachment_expr_file_default), "%s", value);
        LOGDEBUG("        %s: config->attachment_expr_file_default=\"%s\"", module, config->attachment_expr_file_default);
    }

    { /* File Category Filter */
        param = "emgr_file_category";
        if ((value = glcfg_get_param_value(glcfg, module, param, NULL)) == NULL)
        {
            LOGERROR("glcfg_get_param_value(): module=\"%s\", param=\"%s\"", module, param);
            goto leave;
        }
        snprintf(config->category_list, sizeof(config->category_list), "%s", value);
        LOGDEBUG("        %s: config->category_list=\"%s\"", module, config->category_list);
    }

    ret = 0;
   
leave:
    LOGDEBUG("Leave %s(): ret=%d", __FUNCTION__, ret);
    return ret;
}

static int
read_OPP_filter_setting(
    glcfg_t glcfg,
    const char *module,
    struct OPP_filter_setting *config)
{
    int ret = -1;
    const char *param = NULL;
    const char *value = NULL;

    LOGDEBUG("Enter %s(): glcfg=%p, module=\"%s\", config=%p",
             __FUNCTION__, glcfg, module, config);

    if (glcfg == NULL || module == NULL || config == NULL)
    {
        LOGERROR("Invalid argument");
        goto leave;
    }

    { /* Header Filter */
        /* header_attr */
        if (em_filter_OPP_header_attr_init(&config->header_attr) != 0)
        {
            LOGERROR("em_filter_header_attr_init()");
            goto leave;
        }

        LOGDEBUG("        %s: config->header_attr: filter_name=\"%s\"", module, config->header_attr.filter_name);

        /* header_expr_file */
        param = "OPP_subject";
        if ((value = glcfg_get_param_value(glcfg, module, param, NULL)) == NULL)
        {
            LOGERROR("glcfg_get_param_value(): module=\"%s\", param=\"%s\"", module, param);
            goto leave;
        }
        snprintf(config->header_expr_file, sizeof(config->header_expr_file), "%s", value);
        LOGDEBUG("        %s: config->header_expr_file=\"%s\"", module, config->header_expr_file);

        /* header_expr_file_default */
        param = "OPP_subject_default";
        if ((value = glcfg_get_param_value(glcfg, module, param, NULL)) == NULL)
        {
            LOGERROR("glcfg_get_param_value(): module=\"%s\", param=\"%s\"", module, param);
            goto leave;
        }
        snprintf(config->header_expr_file_default, sizeof(config->header_expr_file_default), "%s", value);
        LOGDEBUG("        %s: config->header_expr_file_default=\"%s\"", module, config->header_expr_file_default);
    }

    { /* Body Filter */
        /* body_attr */
        if (em_filter_OPP_body_attr_init(&config->body_attr) != 0)
        {
            LOGERROR("em_filter_body_attr_init()");
            goto leave;
        }

        LOGDEBUG("        %s: config->body_attr: filter_name=\"%s\"", module, config->body_attr.filter_name);

        /* body_expr_file */
        param = "OPP_body";
        if ((value = glcfg_get_param_value(glcfg, module, param, NULL)) == NULL)
        {
            LOGERROR("glcfg_get_param_value(): module=\"%s\", param=\"%s\"", module, param);
            goto leave;
        }
        snprintf(config->body_expr_file, sizeof(config->body_expr_file), "%s", value);
        LOGDEBUG("        %s: config->body_expr_file=\"%s\"", module, config->body_expr_file);

        /* body_expr_file_default */
        param = "OPP_body_default";
        if ((value = glcfg_get_param_value(glcfg, module, param, NULL)) == NULL)
        {
            LOGERROR("glcfg_get_param_value(): module=\"%s\", param=\"%s\"", module, param);
            goto leave;
        }
        snprintf(config->body_expr_file_default, sizeof(config->body_expr_file_default), "%s", value);
        LOGDEBUG("        %s: config->body_expr_file_default=\"%s\"", module, config->body_expr_file_default);
    }

    { /* Attachment Filter */
        /* attachment_attr */
        if (em_filter_OPP_attachment_attr_init(&config->attachment_attr) != 0)
        {
            LOGERROR("em_filter_attachment_attr_init()");
            goto leave;
        }

        LOGDEBUG("        %s: config->attachment_attr: filter_name=\"%s\"", module, config->attachment_attr.filter_name);

        /* attachment_expr_file */
        param = "OPP_filename";
        if ((value = glcfg_get_param_value(glcfg, module, param, NULL)) == NULL)
        {
            LOGERROR("glcfg_get_param_value(): module=\"%s\", param=\"%s\"", module, param);
            goto leave;
        }
        snprintf(config->attachment_expr_file, sizeof(config->attachment_expr_file), "%s", value);
        LOGDEBUG("        %s: config->attachment_expr_file=\"%s\"", module, config->attachment_expr_file);

        /* attachment_expr_file_default */
        param = "OPP_filename_default";
        if ((value = glcfg_get_param_value(glcfg, module, param, NULL)) == NULL)
        {
            LOGERROR("glcfg_get_param_value(): module=\"%s\", param=\"%s\"", module, param);
            goto leave;
        }
        snprintf(config->attachment_expr_file_default, sizeof(config->attachment_expr_file_default), "%s", value);
        LOGDEBUG("        %s: config->attachment_expr_file_default=\"%s\"", module, config->attachment_expr_file_default);
    }

    ret = 0;

leave:
    LOGDEBUG("Leave %s(): ret=%d", __FUNCTION__, ret);
    return ret;
}

static int read_kk_activation_code(kelkea_setting_t *kk_setting)
{
    int ret = -1;
    glcfg_t glcfg = NULL;
    const char *p = NULL;
    
    if ((glcfg = glcfg_open(SYSTEM_CONFIG_FILE, GLCFG_MODE_READ)) == NULL)
    {
        LOGERROR("glcfg_open(): file=%s", SYSTEM_CONFIG_FILE);
        goto leave;
    }
    
    if((p = glcfg_get_param_value(glcfg,"license","std_ac",NULL)) == NULL)
    {
        LOGERROR("Failed to glcfg_get_param_value");
        goto leave;
    }
    snprintf(kk_setting->activation_code, sizeof(kk_setting->activation_code), "%s", p);
    
    ret = 0;
    
leave:

    if(glcfg != NULL)
    {
        (void)glcfg_close(glcfg);
        glcfg = NULL;
    }
    
    return ret;
}
#endif
/*****************************************************/
/*                  EXPORT FNUCTION                  */
/*****************************************************/
#if 0
int mu_read_tmmsg_common_setting(glcfg_t glcfg, tmmsg_config_t *tmmsg_config)
{
    const char *p = NULL;
    unsigned int val = 0;
    
    LOGINFO("+++++mu_read_tmmsg_common_setting+++++");
    
    if ((p = get_param_number("tmmsg", "max_header_num_per_entity", &val,glcfg)) == NULL)
    {
        LOGERROR("Failed to get_param_number");
        return -1;
    }
    tmmsg_config->limit.max_header_num_per_entity = val;
    LOGDEBUG("        tmmsg_config->limit.max_header_num_per_entity = %d", val);
    
    if ((p = get_param_number("tmmsg", "max_entry_num_per_header", &val,glcfg)) == NULL)
    {
        LOGERROR("Failed to get_param_number");
        return -1;
    }
    tmmsg_config->limit.max_entry_num_per_header = val;
    LOGDEBUG("        tmmsg_config->limit.max_entry_num_per_header = %d", tmmsg_config->limit.max_entry_num_per_header);
    
    if ((p = get_param_number("tmmsg", "max_entity_num_per_message", &val,glcfg)) == NULL)
    {
        LOGERROR("Failed to get_param_number");
        return -1;
    }
    tmmsg_config->limit.max_entity_num_per_message = val;
    LOGDEBUG("        tmmsg_config->limit.max_entity_num_per_message = %d", tmmsg_config->limit.max_entity_num_per_message);
    
    if ((p = get_param_number("tmmsg", "max_extract_level_per_message", &val,glcfg)) == NULL)
    {
        LOGERROR("Failed to get_param_number");
        return -1;
    }
    tmmsg_config->limit.max_extract_level_per_message = val;
    LOGDEBUG("        tmmsg_config->limit.max_extract_level_per_message = %d", tmmsg_config->limit.max_extract_level_per_message);
    
    if ((p = get_param_number("tmmsg", "max_byte_per_entity_header", &val,glcfg)) == NULL)
    {
        LOGERROR("Failed to get_param_number");
        return -1;
    }
    tmmsg_config->limit.max_byte_per_entity_header = val;
    LOGDEBUG("        tmmsg_config->limit.max_byte_per_entity_header = %d", tmmsg_config->limit.max_byte_per_entity_header);
    
    if ((p = get_param_number("tmmsg", "max_byte_of_mem_resouce", &val,glcfg)) == NULL)
    {
        LOGERROR("Failed to get_param_number");
        return -1;
    }
    tmmsg_config->limit.max_byte_of_mem_resource = val;
    LOGDEBUG("        tmmsg_config->limit.max_byte_of_mem_resource = %d", tmmsg_config->limit.max_byte_of_mem_resource);
    
    if ((p = glcfg_get_param_value(glcfg, "tmmsg", "temp_file_path", NULL)) == NULL)
    {
        LOGERROR("Failed to glcfg_get_param_value");
        return -1;
    }
    snprintf(tmmsg_config->temp_file_path, TMMSG_MAX_PATH_SIZE, "%s", p);
    LOGDEBUG("        tmmsg_config->temp_file_path = %s", tmmsg_config->temp_file_path);
    
    LOGINFO("-----mu_read_tmmsg_common_setting-----");
    
    return 0;
}
#endif
int mu_read_vscan_common_setting(glcfg_t glcfg, common_config_t *common)
{
    const char *p = NULL;
    unsigned int val = 0;
    
    LOGINFO("+++++mu_read_vscan_common_setting+++++");
    
    /* temp_path */
    if ((p = glcfg_get_param_value(glcfg, "vscan", "temp_path", NULL)) == NULL)
    {
        LOGERROR("Failed to glcfg_get_param_value");
        return -1;
    }
    snprintf(common->tmppath, VSCAN_MAX_PATH_SIZE, "%s", p);
    LOGDEBUG("        common->tmppath = %s", common->tmppath);

    /* engine_path */
    if ((p = glcfg_get_param_value(glcfg, "vscan", "engine_path", NULL)) == NULL)
    {
        LOGERROR("Failed to glcfg_get_param_value");
        return -1;
    }
    snprintf(common->engpath, VSCAN_MAX_PATH_SIZE, "%s", p);
    LOGDEBUG("        common->engpath = %s", common->engpath);
        
    /* virus/spyware_pattern_path */
    if ((p = glcfg_get_param_value(glcfg, "vscan", "pattern_path", NULL)) == NULL)
    {
        LOGERROR("Failed to glcfg_get_param_value");
        return -1;
    }
    snprintf(common->ptnpath, VSCAN_MAX_PATH_SIZE, "%s", p);
    LOGDEBUG("        common->ptnpath = %s", common->ptnpath);
        
    /* virus pattern */
    snprintf(common->ptnfile, sizeof(common->ptnfile), "lpt$vpn.");

    /* spyware pattern*/
    snprintf(common->spyptnfile, sizeof(common->spyptnfile), "ssaptn.");
    
    /* tmblack */
    snprintf(common->tmblack, sizeof(common->tmblack), "tmblack.");
    
    /* tmwhite */
    snprintf(common->tmwhite, sizeof(common->tmwhite), "tmwhite.");

    /* max_scan_num*/
    if ((p = get_param_number("vscan", "max_scan_num", &val,glcfg)) == NULL)
    {
        LOGERROR("Failed to get_param_number");
        return -1;
    }
    common->max_scan_num = val;
    LOGDEBUG("        common->max_scan_num = %d", common->max_scan_num);
    
    /* vsapi default file extension list */
    if ((p = glcfg_get_param_value(glcfg, "vscan", "vsapi_def_file_ext", NULL)) == NULL)
    {
        LOGERROR("Failed to glcfg_get_param_value");
        return -1;
    }
    snprintf(common->vsapi_def_file_ext, VSCAN_MAX_PATH_SIZE, "%s", p);
    LOGDEBUG("        common->common->vsapi_def_file_ext = %s", common->vsapi_def_file_ext);
    
    LOGINFO("-----mu_read_vscan_common_setting-----");

    return 0;
}
#if 0
int mu_read_proxy_common_setting(glcfg_t glcfg, char *module, proxy_common_setting_t *common_setting)
{
    const char *p = NULL;
    unsigned int val = 0;
    
    LOGINFO("+++++mu_read_proxy_common_setting+++++");

    if(read_trickling_config(glcfg, module, common_setting) != 0)
    {
        LOGERROR("Failed to read_trickling_config");
        return -1;
    }
    
    if(read_dlm_config(glcfg, module, common_setting) != 0)
    {
        LOGERROR("Failed to read_dlm_config");
        return -1;
    }
    
    if(read_passlargefile_config(glcfg, module, common_setting) != 0)
    {
        LOGERROR("Failed to read_passlargefile");
        return -1;
    }
    
    if(read_nv_notify(glcfg, module, common_setting) != 0)
    {
        LOGERROR("Failed to read_nv_notify");
        return -1;
    }

    if ((p = get_param_number(module, "proxy_mode", &val, glcfg)) == NULL)
    {
        LOGERROR("get_param_number(): proxy_mode");
        return -1;
    }
    common_setting->proxy_mode = val;
    LOGDEBUG("        %s:proxy_mode=%d", module, common_setting->proxy_mode);
    
    LOGINFO("-----mu_read_proxy_common_setting-----");
    
    return 0;
}

int mu_read_proxy_action_setting(glcfg_t glcfg, char *module, proxy_action_setting_t *action_setting)
{
    const char *p = NULL;

    LOGINFO("+++++mu_read_proxy_action_setting+++++");

    if ((p = glcfg_get_param_value(glcfg, module, "file_error_action", NULL)) == NULL)
    {
        LOGERROR("glcfg_get_param_value(): file_error_action");
        return -1;
    }
    action_setting->file_error_action = action_to_int(p);
    LOGDEBUG("        %s:file_error_action=%d", module, action_setting->file_error_action);

    if ((p = glcfg_get_param_value(glcfg, module, "parse_error_action", NULL)) == NULL)
    {
        LOGERROR("glcfg_get_param_value(): parse_error_action");
        return -1;
    }
    action_setting->parse_error_action = action_to_int(p);
    LOGDEBUG("        %s:parse_error_action=%d", module, action_setting->parse_error_action);

    LOGINFO("-----mu_read_proxy_action_setting-----");

    return 0;
}
#endif
int mu_read_vscan_protocol_setting(glcfg_t glcfg, char *module, protocol_config_t *protocol)
{
    const char *p = NULL;
    unsigned int val = 0;
    
    LOGINFO("+++++mu_read_vscan_protocol_setting+++++");
    
    /* virus_enable */
    if ((p = get_param_number(module, "virus_enable", &val,glcfg)) == NULL)
    {
        LOGERROR("get_param_number(): virus_enable");
        return -1;
    }
    protocol->virus_enable = val;
    LOGDEBUG("        %s:vscan->virus_enable = %d", module, protocol->virus_enable);
    
    /* compress_enable */
    if ((p = get_param_number(module, "compress_enable", &val,glcfg)) == NULL)
    {
        LOGERROR("get_param_number(): compress_enable");
        return -1;
    }
    protocol->compress_enable = val;
    LOGDEBUG("        %s:vscan->compress_enable = %d", module, protocol->compress_enable);
    
    /* spyware_enable */
    if ((p = get_param_number(module, "spyware_enable", &val,glcfg)) == NULL)
    {
        LOGERROR("get_param_number(): spyware_enable");
        return -1;
    }
    protocol->spyware_enable = val;
    LOGDEBUG("        %s:vscan->spyware_enable = %d", module, protocol->spyware_enable);
    
    /* bot_enable */
    if ((p = get_param_number(module, "bot_enable", &val,glcfg)) == NULL)
    {
        LOGERROR("get_param_number(): bot_enable");
        return -1;
    }
    protocol->bot_enable = val;
    LOGDEBUG("        %s:vscan->bot_enable = %d", module, protocol->bot_enable);
    
    /* spyware exclusion list */
    if ((p = glcfg_get_param_value(glcfg, module, "spyware_exclude", NULL)) == NULL)
    {
        LOGERROR("glcfg_get_param_value()): spyware_exclude");
        return -1;
    }
    memset(protocol->spyware_exclude,0,VSCAN_MAX_NAME_LIST_SIZE);
    snprintf(protocol->spyware_exclude, VSCAN_MAX_NAME_LIST_SIZE, "%s", p);
    LOGDEBUG("        %s:vscan->spyware_exclude = %s", module, protocol->spyware_exclude);
    
    /* extract_file_size_limit */
    if ((p = get_param_number(module, "extract_file_size_limit", &val,glcfg)) == NULL)
    {
        LOGERROR("get_param_number(): extract_file_size_limit");
        return -1;
    }
    protocol->extract_file_size_limit = val;
    LOGDEBUG("        %s:vscan->extract_file_size_limit = %zd", module, protocol->extract_file_size_limit);
    
    
    /* extract_file_count_limit */
    if ((p = get_param_number(module, "extract_file_count_limit", &val,glcfg)) == NULL)
    {
        LOGERROR("get_param_number(): extract_file_limit");
        return -1;
    }
    protocol->extract_file_count_limit = val;
    LOGDEBUG("        %s:vscan->extract_file_count_limit = %zd", module, protocol->extract_file_count_limit);
    
    /* extract_file_ratio_limit */
    if ((p = get_param_number(module, "extract_file_ratio_limit", &val,glcfg)) == NULL)
    {
        LOGERROR("get_param_number(): extract_file_ratio_limit");
        return -1;
    }
    protocol->extract_file_ratio_limit = val;
    LOGDEBUG("        %s:vscan->extract_file_ratio_limit = %zd", module, protocol->extract_file_ratio_limit);
    
    /* decompress_layer */
    if ((p = get_param_number(module, "decompress_layer", &val,glcfg)) == NULL)
    {
        LOGERROR("get_param_number(): decompress_layer");
        return -1;
    }
    protocol->decompress_layer = val;
    LOGDEBUG("        %s:vscan->decompress_layer = %zd", module, protocol->decompress_layer);
    
    /* intelli_scan*/
    if ((p = get_param_number(module, "intelli_scan", &val,glcfg)) == NULL)
    {
        LOGERROR("get_param_number(): intelli_scan");
        return -1;
    }
    protocol->intelli_scan = val;
    LOGDEBUG("        %s:vscan->intelli_scan = %d", module, protocol->intelli_scan);
    
    /* process_all_file */
    if ((p = get_param_number(module, "process_all_file", &val,glcfg)) == NULL)
    {
        LOGERROR("get_param_number(): process_all_file");
        return -1;
    }
    protocol->process_all_file = val;
    LOGDEBUG("        %s:vscan->process_all_file = %d", module, protocol->process_all_file);
    
    /* process_all_file_in_arc */
    if ((p = get_param_number(module, "process_all_file_in_arc", &val,glcfg)) == NULL)
    {
        LOGERROR("get_param_number(): process_all_file_in_arc");
        return -1;
    }
    protocol->process_all_file_in_arc = val;
    LOGDEBUG("        %s:vscan->process_all_file_in_arc = %d", module, protocol->process_all_file_in_arc);
    
    /* scan_spyware */
    if ((p = get_param_number(module, "scan_spyware", &val,glcfg)) == NULL)
    {
        LOGERROR("get_param_number(): scan_spyware");
        return -1;
    }
    protocol->scan_spyware = val;
    LOGDEBUG("        %s:vscan->scan_spyware = %d", module, protocol->scan_spyware);
    
    /* scan_adware */
    if ((p = get_param_number(module, "scan_adware", &val,glcfg)) == NULL)
    {
        LOGERROR("get_param_number(): scan_adware");
        return -1;
    }
    protocol->scan_adware = val;
    LOGDEBUG("        %s:vscan->scan_adware = %d", module, protocol->scan_adware);
    
    /* scan_dialer */
    if ((p = get_param_number(module, "scan_dialer", &val,glcfg)) == NULL)
    {
        LOGERROR("get_param_number(): scan_dialer");
        return -1;
    }
    protocol->scan_dialer = val;
    LOGDEBUG("        %s:vscan->scan_dialer = %d", module, protocol->scan_dialer);
    
    /* scan_hacktool */
    if ((p = get_param_number(module, "scan_hacktool", &val,glcfg)) == NULL)
    {
        LOGERROR("get_param_number(): scan_hacktool");
        return -1;
    }
    protocol->scan_hacktool = val;
    LOGDEBUG("        %s:vscan->scan_hacktool = %d", module, protocol->scan_hacktool);
    
    /* scan_joke */
    if ((p = get_param_number(module, "scan_joke", &val,glcfg)) == NULL)
    {
        LOGERROR("get_param_number(): scan_joke");
        return -1;
    }
    protocol->scan_joke = val;
    LOGDEBUG("        %s:vscan->scan_joke = %d", module, protocol->scan_joke);
    
    /* scan_remoteaccess */
    if ((p = get_param_number(module, "scan_remoteaccess", &val,glcfg)) == NULL)
    {
        LOGERROR("get_param_number(): scan_remoteaccess");
        return -1;
    }
    protocol->scan_remoteaccess = val;
    LOGDEBUG("        %s:vscan->scan_remoteaccess = %d", module, protocol->scan_remoteaccess);
    
    /* scan_passwdcrack */
    if ((p = get_param_number(module, "scan_passwdcrack", &val,glcfg)) == NULL)
    {
        LOGERROR("get_param_number(): scan_passwdcrack");
        return -1;
    }
    protocol->scan_passwdcrack = val;
    LOGDEBUG("        %s:vscan->scan_passwdcrack = %d", module, protocol->scan_passwdcrack);
    
    /* scan_others */
    if ((p = get_param_number(module, "scan_others", &val,glcfg)) == NULL)
    {
        LOGERROR("get_param_number(): scan_others");
        return -1;
    }
    protocol->scan_others = val;
    LOGDEBUG("        %s:vscan->scan_others = %d", module, protocol->scan_others);

    /* detection_level */
    if ((p = get_param_number(module, "detection_level", &val,glcfg)) == NULL)
    {
        LOGERROR("get_param_number(): detection_level");
        return -1;
    }
    protocol->detection_level = val;
    LOGDEBUG("        %s:vscan->detection_level = %d", module, protocol->detection_level);
    /* include extension name list */
    if ((p = glcfg_get_param_value(glcfg, module, "ext_include", NULL)) == NULL)
    {
        LOGERROR("glcfg_get_param_value(): ext_include");
        return -1;
    }
    memset(protocol->ext_include,0,VSCAN_MAX_NAME_LIST_SIZE);
    snprintf(protocol->ext_include, VSCAN_MAX_NAME_LIST_SIZE, "%s", p); 
    LOGDEBUG("        %s:vscan->ext_include = %s", module, protocol->ext_include);

    LOGINFO("-----mu_read_vscan_protocol_setting-----");
    
    return 0;
    
}

#if 0
int mu_read_vscan_setting(glcfg_t glcfg, char *module, vscan_setting_t *vscan_setting)
{
    const char *p = NULL;
    unsigned int val;
    
    LOGINFO("+++++mu_read_vscan_setting+++++");
    
    if(mu_read_vscan_protocol_setting(glcfg, module, &(vscan_setting->protocol)) != 0)
    {
        LOGERROR("Failed to mu_read_vscan_protocol_setting");
        return -1;
    }
    
    if((p = get_param_number(module,"vscan_timeout",&val,glcfg)) == NULL)
    {
        LOGERROR("Failed to get_param_number");
        return -1;
    }
    vscan_setting->vscan_timeout = (int)val;
    LOGDEBUG("        vscan_setting->vscan_timeout = %d", vscan_setting->vscan_timeout);
    
    if(read_vscan_action(glcfg,module,&(vscan_setting->action)) != 0)
    {
        LOGERROR("Failed to read_vscan_action");
        return -1;
    }
    
    if(read_vscan_inline(glcfg,module,&(vscan_setting->inline_notification)) != 0)
    {
        LOGERROR("Failed to read_vscan_inline");
        return -1;
    }
    
    if(read_vscan_notify(glcfg,module,&(vscan_setting->notify)) != 0)
    {
        LOGERROR("Failed to read_vscan_notify");
        return -1;
    }
    
    LOGINFO("-----mu_read_vscan_setting-----");
    
    return 0;
}

int   mu_read_spam_common_setting(glcfg_t glcfg,spam_common_config *config)
{
    const char *p = NULL;
    unsigned int val = 0;
    
    LOGINFO("+++++mu_read_spam_common_setting+++++");
    
    memset(config, '\0', sizeof(spam_common_config));
    
    /* Rule file directory */
    if ((p = glcfg_get_param_value(glcfg, "tmase", "RuleFileDir", NULL)) == NULL)
    {
        LOGERROR("Failed to glcfg_get_param_value");
        return -1;
    }
    snprintf(config->RuleFileDir, SPAM_MAX_FILE_PATH, "%s", p);
    LOGDEBUG("        config->RuleFileDir = %s", config->RuleFileDir);
    
    /* Case sensitive */
    if ((p = get_param_number("tmase", "CaseSensitive", &val,glcfg)) == NULL)
    {
        LOGERROR("Failed to get_param_number");
        return -1;
    }
    config->CaseSensitive = val;
    LOGDEBUG("        config->CaseSensitive = %d", config->CaseSensitive);
    
    
    /* Temporary file directory */
    if ((p = glcfg_get_param_value(glcfg, "tmase", "TempDir", NULL)) == NULL)
    {
        LOGERROR("Failed to glcfg_get_param_value");     
        return -1;
    }
    snprintf(config->TempDir, SPAM_MAX_FILE_PATH, "%s", p);
    LOGDEBUG("        config->TempDir = %s", config->TempDir);
    
    /* Cache file directory */
    if ((p = glcfg_get_param_value(glcfg, "tmase", "CacheDir", NULL)) == NULL)
    {
        LOGERROR("Failed to glcfg_get_param_value");
        return -1;
    }
    snprintf(config->CacheDir, SPAM_MAX_FILE_PATH, "%s", p);
    LOGDEBUG("        config->CacheDir = %s", config->CacheDir);
    
    /* Black list first falg*/
    if ((p = get_param_number("tmase", "BlackListFirst", &val,glcfg)) == NULL)
    {
        LOGERROR("Failed to get_param_number");
        return -1;
    }
    config->BlacklistFirst = val;
    LOGDEBUG("        config->BlacklistFirst = %d", config->BlacklistFirst);
    
    LOGINFO("-----mu_read_spam_common_setting-----");
    
    return 0;
}

int mu_read_spam_setting(glcfg_t glcfg, char *module, spam_setting_t *spam_setting)
{
    const char *p = NULL;
    unsigned int val;
    
    LOGINFO("+++++mu_read_spam_setting+++++");
    
    /*spam enable flag*/
    if((p = get_param_number(module,"spam_enable",&val,glcfg)) == NULL)
    {
        LOGERROR("Failed to get_param_number");
        return -1;
    }       
    spam_setting->spam_enable = (int)val;
    LOGDEBUG("        spam_setting->spam_enable = %d", spam_setting->spam_enable);
    
    /*spam threshold*/
    if((p = get_param_number(module,"threshold",&val,glcfg)) == NULL)
    {
        LOGERROR("Failed to get_param_number");
        return -1;
    }       
    spam_setting->protocol.Threshold = (int)val;
    LOGDEBUG("        spam_setting->protocol.Threshold = %d", spam_setting->protocol.Threshold);
    
    /*white list*/
    if ((p = glcfg_get_param_value(glcfg, module, "white_list", NULL)) == NULL)
    {
        LOGERROR("Failed to glcfg_get_param_value");
        return -1;
    }
    snprintf(spam_setting->protocol.WhiteList, SPAM_MAX_FILE_PATH, "%s", p);
    LOGDEBUG("        spam_setting->protocol.WhiteList = %s", spam_setting->protocol.WhiteList);
    
    /*black list*/
    if ((p = glcfg_get_param_value(glcfg, module, "black_list", NULL)) == NULL)
    {
        LOGERROR("Failed to glcfg_get_param_value");
        return -1;
    }
    snprintf(spam_setting->protocol.BlackList, SPAM_MAX_FILE_PATH, "%s", p);
    LOGDEBUG("        spam_setting->protocol.BlackList = %s", spam_setting->protocol.BlackList);

    /*white keyword*/
    if ((p = glcfg_get_param_value(glcfg, module, "white_keyword", NULL)) == NULL)
    {
        LOGERROR("Failed to glcfg_get_param_value");
        return -1;
    }
    snprintf(spam_setting->protocol.WhiteKeyword, SPAM_MAX_FILE_PATH, "%s", p);
    LOGDEBUG("        spam_setting->protocol.WhiteKeyword = %s", spam_setting->protocol.WhiteKeyword);
    
    /*black keyword*/
    if ((p = glcfg_get_param_value(glcfg, module, "black_keyword", NULL)) == NULL)
    {
        LOGERROR("Failed to glcfg_get_param_value");
        return -1;
    }
    snprintf(spam_setting->protocol.BlackKeyword, SPAM_MAX_FILE_PATH, "%s", p);
    LOGDEBUG("        spam_setting->protocol.BlackKeyword = %s", spam_setting->protocol.BlackKeyword);
    
    /*skip keyword*/
    if ((p = glcfg_get_param_value(glcfg, module, "skip_keyword", NULL)) == NULL)
    {
        LOGERROR("Failed to glcfg_get_param_value");
        return -1;
    }
    snprintf(spam_setting->protocol.SkipKeyword, SPAM_MAX_FILE_PATH, "%s", p);
    LOGDEBUG("        spam_setting->protocol.SkipKeyword = %s", spam_setting->protocol.SkipKeyword);
    
    /*spam prefix*/
    if ((p = glcfg_get_param_value(glcfg, module, "spam_prefix", NULL)) == NULL)
    {
        LOGERROR("Failed to glcfg_get_param_value");
        return -1;
    }
    snprintf(spam_setting->spam_prefix, MU_MAX_PREFIX_SIZE, "%s", p);
    LOGDEBUG("        spam_setting->spam_prefix = %s", spam_setting->spam_prefix);
    
    /*spam action*/
    if((p = glcfg_get_param_value(glcfg,module,"spam_action",NULL)) == NULL)
    {
        LOGERROR("Failed to glcfg_get_param_value");
        return -1;
    }
    spam_setting->spam_action = action_to_int(p);
    LOGDEBUG("        spam_setting->spam_action = %d", spam_setting->spam_action);
    
    /*phishing enable flag*/
    if((p = get_param_number(module,"phishing_enable",&val,glcfg)) == NULL)
    {
        LOGERROR("Failed to get_param_number");
        return -1;
    }       
    spam_setting->phishing_enable = (int)val;
    LOGDEBUG("        spam_setting->phishing_enable = %d", spam_setting->phishing_enable);

    /*phishing prefix*/
    if ((p = glcfg_get_param_value(glcfg, module, "phishing_prefix", NULL)) == NULL)
    {
        LOGERROR("Failed to glcfg_get_param_value");
        return -1;
    }
    snprintf(spam_setting->phishing_prefix, MU_MAX_PREFIX_SIZE, "%s", p);
    LOGDEBUG("        spam_setting->phishing_prefix = %s", spam_setting->phishing_prefix);
    
    /*phishing action*/
    if((p = glcfg_get_param_value(glcfg,module,"phishing_action",NULL)) == NULL)
    {
        LOGERROR("Failed to glcfg_get_param_value");
        return -1;
    }
    spam_setting->phishing_action = action_to_int(p);
    LOGDEBUG("        spam_setting->phishing_action = %d", spam_setting->phishing_action);
    
    LOGINFO("-----mu_read_spam_setting-----");
    
    return 0;
}

int mu_read_emgr_setting(glcfg_t glcfg, char *module, emgr_setting_t *emgr_setting)
{
    const char *p = NULL;
    unsigned int val = 0;
    
    LOGINFO("+++++mu_read_emgr_setting+++++");
    
    if ((p = get_param_number(module, "content_filtering_enable", &val,glcfg)) == NULL)
    {
        LOGERROR("Failed to get_param_number");
        return -1;
    }
    emgr_setting->emgr_enable = val;
    LOGDEBUG("        %s:emgr->emgr_enable=%d", module, emgr_setting->emgr_enable);
    
    if ((p = get_param_number(module, "OPP_enable", &val,glcfg)) == NULL)
    {
        LOGERROR("Failed to get_param_number");
        return -1;
    }
    emgr_setting->OPP_enable = val;
    LOGDEBUG("        %s:emgr->OPP_enable=%d", module, emgr_setting->OPP_enable);
    
    if (read_emgr_filter_setting(glcfg, module, &emgr_setting->emgr_filter) != 0)
    {
        LOGERROR("Failed to mu_read_emgr_filter_setting");
        return -1;
    }

    if (read_OPP_filter_setting(glcfg, module, &emgr_setting->OPP_filter) != 0)
    {
        LOGERROR("Failed to mu_read_OPP_filter_setting");
        return -1;
    }

    if ((p = glcfg_get_param_value(glcfg, module, "emgr_action", NULL)) == NULL)
    {
        LOGERROR("Failed to glcfg_get_param_value");
        return -1;
    }
    emgr_setting->emgr_action = action_to_int(p);
    LOGDEBUG("        %s:emgr->emgr_action=%d", module, emgr_setting->emgr_action);
    
    if ((p = glcfg_get_param_value(glcfg, module, "OPP_action", NULL)) == NULL)
    {
        LOGERROR("Failed to glcfg_get_param_value");
        return -1;
    }
    emgr_setting->OPP_action = action_to_int(p);
    LOGDEBUG("        %s:emgr->OPP_action=%d", module, emgr_setting->OPP_action);
    
    if ((p = get_param_number(module, "delete_triggered_attachment", &val,glcfg)) == NULL)
    {
        LOGERROR("Failed to get_param_number");
        return -1;
    }
    emgr_setting->delete_triggered_attachment = val;
    LOGDEBUG("        %s:emgr->delete_triggered_attachment=%d", module, emgr_setting->delete_triggered_attachment);
    
    if ((p = get_param_number(module, "enable_size_filter", &val,glcfg)) == NULL)
    {
        LOGERROR("Failed to get_param_number");
        return -1;
    }
    emgr_setting->enable_size_filter = val;
    LOGDEBUG("        %s:emgr->enable_size_filter=%d", module, emgr_setting->enable_size_filter);
    
    LOGINFO("-----mu_read_emgr_setting-----");
    
    return 0;
}

int
mu_read_emgr_common_setting(
    glcfg_t glcfg,
    struct em_filter_config *config)
{
    int ret = -1;
    const char *module = "emgr";
    const char *param = NULL;
    const char *value = NULL;
    
    LOGDEBUG("Enter %s(): glcfg=%p, config=%p",
             __FUNCTION__, glcfg, config);

    if (glcfg == NULL || config == NULL)
    {
        LOGERROR("Invalid argument");
        goto leave;
    }

    assert(sizeof(*config) == sizeof(struct em_filter_config));
    memset(config, 0, sizeof(struct em_filter_config));

    { /* debug_log_enable */
        param = "debug_log_enable";
        if ((value = get_param_number(module, param, &config->debug_log_enable, glcfg)) == NULL)
        {
            LOGERROR("glcfg_get_param_value(): module=\"%s\", param=\"%s\"",
                     module, param);
            goto leave;
        }
        LOGDEBUG("config->debug_log_enable=%u", config->debug_log_enable);
    }

    { /* debug_log_level */
        param = "debug_log_level";
        if ((value = get_param_number(module, param, &config->debug_log_level, glcfg)) == NULL)
        {
            LOGERROR("glcfg_get_param_value(): module=\"%s\", param=\"%s\"",
                     module, param);
            goto leave;
        }
        LOGDEBUG("config->debug_log_level=%u", config->debug_log_level);
    }

    { /* debug_log_path */
        param = "debug_log_path";
        if ((value = glcfg_get_param_value(glcfg, module, param, NULL)) == NULL)
        {
            LOGERROR("glcfg_get_param_value(): module=\"%s\", param=\"%s\"",
                     module, param);
            goto leave;
        }
        snprintf(config->debug_log_path, sizeof(config->debug_log_path), "%s", value);
        LOGDEBUG("config->debug_log_path=\"%s\"", config->debug_log_path);
    }

    { /* default_charset */
        param = "default_charset";
        if ((value = glcfg_get_param_value(glcfg, module, param, NULL)) == NULL)
        {
            LOGERROR("glcfg_get_param_value(): module=\"%s\", param=\"%s\"",
                     module, param);
            goto leave;
        }
        snprintf(config->default_charset, sizeof(config->default_charset), "%s", value);
        LOGDEBUG("config->default_charset=\"%s\"", config->default_charset);
    }

    { /* max_decompose_depth */
        param = "max_decompose_depth";
        if ((value = get_param_number(module, param, &config->max_decompose_depth, glcfg)) == NULL)
        {
            LOGERROR("glcfg_get_param_value(): module=\"%s\", param=\"%s\"",
                     module, param);
            goto leave;
        }
        LOGDEBUG("config->max_decompose_depth=%u", config->max_decompose_depth);
    }

    { /* max_front_scansize*/
        param = "max_front_scan_size";
        if ((value = get_param_number(module, param, &config->max_front_scan_size, glcfg)) == NULL)
        {
            LOGERROR("glcfg_get_param_value(): module=\"%s\", param=\"%s\"",
                     module, param);
            goto leave;
        }
        LOGDEBUG("config->max_front_scan_size=%u", config->max_front_scan_size);
    }

    { /* max_back_scan_size */
        param = "max_back_scan_size";
        if ((value = get_param_number(module, param, &config->max_back_scan_size, glcfg)) == NULL)
        {
            LOGERROR("glcfg_get_param_value(): module=\"%s\", param=\"%s\"",
                     module, param);
            goto leave;
        }
        LOGDEBUG("config->max_back_scan_size=%u", config->max_back_scan_size);
    }

    { /* extract_file_size_limit*/
        param = "extract_file_size_limit";
        if ((value = get_param_number(module, param, &config->extract_file_size_limit, glcfg)) == NULL)
        {
            LOGERROR("glcfg_get_param_value(): module=\"%s\", param=\"%s\"",
                     module, param);
            goto leave;
        }
        LOGDEBUG("config->extract_file_size_limit=%u", config->extract_file_size_limit);
    }

    { /* timeout */
        param = "timeout";
        if ((value = get_param_number(module, param, &config->timeout, glcfg)) == NULL)
        {
            LOGERROR("glcfg_get_param_value(): module=\"%s\", param=\"%s\"",
                     module, param);
            goto leave;
        }
        LOGDEBUG("config->timeout=%u", config->timeout);
    }

    { /* home */
        param = "home";
        if ((value = glcfg_get_param_value(glcfg, module, param, NULL)) == NULL)
        {
            LOGERROR("glcfg_get_param_value(): module=\"%s\", param=\"%s\"",
                     module, param);
            goto leave;
        }
        snprintf(config->home, sizeof(config->home), "%s", value);
        LOGDEBUG("config->home=\"%s\"", config->home);
    }

    { /* serial_num */
        param = "serial_num";
        if ((value = glcfg_get_param_value(glcfg, module, param, NULL)) == NULL)
        {
            LOGERROR("glcfg_get_param_value(): module=\"%s\", param=\"%s\"",
                     module, param);
            goto leave;
        }
        snprintf(config->serial_num, sizeof(config->serial_num), "%s", value);
        LOGDEBUG("config->serial_num=\"%s\"", config->serial_num);
    }

    { /* charset_of_detect */
        param = "charset_of_detect";
        if ((value = glcfg_get_param_value(glcfg, module, param, NULL)) == NULL)
        {
            LOGERROR("glcfg_get_param_value(): module=\"%s\", param=\"%s\"",
                     module, param);
            goto leave;
        }
        snprintf(config->charset_of_detect, sizeof(config->charset_of_detect), "%s", value);
        LOGDEBUG("config->charset_of_detect=\"%s\"", config->charset_of_detect);
    }

    { /* content_filter_detect */
        param = "content_filter_detect";
        if ((value = glcfg_get_param_value(glcfg, module, param, NULL)) == NULL)
        {
            LOGERROR("glcfg_get_param_value(): module=\"%s\", param=\"%s\"",
                     module, param);
            goto leave;
        }
        snprintf(config->content_filter_detect, sizeof(config->content_filter_detect), "%s", value);
        LOGDEBUG("config->content_filter_detect=\"%s\"", config->content_filter_detect);
    }

    { /* attachment_filter_detect */
        param = "attachment_filter_detect";
        if ((value = glcfg_get_param_value(glcfg, module, param, NULL)) == NULL)
        {
            LOGERROR("glcfg_get_param_value(): module=\"%s\", param=\"%s\"",
                     module, param);
            goto leave;
        }
        snprintf(config->attachment_filter_detect, sizeof(config->attachment_filter_detect), "%s", value);
        LOGDEBUG("config->attachment_filter_detect=\"%s\"", config->attachment_filter_detect);
    }

    { /* standard_filter_detect */
        param = "standard_filter_detect";
        if ((value = glcfg_get_param_value(glcfg, module, param, NULL)) == NULL)
        {
            LOGERROR("glcfg_get_param_value(): module=\"%s\", param=\"%s\"",
                     module, param);
            goto leave;
        }
        snprintf(config->standard_filter_detect, sizeof(config->standard_filter_detect), "%s", value);
        LOGDEBUG("config->standard_filter_detect=\"%s\"", config->standard_filter_detect);
    }

    { /* size_filter_detect */
        param = "size_filter_detect";
        if ((value = glcfg_get_param_value(glcfg, module, param, NULL)) == NULL)
        {
            LOGERROR("glcfg_get_param_value(): module=\"%s\", param=\"%s\"",
                     module, param);
            goto leave;
        }
        snprintf(config->size_filter_detect, sizeof(config->size_filter_detect), "%s", value);
        LOGDEBUG("config->size_filter_detect=\"%s\"", config->size_filter_detect);
    }

    { /* msg_size_detect */
        param = "msg_size_detect";
        if ((value = glcfg_get_param_value(glcfg, module, param, NULL)) == NULL)
        {
            LOGERROR("glcfg_get_param_value(): module=\"%s\", param=\"%s\"",
                     module, param);
            goto leave;
        }
        snprintf(config->msg_size_detect, sizeof(config->msg_size_detect), "%s", value);
        LOGDEBUG("config->msg_size_detect=\"%s\"", config->msg_size_detect);
    }

    { /* attach_size_detect */
        param = "attach_size_detect";
        if ((value = glcfg_get_param_value(glcfg, module, param, NULL)) == NULL)
        {
            LOGERROR("glcfg_get_param_value(): module=\"%s\", param=\"%s\"",
                     module, param);
            goto leave;
        }
        snprintf(config->attach_size_detect, sizeof(config->attach_size_detect), "%s", value);
        LOGDEBUG("config->attach_size_detect=\"%s\"", config->attach_size_detect);
    }

    { /* attach_num_detect */
        param = "attach_num_detect";
        if ((value = glcfg_get_param_value(glcfg, module, param, NULL)) == NULL)
        {
            LOGERROR("glcfg_get_param_value(): module=\"%s\", param=\"%s\"",
                     module, param);
            goto leave;
        }
        snprintf(config->attach_num_detect, sizeof(config->attach_num_detect), "%s", value);
        LOGDEBUG("config->attach_num_detect=\"%s\"", config->attach_num_detect);
    }

    { /* exp_detect */
        param = "exp_detect";
        if ((value = glcfg_get_param_value(glcfg, module, param, NULL)) == NULL)
        {
            LOGERROR("glcfg_get_param_value(): module=\"%s\", param=\"%s\"",
                     module, param);
            goto leave;
        }
        snprintf(config->exp_detect, sizeof(config->exp_detect), "%s", value);
        LOGDEBUG("config->exp_detect=\"%s\"", config->exp_detect);
    }

    { /* real_file_type_detect */
        param = "real_file_type_detect";
        if ((value = glcfg_get_param_value(glcfg, module, param, NULL)) == NULL)
        {
            LOGERROR("glcfg_get_param_value(): module=\"%s\", param=\"%s\"",
                     module, param);
            goto leave;
        }
        snprintf(config->real_file_type_detect, sizeof(config->real_file_type_detect), "%s", value);
        LOGDEBUG("config->real_file_type_detect=\"%s\"", config->real_file_type_detect);
    }

    { /* product_code */
        param = "product_code";
        if ((value = glcfg_get_param_value(glcfg, module, param, NULL)) == NULL)
        {
            LOGERROR("glcfg_get_param_value(): module=\"%s\", param=\"%s\"",
                     module, param);
            goto leave;
        }
        /* 2 byte product code; no NULL terminated character included */
        strncpy(config->product_code, value, sizeof(config->product_code));
    }
    
    ret = 0;

leave:
    LOGDEBUG("Leave %s(): ret=%d", __FUNCTION__, ret);
    return ret;
}


int mu_read_kk_setting(glcfg_t glcfg, char *module, kelkea_setting_t *kk_setting)
{
    const char *p = NULL;
    unsigned int val = 0;
    
    LOGINFO("+++++mu_read_kk_setting+++++");
    
    if ((p = get_param_number(module, "enable_kk", &val,glcfg)) == NULL)
    {
        LOGERROR("Failed to get_param_number");
        return -1;
    }
    kk_setting->enable_kk = val;
    LOGDEBUG("        kk_setting->enable_kk=%d",val);
    
    if ((p = get_param_number(module, "RBL_only", &val,glcfg)) == NULL)
    {
        LOGERROR("Failed to get_param_number");
        return -1;
    }
    kk_setting->RBL_only = val;
    LOGDEBUG("        kk_setting->RBL_only=%d", val);
    
    if((p = glcfg_get_param_value(glcfg,module,"kk_exception_list",NULL)) == NULL)
    {
        LOGERROR("Failed to glcfg_get_param_value");
        return -1;
    }
    snprintf(kk_setting->kk_exception_list, sizeof(kk_setting->kk_exception_list), "%s", p);
    LOGDEBUG("        kk_setting->kk_exception_list=\"%s\"", kk_setting->kk_exception_list);
    
    if ((p = glcfg_get_param_value(glcfg,module,"RBL_action",NULL)) == NULL)
    {
        LOGERROR("Failed to glcfg_get_param_value");
        return -1;
    }
    snprintf(kk_setting->RBL_action, sizeof(kk_setting->RBL_action), "%s", p);
    LOGDEBUG("        kk_setting->RBL_action=\"%s\"", kk_setting->RBL_action);
    
    if ((p = get_param_number(module, "RBL_error_code", &val, glcfg)) == NULL)
    {
        LOGERROR("Failed to get_param_number");
        return -1;
    }
    kk_setting->RBL_error_code = val;
    LOGDEBUG("        kk_setting->RBL_error_code=%d", val);
    
    if((p = glcfg_get_param_value(glcfg,module, "QIL_action",NULL)) == NULL)
    {
        LOGERROR("Failed to glcfg_get_param_value");
        return -1;
    }
    snprintf(kk_setting->QIL_action, sizeof(kk_setting->QIL_action), "%s", p);
    LOGDEBUG("        k_setting->QIL_action=\"%s\"", kk_setting->QIL_action);
    
    if ((p = get_param_number(module, "QIL_error_code", &val,glcfg)) == NULL)
    {
        LOGERROR("Failed to get_param_number");
        return -1;
    }
    kk_setting->QIL_error_code = val;
    LOGDEBUG("        kk_setting->QIL_error_code=%d", val);
    
    if (read_kk_activation_code(kk_setting) != 0)
    {
        LOGERROR("Failed to read_kk_activation_code");
        return -1;
    }
    
    LOGINFO("-----mu_read_kk_setting-----");
    
    return 0;

}

int mu_read_license_setting(license_setting_t *license_setting)
{
    glcfg_t glcfg = NULL;
    int ret = 0;
    const char *p = NULL;
    unsigned int val;
    
    LOGINFO("+++++mu_read_license_setting+++++");

    if ((glcfg = glcfg_open(SYSTEM_CONFIG_FILE, GLCFG_MODE_READ)) == NULL)
    {
        ret = -1;
        LOGERROR("glcfg_open(): file=%s", SYSTEM_CONFIG_FILE);
        goto leave;
    }

    if((p = get_param_number("license", "std_valid", &val,glcfg)) == NULL)
    {
        ret = -1;
        LOGERROR("get_param_number(): module=license, param=std_valid");
        goto leave;
    }
    license_setting->std_valid = val;
    LOGDEBUG("        license->std_valid=%d", license_setting->std_valid);

/*    if((p = get_param_number("license", "eps_valid",&val,glcfg)) == NULL)
    {
        ret = -1;
        LOGERROR("get_param_number(): module=license, param=eps_valid");
        goto leave;
    }
    license_setting->eps_valid = val;
    LOGDEBUG("        license->eps_valid=%d", license_setting->eps_valid);*/

    ret = 0;

leave:
    if (glcfg != NULL)
    {
        (void)glcfg_close(glcfg);
        glcfg = NULL;
    }
    
    LOGINFO("-----mu_read_license_setting-----");

    return ret;
}
#endif
