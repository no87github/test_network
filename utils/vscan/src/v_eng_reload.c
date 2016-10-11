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
 * v_eng_reload.c
 *
 * Description: source file for vsapi engine reload
 * Author: HY Cheng
 *
 * #001 Aug 11, 2005 HY Cheng Initial implementation.
 */
 
#include <dlfcn.h>
#include <string.h>
#include <msg_utils.h>
#include "v_common.h"
#include "v_eng_reload.h"

/*****************************************************/
/*                  EXPORT FNUCTION                  */
/*****************************************************/

int vsapi_compose_func_table(void *vsapi_handle, vscan_func_table_t *func_table)
{
    memset(func_table, 0 , sizeof(vscan_func_table_t));
    
    /*resolve all symbols of vsapi engine*/
    
    if(mu_library_loader_resolve(vsapi_handle,"VSInit",(void *)&func_table->VSInit) != 0)
    {
        LOGERROR("Failed to mu_library_loader_resolve(%s)","VSInit");
        return -1;
    }
    if(mu_library_loader_resolve(vsapi_handle,"VSQuit",(void *)&func_table->VSQuit) != 0)
    {
        LOGERROR("Failed to mu_library_loader_resolve(%s)","VSQuit");
        return -1;
    }
    if(mu_library_loader_resolve(vsapi_handle,"VSReadVirusPattern",(void *)&func_table->VSReadVirusPattern) != 0)
    {
        LOGERROR("Failed to mu_library_loader_resolve(%s)","VSReadVirusPattern");
        return -1;
    }
    if(mu_library_loader_resolve(vsapi_handle,"VSSetTempPath",(void *)&func_table->VSSetTempPath) != 0)
    {
        LOGERROR("Failed to mu_library_loader_resolve(%s)","VSSetTempPath");
        return -1;
    }
    if(mu_library_loader_resolve(vsapi_handle,"VSGetTempPath",(void *)&func_table->VSGetTempPath) != 0)
    {
        LOGERROR("Failed to mu_library_loader_resolve(%s)","VSGetTempPath");
        return -1;
    }
    if(mu_library_loader_resolve(vsapi_handle,"VSSetPatternPath",(void *)&func_table->VSSetPatternPath) != 0)
    {
        LOGERROR("Failed to mu_library_loader_resolve(%s)","VSSetPatternPath");
        return -1;
    }
    if(mu_library_loader_resolve(vsapi_handle,"VSGetPatternPath",(void *)&func_table->VSGetPatternPath) != 0)
    {
        LOGERROR("Failed to mu_library_loader_resolve(%s)","VSGetPatternPath");
        return -1;
    }
    if(mu_library_loader_resolve(vsapi_handle,"VSSetCleanZipFlag",(void *)&func_table->VSSetCleanZipFlag) != 0)
    {
        LOGERROR("Failed to mu_library_loader_resolve(%s)","VSSetCleanZipFlag");
        return -1;
    }
    if(mu_library_loader_resolve(vsapi_handle,"VSSetSmartDecompressFlag",(void *)&func_table->VSSetSmartDecompressFlag) != 0)
    {
        LOGERROR("Failed to mu_library_loader_resolve(%s)","VSSetSmartDecompressFlag");
        return -1;
    }
    if(mu_library_loader_resolve(vsapi_handle,"VSSetProcessFileCallBackFunc",(void *)&func_table->VSSetProcessFileCallBackFunc) != 0)
    {
        LOGERROR("Failed to mu_library_loader_resolve(%s)","VSSetProcessFileCallBackFunc");
        return -1;
    }
    if(mu_library_loader_resolve(vsapi_handle,"VSSetConfig",(void *)&func_table->VSSetConfig) != 0)
    {
        LOGERROR("Failed to mu_library_loader_resolve(%s)","VSSetConfig");
        return -1;
    }
    if(mu_library_loader_resolve(vsapi_handle,"VSGetConfig",(void *)&func_table->VSGetConfig) != 0)
    {
        LOGERROR("Failed to mu_library_loader_resolve(%s)","VSGetConfig");
        return -1;
    }
    if(mu_library_loader_resolve(vsapi_handle,"VSSetExtractFileSizeLimit",(void *)&func_table->VSSetExtractFileSizeLimit) != 0)
    {
        LOGERROR("Failed to mu_library_loader_resolve(%s)","VSSetExtractFileSizeLimit");
        return -1;
    }
    if(mu_library_loader_resolve(vsapi_handle,"VSGetExtractFileSizeLimit",(void *)&func_table->VSGetExtractFileSizeLimit) != 0)
    {
        LOGERROR("Failed to mu_library_loader_resolve(%s)","VSGetExtractFileSizeLimit");
        return -1;
    }
    if(mu_library_loader_resolve(vsapi_handle,"VSSetDecompressLayer",(void *)&func_table->VSSetDecompressLayer) != 0)
    {
        LOGERROR("Failed to mu_library_loader_resolve(%s)","VSSetDecompressLayer");
        return -1;
    }
    if(mu_library_loader_resolve(vsapi_handle,"VSGetDecompressLayer",(void *)&func_table->VSGetDecompressLayer) != 0)
    {
        LOGERROR("Failed to mu_library_loader_resolve(%s)","VSGetDecompressLayer");
        return -1;
    }
    if(mu_library_loader_resolve(vsapi_handle,"VSSetExtractFileCountLimit",(void *)&func_table->VSSetExtractFileCountLimit) != 0)
    {
        LOGERROR("Failed to mu_library_loader_resolve(%s)","VSSetExtractFileCountLimit");
        return -1;
    }
    if(mu_library_loader_resolve(vsapi_handle,"VSSetExtractFileRatioLimit",(void *)&func_table->VSSetExtractFileRatioLimit) != 0)
    {
        LOGERROR("Failed to mu_library_loader_resolve(%s)","VSSetExtractFileRatioLimit");
        return -1;
    }
    if(mu_library_loader_resolve(vsapi_handle,"VSSetActiveScanFlag",(void *)&func_table->VSSetActiveScanFlag) != 0)
    {
        LOGERROR("Failed to mu_library_loader_resolve(%s)","VSSetActiveScanFlag");
        return -1;
    }
    if(mu_library_loader_resolve(vsapi_handle,"VSGetActiveScanFlag",(void *)&func_table->VSGetActiveScanFlag) != 0)
    {
        LOGERROR("Failed to mu_library_loader_resolve(%s)","VSGetActiveScanFlag");
        return -1;
    }
    if(mu_library_loader_resolve(vsapi_handle,"VSSetProcessAllFileFlag",(void *)&func_table->VSSetProcessAllFileFlag) != 0)
    {
        LOGERROR("Failed to mu_library_loader_resolve(%s)","VSSetProcessAllFileFlag");
        return -1;
    }
    if(mu_library_loader_resolve(vsapi_handle,"VSGetProcessAllFileFlag",(void *)&func_table->VSGetProcessAllFileFlag) != 0)
    {
        LOGERROR("Failed to mu_library_loader_resolve(%s)","VSGetProcessAllFileFlag");
        return -1;
    }
    if(mu_library_loader_resolve(vsapi_handle,"VSSetProcessAllFileInArcFlag",(void *)&func_table->VSSetProcessAllFileInArcFlag) != 0)
    {
        LOGERROR("Failed to mu_library_loader_resolve(%s)","VSSetProcessAllFileInArcFlag");
        return -1;
    }
    if(mu_library_loader_resolve(vsapi_handle,"VSGetProcessAllFileInArcFlag",(void *)&func_table->VSGetProcessAllFileInArcFlag) != 0)
    {
        LOGERROR("Failed to mu_library_loader_resolve(%s)","VSGetProcessAllFileInArcFlag");
        return -1;
    }
    if(mu_library_loader_resolve(vsapi_handle,"VSGetVirusPropertyByName",(void *)&func_table->VSGetVirusPropertyByName) != 0)
    {
        LOGERROR("Failed to mu_library_loader_resolve(%s)","VSGetVirusPropertyByName");
        return -1;
    }
    if(mu_library_loader_resolve(vsapi_handle,"VSGetDefaultExtListSize",(void *)&func_table->VSGetDefaultExtListSize) != 0)
    {
        LOGERROR("Failed to mu_library_loader_resolve(%s)","VSGetDefaultExtListSize");
        return -1;
    }
    if(mu_library_loader_resolve(vsapi_handle,"VSGetDefaultExtList",(void *)&func_table->VSGetDefaultExtList) != 0)
    {
        LOGERROR("Failed to mu_library_loader_resolve(%s)","VSGetDefaultExtList");
        return -1;
    }
    if(mu_library_loader_resolve(vsapi_handle,"VSOpenResource",(void *)&func_table->VSOpenResource) != 0)
    {
        LOGERROR("Failed to mu_library_loader_resolve(%s)","VSOpenResource");
        return -1;
    }
    if(mu_library_loader_resolve(vsapi_handle,"VSScanResource",(void *)&func_table->VSScanResource) != 0)
    {
        LOGERROR("Failed to mu_library_loader_resolve(%s)","VSScanResource");
        return -1;
    }
    if(mu_library_loader_resolve(vsapi_handle,"VSCloseResource",(void *)&func_table->VSCloseResource) != 0)
    {
        LOGERROR("Failed to mu_library_loader_resolve(%s)","VSCloseResource");
        return -1;
    }
    if(mu_library_loader_resolve(vsapi_handle,"VSResourceDataType",(void *)&func_table->VSResourceDataType) != 0)
    {
        LOGERROR("Failed to mu_library_loader_resolve(%s)","VSResourceDataType");
        return -1;
    }
    if(mu_library_loader_resolve(vsapi_handle,"VSGetVSCInfo",(void *)&func_table->VSGetVSCInfo) != 0)
    {
        LOGERROR("Failed to mu_library_loader_resolve(%s)","VSGetVSCInfo");
        return -1;
    }
    if(mu_library_loader_resolve(vsapi_handle,"VSGetCurrentPatternFileInternalVersion",(void *)&func_table->VSGetCurrentPatternFileInternalVersion) != 0)
    {
        LOGERROR("Failed to mu_library_loader_resolve(%s)","VSGetCurrentPatternFileInternalVersion");
        return -1;
    }
    if(mu_library_loader_resolve(vsapi_handle,"VSCheckPatternFile",(void *)&func_table->VSCheckPatternFile) != 0)
    {
        LOGERROR("Failed to mu_library_loader_resolve(%s)","VSCheckPatternFile");
        return -1;
    }
    if(mu_library_loader_resolve(vsapi_handle,"VSGetPatternProperty",(void *)&func_table->VSGetPatternProperty) != 0)
    {
        LOGERROR("Failed to mu_library_loader_resolve(%s)","VSGetPatternProperty");
        return -1;
    }
    if(mu_library_loader_resolve(vsapi_handle,"VSClearSpywareExcludeNameTable",(void *)&func_table->VSClearSpywareExcludeNameTable) != 0)
    {
        LOGERROR("Failed to mu_library_loader_resolve(%s)","VSClearSpywareExcludeNameTable");
        return -1;
    }
    if(mu_library_loader_resolve(vsapi_handle,"VSAddSpywareExcludeName",(void *)&func_table->VSAddSpywareExcludeName) != 0)
    {
        LOGERROR("Failed to mu_library_loader_resolve(%s)","VSAddSpywareExcludeName");
        return -1;
    }
    if(mu_library_loader_resolve(vsapi_handle,"VSGetVersion",(void *)&func_table->VSGetVersion) != 0)
    {
        LOGERROR("Failed to mu_library_loader_resolve(%s)","VSGetVersion");
        return -1;
    }
    if(mu_library_loader_resolve(vsapi_handle,"VSDataTypeFD",(void *)&func_table->VSDataTypeFD) != 0)
    {
        LOGERROR("Failed to mu_library_loader_resolve(%s)","VSDataTypeFD");
        return -1;
    }
#ifdef USE_ATSE
    if(mu_library_loader_resolve(vsapi_handle,"VSSetAdvFileInfoCallBackFunc",(void *)&func_table->VSSetAdvFileInfoCallBackFunc) != 0)
    {
        LOGERROR("Failed to mu_library_loader_resolve(%s)","VSSetAdvFileInfoCallBackFunc");
        return -1;
    }
#endif
    return 0;
}

