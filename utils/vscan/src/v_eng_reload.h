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
 * v_eng_reload.h
 *
 * Description: header file for vsapi engine reload
 * Author: HY Cheng
 *
 * #001 Aug 11, 2005 HY Cheng Initial implementation.
 */
 
#ifndef VSCAN_ENG_RELOAD_H
#define VSCAN_ENG_RELOAD_H

#include <tmvs.h>

/* function prototype declaration */
typedef int (*VSInit_fp) (long CallerID, char *LodID, VSCTYPE OldCfgSection, VSCTYPE *NewSection);
typedef int (*VSQuit_fp) (VSCTYPE vsc);
typedef int (*VSReadVirusPattern_fp) (VSCTYPE vsc,VSCTYPE OldSection,char *ptnfile, VSPTN_HANDLE *ptn_handle);
typedef int (*VSSetTempPath_fp) (VSCTYPE vsc, char *TempPath);
typedef int (*VSGetTempPath_fp) (VSCTYPE vsc, char *TempPath, int cbLength);
typedef int (*VSSetPatternPath_fp) (VSCTYPE vsc,char *patternpath);
typedef int (*VSGetPatternPath_fp) (VSCTYPE vsc, char *patternpath, int cbLength);
typedef int (*VSSetCleanZipFlag_fp) (VSCTYPE vsc, int NewSetting);
typedef int (*VSSetSmartDecompressFlag_fp) (VSCTYPE vsc, int NewSetting);
typedef int (*VSSetProcessFileCallBackFunc_fp) (VSCTYPE vsc,VS_PROCESS_FILE_CALLBACK_FUNC *Function);
typedef int (*VSSetConfig_fp) (VSCTYPE vsc, VULONG CfgID, VULONG NewValue, VULONG *OldValue);
typedef int (*VSGetConfig_fp) (VSCTYPE vsc, VULONG CfgID, VULONG *OldValue);
typedef int (*VSSetExtractFileSizeLimit_fp) (VSCTYPE vsc, VULONG  newSize);
typedef int (*VSGetExtractFileSizeLimit_fp) (VSCTYPE vsc, VULONG* SizePtr);
typedef int (*VSSetDecompressLayer_fp) (VSCTYPE vsc, int DLayer);
typedef int (*VSGetDecompressLayer_fp) (VSCTYPE vsc);
typedef int (*VSSetExtractFileCountLimit_fp) (VSCTYPE vsc, VULONG  NewCount, VULONG  *OldCount);
typedef int (*VSSetExtractFileRatioLimit_fp)(VSCTYPE vsc, VULONG  NewRatio, VULONG  *OldRatio);
typedef int (*VSSetActiveScanFlag_fp) (VSCTYPE vsc, int NewSetting);
typedef int (*VSGetActiveScanFlag_fp) (VSCTYPE vsc);
typedef int (*VSSetProcessAllFileFlag_fp) (VSCTYPE vsc, int NewSetting);
typedef int (*VSGetProcessAllFileFlag_fp) (VSCTYPE vsc);
typedef int (*VSSetProcessAllFileInArcFlag_fp) (VSCTYPE vsc, int NewSetting);
typedef int (*VSGetProcessAllFileInArcFlag_fp) (VSCTYPE vsc);
typedef int (*VSGetVirusPropertyByName_fp) (VSCTYPE vsc,char *VirusName, VULONG Command,  void* in, void* out);
typedef int (*VSGetDefaultExtListSize_fp) (VSCTYPE vsc, VULONG* SizePtr);
typedef int (*VSGetDefaultExtList_fp) (VSCTYPE vsc, char* BufPtr);
typedef int (*VSOpenResource_fp) (char *Resource, short type, short mode, long StartOffset, long AccessableSize, VSHANDLE **Handle);
typedef int (*VSScanResource_fp) (VSCTYPE  vsc, RESOURCE *res, void *para);
typedef int (*VSCloseResource_fp) (VSHANDLE *handle);
typedef int (*VSResourceDataType_fp) (VSCTYPE vsc, char *file, int ResourceType, long ResourceOffset, long ResourceSize, VSDTYPE *dt);
typedef int (*VSGetVSCInfo_fp) (VSCINFO *vscinfo);
typedef int (*VSGetCurrentPatternFileInternalVersion_fp) (VSCTYPE vsc, unsigned long *InternalVer);
typedef int (*VSCheckPatternFile_fp) (char *FileName);
typedef int (*VSGetPatternProperty_fp) (VSCTYPE vsc, VULONG Command, void* in, void* out);
typedef int (*VSClearSpywareExcludeNameTable_fp) (VSCTYPE vsc);
typedef int (*VSAddSpywareExcludeName_fp) (VSCTYPE vsc,const char *strSpyName);
typedef int (*VSGetVersion_fp) (VSVERSION *version);
typedef int (*VSDataTypeFD_fp) (VSCTYPE vsc, VSHANDLE *handle);

#ifdef USE_ATSE
typedef int (*VSSetAdvFileInfoCallBackFunc_fp)(VSCTYPE vsc, VS_ADV_FILE_INFO_CALLBACK_FUNC *func);
#endif


/* vsapi function table struct*/
typedef struct vscan_func_table_st
{
     VSInit_fp  VSInit;
     VSQuit_fp  VSQuit; 
     VSReadVirusPattern_fp VSReadVirusPattern;
     VSSetTempPath_fp VSSetTempPath;
     VSGetTempPath_fp VSGetTempPath;
     VSSetPatternPath_fp VSSetPatternPath;
     VSGetPatternPath_fp VSGetPatternPath;
     VSSetCleanZipFlag_fp VSSetCleanZipFlag;
     VSSetSmartDecompressFlag_fp VSSetSmartDecompressFlag;
     VSSetProcessFileCallBackFunc_fp VSSetProcessFileCallBackFunc;
     VSSetConfig_fp VSSetConfig;
     VSGetConfig_fp VSGetConfig;
     VSSetExtractFileSizeLimit_fp VSSetExtractFileSizeLimit;
     VSGetExtractFileSizeLimit_fp VSGetExtractFileSizeLimit;
     VSSetDecompressLayer_fp VSSetDecompressLayer;
     VSGetDecompressLayer_fp VSGetDecompressLayer;
     VSSetExtractFileCountLimit_fp VSSetExtractFileCountLimit;
     VSSetExtractFileRatioLimit_fp VSSetExtractFileRatioLimit;
     VSSetActiveScanFlag_fp VSSetActiveScanFlag;
     VSGetActiveScanFlag_fp VSGetActiveScanFlag;
     VSSetProcessAllFileFlag_fp VSSetProcessAllFileFlag;
     VSGetProcessAllFileFlag_fp VSGetProcessAllFileFlag;
     VSSetProcessAllFileInArcFlag_fp VSSetProcessAllFileInArcFlag;
     VSGetProcessAllFileInArcFlag_fp VSGetProcessAllFileInArcFlag;
     VSGetVirusPropertyByName_fp VSGetVirusPropertyByName;
     VSGetDefaultExtListSize_fp VSGetDefaultExtListSize;
     VSGetDefaultExtList_fp VSGetDefaultExtList;
     VSOpenResource_fp VSOpenResource;
     VSScanResource_fp VSScanResource;
     VSCloseResource_fp VSCloseResource;
     VSResourceDataType_fp VSResourceDataType;
     VSGetVSCInfo_fp VSGetVSCInfo;
     VSGetCurrentPatternFileInternalVersion_fp VSGetCurrentPatternFileInternalVersion;
     VSCheckPatternFile_fp  VSCheckPatternFile;
     VSGetPatternProperty_fp VSGetPatternProperty;
     VSClearSpywareExcludeNameTable_fp VSClearSpywareExcludeNameTable;
     VSAddSpywareExcludeName_fp VSAddSpywareExcludeName;
     VSGetVersion_fp VSGetVersion;
     VSDataTypeFD_fp VSDataTypeFD;
#ifdef USE_ATSE
    VSSetAdvFileInfoCallBackFunc_fp VSSetAdvFileInfoCallBackFunc;
#endif
}vscan_func_table_t;

#ifdef __cplusplus
extern "C" {
#endif

int vsapi_compose_func_table(void *vsapi_handle, vscan_func_table_t *func_table);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
