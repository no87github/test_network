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
* vscan_def.h
*
* Description: header file for common struct definition, constant, enumeration for virus scan module .
* Author: HY Cheng
*
* #001 Aug 11, 2005 HY Cheng Initial implementation.
*/

#ifndef VSCAN_DEF_H
#define VSCAN_DEF_H

#define VSCTYPE_INVALID (0)
#define VSCAN_MAX_PATH_SIZE (256)
#define VSCAN_MAX_NAME_LIST_SIZE (1024)
#define VSCAN_MAX_ENGINE_VERSION_SIZE (256)
#define VSCAN_MAX_PATTERN_VERSION_SIZE (13)

enum { 
	VSCAN_FALSE =0,
	VSCAN_TRUE = 1	
};

enum {
	VSCAN_SUCCESS = 0,
    /* virus scan return value (error condition)*/
	VSCAN_ERROR_INTERNAL = -100
};

typedef struct common_config_st
{
    char tmppath[VSCAN_MAX_PATH_SIZE]; /* path for temporary files that VSAPI use */
    char engpath[VSCAN_MAX_PATH_SIZE]; /* path for vsapi engine */
    char ptnpath[VSCAN_MAX_PATH_SIZE]; /* virus/spyware pattern file path */ 
    char ptnfile[VSCAN_MAX_PATH_SIZE]; /* virus pattern filename */
    char spyptnfile[VSCAN_MAX_PATH_SIZE]; /* spyware pattern filename */
    char tmblack[VSCAN_MAX_PATH_SIZE]; /* tmblack */
    char tmwhite[VSCAN_MAX_PATH_SIZE]; /* tmwhite */
    int  max_scan_num;                             /*max scan num*/
    char vsapi_def_file_ext[VSCAN_MAX_PATH_SIZE];  /*default vsapi file extension list*/
}common_config_t;

typedef struct protocol_config_st
{
    /* enable falg*/
    int virus_enable;               /*enable virus scanning*/
    int compress_enable;            /*enable archive file scanning*/
    int spyware_enable;             /*enable spyware scanning*/
    int bot_enable;                 /*enable bot scanning*/
     
	/* limit */
	size_t decompress_layer;        /*limit to the layer of compression*/				      
	size_t extract_file_size_limit; /*limit to the extracted file size*/
	size_t extract_file_count_limit;/*sets the maximum amount of files to be decompressed*/
	size_t extract_file_ratio_limit;/*sets the decompress ratio limit of the file*/
	
	/* scan flag */
	int intelli_scan;               /*flag to IntelliScan, 0 to disable, 1 to enable*/
	int process_all_file;           /*flag to process all files, 0 to disable, 1 to enable*/
	int process_all_file_in_arc;    /*flag to process all files in archive file, 0 to disable,1 to enable*/
    
    /*include extension name list*/
	char ext_include[VSCAN_MAX_NAME_LIST_SIZE];
	
	/*grey area*/
	int  scan_spyware;
	int  scan_adware;
	int  scan_dialer;
	int  scan_hacktool;
	int  scan_joke;
	int  scan_remoteaccess;
	int  scan_passwdcrack;
	int  scan_others;
     
    /*spyware exclude list*/
    char spyware_exclude[VSCAN_MAX_NAME_LIST_SIZE];
    
    /* ATSE detection level */
        int detection_level;

}protocol_config_t;

typedef struct vscan_config_st
{
	common_config_t common;       /*common setting of vscan module*/
	protocol_config_t protocol;   /*specific setting for each protocol*/
}vscan_config_t;

typedef int VscanHandle;

typedef struct pattern_list_st
{
	char ptnpath[VSCAN_MAX_PATH_SIZE];       /*path of virus pattern*/
	char ptnfile_base[VSCAN_MAX_PATH_SIZE];  /*basename of virus pattern*/
	struct pattern_list_st *next;
}pattern_list;

typedef struct vscan_version_st
{
    char vsapi_engine[VSCAN_MAX_ENGINE_VERSION_SIZE]; /* vsapi engine version */
    char vsapi_engine_for_au[VSCAN_MAX_ENGINE_VERSION_SIZE]; /* vsapi engine version */
    unsigned int vsapi_engine_major;
    unsigned int vsapi_engine_minor;
    unsigned int vsapi_engine_revision;
    unsigned int vsapi_engine_build;

    char virus_pattern[VSCAN_MAX_PATTERN_VERSION_SIZE]; /*virus pattern version*/
    char spyware_pattern[VSCAN_MAX_PATTERN_VERSION_SIZE]; /*spyware pattern version*/
    char tmwhite_pattern[VSCAN_MAX_PATTERN_VERSION_SIZE]; /*tmwhite pattern version*/
    char tmblack_pattern[VSCAN_MAX_PATTERN_VERSION_SIZE]; /*tmblack pattern version*/
} vscan_version_t;

#endif
