/**
 * Copyright (C) 2005, Trend Micro Incorporated. All Rights Reserved. This
 * program is an unpublished copyrighted work which is proprietary to Trend
 * Micro Incorporated and contains confidential information that is not to be
 * reproduced or disclosed to any other person or entity without prior written
 * consent from Trend Micro, Inc. in each and every instance.
 *
 * WARNING: Unauthorized reproduction of this program as well as unauthorized
 * preparation of derivative works based upon the program or distribution of
 * copies by sale, rental, lease or lending are violations of federal copyright
 * laws and state trade secret laws, punishable by civil and criminal
 * penalties.
 */

#ifndef __FS_CACHE_H__
#define __FS_CACHE_H__

#include <openssl/sha.h>
#include "list.h"
#include "fs.h"
#include "fsctl_common.h"

//#define FS_CACHE_HASH_SIZE (4*1024)

/****************************************************************************/
/* STRUCTURE DECLARATIONS                                                   */
/****************************************************************************/
typedef struct FileScanResult_st {
	list_head lru_list, hash_list;
	unsigned int ref_count;
	unsigned char sha1[SHA_DIGEST_LENGTH];
	vscan_result_t scan_result;
	VirusResult *virus_result;
#ifdef USE_ATSE
    scan_evae_result_t *evae_result;
#endif
} FileScanResult;

typedef struct FileScanResultCache_st {
	pthread_mutex_t mutex;
	list_head lru_head;
	list_head *hash_heads;
	unsigned int count;
	unsigned int size;
	struct {
		unsigned long long miss, hit, add, dup;
	} stats;
} FileScanResultCache;


int fs_cache_dump(char *str, size_t count);
int fs_cache_purge(int32_t val);
int fs_cache_size_write(uint32_t new_size);


int FileScanResultCache_init(unsigned int hash_size, unsigned int cache_size);
void FileScanResultCache_fini();

FileScanResult *FileScanResultCache_get(unsigned char *sha1);
FileScanResult *FileScanResultCache_get_simulated(unsigned char *sha1, double hit_rate_limit);
void FileScanResultCache_add(FileScanResult *fr, unsigned char *sha1);
void FileScanResultCache_del(unsigned char *sha1);
FileScanResult *FileScanResult_new();
void FileScanResult_del(FileScanResult *fr);
void FileScanResult_put(FileScanResult *fr);
void FileScanResult_get(FileScanResult *fr);


#endif /* __FS_CACHE_H__ */
