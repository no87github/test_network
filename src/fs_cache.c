#include <openssl/sha.h>
#include <pthread.h>
#include "fs_cache.h"
#include "list.h"

pthread_mutex_t gmutex_fs_result=PTHREAD_MUTEX_INITIALIZER;

FileScanResultCache fs_cache;

int fs_cache_hash_size;

void FileScanResult_del(FileScanResult *fr) {
	if(fr==NULL) {
		return;
	}

#ifdef USE_ATSE
    if (fr->evae_result) {
		scan_evae_result_free(fr->evae_result);
		fr->evae_result = NULL;
	}
#endif

    if(fr->virus_result) {
		VirusResult_free(fr->virus_result);
		fr->virus_result = NULL;
	}

	free(fr);
}

FileScanResult *FileScanResult_new() {
	FileScanResult *fr;

	fr = malloc(sizeof(FileScanResult));
	if(fr==NULL) {
		return NULL;
	}

	memset(fr, 0, sizeof(FileScanResult));
	if(NULL == (fr->virus_result = VirusResult_new())) {
		FileScanResult_del(fr);
		return NULL;
	}

#ifdef USE_ATSE
	if(NULL == (fr->evae_result = scan_evae_result_new())) {
		FileScanResult_del(fr);
		return NULL;
	}
#endif

	fr->ref_count = 1;
	list_head_init(&fr->hash_list);
	list_head_init(&fr->lru_list);

	return fr;
}

void FileScanResult_put(FileScanResult *fr) {
	unsigned int ref_count;
#if 1
	pthread_mutex_lock(&gmutex_fs_result);
	ref_count = --fr->ref_count;
	pthread_mutex_unlock(&gmutex_fs_result);
#else
	ref_count = __sync_sub_and_fetch(&fr->ref_count, 1);
#endif
	if(ref_count==0) {
		FileScanResult_del(fr);
		return;
	}
}

void FileScanResult_get(FileScanResult *fr) {
#if 1
	pthread_mutex_lock(&gmutex_fs_result);
	fr->ref_count++;
	pthread_mutex_unlock(&gmutex_fs_result);
#else
	__sync_add_and_fetch(&fr->ref_count, 1);
#endif
}

int FileScanResultCache_init(unsigned int hash_size, unsigned int cache_size) {
	int i;

	memset(&fs_cache, 0, sizeof(fs_cache));
	pthread_mutex_init(&fs_cache.mutex, NULL);
	
	fs_cache_hash_size = hash_size * 1024;
	
	fs_cache.hash_heads = (list_head *)malloc(sizeof(list_head)*fs_cache_hash_size);
    if(fs_cache.hash_heads==NULL) {
        return -1;
    }
	memset(fs_cache.hash_heads, 0, sizeof(list_head)*fs_cache_hash_size);

	list_head_init(&fs_cache.lru_head);
	for(i=0; i<fs_cache_hash_size; i++) {
		list_head_init(&fs_cache.hash_heads[i]);
	}
	fs_cache.count = 0;
	fs_cache.size = cache_size * 1024;

    return 0;
}

static void _FileScanResultCache_drop_lru(int count) {
	int i;

	for(i=0; i<count; i++) {
		FileScanResult *old_fr;
		if(list_empty(&fs_cache.lru_head)) {
			break;
		}
		old_fr = list_entry(fs_cache.lru_head.prev, FileScanResult, lru_list);
		LOGDEBUG("#KK: fs_cache lru del, sha1=%*b", SHA_DIGEST_LENGTH, old_fr->sha1);
		list_del(&old_fr->lru_list);
		list_del(&old_fr->hash_list);
		FileScanResult_put(old_fr);
		fs_cache.count--;
	}
}

static void _FileScanResultCache_purge() {
	list_head *iter, *next;
	list_for_each_safe(iter, next, &fs_cache.lru_head) {
		FileScanResult *fr;
		fr = list_entry(iter, FileScanResult, lru_list);
		list_del(&fr->lru_list);
		list_del(&fr->hash_list);
		FileScanResult_put(fr);
		fs_cache.count--;
	}
	fs_cache.stats.miss = 0;
	fs_cache.stats.hit = 0;
	fs_cache.stats.add = 0;
	fs_cache.stats.dup = 0;
}

void FileScanResultCache_purge() {
	pthread_mutex_lock(&fs_cache.mutex);
	_FileScanResultCache_purge();
	pthread_mutex_unlock(&fs_cache.mutex);
}

void FileScanResultCache_fini() {
	_FileScanResultCache_purge();
	if (fs_cache.hash_heads != NULL)
	{
		free(fs_cache.hash_heads);
		fs_cache.hash_heads = NULL;
	}
	pthread_mutex_destroy(&fs_cache.mutex);
}

static FileScanResult *_FileScanResultCache_get(unsigned char *sha1) {
	unsigned int hash;
	list_head *iter;
	int cmp;

	hash=(1<<24)*sha1[0]+(1<<16)*sha1[1]+(1<<8)*sha1[2]+sha1[3];
	hash%=fs_cache_hash_size;
	list_for_each(iter, &fs_cache.hash_heads[hash]) {
		FileScanResult *fr;
		fr = list_entry(iter, FileScanResult, hash_list);
		cmp=memcmp(fr->sha1, sha1, sizeof(fr->sha1));
		if(cmp==0) {
			list_del(&fr->lru_list);
			list_add(&fr->lru_list, &fs_cache.lru_head);
			FileScanResult_get(fr);
			fs_cache.stats.hit++;
			return fr;
		} else if(cmp>0) {
			break;
		}
	}
	fs_cache.stats.miss++;
	return NULL;
}

FileScanResult *FileScanResultCache_get(unsigned char *sha1) {
	FileScanResult *fr;
	pthread_mutex_lock(&fs_cache.mutex);
	fr = _FileScanResultCache_get(sha1);
	pthread_mutex_unlock(&fs_cache.mutex);
	return fr;
}

static void _FileScanResultCache_add(FileScanResult *fr, unsigned char *sha1) {
	unsigned int hash;
	list_head *iter;
	int cmp;

	if(fs_cache.size==0) {
		return;
	}

	hash=(1<<24)*sha1[0]+(1<<16)*sha1[1]+(1<<8)*sha1[2]+sha1[3];
	hash%=fs_cache_hash_size;

	if(fs_cache.count==fs_cache.size) {
		_FileScanResultCache_drop_lru(1);
	}

	list_for_each(iter, &fs_cache.hash_heads[hash]) {
		FileScanResult *fr;
		fr = list_entry(iter, FileScanResult, hash_list);
		cmp=memcmp(fr->sha1, sha1, sizeof(fr->sha1));
		if(cmp==0) {
			LOGDEBUG("#KK: fs_cache dup, sha1=%*b", SHA_DIGEST_LENGTH, sha1);
			fs_cache.stats.dup++;
			return;
		} else if(cmp>0) {
			break;
		}
	}

	memcpy(fr->sha1, sha1, sizeof(fr->sha1));
	list_add(&fr->lru_list, &fs_cache.lru_head);
	list_add_tail(&fr->hash_list, iter);
	fs_cache.count++;
	fs_cache.stats.add++;
	FileScanResult_get(fr);
}

void FileScanResultCache_add(FileScanResult *fr, unsigned char *sha1) {
	pthread_mutex_lock(&fs_cache.mutex);
	_FileScanResultCache_add(fr, sha1);
	pthread_mutex_unlock(&fs_cache.mutex);
}

static void _FileScanResultCache_del(unsigned char *sha1) {
	unsigned int hash;
	list_head *iter, *next;
	int cmp;

	if(fs_cache.size==0) {
		return;
	}

	hash=(1<<24)*sha1[0]+(1<<16)*sha1[1]+(1<<8)*sha1[2]+sha1[3];
	hash%=fs_cache_hash_size;

	list_for_each_safe(iter, next, &fs_cache.hash_heads[hash]) {
		FileScanResult *fr;
		fr = list_entry(iter, FileScanResult, hash_list);
		cmp=memcmp(fr->sha1, sha1, sizeof(fr->sha1));
		if(cmp==0) {
			list_del(&fr->lru_list);
			list_del(&fr->hash_list);
			FileScanResult_put(fr);
			fs_cache.count--;
			LOGDEBUG("fs_cache del, sha1=%*b", SHA_DIGEST_LENGTH, sha1);
			return;
		} else if(cmp>0) {
			break;
		}
	}
}

void FileScanResultCache_del(unsigned char *sha1)
{
	pthread_mutex_lock(&fs_cache.mutex);
	_FileScanResultCache_del(sha1);
	pthread_mutex_unlock(&fs_cache.mutex);
}

FileScanResult *FileScanResultCache_get_simulated(unsigned char *sha1, double hit_rate_limit) {
	FileScanResult *fr = NULL;
	pthread_mutex_lock(&fs_cache.mutex);
	fr = _FileScanResultCache_get(sha1);

	if(fr) {
		if(fs_cache.stats.hit >= (unsigned long long)((fs_cache.stats.hit + fs_cache.stats.miss) * hit_rate_limit)) {
			fs_cache.stats.hit--;
			fs_cache.stats.miss++;
			_FileScanResultCache_del(sha1);
			FileScanResult_put(fr);
			fr = NULL;
			LOGDEBUG("fs_cache miss (simulated), sha1=%*b", SHA_DIGEST_LENGTH, sha1);
		}
	}
	pthread_mutex_unlock(&fs_cache.mutex);
	return fr;
}

int fs_cache_size_write(uint32_t new_size) {
	pthread_mutex_lock(&fs_cache.mutex);

	new_size *= 1024; //in kilobytes

	if(new_size<fs_cache.count) {
		_FileScanResultCache_drop_lru(fs_cache.count-new_size);
	}
	fs_cache.size=new_size;
	pthread_mutex_unlock(&fs_cache.mutex);
	return 0;
}

int fs_cache_purge(int32_t val) {
	FileScanResultCache_purge();
	return 0;
}

int fs_cache_dump(char *str, size_t count) {
    int ret = 0;
    char *p = NULL, *e = NULL;

    LOGDEBUG("Enter %s()", __FUNCTION__);
    if (str == NULL || count == 0)
    {
        ret = -1;
        LOGERROR("Internal Errors: str=NULL or count=0");
        goto leave;
    }

    p = str;
    e = str + count - 1;

    {
		unsigned long long nr_miss, nr_hit, nr_add, nr_dup;
		unsigned int nr_count, size;

		pthread_mutex_lock(&fs_cache.mutex);
		nr_miss = fs_cache.stats.miss;
		nr_hit = fs_cache.stats.hit;
		nr_add = fs_cache.stats.add;
		nr_dup = fs_cache.stats.dup;
		nr_count = fs_cache.count;
		size = fs_cache.size;
		pthread_mutex_unlock(&fs_cache.mutex);

		ret = snprintf(p, e - p, "fs_cache: miss/hit/add/dup/count/size = %llu, %llu, %llu, %llu, %u, %u", nr_miss, nr_hit, nr_add, nr_dup, nr_count, size);
        if ((ret < 0) || (ret >= (e - p))) {
            LOGDEBUG("end print table header");
            goto leave;
        }
        p += ret;
    }

    ret = (p - str);

leave:
    LOGDEBUG("Leave %s(): ret=%d str=\"%.*s\"", __FUNCTION__, ret, (int)(p - str), str);
    return ret;
}
