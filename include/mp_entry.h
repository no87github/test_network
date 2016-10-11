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

#ifndef MP_ENTRY_H
#define MP_ENTRY_H

#include <stdint.h>
#include <sys/types.h>

__BEGIN_DECLS

enum {
    /* BEGIN */
    MP_ENTRY_TYPE_NONE = 0,
    MP_ENTRY_TYPE_RAW,
    MP_ENTRY_TYPE_STRING,
    MP_ENTRY_TYPE_INT8,
    MP_ENTRY_TYPE_UINT8,
    MP_ENTRY_TYPE_INT16,
    MP_ENTRY_TYPE_UINT16,
    MP_ENTRY_TYPE_INT32,
    MP_ENTRY_TYPE_UINT32,
    MP_ENTRY_TYPE_INT64,
    MP_ENTRY_TYPE_UINT64,
    /* END */
    MP_ENTRY_TYPE_MAX,
};

/**
 * On success, mp_entry_read_raw()/mp_entry_read_string() return the number of
 * bytes read (zero indicates nothing was read), and others return 0.
 * On error, -1 is returned.
 */
typedef ssize_t (*mp_entry_read_raw_t)(void *buf, size_t count);
typedef ssize_t (*mp_entry_read_string_t)(char *str, size_t count);
typedef int (*mp_entry_read_int8_t)(int8_t *val);
typedef int (*mp_entry_read_uint8_t)(uint8_t *val);
typedef int (*mp_entry_read_int16_t)(int16_t *val);
typedef int (*mp_entry_read_uint16_t)(uint16_t *val);
typedef int (*mp_entry_read_int32_t)(int32_t *val);
typedef int (*mp_entry_read_uint32_t)(uint32_t *val);
typedef int (*mp_entry_read_int64_t)(int64_t *val);
typedef int (*mp_entry_read_uint64_t)(uint64_t *val);

/**
 * On success, mp_entry_write_raw()/mp_entry_write_string() return the number of
 * bytes written (zero indicates nothing was written), and others return 0.
 * On error, -1 is returned.
 */
typedef ssize_t (*mp_entry_write_raw_t)(const void *buf, size_t count);
typedef ssize_t (*mp_entry_write_string_t)(const char *str, size_t count);
typedef int (*mp_entry_write_int8_t)(int8_t val);
typedef int (*mp_entry_write_uint8_t)(uint8_t val);
typedef int (*mp_entry_write_int16_t)(int16_t val);
typedef int (*mp_entry_write_uint16_t)(uint16_t val);
typedef int (*mp_entry_write_int32_t)(int32_t val);
typedef int (*mp_entry_write_uint32_t)(uint32_t val);
typedef int (*mp_entry_write_int64_t)(int64_t val);
typedef int (*mp_entry_write_uint64_t)(uint64_t val);

/**
 * All functions return 0 on success and -1 on error.
 */
typedef int (*mp_entry_exec_raw_t)(const void *buf, size_t count);
typedef int (*mp_entry_exec_string_t)(const char *str, size_t count);
typedef int (*mp_entry_exec_int8_t)(int8_t val);
typedef int (*mp_entry_exec_uint8_t)(uint8_t val);
typedef int (*mp_entry_exec_int16_t)(int16_t val);
typedef int (*mp_entry_exec_uint16_t)(uint16_t val);
typedef int (*mp_entry_exec_int32_t)(int32_t val);
typedef int (*mp_entry_exec_uint32_t)(uint32_t val);
typedef int (*mp_entry_exec_int64_t)(int64_t val);
typedef int (*mp_entry_exec_uint64_t)(uint64_t val);

struct mp_entry_ops {
    /* User fills in from here down. */
    const char *name;
    /* read */
    int read_type;
    void *read_func;
    /* write */
    int write_type;
    void *write_func;
    /* exec */
    int exec_type;
    void *exec_func;
};

struct mp_entry_ops *mp_find_entry(struct mp_entry_ops entry_list[], const char *name);

__END_DECLS

#endif /* MP_ENTRY_H */
