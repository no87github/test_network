/*
 * sk_common.h
 */

#ifndef SK_COMMON_H
#define SK_COMMON_H

#include <assert.h> /* assert() */
#include <stddef.h> /* offsetof() */
#include <stdint.h> /* uint16_t */

#include <tmdebug.h> /* TmDebug_t */

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

/*
 * This macro expands to the number of elements of an array. For example, SK_NUMOF(an_array) expands
 * to 6, where an_array is defined as:
 *     int an_array[6];
 */
#define SK_NUMOF(array__) (sizeof(array__) / sizeof((array__)[0]))


#define SK_LOG_FATAL(format__, args__...)\
    tmDebugWrite(g_sk_dblog_, TMDEBUG_LEVEL_FATAL, format__, ##args__)
#define SK_LOG_ERROR(format__, args__...)\
    tmDebugWrite(g_sk_dblog_, TMDEBUG_LEVEL_ERROR, format__, ##args__)
#define SK_LOG_WARN(format__, args__...)\
    tmDebugWrite(g_sk_dblog_, TMDEBUG_LEVEL_WARN, format__, ##args__)
#define SK_LOG_INFO(format__, args__...)\
    tmDebugWrite(g_sk_dblog_, TMDEBUG_LEVEL_INFO, format__, ##args__)
#define SK_LOG_DEBUG(format__, args__...)\
    tmDebugWrite(g_sk_dblog_, TMDEBUG_LEVEL_DEBUG, format__, ##args__)

extern TmDebug_t *g_sk_dblog_;

int sk_get_errno(void);
void sk_update_errno(int *en_old, int en_new);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* SK_COMMON_H */
