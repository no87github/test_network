/*
 * sk_string.h
 */

#ifndef SK_STRING_H
#define SK_STRING_H

/*
 * Disable SK_DEBUG_STRING.
 */
#ifdef SK_DEBUG_STRING
#undef SK_DEBUG_STRING
#endif /* SK_DEBUG_STRING */

#ifdef SK_DEBUG_STRING
#   include <sk_buffer.h>
#   ifndef SK_DEBUG_BUFFER
#       warning SK_DEBUG_BUFFER is not defined
#   endif /* SK_DEBUG_BUFFER */
#   define SK_STRING_DIFF (SK_BUFFER_DIFF)
#else /* SK_STRING_H */
#   define SK_STRING_DIFF (0)
#endif /* SK_STRING_H */

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

#define SK_STRING_FORMATTER_PREFIX '$'
#define SK_STRING_ERROR_STRING "(error)"

typedef struct
{
#ifdef SK_DEBUG_STRING
    /*
     * Use sk_buffer to protect the buffer.
     */
    sk_buffer_t debug_buffer_;
#endif /* SK_STRING_H */
    char *buffer_;
    int capacity_;
    int size_;
}
sk_string_t;

int sk_string_create(sk_string_t *s, char *buffer, int capacity);
int sk_string_destroy(sk_string_t *s);
int sk_string_reset(sk_string_t *s);

int sk_string_get_size(const sk_string_t *s, int *size);
int sk_string_get_string(const sk_string_t *s, char **string);
int sk_string_get_range(const sk_string_t *s, char **begin, char **end);
int sk_string_get_internal(const sk_string_t *s, char **buffer, int *capacity);

int sk_string_append_range(sk_string_t *s, const char *begin, const char *end);
int sk_string_append_range_urlenc(sk_string_t *s, const char *begin, const char *end);
int sk_string_append_string(sk_string_t *s, const char *string);
int sk_string_append_string_urlenc(sk_string_t *s, const char *string);
int sk_string_append_printf(sk_string_t *s, const char *format, ...);
int sk_string_append_format(sk_string_t *s, const char *format, ...);
int sk_string_append_binary(sk_string_t *s, const char *begin, const char *end);

const char *sk_string_get_content(const sk_string_t *s);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* SK_STRING_H */
