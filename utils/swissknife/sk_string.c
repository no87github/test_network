/*
 * sk_string.c
 */

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <url_translator.h>

#include <sk_common.h>
#include <sk_string.h>

#ifdef SK_DEBUG_STRING

void sk_string_invariant(const sk_string_t *s)
{
    assert(s != NULL);
    assert(s->buffer_ != NULL);
    assert(s->capacity_ >= 1);
    assert(1 <= s->size_);
    assert(s->size_ <= s->capacity_);
    assert(s->buffer_[s->size_ - 1] == '\0');
#ifdef SK_DEBUG_STRING
    {
        char *buffer;
        int capacity;

        /*
         * Call sk_buffer_get() to enforce the invariant checking of sk_buffer.
         */
        assert(sk_buffer_get(&s->debug_buffer_, &buffer, &capacity) == 0);
        assert(buffer == s->buffer_);
        assert(capacity == s->capacity_);
    }
#endif /* SK_STRING_H */
}

#else /* SK_DEBUG_STRING */
#define sk_string_invariant(s)
#endif /* SK_DEBUG_STRING */

int sk_string_create(sk_string_t *s, char *buffer, int capacity)
{
    int ret = 0;
    if (s == NULL || buffer == NULL || capacity <= 0)
    {
        ret = EINVAL;
        goto leave;
    }
#ifdef SK_DEBUG_STRING
    assert(sk_buffer_create(&s->debug_buffer_, buffer, capacity) == 0);
    assert(sk_buffer_get(&s->debug_buffer_, &buffer, &capacity) == 0);
#endif /* SK_STRING_H */
    s->buffer_ = buffer;
    s->capacity_ = capacity;
    s->size_ = 1;
    s->buffer_[0] = '\0';
    sk_string_invariant(s);
leave:
    return ret;
}

int sk_string_destroy(sk_string_t *s)
{
    int ret = 0;
    sk_string_invariant(s);
    if (s == NULL)
    {
        ret = EINVAL;
        goto leave;
    }
#ifdef SK_DEBUG_STRING
    assert(sk_buffer_destroy(&s->debug_buffer_) == 0);
#endif /* SK_STRING_H */
leave:
    return ret;
}

int sk_string_reset(sk_string_t *s)
{
    int ret = 0;
    sk_string_invariant(s);
    if (s == NULL)
    {
        ret = EINVAL;
        goto leave;
    }
    s->buffer_[0] = '\0';
    s->size_ = 1;
leave:
    sk_string_invariant(s);
    return 0;
}

int sk_string_get_size(const sk_string_t *s, int *size)
{
    int ret = 0;
    sk_string_invariant(s);
    if (s == NULL || size == NULL)
    {
        ret = EINVAL;
        goto leave;
    }
    *size = s->size_ - 1;
leave:
    return ret;
}

int sk_string_get_string(const sk_string_t *s, char **string)
{
    int ret = 0;
    sk_string_invariant(s);
    if (s == NULL || string == NULL)
    {
        ret = EINVAL;
        goto leave;
    }
    *string = s->buffer_;
leave:
    return ret;
}

int sk_string_get_range(const sk_string_t *s, char **begin, char **end)
{
    int ret = 0;
    sk_string_invariant(s);
    if (s == NULL || begin == NULL || end == NULL)
    {
        ret = EINVAL;
        goto leave;
    }
    *begin = s->buffer_;
    *end = s->buffer_ + s->size_ - 1;
leave:
    return ret;
}

int sk_string_get_internal(const sk_string_t *s, char **buffer, int *capacity)
{
    int ret = 0;
    sk_string_invariant(s);
    if (s == NULL || buffer == NULL || capacity == NULL)
    {
        ret = EINVAL;
        goto leave;
    }
    *buffer = s->buffer_;
    *capacity = s->capacity_;
leave:
    return ret;
}

int sk_string_append_range(sk_string_t *s, const char *begin, const char *end)
{
    int ret = 0;
    int len_f; /* The length of the free space. */
    int len_s; /* The length of the source data. */

    sk_string_invariant(s);
    if (s == NULL || begin == NULL || end < begin)
    {
        ret = EINVAL;
        goto leave;
    }

    if (begin == end)
        goto leave;
    if ((len_f = s->capacity_ - s->size_) == 0)
    {
        ret = ENOSPC;
        SK_LOG_WARN("len_f=0");
        goto leave;
    }
    if ((len_s = end - begin) > len_f)
    {
        ret = ENOSPC;
        SK_LOG_WARN("len_s=%d > len_f=%d", len_s, len_f);
        len_s = len_f;
    }
    memcpy(s->buffer_ + s->size_ - 1, begin, len_s);
    s->size_ += len_s;
    s->buffer_[s->size_ - 1] = '\0';
leave:
    sk_string_invariant(s);
    return ret;
}

int sk_string_append_range_urlenc(sk_string_t *s, const char *begin, const char *end)
{
    int ret = 0;

    sk_string_invariant(s);
    if (s == NULL || begin == NULL || end < begin)
    {
        ret = EINVAL;
        goto leave;
    }
    if (begin == end)
        SK_LOG_WARN("begin == end");
    while (begin < end)
    {
        int32_t length;
        char output[8];

        length = url_encodeChar(*begin, output, sizeof(output));
        if (length < 0)
            SK_LOG_ERROR("url_encodeChar() failed: %d", length);
        else if (length > sizeof(output))
            SK_LOG_ERROR("Internal Errors: length=%d > sizeof(output)=%zd",
                         length, sizeof(output));
        else
            sk_string_append_range(s, output, output + length);
        ++begin;
    }
leave:
    sk_string_invariant(s);
    return ret;
}

int sk_string_append_string(sk_string_t *s, const char *string)
{
    int ret = 0;
    int len;

    sk_string_invariant(s);
    if (s == NULL || string == NULL)
    {
        ret = EINVAL;
        goto leave;
    }
    if ((len = strlen(string)) == 0)
        goto leave;
    ret = sk_string_append_range(s, string, string + len);
leave:
    sk_string_invariant(s);
    return ret;
}

int sk_string_append_string_urlenc(sk_string_t *s, const char *string)
{
    int ret = 0;
    int len;

    sk_string_invariant(s);
    if (s == NULL || string == NULL)
    {
        ret = EINVAL;
        goto leave;
    }
    if ((len = strlen(string)) == 0)
        goto leave;
    ret = sk_string_append_range_urlenc(s, string, string + len);
leave:
    sk_string_invariant(s);
    return ret;
}

int sk_string_append_printf(sk_string_t *s, const char *format, ...)
{
    int ret = 0;
    int len_f; /* The length of the free space. */
    int len_s; /* The length of the formatted string. */
    va_list ap;

    sk_string_invariant(s);
    if (s == NULL || format == NULL)
    {
        ret = EINVAL;
        goto leave;
    }
    if ((len_f = s->capacity_ - s->size_ + 1) == 0)
    {
        ret = ENOSPC;
        SK_LOG_WARN("len_f=0");
        goto leave;
    }
    va_start(ap, format);
    len_s = vsnprintf(s->buffer_ + s->size_ - 1, len_f, format, ap);
    va_end(ap);
    if (len_s >= len_f)
    {
        ret = ENOSPC;
        SK_LOG_WARN("len_s=%d >= len_f=%d", len_s, len_f);
        len_s = len_f - 1;
    }
    s->size_ += len_s;
leave:
    sk_string_invariant(s);
    return ret;
}

/*
 * The output parameter (*number) will be the number of formatters in the format string (format).
 * For example, *number will be 5 if format is "$4 = $0 + $1". Note that, in format, there are 5
 * formatters ($0, $1, $2, and $3, $4), although 2 of them ($2 and $3) are omitted. On error,
 * *number will remain unchanged.
 */
static int sk_string_parse_format(const char *format, int *number)
{
    int ret = 0;
    int i;
    int has[10]; /* has[i] is true iff format contains $i, where i = 0, 1, ..., 9. */

    assert(format != NULL);
    assert(number != NULL);
    if (format == NULL || number == NULL)
    {
        ret = EINVAL;
        goto leave;
    }

    for (i = 0; i < SK_NUMOF(has); i++)
        has[i] = 0;
    {
        int prefix = 0;
        while (*format != '\0')
        {
            if (prefix) /* *(format - 1) == SK_STRING_FORMATTER_PREFIX */
            {
                if (isdigit(*format))
                    has[*format - '0'] = 1;
                prefix = 0;
            }
            else /* *(format - 1) != SK_STRING_FORMATTER_PREFIX */
            {
                if (*format == SK_STRING_FORMATTER_PREFIX)
                    prefix = 1;
            }
            format++;
        }
    }
    {
        int num = 0; /* The number of formatters. */
        for (i = SK_NUMOF(has) - 1; i >= 0; i--)
            if (has[i])
            {
                num = i + 1;
                break;
            }
        *number = num;
    }
leave:
    return ret;
}

/*
 * For example, sk_string_append_format(s, "$0 + $1 = $1 + $0", "x", "y") will append
 * "x + y = y + x" to s.
 */
int sk_string_append_format(sk_string_t *s, const char *format, ...)
{
    int ret = 0;
    int num = -1; /* The number of formatters. */
    int i;
    const char *str[10];

    sk_string_invariant(s);
    if (s == NULL || format == NULL)
    {
        ret = EINVAL;
        goto leave;
    }

    if ((ret = sk_string_parse_format(format, &num)) != 0)
    {
        SK_LOG_ERROR("sk_string_parse_format(\"%s\", ?) failed: %d", format, ret);
        assert(0);
        goto leave;
    }
    assert(0 <= num && num <= SK_NUMOF(str));
    if (num == 0)
        SK_LOG_WARN("format=\"%s\" contains zero formatters.", format);

    {
        va_list ap;

        va_start(ap, format);
        for (i = 0; i < num; i++)
        {
            str[i] = va_arg(ap, const char *);
            if (str[i] == NULL)
            {
                SK_LOG_WARN("Internal Errors: str[%i]=NULL", i);
                str[i] = SK_STRING_ERROR_STRING;
            }
        }
        for (i = num; i < SK_NUMOF(str); i++)
            str[i] = SK_STRING_ERROR_STRING;
        va_end(ap);
    }
    {
        const char *pending = format;
        int prefix = 0;
        char now[128] = {'\0'};

        while (*format != '\0')
        {
            if (prefix) /* *(format - 1) == SK_STRING_PREFIX */
            {
                if (isdigit(*format)) /* $i for i = 0, 1, ..., 9 */
                {
                    sk_update_errno(&ret, sk_string_append_range(s, pending, format - 1));
                    sk_update_errno(&ret, sk_string_append_string(s, str[*format - '0']));
                }
                else if (*format == 'N') /* $N */
                {
                    if (now[0] == '\0')
                    {
                        time_t now_time_t;
                        struct tm now_struct_tm;

                        strncpy(now, SK_STRING_ERROR_STRING, sizeof(now)-1);
//                        now[sizeof(now) - 1] = '\0';
                        if ((now_time_t = time(NULL)) == (time_t)-1)
                            SK_LOG_ERROR("localetime_r() failed: %d", errno);
                        else if (localtime_r(&now_time_t, &now_struct_tm) == NULL)
                            SK_LOG_ERROR("localetime_r() failed: %d", errno);
                        else if (strftime(now, sizeof(now), "%c", &now_struct_tm) == 0)
                            SK_LOG_ERROR("localetime_r() failed: %d", errno);
                    }
                    now[sizeof(now) - 1] = '\0';
                    sk_update_errno(&ret, sk_string_append_range(s, pending, format - 1));
                    sk_update_errno(&ret, sk_string_append_string(s, now));
                }
                else if (*format == SK_STRING_FORMATTER_PREFIX) /* $$ */
                    sk_update_errno(&ret, sk_string_append_range(s, pending, format));
                else
                {
                    sk_update_errno(&ret, sk_string_append_range(s, pending, format - 1));
                    SK_LOG_WARN("Unknown Formatter: $%c", *format);
                }
                pending = format + 1;
                prefix = 0;
            }
            else /* *(format - 1) != SK_STRING_PREFIX */
            {
                if (*format == SK_STRING_FORMATTER_PREFIX)
                    prefix = 1;
            }
            format++;
        }
        sk_update_errno(&ret, sk_string_append_range(s, pending, format));
    }
leave:
    sk_string_invariant(s);
    return ret;
}

int sk_string_append_binary(sk_string_t *s, const char *begin, const char *end)
{
    int ret = 0;

    sk_string_invariant(s);
    if (s == NULL || begin == NULL || end < begin)
    {
        ret = EINVAL;
        goto leave;
    }

    /*
     * It's okay if begin == end.
     */
    for (; begin < end; begin++)
    {
        if (isprint(*begin))
            sk_update_errno(&ret, sk_string_append_printf(s, "%c", *begin));
        else if (*begin == '\r')
            sk_update_errno(&ret, sk_string_append_string(s, "\\r"));
        else if (*begin == '\n')
            sk_update_errno(&ret, sk_string_append_string(s, "\\n"));
        else if (*begin == '\t')
            sk_update_errno(&ret, sk_string_append_string(s, "\\t"));
        else
            sk_update_errno(&ret, sk_string_append_printf(s, "\\x%02X", (unsigned char)*begin));
        if (ret != 0)
            break;
    }
leave:
    sk_string_invariant(s);
    return ret;
}

/*
 * Return the content of s. This function is guaranteed to return a null-terminated string even if s
 * is invalid (e.g., s is NULL) or something is wrong (e.g., sk_string_get_string() fails). On
 * error, the event will be logged.
 */
const char *sk_string_get_content(const sk_string_t *s)
{
    char *ret = SK_STRING_ERROR_STRING;
    int en;

    sk_string_invariant(s);
    if (s == NULL)
    {
        SK_LOG_ERROR("Internal Errors: s=NULL");
        assert(0);
        goto leave;
    }
    if ((en = sk_string_get_string(s, &ret)) != 0)
    {
        SK_LOG_ERROR("sk_string_get_string() failed: %d", en);
        goto leave;
    }
leave:
    sk_string_invariant(s);
    return ret;
}
