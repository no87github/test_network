/*
 * sk_buffer.h
 */

#ifndef SK_BUFFER_H
#define SK_BUFFER_H

#ifdef SK_DEBUG_BUFFER
#define SK_BUFFER_DIFF (2 * sizeof(int))
#else /* SK_DEBUG_BUFFER */
#define SK_BUFFER_DIFF (0)
#endif /* SK_DEBUG_BUFFER */

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

typedef struct
{
    char *memory_;
    int capacity_;
}
sk_buffer_t;

int sk_buffer_create(sk_buffer_t *buffer, char *memory, int capacity);
int sk_buffer_destroy(sk_buffer_t *buffer);

int sk_buffer_get(const sk_buffer_t *buffer, char **memory, int *capacity);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* SK_BUFFER_H */
