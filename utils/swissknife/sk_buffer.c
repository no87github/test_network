/*
 * sk_buffer.c
 */

#include <assert.h>
#include <errno.h>
#include <stddef.h>

#include <sk_buffer.h>

#ifdef SK_DEBUG_BUFFER

static const int sk_buffer_signature_head = 0x0CF2024B;
static const int sk_buffer_signature_tail = 0x29D8C805;

static inline int *sk_buffer_head(char *memory, int capacity)
{
    assert(memory != NULL);
    assert(capacity > 0);
    return ((int *)memory) - 1;
}

static inline int *sk_buffer_tail(char *memory, int capacity)
{
    assert(memory != NULL);
    assert(capacity > 0);
    return (int *)(memory + capacity);
}

static void sk_buffer_invariant(const sk_buffer_t *buffer)
{
    assert(buffer != NULL);
    assert(buffer->memory_ != NULL);
    assert(buffer->capacity_ > 0);
    assert(*sk_buffer_head(buffer->memory_, buffer->capacity_) == sk_buffer_signature_head);
    assert(*sk_buffer_tail(buffer->memory_, buffer->capacity_) == sk_buffer_signature_tail);
}

#else /* SK_DEBUG_BUFFER */
#define sk_buffer_invariant(buffer__)
#endif /* SK_DEBUG_BUFFER */

int sk_buffer_create(sk_buffer_t *buffer, char *memory, int capacity)
{
    int ret = 0;

    if (buffer == NULL || memory == NULL || capacity <= 0)
    {
        assert(0);
        ret = EINVAL;
        goto leave;
    }
#ifdef SK_DEBUG_BUFFER
    assert(capacity > 2 * sizeof(int));
    memory += sizeof(int);
    capacity -= 2 * sizeof(int);
    *sk_buffer_head(memory, capacity) = sk_buffer_signature_head;
    *sk_buffer_tail(memory, capacity) = sk_buffer_signature_tail;
#endif /* SK_DEBUG_BUFFER */
    buffer->memory_ = memory;
    buffer->capacity_ = capacity;
    sk_buffer_invariant(buffer);
leave:
    return ret;
}

int sk_buffer_destroy(sk_buffer_t *buffer)
{
    int ret = 0;
    sk_buffer_invariant(buffer);
    if (buffer == NULL)
    {
        assert(0);
        ret = EINVAL;
        goto leave;
    }
#ifdef SK_DEBUG_BUFFER
    *sk_buffer_head(buffer->memory_, buffer->capacity_) = ~sk_buffer_signature_head;
    *sk_buffer_tail(buffer->memory_, buffer->capacity_) = ~sk_buffer_signature_tail;
#endif /* SK_DEBUG_BUFFER */
leave:
    return ret;
}

int sk_buffer_get(const sk_buffer_t *buffer, char **memory, int *capacity)
{
    int ret = 0;
    sk_buffer_invariant(buffer);
    if (buffer == NULL || memory == NULL || capacity == NULL)
    {
        assert(0);
        ret = EINVAL;
        goto leave;
    }
    *memory = buffer->memory_;
    *capacity = buffer->capacity_;
leave:
    return ret;
}
