/*
 * sk_common.c
 */

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fnmatch.h>
#include <string.h>

#include <sk_common.h>

TmDebug_t *g_sk_dblog_ = NULL;

int sk_get_errno(void)
{
    if (errno != 0)
        return errno;
    else
        return -1;
}

void sk_update_errno(int *en_old, int en_new)
{
    assert(en_old != NULL);
    if (*en_old == 0 && en_new != 0)
        *en_old = en_new;
}


