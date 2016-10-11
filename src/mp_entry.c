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

//#include <sys/types.h>
//#include <errno.h>
#include <string.h>

#include "mp_entry.h"

/****************************************************************************/
/* FUNCTION DEFINITIONS                                                     */
/****************************************************************************/

struct mp_entry_ops *
mp_find_entry(
        struct mp_entry_ops entry_list[],
        const char *name)
{
    struct mp_entry_ops * entry = entry_list;

    if (name == NULL || !entry)
        return NULL;

    /* TODO: lock */

    while(entry->name)
    {
        if (strcmp(entry->name, name) == 0)
             goto leave;
        ++entry;
    }
    entry = NULL;

    /* TODO: unlock */

leave:
    return entry;
}
