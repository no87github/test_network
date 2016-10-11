/*
* Copyright (C) 2005, Trend Micro Incorporated. All Rights Reserved. This program is an unpublished
* copyrighted work which is proprietary to Trend Micro Incorporated and contains confidential
* information that is not to be reproduced or disclosed to any other person or entity without prior
* written consent from Trend Micro, Inc. in each and every instance.
*
* WARNING: Unauthorized reproduction of this program as well as unauthorized preparation of
* derivative works based upon the program or distribution of copies by sale, rental, lease or
* lending are violations of federal copyright laws and dot_state trade secret laws, punishable by civil
* and criminal penalties.
*/

/*
* msg_utils.c
*
* Description: source file of common functions for message related module
* Author: HY Cheng
*
* #001 Aug 11, 2005 HY Cheng Initial implementation.
*/

#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <assert.h>
#include <config_def.h>
#include <msg_utils.h>
#include <sk_io.h>
#include "msg_utils_common.h"

/*****************************************************/
/*                 GLOBAL  VARIABLE                  */
/*****************************************************/

static const char *g_last_error = NULL; /* to keep the error code of dlopen/dlsym/dlclose functions */

/*****************************************************/
/*                  EXPORT FNUCTION                  */
/*****************************************************/
ssize_t
mu_read_line_from_file(
    const char *file,
    char *entry_list[],
    size_t entry_max)
{
    int ret = -1;
    FILE *fp = NULL;
    size_t line_count = 0;
    size_t line_empty = 0;
    char *line_buffer = NULL;
    size_t line_size = 0;
    int n = 0;

    LOGDEBUG("Enter %s(): file=\"%s\", entry_list=%p, entry_max=%zu",
             __FUNCTION__, file, entry_list, entry_max);

    if ((file == NULL) || (entry_list == NULL) || (entry_max == 0))
    {
        errno = EINVAL;
        LOGERROR("file=\"%s\", entry_list=%p, entry_max=%zu: %m",
                 file, entry_list, entry_max);
        goto leave;
    }

    if ((fp = fopen(file, "r")) == NULL)
    {
        LOGERROR("fopen(): file=\"%s\"", file);
        goto leave;
    }

    line_buffer = NULL;
    line_size = 0;
    line_count = 0;
    while ((n = getline(&line_buffer, &line_size, fp)) != -1)
    {
        if (line_buffer == NULL)
            break;

        while (n > 0)
        {
            if ((line_buffer[n - 1] == '\r') || (line_buffer[n - 1] == '\n'))
            {
                line_buffer[n - 1] = '\0';
                --n;
                continue;
            }

            break;
        }

        if (n == 0)
        {
            ++line_empty;
            continue;
        }

        entry_list[line_count] = strdup(line_buffer);
        if (entry_list[line_count] == NULL)
        {
            ++line_empty;
            continue;
        }

        ++line_count;
        if ((line_count >= entry_max) || (line_count >= INT_MAX))
            break;

    }

    ret = line_count;

leave:
    if (line_buffer != NULL)
    {
        xfree(line_buffer);
        line_buffer = NULL;
    }
    if (fp != NULL)
    {
        fclose(fp);
        fp = NULL;
    }

    LOGDEBUG("Leave %s(): line_count=%zu, line_empty=%zu, ret=%d",
             __FUNCTION__, line_count, line_empty, ret);
    return ret;
}

void *mu_library_loader_open(const char *path)
{
    void *handle = NULL;

    LOGDEBUG("Enter %s(): path=%s", __FUNCTION__, path);

    /* Flag  must  be  either  RTLD_LAZY, meaning resolve undefined symbols as
     * code from the dynamic library is executed, or RTLD_NOW, meaning resolve
     * all undefined symbols before dlopen returns, and fail if this cannot be
     * done.  Optionally, RTLD_GLOBAL may be or'ed with flag,  in  which  case
     * the  external  symbols defined in the library will be made available to
     * subsequently loaded libraries.
     */

    handle = dlopen(path, RTLD_LOCAL | RTLD_NOW);
    g_last_error = dlerror();

    LOGDEBUG("Leave %s(): err=\"%s\", handle=%p",
             __FUNCTION__, g_last_error ? : "", handle);

    return handle;
}

int
mu_library_loader_resolve(void *handle,const char *symbol,void **ppv)
{
    int ret = 0;
    void *symbol_addr = NULL;

    LOGDEBUG("Enter %s(): handle=%p, symbol=\"%s\", return_addr=%p", __FUNCTION__, handle, symbol, ppv);

    /* Since the value of the symbol could actually be NULL (so that a NULL
     * return from dlsym() does not indicate an error), the correct way to test
     * test or an error is to call dlerror() to clear any old error conditions,
     * then call dlsym(), and then call dlerror() again, saving its return
     * value into a variable, and check whether this saved value is not NULL.
     */

    (void)dlerror(); /* clear any existing error */
    g_last_error = NULL;

    symbol_addr = dlsym(handle, symbol);
    if (ppv != NULL)
        (*ppv) = symbol_addr;

    g_last_error = dlerror();
    ret = (g_last_error != NULL) ? -1 : 0;

    LOGDEBUG("Leave %s(): ret=%d, symbol_addr=%p", __FUNCTION__, ret, symbol_addr);

    return ret;
}

int
mu_library_loader_close(void *handle)
{
    int ret = 0;

    LOGDEBUG("Enter %s(): handle=%p", __FUNCTION__, handle);

    (void)dlerror(); /* clear any existing error */

    ret = dlclose(handle);
    g_last_error = dlerror();

    LOGDEBUG("Leave %s(): err=\"%s\", ret=%d",
             __FUNCTION__, g_last_error ? : "", ret);
    return ret;
}

const char *
mu_library_loader_error(void)
{
    return g_last_error;
}

