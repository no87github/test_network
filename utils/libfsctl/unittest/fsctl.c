#include <sysexits.h>
#include <limits.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libfsctl.h"

#define BUF_MAX (FSCTL_MAX_BUF)
#if 0
enum {
    FSCTL_CMD_NONE,
    FSCTL_CMD_READ,
    FSCTL_CMD_WRITE,
    FSCTL_CMD_EXEC,
};

enum {
    FSCTL_CONTENT_TYPE_NONE,
    FSCTL_CONTENT_TYPE_RAW,
    FSCTL_CONTENT_TYPE_STRING,
    FSCTL_CONTENT_TYPE_INT32,
    FSCTL_CONTENT_TYPE_UINT32,
};
#endif
static void usage(void);

static char buf[BUF_MAX];
static char progname[PATH_MAX];

int main(int argc, char *argv[])
{
    int ret = 0;
    int c;
    unsigned int cmd = FSCTL_CMD_NONE;
    unsigned int content_type = FSCTL_CONTENT_TYPE_NONE;
    char *name = NULL;

    const char *p = strrchr(argv[0], '/');
    p = ((p != NULL) ? (p + 1) : argv[0]);
    (void)snprintf(progname, sizeof(progname), "%s", p);

    while (1)
    {
        c = getopt(argc, argv, "ar:w:x:t:h");
        if (c == -1)
            break;

        switch (c)
        {
            case 'a':
            {
                cmd = FSCTL_CMD_READ;
                name = "all";
                content_type = FSCTL_CONTENT_TYPE_STRING;
            }
            break;
          
            case 'r':
            {
                cmd = FSCTL_CMD_READ;
                name = strdup(optarg);
            }
            break;

            case 'w':
            {
                cmd = FSCTL_CMD_WRITE;
                name = strdup(optarg);
            }
            break;

            case 'x':
            {
                cmd = FSCTL_CMD_EXEC;
                name = strdup(optarg);
            }
            break;

            case 't':
            {
                if (strcasecmp("raw", optarg) == 0)
                    content_type = FSCTL_CONTENT_TYPE_RAW;
                else if (strcasecmp("string", optarg) == 0)
                    content_type = FSCTL_CONTENT_TYPE_STRING;
                else if (strcasecmp("int32", optarg) == 0)
                    content_type = FSCTL_CONTENT_TYPE_INT32;
                else if (strcasecmp("uint32", optarg) == 0)
                    content_type = FSCTL_CONTENT_TYPE_UINT32;
            }
            break;

            case 'h': // follow-through
            default:
                usage();
        }
    }

    argc -= optind;
    argv += optind;

    if (cmd == FSCTL_CMD_READ)
    {
        if (content_type == FSCTL_CONTENT_TYPE_RAW)
        {
            if ((ret = fsctl_read_raw(name, buf, sizeof(buf))) < 0)
                goto error;

            printf("read %d bytes of raw data\n", ret);
        }
        else if (content_type == FSCTL_CONTENT_TYPE_STRING)
        {
            if ((ret = fsctl_read_string(name, buf, sizeof(buf))) < 0)
                goto error;

            printf("%.*s\n", ret, buf);
        }
        else if (content_type == FSCTL_CONTENT_TYPE_INT32)
        {
            int32_t val;
            if ((ret = fsctl_read_int32(name, &val)) != 0)
                goto error;

            printf("%d\n", val);
        }
        else if (content_type == FSCTL_CONTENT_TYPE_UINT32)
        {
            uint32_t val;
            if ((ret = fsctl_read_uint32(name, &val)) != 0)
                goto error;

            printf("%u\n", val);
        }
        else
        {
            usage();
        }
    }
    else if (cmd == FSCTL_CMD_WRITE)
    {
        if ((argc != 1) || (content_type == FSCTL_CONTENT_TYPE_NONE))
            usage();

        if (content_type == FSCTL_CONTENT_TYPE_RAW)
        {
            /* TODO: User cannot input the raw command with data from the command line. */
            if ((ret = fsctl_write_raw(name, NULL, 0)) < 0)
                goto error;
        }
        else if (content_type == FSCTL_CONTENT_TYPE_STRING)
        {
            (void)strncpy(buf, argv[0], sizeof(buf) - 1);
            buf[sizeof(buf) - 1] = '\0';
            if ((ret = fsctl_write_string(name, buf, strlen(buf))) < 0)
                goto error;
        }
        else if (content_type == FSCTL_CONTENT_TYPE_INT32)
        {
            int32_t val = 0;
            char *end = NULL;
            val = strtol(argv[0], &end, 0);
            if(NULL != end && 0 != *end) {
                fprintf(stderr, "Invalid int32: argv=%s\n", argv[0]);
                goto error;
            }
            if ((ret = fsctl_write_int32(name, val)) != 0)
                goto error;
        }
        else if (content_type == FSCTL_CONTENT_TYPE_UINT32)
        {
            uint32_t val = 0;
            char *end = NULL;
            val = strtoul(argv[0], &end, 0);
            if(NULL != end && 0 != *end) {
                fprintf(stderr, "Invalid uint32: argv=%s\n", argv[0]);
                goto error;
            }

            if ((ret = fsctl_write_uint32(name, val)) != 0)
                goto error;
        }
        else
        {
            usage();
        }
    }
    else if (cmd == FSCTL_CMD_EXEC)
    {
        if ((argc != 1) || (content_type == FSCTL_CONTENT_TYPE_NONE))
            usage();

        if (content_type == FSCTL_CONTENT_TYPE_RAW)
        {
            /* TODO: User cannot input the raw command with data from the command line. */
            if ((ret = fsctl_exec_raw(name, NULL, 0)) < 0)
                goto error;
        }
        else if (content_type == FSCTL_CONTENT_TYPE_STRING)
        {
            (void)strncpy(buf, argv[0], sizeof(buf) - 1);
            buf[sizeof(buf) - 1] = '\0';
            if ((ret = fsctl_exec_string(name, buf, strlen(buf))) < 0)
                goto error;
        }
        else if (content_type == FSCTL_CONTENT_TYPE_INT32)
        {
            int32_t val = 0;
            char *end = NULL;
            val = strtol(argv[0], &end, 0);
            if(NULL != end && 0 != *end) {
                fprintf(stderr, "Invalid int32: argv=%s\n", argv[0]);
                goto error;
            }

            if ((ret = fsctl_exec_int32(name, val)) != 0)
                goto error;
        }
        else if (content_type == FSCTL_CONTENT_TYPE_UINT32)
        {
            uint32_t val = 0;
            char *end = NULL;
            val = strtoul(argv[0], &end, 0);
            if(NULL != end && 0 != *end) {
                fprintf(stderr, "Invalid uint32: argv=%s\n", argv[0]);
                goto error;
            }

            if ((ret = fsctl_exec_uint32(name, val)) != 0)
                goto error;
        }
        else
        {
            usage();
        }
    }
    else
    {
        usage();
    }

    return EXIT_SUCCESS;

error:
    return EXIT_FAILURE;
}

static void
usage()
{
    fprintf(stderr, "usage: %s [options]\n", progname);
    fprintf(stderr, "  -a\n");
    fprintf(stderr, "  -r <name> -t [raw|string|int32|uint32]\n");
    fprintf(stderr, "  -w <name> -t [raw|string|int32|uint32] <value>\n");
    fprintf(stderr, "  -x <name> -t [raw|string|int32|uint32] <value>\n");
    exit(EX_USAGE);
}
