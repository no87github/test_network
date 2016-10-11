#include <assert.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <libintl.h>
#include "list.h"
#include "fs.h"

#define gettext_noop(String)String

extern tmSyslog_t * g_sys_log;

struct filescan_msg_code_t {
    int     code;
    char    *msg;
};

struct filescan_msg_code_t msgcode_2_string_table[] = {
    {FILESCAN_LOGMSG_DISK_ERROR,            gettext_noop("The Advanced Threat Scan Engine encountered a disk error when scanning. Contact your support provider for more information.")},
    {FILESCAN_LOGMSG_CONFIG_CORRUPT,        gettext_noop("The Advanced Threat Scan Engine is unable to load the configuration file. The file may be corrupted. Restore settings by using a backup copy of the configuration file. If problem persists, contact your support provider.")},
    {FILESCAN_LOGMSG_INTERNAL_ERROR,        gettext_noop("Unable to initialize Advanced Threat Scan Engine due to an internal error. Contact your support provider for a rescue system image.")},
    {FILESCAN_LOGMSG_VSCAN_ERROR,           gettext_noop("Unable to load the Advanced Threat Scan Engine or virus pattern. The engine or pattern file may be corrupted or pattern update was unsuccessful. Contact your support provider for a rescue system image.")},
    {FILESCAN_LOGMSG_CTRL_SVR_START_ERR,    gettext_noop("Unable to initialize the Advanced Threat Scan Engine. Contact your support provider for a rescue system image.")},
    {FILESCAN_LOGMSG_SCAN_SVR_START_ERR,    gettext_noop("The Advanced Threat Scan Engine is unable to initialize the scanning server. Contact your support provider for a rescue system image.")},
    {FILESCAN_LOGMSG_SCAN_SERVICE_ERR,      gettext_noop("The Advanced Threat Scan Engine scanning service stopped due to an internal error. Contact your support provider for a rescue system image.")},
};

static const char * msgcode_2_string(const int msgcode) {
    if (FILESCAN_LOGMSG_COUNT <= msgcode) {
        LOGDEBUG("Invalide system log msgcode:%d", msgcode);
        return "";
    }
    return msgcode_2_string_table[msgcode].msg;
}

int
fs_syslog(const int evt_type, const int severity, const int msgcode)
{
    int ret = 0;
    
    LOGDEBUG("system log : "
            "Type=%d&"
            "EventType=%d&"
            "Severity=%d&"
            "Description=%U&",
            FILESCAN_LOGTYPE_SYSTEM,
            evt_type,
            severity,
            msgcode_2_string(msgcode));
    ret = tmSyslog(g_sys_log, TM_SYSLOG_WARNING,
            "Type=%d&"
            "EventType=%d&"
            "Severity=%d&"
            "Description=%U&",
            FILESCAN_LOGTYPE_SYSTEM,
            evt_type,
            severity,
            gettext(msgcode_2_string(msgcode)));

    return ret;
}
