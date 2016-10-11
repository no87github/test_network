#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "list.h"
#include "fsctl_common.h"
#include "vscan.h"
#include "fs_cache.h"

/*****************************************************/
/*                 GLOBAL  VARIABLE                  */
/*****************************************************/

static int m_inited = 0;

static VscanHandle *m_vsh = NULL;
/*
 *  * A read-write lock for protecting m_config and m_vsh.
 *   */
static pthread_rwlock_t m_rwlock = PTHREAD_RWLOCK_WRITER_NONRECURSIVE_INITIALIZER_NP;

extern vscan_config_t gvscan_config;
extern VscanHandle *g_handle_vsh;

/*****************************************************/
/*                  STATIC FNUCTION                  */
/*****************************************************/


int
reload_pattern(
    const void *buf,
    size_t count)
{
    int ret = -1;
    glcfg_t glcfg = NULL;
    pattern_list virusptn,spyptn,blackptn,whiteptn;
    const char *pattern_path = NULL;

    glcfg = glcfg_open(var_config_file, GLCFG_MODE_READ);
    if (glcfg == NULL)
    {
        ret = -1;
        LOGERROR("Failed to read config file: %s\n", var_config_file);
        goto leave;
    }

    /* pattern path */
    if ((pattern_path = glcfg_get_param_value(glcfg, "vscan", "pattern_path", NULL)) == NULL)
    {
        ret = -1;
        LOGERROR("glcfg_get_param_value(): module=\"vscan\", param=\"pattern_path\"");
        goto leave;
    }
    LOGDEBUG("pattern_path=%s", pattern_path);
    
    memset(&virusptn,0,sizeof(virusptn));
    strncpy(virusptn.ptnpath,pattern_path,VSCAN_MAX_PATH_SIZE);
    strncpy(virusptn.ptnfile_base,"lpt$vpn.",VSCAN_MAX_PATH_SIZE);
    LOGDEBUG("virus ptnpath=\"%s\", ptnfile_base=\"%s\"", virusptn.ptnpath, virusptn.ptnfile_base);
    virusptn.next = &spyptn;
    
    memset(&spyptn,0,sizeof(spyptn));
    strncpy(spyptn.ptnpath,pattern_path,VSCAN_MAX_PATH_SIZE);
    strncpy(spyptn.ptnfile_base,"ssaptn.",VSCAN_MAX_PATH_SIZE);
    LOGDEBUG("spyware ptnpath=\"%s\", ptnfile_base=\"%s\"", spyptn.ptnpath, spyptn.ptnfile_base);
    spyptn.next = &blackptn;
    
    memset(&blackptn,0,sizeof(blackptn));
    strncpy(blackptn.ptnpath,pattern_path,VSCAN_MAX_PATH_SIZE);
    strncpy(blackptn.ptnfile_base,"tmblack.",VSCAN_MAX_PATH_SIZE);
    LOGDEBUG("black ptnpath=\"%s\", ptnfile_base=\"%s\"", blackptn.ptnpath, blackptn.ptnfile_base);
    blackptn.next = &whiteptn;
    
    memset(&whiteptn,0,sizeof(whiteptn));
    strncpy(whiteptn.ptnpath,pattern_path,VSCAN_MAX_PATH_SIZE);
    strncpy(whiteptn.ptnfile_base,"tmwhite.",VSCAN_MAX_PATH_SIZE);
    LOGDEBUG("white ptnpath=\"%s\", ptnfile_base=\"%s\"", whiteptn.ptnpath, whiteptn.ptnfile_base);
    whiteptn.next = NULL;

    // put glcfg_close() here to free just allocated memory in heap
    // this is to avoid heap grow
    glcfg_close(glcfg);
    glcfg = NULL;
    
    if (vscan_reload_pattern(&virusptn) != VSCAN_SUCCESS)
    {
        ret = -1;
        LOGERROR("Failed to vscan_reload_pattern");
        goto leave;
    }
    
    fs_cache_purge(0);

    ret = 0;

leave:
    if (glcfg != NULL)
    {
        glcfg_close(glcfg);
        glcfg = NULL;
    }

    return ret;
}

int
reload_engine(
    const void *buf,
    size_t count)
{
    int ret = -1;
    glcfg_t glcfg = NULL;
    pattern_list virusptn,spyptn,blackptn,whiteptn;
    const char *engine_path = NULL;
    const char *pattern_path = NULL;

    glcfg = glcfg_open(var_config_file, GLCFG_MODE_READ);
    if (glcfg == NULL)
    {
        ret = -1;
        LOGERROR("Failed to read config file: %s\n", var_config_file);
        goto leave;
    }

#if 0
    /* engine path */
    if ((engine_path = glcfg_get_param_value(glcfg, "vscan", "engine_path", NULL)) == NULL)
    {
        ret = -1;
        LOGERROR("glcfg_get_param_value(): module=\"vscan\", param=\"engine_path\"");
        goto leave;
    }
#endif

    engine_path = buf;
    /* @todo remove hardcode */
    //engine_path = "libvsapi.so.new";
    LOGDEBUG("engine_path=%s", engine_path);

    /* pattern path */
    if ((pattern_path = glcfg_get_param_value(glcfg, "vscan", "pattern_path", NULL)) == NULL)
    {
        ret = -1;
        LOGERROR("glcfg_get_param_value(): module=\"vscan\", param=\"pattern_path\"");
        goto leave;
    }
    LOGDEBUG("pattern_path=%s", pattern_path);

    memset(&virusptn,0,sizeof(virusptn));
    strncpy(virusptn.ptnpath,pattern_path,VSCAN_MAX_PATH_SIZE);
    strncpy(virusptn.ptnfile_base,"lpt$vpn.",VSCAN_MAX_PATH_SIZE);
    LOGDEBUG("virus ptnpath=\"%s\", ptnfile_base=\"%s\"", virusptn.ptnpath, virusptn.ptnfile_base);
    virusptn.next = &spyptn;

    memset(&spyptn,0,sizeof(spyptn));
    strncpy(spyptn.ptnpath,pattern_path,VSCAN_MAX_PATH_SIZE);
    strncpy(spyptn.ptnfile_base,"ssaptn.",VSCAN_MAX_PATH_SIZE);
    LOGDEBUG("spyware ptnpath=\"%s\", ptnfile_base=\"%s\"", spyptn.ptnpath, spyptn.ptnfile_base);
    spyptn.next = &blackptn;

    memset(&blackptn,0,sizeof(blackptn));
    strncpy(blackptn.ptnpath,pattern_path,VSCAN_MAX_PATH_SIZE);
    strncpy(blackptn.ptnfile_base,"tmblack.",VSCAN_MAX_PATH_SIZE);
    LOGDEBUG("black ptnpath=\"%s\", ptnfile_base=\"%s\"", blackptn.ptnpath, blackptn.ptnfile_base);
    blackptn.next = &whiteptn;

    memset(&whiteptn,0,sizeof(whiteptn));
    strncpy(whiteptn.ptnpath,pattern_path,VSCAN_MAX_PATH_SIZE);
    strncpy(whiteptn.ptnfile_base,"tmwhite.",VSCAN_MAX_PATH_SIZE);
    LOGDEBUG("white ptnpath=\"%s\", ptnfile_base=\"%s\"", whiteptn.ptnpath, whiteptn.ptnfile_base);
    whiteptn.next = NULL;

    if (vscan_reload_engine(engine_path, &virusptn) != VSCAN_SUCCESS)
    {
        ret = -1;
        LOGERROR("Failed to vscan_load_engine");
        goto leave;
    }

    fs_cache_purge(0);

    ret = 0;

leave:
    if (glcfg != NULL)
    {
        glcfg_close(glcfg);
        glcfg = NULL;
    }

    return ret;
}

int
report_version(
    char *str,
    size_t count)
{
    int ret = 0;
    int en;
    char *p = NULL, *e = NULL;
    vscan_version_t version;

    LOGDEBUG("Enter %s()", __FUNCTION__);
    if (str == NULL || count == 0)
    {
        ret = -1;
        LOGERROR("Internal Errors: str=NULL or count=0");
        goto leave;
    }

    p = str;
    e = str + count;

    if ((en = vscan_get_version(m_vsh, &version)) != VSCAN_SUCCESS)
    {
        ret = -1;
        LOGERROR("vscan_get_version(): %d", en);
        goto leave;
    }

    ret = snprintf(p, e - p,
                   "vsapi_engine: %s\n"
                   "vsapi_engine_major: %u\n"
                   "vsapi_engine_minor: %u\n"
                   "vsapi_engine_revision: %u\n"
                   "vsapi_engine_build: %u\n"
                   "virus_pattern: %s\n"
                   "spyware_pattern: %s\n"
                   "tmwhite_pattern: %s\n"
                   "tmblack_pattern: %s\n"
                   "vsapi_engine_au_version: %s\n",
                   version.vsapi_engine,
                   version.vsapi_engine_major,
                   version.vsapi_engine_minor,
                   version.vsapi_engine_revision,
                   version.vsapi_engine_build,
                   version.virus_pattern,
                   version.spyware_pattern,
                   version.tmwhite_pattern,
                   version.tmblack_pattern,
                   version.vsapi_engine_for_au);
    if ((ret < 0) || (ret >= (e - p)))
        goto leave;
    p += ret;

    ret = (p - str);

leave:
    LOGDEBUG("Leave %s(): ret=%d str=\"%.*s\"", __FUNCTION__, ret, (int)(p - str), str);
    return ret;
}

static int load_vscan_config(vscan_config_t *vscan_config)
{
    int ret = 0;
    glcfg_t glcfg = NULL;

    glcfg = glcfg_open(var_config_file, GLCFG_MODE_READ);
    if (glcfg == NULL)
    {
        ret = -1;
        LOGERROR("Failed to read config file: %s\n", var_config_file);
        goto leave;
    }
        
    memset(vscan_config, '\0', sizeof(vscan_config_t));

    if (mu_read_vscan_common_setting(glcfg, &(vscan_config->common)) != 0)
    {
        ret = -1;
        LOGERROR("Failed to read_vscan_common_setting");
        goto leave;
    }
        
    if (mu_read_vscan_protocol_setting(glcfg, "vscan", &(vscan_config->protocol)) != 0)
    {
        ret = -1;
        LOGERROR("Failed to read_vscan_protocol_setting");
        goto leave;
    }

    ret = 0;

leave:
    if (glcfg != NULL)
    {
        glcfg_close(glcfg);
        glcfg = NULL;
    }

    return ret;
}

int
reload_config(
        const void *str,
        size_t count)
{
    int ret = 0;
    int unlock = 0;
    vscan_config_t new_config;
    int en;

    if ((ret = pthread_rwlock_wrlock(&m_rwlock)) != 0)
    {
        LOGERROR("pthread_rwlock_wrlock() failed: %d", ret);
        goto leave;
    }
    unlock = 1;
    if ((ret = load_vscan_config(&new_config)) != 0)
    {
        LOGERROR("load_config() failed: %d", ret);
        goto leave;
    }
    memcpy(&gvscan_config, &new_config, sizeof(vscan_config_t));
    if (g_handle_vsh == NULL)
    {
        if ((g_handle_vsh = vscan_create_handle(gvscan_config.protocol)) == NULL)
        {
            ret = -1;
            LOGERROR("vscan_create_handle() failed");
            goto leave;
        }
    }
    else /* g_handle_vsh != NULL */
    {
        if (vscan_set_config(g_handle_vsh, &(gvscan_config.protocol)) != VSCAN_SUCCESS)
        {
            ret = -1;
            LOGERROR("vscan_set_config() failed");
            goto leave;
        }
    }
leave:
    if (unlock)
        if ((en = pthread_rwlock_unlock(&m_rwlock)) != 0)
        {
            LOGERROR("pthread_rwlock_unlock() failed: %d", en);
            if (ret != 0)
                ret = en;
        }

    if(ret == 0) {
	    fs_cache_purge(0);
    }
    return ret;
}

int
fsctl_vscan_init(vscan_config_t * vscan_config)
{
    int ret = 0;

    if (m_inited != 0)
        return 0;
    
    if (0 > (ret = load_vscan_config(vscan_config)))
    {
        LOGERROR("Failed to load_vscan_config");
        goto leave;
    }
    
    if ((m_vsh = vscan_init(vscan_config)) == NULL)
    {
        ret = -1;
        LOGERROR("Failed to vscan_init");
        goto leave;
    }
    g_handle_vsh = vscan_create_handle(gvscan_config.protocol);
    
    m_inited = 1;
    ret = 0;

leave:
    return ret;
}

void
fsctl_vscan_exit(void)
{
    if (!m_inited)
        return;

    m_inited = 0;

    vscan_fini(m_vsh);
}
