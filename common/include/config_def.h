#ifndef CONFIG_DEF_H
#define CONFIG_DEF_H

#ifndef CONFIG_ERROR_MESSAGE
#define CONFIG_ERROR_MESSAGE "Failed to read configuration with module_name=%s, param_name=%s"
#endif /* CONFIG_ERORR_MESSAGE */

/**
 * Add your modules and params here
 */

/**
 * mod_mpm_worker
 */
#define CONFIG_MPM_WORKER                               "mod_mpm_worker"
#define CONFIG_MPM_WORKER_THREAD_MIN                    "thread_min"
#define CONFIG_MPM_WORKER_THREAD_MAX                    "thread_max"
#define CONFIG_MPM_WORKER_THREAD_STACK_SIZE             "thread_stack_size"
#define CONFIG_MPM_WORKER_THREAD_LOW_WATERMARK          "thread_low_watermark"
#define CONFIG_MPM_WORKER_THREAD_HIGH_WATERMARK         "thread_high_watermark"
#define CONFIG_MPM_WORKER_TASK_QUEUE_SIZE               "task_queue_size"
#define CONFIG_MPM_WORKER_THREAD_EXIT_TIMEOUT           "thread_exit_timeout"
#define CONFIG_MPM_WORKER_LISTEN_TIMEOUT                "listen_timeout"  

/**
 * mod_proxy_http
 */
#define CONFIG_PROXY_HTTP                                "mod_proxy_http"
#define CONFIG_PROXY_HTTP_PROXY_MODE                     "proxy_mode"
#define CONFIG_PROXY_HTTP_SERVER_ADDR                    "server_addr"
#define CONFIG_PROXY_HTTP_LARGE_FILE_THRESHOLD           "large_file_threshold"
#define CONFIG_PROXY_HTTP_DLM_TIMEOUT                    "dlm_timeout"
#define CONFIG_PROXY_HTTP_VSCAN_TIMEOUT                  "vscan_timeout"
#define CONFIG_PROXY_HTTP_VSCAN_ACTION_VIRUS             "vscan_action_virus"
#define CONFIG_PROXY_HTTP_VSCAN_ACTION_VIRUS_UNCLEANABLE "vscan_action_virus_uncleanable"
#define CONFIG_PROXY_HTTP_VSCAN_ACTION_SPYWARE           "vscan_action_spyware"
#define CONFIG_PROXY_HTTP_VSCAN_ACTION_ERROR             "vscan_action_error"
#define CONFIG_PROXY_HTTP_TRICKLING_ENABLE               "trickling_enable"
#define CONFIG_PROXY_HTTP_TRICKLING_START                "trickling_start"
#define CONFIG_PROXY_HTTP_TRICKLING_INTERVAL             "trickling_interval"
#define CONFIG_PROXY_HTTP_TRICKLING_AMOUNT               "trickling_amount"
#define CONFIG_PROXY_HTTP_TRICKLING_LIMITATION           "trickling_limitation"
#define CONFIG_PROXY_HTTP_ONLY_WEBMAIL                   "only_webmail"
#define CONFIG_PROXY_HTTP_URLFILTER                      "urlfilter"
#define CONFIG_PROXY_HTTP_FILEBLOCKING_ENABLE            "fileblocking_enable"
#define CONFIG_PROXY_HTTP_FILEBLOCKING_EXT               "fileblocking_ext"
#define CONFIG_PROXY_HTTP_FILEBLOCKING_TFT               "fileblocking_tft"

/**
 * mod_proxy_ftp
 */
#define CONFIG_PROXY_FTP                       "mod_proxy_ftp"
#define CONFIG_PROXY_FTP_PROXY_MODE            "proxy_mode"
#define CONFIG_PROXY_FTP_KEEPALIVE             "keepalive"
#define CONFIG_PROXY_FTP_KEEPIDLE              "keepidle"
#define CONFIG_PROXY_FTP_KEEPINTVL             "keepintvl"
#define CONFIG_PROXY_FTP_KEEPCNT               "keepcnt"
#define CONFIG_PROXY_FTP_TIMEOUT_CONTROL       "timeout_control"
#define CONFIG_PROXY_FTP_TIMEOUT_CONNECTION    "timeout_connection"
#define CONFIG_PROXY_FTP_TIMEOUT_DATA          "timeout_data"
#define CONFIG_PROXY_FTP_LARGE_FILE_THRESHOLD  "large_file_threshold"
#define CONFIG_PROXY_FTP_PASS_UNKNOWN_COMMANDS "pass_unknown_commands"
#define CONFIG_PROXY_FTP_PASS_LARGE_FILES      "pass_large_files"
#define CONFIG_PROXY_FTP_TRICKLING_ENABLE      "trickling_enable"
#define CONFIG_PROXY_FTP_TRICKLING_START       "trickling_start"
#define CONFIG_PROXY_FTP_TRICKLING_INTERVAL    "trickling_interval"
#define CONFIG_PROXY_FTP_TRICKLING_AMOUNT      "trickling_amount"
#define CONFIG_PROXY_FTP_TRICKLING_LIMITATION  "trickling_limitation"
#define CONFIG_PROXY_FTP_REPLIER_ENABLE        "replier_enable"
#define CONFIG_PROXY_FTP_REPLIER_START         "replier_start"
#define CONFIG_PROXY_FTP_REPLIER_INTERVAL      "replier_interval"
#define CONFIG_PROXY_FTP_DLM_TIMEOUT           "dlm_timeout"
#define CONFIG_PROXY_FTP_FILEBLOCKING_ENABLE   "fileblocking_enable"
#define CONFIG_PROXY_FTP_FILEBLOCKING_EXT      "fileblocking_ext"
#define CONFIG_PROXY_FTP_FILEBLOCKING_TFT      "fileblocking_tft"
#define CONFIG_PROXY_FTP_VSCAN_TIMEOUT         "vscan_timeout"
#define CONFIG_PROXY_FTP_VSCAN_ACTION_1ST      "vscan_action_1st"
#define CONFIG_PROXY_FTP_VSCAN_ACTION_2ND      "vscan_action_2nd"
#define CONFIG_PROXY_FTP_VSCAN_ACTION_SPY      "vscan_action_spy"
#define CONFIG_PROXY_FTP_VSCAN_ACTION_ERR      "vscan_action_err"

/**
 * mod_proxy_smtp
 */
#define CONFIG_PROXY_SMTP                       "mod_proxy_smtp"
#define CONFIG_SMTP_INCOMING                    "smtp_incoming"
#define CONFIG_SMTP_OUTGOING                    "smtp_outgoing"

/**
 * mod_proxy_pop3
 */
#define CONFIG_PROXY_POP3                       "mod_proxy_pop3"


/**
 * dmgr
 */
#define CONFIG_DMGR                          "dmgr"
#define CONFIG_DMGR_MAX_MEMORY_LEVEL         "max_memory_level"
#define CONFIG_DMGR_MEMORY_CAPACITY          "memory_capacity"
#define CONFIG_DMGR_MEMORY_UNIT_SIZE         "memory_unit_size"
#define CONFIG_DMGR_POOL_WATERLEVEL          "pool_waterlevel"
#define CONFIG_DMGR_POOL_LOW_WATERMARK       "pool_low_watermark"
#define CONFIG_DMGR_POOL_UNIT_SIZE           "pool_unit_size"
#define CONFIG_DMGR_POND_SIZE                "pond_size"
#define CONFIG_DMGR_POND_THRESHOLD           "pond_threshold"
#define CONFIG_DMGR_TIMEOUT                  "timeout"
#define CONFIG_DMGR_SOFTLIMIT                "softlimit"
#define CONFIG_DMGR_TMP_TEMPLATE             "tmp_template"
#define CONFIG_DMGR_HD_LAYER_STORAGE         "hd_layer_storage"
#define CONFIG_DMGR_HD_AVAILABLE             "hd_available"

              
/**
 * temp_disk
 */
#define CONFIG_TEMP_DISK                                "temp_disk"
#define CONFIG_TEMP_DISK_PATH                           "path"
#define CONFIG_TEMP_DISK_SIZE_LIMIT                     "size_limit"
#define CONFIG_TEMP_DISK_TIMEOUT                        "timeout"
#define CONFIG_TEMP_DISK_HD_AVAILABLE                   "hd_available"
#define CONFIG_TEMP_DISK_HD_PATH                        "hd_path"

/**
 * mail client
 */
#define CONFIG_MAIL_CLIENT                              "mail_client"
#define CONFIG_SERVER                                   "server"
#define CONFIG_SERVER_PORT                              "server_port"
#define CONFIG_MAIL_COMMAND                             "command"
#define CONFIG_FILENAME_TEMPLATE                        "filename_template"
#define CONFIG_ADMIN_ADDRESS                            "admin_address"
#define CONFIG_FROM_ADDRESS                             "from"
#define CONFIG_FREQ_LIMIT_ENABLE                        "freq_limit_enable"
#define CONFIG_FREQ_LIMIT_INTERVAL                      "freq_limit_interval"
#define CONFIG_FREQ_LIMIT_SOFTLIMIT                     "freq_limit_softlimit"

#endif /* CONFIG_DEF_H */
