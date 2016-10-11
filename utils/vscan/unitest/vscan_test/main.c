#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include "vscan.h"

/*****************************************************/
/*                   DATA STRUCTURE                  */
/*****************************************************/

typedef struct
{
    int num;
    char *filename;
    VscanHandle *vsh;
}thread_data_t;

/*****************************************************/
/*                  MACRO DEFINITION                 */
/*****************************************************/
#define THREAD_NUM           (1)
#define TIMEOUT_PERIOD       (1)

/*****************************************************/
/*                 GLOBAL  VARIABLE                  */
/*****************************************************/

static VscanHandle *g_handle_vsh = NULL;

/*****************************************************/
/*                   STATIC FUNCTION                 */
/*****************************************************/

void reload_pattern(int signo)
{           
  pattern_list *ptnlist = NULL,*spyptn = NULL;
  
  ptnlist = (pattern_list *)malloc(sizeof(pattern_list));
  memset(ptnlist,0,sizeof(pattern_list));
  
  spyptn = (pattern_list *)malloc(sizeof(pattern_list));
  memset(spyptn,0,sizeof(pattern_list));
  
  strncpy(ptnlist->ptnpath, "../newpattern",VSCAN_MAX_PATH_SIZE);
  strncpy(ptnlist->ptnfile_base,"lpt$vpn.",VSCAN_MAX_PATH_SIZE);
  strncpy(spyptn->ptnpath,"../newpattern",VSCAN_MAX_PATH_SIZE);
  strncpy(spyptn->ptnfile_base ,"ssaptn.",VSCAN_MAX_PATH_SIZE);
  ptnlist->next = spyptn;  
  printf("+++++++++++++++ reload pattern start +++++++++++++++\n");
  sleep(1);
  if(vscan_reload_pattern(ptnlist) != VSCAN_SUCCESS);
  {
      printf("Failed to vscan_reload_pattern\n");
  }
  sleep(2);
  printf("--------------- reload engine end ---------------\n");
  
  free(ptnlist);
  free(spyptn);
  
}

void reload_engine(void *p)
{
  pattern_list *ptnlist = NULL,*spyptn = NULL;
  
  ptnlist = (pattern_list *)malloc(sizeof(pattern_list));
  memset(ptnlist,0,sizeof(pattern_list));
  
  spyptn = (pattern_list *)malloc(sizeof(pattern_list));
  memset(spyptn,0,sizeof(pattern_list));
  
  strncpy(ptnlist->ptnpath, "../newpattern",VSCAN_MAX_PATH_SIZE);
  strncpy(ptnlist->ptnfile_base,"lpt$vpn.",VSCAN_MAX_PATH_SIZE);
  strncpy(spyptn->ptnpath,"../newpattern",VSCAN_MAX_PATH_SIZE);
  strncpy(spyptn->ptnfile_base ,"ssaptn.",VSCAN_MAX_PATH_SIZE);
  ptnlist->next = spyptn;  
  printf("+++++++++++++++ reload engine start +++++++++++++++\n");
  sleep(1);
  if(vscan_reload_engine("libvsapi7.so",ptnlist) != VSCAN_SUCCESS)
  {
      printf("Failed to vscan_reload_engine\n");
  }
  sleep(2);
  printf("--------------- reload engine end ---------------\n");
  
  free(ptnlist);
  free(spyptn);
  
}

void change_config(int signo)
{
  protocol_config_t protocol;
  /*grey area*/
  protocol.scan_spyware = 0;
  protocol.scan_adware = 0;
  protocol.scan_dialer = 0;
  protocol.scan_hacktool = 0;
  protocol.scan_joke = 0;
  protocol.scan_remoteaccess = 0;
  protocol.scan_passwdcrack = 0;
  protocol.scan_others = 0;

  protocol.max_scan_loop = 2;
  
  protocol.decompress_layer = 2;
  protocol.extract_file_size_limit = 4 * 1024 * 1024;
  protocol.extract_file_count_limit = 100;
  protocol.extract_file_ratio_limit = 90;
  
  
  protocol.process_all_file = 1;
  protocol.process_all_file_in_arc = 1;

  printf("+++++++++++++++ change config start +++++++++++++++\n");
  if(vscan_set_config(g_handle_vsh, &protocol) != VSCAN_SUCCESS)
  {
      printf("Failed to vscan_set_config\n");
  }
  sleep(2);
  printf("--------------- change config end ---------------\n");
}


void show_virus_result(char *filename, VirusResult *virus_result)
{
    VirusResult *vr=NULL;
    printf("++++++++++++++++++++++++++\n");
    printf("%s\n",filename);
    vr = virus_result;
    /* attach on */
    while(vr)
    {
        if(vr->filename && vr->virusname && vr->majortype)
        {
            printf("vr->filename[%s], vr->virusname[%s], vr->majortype[%s]\n",
            vr->filename,
            vr->virusname,
            vr->majortype);
        }
        vr = vr->next;
    }
    printf("-------------------------\n\n");
}

void show_scan_result(vscan_result_t *scan_result)
{
   printf("scan_result->scan_cb_count = %d\n",scan_result->scan_cb_count);
   printf("scan_result->no_virus_count = %d\n",scan_result->no_virus_count);
   printf("scan_result->virus_count = %d\n",scan_result->virus_count);
   printf("scan_result->spyware_count = %d\n",scan_result->spyware_count);
   printf("scan_result->bot_count = %d\n",scan_result->bot_count);
   printf("scan_result->clean_ok_count = %d\n",scan_result->clean_ok_count);
   printf("scan_result->clean_err_count = %d\n",scan_result->clean_err_count);
   printf("scan_result->err_compressdeep_count = %d\n",scan_result->err_compressdeep_count);
   printf("scan_result->err_filesize_count = %d\n",scan_result->err_filesize_count);
   printf("scan_result->err_filecount_count = %d\n",scan_result->err_filecount_count);
   printf("scan_result->err_fileratio_count = %d\n",scan_result->err_fileratio_count);
   printf("scan_result->err_unhandle_count = %d\n",scan_result->err_unhandle_count);
   printf("scan_result->err_max_scan_loop = %d\n",scan_result->err_max_scan_loop);
}

void *scan_file_thread(void *ptr)
{
   int ret = 0;
   VirusResult *virus_result = NULL;
   vscan_result_t scan_result = {0};
   thread_data_t *data = NULL;
   vscan_runtime_option_t option;
   
   data = (thread_data_t *)ptr;
   
   printf("Thread #%d started\n", (int)data->num);
   
   virus_result = VirusResult_new();
   option.clean = 1;
   printf("file name = %s , file type = %s\n",data->filename,vscan_getcategory_file(data->vsh,data->filename));
   ret = vscan_scan_file(data->vsh,data->filename,data->filename,&option,virus_result,&scan_result,TIMEOUT_PERIOD);
   if(ret == VSCAN_SUCCESS)
   {
       show_virus_result(data->filename,virus_result);
       VirusResult_free(virus_result);
   }
   show_scan_result(&scan_result);
   
   printf("Thread #%d finished\n", (int)data->num);
   
   free(data);
   
   
   return 0;
}

int main(int argc, char *argv[])
{
  struct sigaction act;
  VscanHandle *init_vsh = NULL;
  VscanHandle *handle_vsh = NULL;
  vscan_config_t vscan_config;
  int i;
  pthread_t *threadid;
  
  if(argc!=2)
  {
   fprintf(stderr,"usage: %s <filename>\n",argv[0]);
   return -1;
  }
  threadid = malloc(sizeof(pthread_t) * THREAD_NUM);
  
  act.sa_handler = reload_engine;
  act.sa_flags = 0;
  sigemptyset(&act.sa_mask);
  sigaction(SIGALRM,&act,NULL);
  
  /*alarm(3);*/
  
  /*set VSAPI configuration*/
  memset(&vscan_config, 0, sizeof(vscan_config_t));     
  strncpy(vscan_config.common.tmppath, "/tmp", VSCAN_MAX_PATH_SIZE);
  strncpy(vscan_config.common.ptnpath,"/opt/TrendMicro/pattern", VSCAN_MAX_PATH_SIZE);
  strncpy(vscan_config.common.ptnfile,"lpt$vpn.", VSCAN_MAX_PATH_SIZE);
  strncpy(vscan_config.common.spyptnfile,"ssaptn.",VSCAN_MAX_PATH_SIZE);
  vscan_config.common.max_scan_num = 4;
  vscan_config.common.default_runtime_option.clean = 0;
  
  vscan_config.protocol.scan_spyware = 0;
  vscan_config.protocol.scan_adware = 0;
  vscan_config.protocol.scan_dialer = 0;
  vscan_config.protocol.scan_hacktool = 0;
  vscan_config.protocol.scan_joke = 0;
  vscan_config.protocol.scan_remoteaccess = 0;
  vscan_config.protocol.scan_passwdcrack = 0;
  vscan_config.protocol.scan_others = 0;
  
  vscan_config.protocol.max_scan_loop = 2;
  
  vscan_config.protocol.decompress_layer = 4;
  vscan_config.protocol.extract_file_size_limit = 12 * 1024 * 1024;
  vscan_config.protocol.extract_file_count_limit = 100;
  vscan_config.protocol.extract_file_ratio_limit = 90;
  
  vscan_config.protocol.process_all_file = 1;
  vscan_config.protocol.process_all_file_in_arc = 1; 
  vscan_config.protocol.intelli_scan = 0;
  vscan_config.protocol.virus_enable = 1;
  vscan_config.protocol.compress_enable = 1;
  vscan_config.protocol.spyware_enable = 0;
  vscan_config.protocol.bot_enable = 1;
  
  /*initialize VSAPI*/
  if ((init_vsh = vscan_init(vscan_config)) == NULL)
  {
        printf("Failed to vscan_init\n");
        return -1;
  }
  
  handle_vsh = vscan_create_handle(vscan_config.protocol);
  g_handle_vsh = handle_vsh;
 
  for(i = 0 ; i < THREAD_NUM ; i++)
  {
      thread_data_t *data = NULL;
      data = (thread_data_t *)malloc(sizeof(thread_data_t));
      data->num = i;
      data->filename = argv[1];
      data->vsh = handle_vsh;
//      usleep(50000);
      if(pthread_create(&threadid[i],NULL,scan_file_thread,(void *)data)!=0)
      {
        printf("Failed to create thread\n");
        return -1;
      }
  }
  
  for(i = 0 ; i < THREAD_NUM ; i++)
  {
    if(pthread_join(threadid[i],NULL)!=0)
    {
      printf("Failed to join thread\n");
      return -1;
    }
  }
  
  free(threadid);
  vscan_delete_handle(handle_vsh);
  vscan_fini(init_vsh);
  
  return 0;
}

