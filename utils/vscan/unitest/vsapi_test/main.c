/* 
 *  Test program for vsapi
 */

#include <tmvs.h>   /*vsapi header*/
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include "msr.h"

int scan_method = 0;

int PASCAL EXPORT ScanProcessFile(long vsc, VSPFCB *pf, int time, int *action) {

    if(time == 1)
    {
      switch(pf->pfcb_status)
      {
        case 0:
          printf("No virus\n");
        break;
        case MAXDECOM_ERR:
         printf("comp deep\n");
        break;
        case EXTRACT_TOO_BIG_ERR:
       break;
    }
    VIRINFO *pvirinfo = (VIRINFO *) (pf->pfcb_Info);

     if(pvirinfo&&pvirinfo->vi_VirusName)
     {
      printf("Infected virus: %s in %s\n",pvirinfo->vi_VirusName,pf->pfcb_FileName);
     }
    }
    return 0;

}

void LoadPattern(VSCTYPE vc,char* PatternPath) {

    char PatternName[] = "lpt$vpn." ;
    char SpyPatternName[] = "ssaptn.";
    char NewestPattern[3]; 
    int ret = 0;
    if((ret = VSSetPatternPath(vc,PatternPath)) == 0) 
        printf("Set virus pattern searching path to %s\n",PatternPath);
    if((ret = VSFindNewestPattern(vc,PatternPath,PatternName,NewestPattern)) == 0)
        printf("The Newest Pattern file is : %s\n",NewestPattern);

    if((ret = VSReadVirusPattern(vc, 0, PatternName, 0)) == 0)
        printf("Virus Pattern is loaded\n");

    if((ret = VSReadVirusPattern(vc, 0, SpyPatternName, 0)) == 0)
        printf("Spyware Pattern is loaded\n");
}

void SetConfig(VSCTYPE vc)
{
    int ret;
    if((ret = VSSetDecompressLayer (vc, 2))<0)
     {
        printf("failed to VSSetDecompressLayer\n");
        return;
     }

    VSSetProcessFileCallBackFunc(vc, ScanProcessFile);


   VSSetConfig(vc, VSCFG_GREY_FLAG ,VSGREY_SPYWARE|VSGREY_ADWARE|VSGREY_DIALER|VSGREY_HACKTOOL|VSGREY_JOKE|VSGREY_REMOTEACCESS|VSGREY_PASSWDCRACK , NULL);  
   if(scan_method == 0)
   {
     int rc = -1;
   VSSetActiveScanFlag(vc,0);
   VSSetProcessAllFileFlag(vc,1);
   VSSetProcessAllFileInArcFlag(vc,1);
   }
   else if(scan_method == 1)
   { 
    VSSetActiveScanFlag(vc,1);
   VSSetProcessAllFileFlag(vc,1);
   VSSetProcessAllFileInArcFlag(vc,0);
   }
   else
   {
    VSSetActiveScanFlag(vc,0);
    VSSetProcessAllFileFlag(vc,0);
    VSSetProcessAllFileInArcFlag(vc,0);
   }
}

int main(int argc, char *argv[]) {

    VSCTYPE vc;
    RESOURCE res;  
    int ret = 0;
    int i; 
    unsigned long long tm1, tm2;
    int pattern_version = 0;
    DIR *dp;
    struct dirent *entry;
    if(argc!=5)
    {
      fprintf(stderr,"Usage:%s <pathname> <loop> <pattern:0(old),1(new)> <scan:0(full),1(intelli)>\n",argv[0]);
      return -1;
    }

    /*Initialize scan engine*/
    if(VSInit(0, "test", 0, &vc) != 0)  
    {
      printf("failed to VSInit\n");
      return -1;
    }
    
    /*Load virus/spyware pattern*/
    pattern_version = atoi(argv[3]);    
    if(pattern_version == 0)
      LoadPattern(vc,"../pattern");
    else
      LoadPattern(vc,"../newpattern");

    scan_method = atoi(argv[4]);

    /*Setup vsapi's configuration*/
    SetConfig(vc);

    /*scanning*/
    if((dp = opendir(argv[1]))== NULL)
    {
      printf("failed to opendir\n");
      return -1;
    }
    chdir(argv[1]);
    rdtscll(tm1);
    while((entry = readdir(dp)) != NULL)
    {
#if 1
      res.r_File = entry->d_name;
      res.r_Name = entry->d_name;
      res.r_Handle = 0;
      res.r_Type = 0;
      VSOpenResource(res.r_File,res.r_Type,VS_READ,0,0,&res.r_Handle);
      for( i=0 ; i < atoi(argv[2]) ; i++)
        ret = VSScanResource(vc, &res, 0);
      VSCloseResource(res.r_Handle);
      
#else
      VSVirusScanFile(vc,entry->d_name,0);
#endif
    }
    rdtscll(tm2);
    printf("Elapsed time of virus scanning = %llu\n",tm2-tm1);
    /*quit scan engine*/
    VSQuit(vc);
    chdir("../vsapi_test");
    closedir(dp);
    return 0;
}

 
