#!/bin/sh
#export LD_LIBRARY_PATH=/opt/TrendMicro/_PRJNMAE_/lib
for i in ../malware/virus/*
#for i in ../malware/normal/*
do
./vscan_test_fd $i 
done
