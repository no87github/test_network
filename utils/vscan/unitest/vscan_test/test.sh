#!/bin/sh
export LD_LIBRARY_PATH=/opt/trend/lib
for i in ../malware/virus/*
do
./vscan_test $i 
done
