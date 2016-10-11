#!/bin/sh
file_dir=$1
if [ ! -d $file_dir ]; then
    echo "please enter the sample directory!"
    exit -1
fi;
file_list=`find $file_dir/*`
this_sh=$0
i=$2
for file in $file_list; do
#    if [[ -d $file ]]; then
#        $this_sh $file $i
#        i=$?
#    fi;
    if [[ -f $file ]]; then 
        ./send_fd -i $i -f $file
        sleep 1
        i=`expr $i + 1`
    fi;
done;
exit $i
