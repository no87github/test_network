#!/bin/sh

export LD_LIBRARY_PATH=../src

echo "<< READ all"
./mpctl -r all -t string
echo ">> RETURN: $?"
echo
echo "<< READ modules.mpm.worker.stats"
./mpctl -r modules.mpm.worker.stats -t string
echo ">> RETURN: $?"
echo
echo "<< READ system.log.level"
./mpctl -r system.log.level -t int32
echo ">> RETURN: $?"
echo
echo "<< WRITE system.log.level"
./mpctl -w system.log.level -t int32 3
echo ">> RETURN: $?"
echo
echo "<< READ system.log.level"
./mpctl -r system.log.level -t int32
echo ">> RETURN: $?"
