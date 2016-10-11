#!/bin/sh

# owner id or name
OWNER=0
# group id or name
GROUP=0
PRJNAME=_PRJNAME_
CONFIG_FILE=/opt/TrendMicro/${PRJNAME}/etc/filescan.conf
PID_FILE=/var/run/filescan.pid
LOG_FILE=/var/log/filescan.log

ARCH=_ARCH_

if [ "${ARCH}" = "x86_64" ]; then
	LIB=lib64
	ENGINE=engine
else
	LIB=lib
	ENGINE=engine
fi

export LD_LIBRARY_PATH=/opt/TrendMicro/${PRJNAME}/${LIB}:/opt/TrendMicro/${PRJNAME}/${ENGINE}
export MALLOC_MMAP_THRESHOLD_=61440

start()
{
    ulimit -n 5000
    find /var/fs2_tmp -name 'V*' -type f -print0 | xargs -0 rm -f
    exec /opt/TrendMicro/${PRJNAME}/bin/filescan
}

stop()
{
    if [ -e ${PID_FILE} ]
    then
        /bin/kill -TERM $(cat ${PID_FILE})
        rm ${PID_FILE}
    fi
}

#NOTE: Currently we don't support filescan.sh reload 
#      for fear of the confusion on implicit reload actions.
#
#reload()
#{
#    /opt/TrendMicro/${PRJNAME}/bin/fsctl -x filescan.reload_config -t raw 0
#    /opt/TrendMicro/${PRJNAME}/bin/fsctl -x vscan.reload_config -t raw 0
#}

case "$1" in
    start)
        start
        ;;
    stop)
        stop
        ;;
#   reload)
#       reload
#       ;;
    debug)
        echo run --config-file=${CONFIG_FILE} --pid-file=${PID_FILE} --log-file=${LOG_FILE}
        gdb /opt/TrendMicro/${PRJNAME}/bin/filescan
        ;;
    *)
        echo "Usage: $0 {start|stop|debug}"
esac
