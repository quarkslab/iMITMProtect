#!/bin/bash
killall imagent
echo "waiting a few"
sleep 10
pid=`ps -e | grep imagent | grep -v grep | grep -v $0 | awk '{ print $1 }'`
echo "Overriding PID: $pid"
./tester $pid override.dylib
tail -n 10 /var/log/system.log
