#!/bin/bash

MODULE=`lsmod | grep e1 | awk '{ print $1 }'`

echo "Loaded module :" $MODULE
if [[ $MODULE = "e1000" ]];
  then  exit 1
  else  sudo rmmod $MODULE
fi
sudo insmod /lib/modules/`uname -r`/kernel/drivers/net/ethernet/intel/e1000/e1000.ko
echo "Reload module :" `lsmod | grep e1 | awk '{ print $1 }'`

