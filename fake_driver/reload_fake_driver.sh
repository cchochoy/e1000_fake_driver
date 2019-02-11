#!/bin/bash

sudo rmmod e1k
rm *.symvers
rm *.ko
rm *.o
rm *.mod*
rm *.order

make
sudo dmesg -C
sudo insmod e1k.ko
echo "Loaded module :" `lsmod | grep e1 | awk '{ print $1 }'`

