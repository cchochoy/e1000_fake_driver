#!/bin/bash

echo "Updating system ..."
sudo apt-get -y -q update
sudo apt-get -y -q upgrade

echo ""
echo "Remove previous build ..."
rm *.symvers
rm *.ko
rm *.o
rm *.mod*
rm *.order

echo ""
echo "Build module ..."
make

echo ""
echo "Removing old driver ..."
sudo rmmod e1000
sudo dmesg -C
sudo insmod e1k.ko
echo "Loaded module :" `lsmod | grep e1 | awk '{ print $1 }'`
