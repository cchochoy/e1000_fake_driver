#!/bin/bash
echo ""
echo "Remove previous build ..."
make clean

echo ""
echo "Build module ..."
make

echo ""
MODULE=`lsmod | grep e1 | awk '{ print $1 }'`
echo "Loaded driver :" $MODULE
echo "Removing old driver ..."
sudo rmmod $MODULE
sudo dmesg -C
sudo insmod e1k.ko
dmesg
