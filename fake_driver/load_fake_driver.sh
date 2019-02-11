#!/bin/bash

echo "Updating system ..."
sudo apt-get -y -qq update
sudo apt-get -y -qq upgrade

echo ""
echo "Build module ..."
make

echo ""
echo "Removing old driver ..."
sudo rmmod e1000
sudo dmesg -C
sudo insmod e1k.ko
echo "Loaded module :" `lsmod | grep e1 | awk '{ print $1 }'`
