#!/bin/bash

cd VirtualBox-5.2.10/out/linux.amd64/debug/bin
echo ""
echo "============================================================="
echo "                           CLEAN                             "
echo "============================================================="
sudo rm *.log
sleep 2

echo ""
echo "============================================================="
echo "                           BUILD                             "
echo "============================================================="
cd ../../../..
kmk BUILD_TYPE=debug
sleep 2

echo ""
echo "============================================================="
echo "                          INSTALL                            "
echo "============================================================="
cd out/linux.amd64/debug/bin/src
make
sudo make install
cd ..
sleep 2

echo ""
echo "============================================================="
echo "Go Fucking Bastard!"
echo ""
sudo modprobe vboxdrv
sudo ./VirtualBox --startvm ProjetLong
