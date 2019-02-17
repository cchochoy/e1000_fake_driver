#!/bin/bash

cd VirtualBox-5.2.10/out/linux.amd64/debug/bin

FILES=`ls | grep 20..-.*\.log`
sudo cat $FILES
