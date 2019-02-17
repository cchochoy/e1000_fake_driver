#!/bin/bash

cd VirtualBox-5.2.10/out/linux.amd64/debug/bin

FILES=`ls | grep 20..-.*\.log`
for i in $FILES; do
	sudo chmod 666 $i
	echo "Cleaning" $i
	> $i
done
echo ""
if [[ $(cat $FILES | wc -l) -eq "0" ]];
	then echo "Cleaning done!"
	else echo "Cleaning failed!"
fi
