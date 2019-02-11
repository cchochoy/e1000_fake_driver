# e1000_vulnerability_exploit

## Installation

> $ ./install.sh

Only own version build are supported yet. Please choose *own* and *debug* to build your debug version.

Warning : During the process an error can occur, especially during the sources compilation. You can have something like "Exit with error status 2."

Please contact us at nicolas.dureisseix@etu.enseeiht.fr if an error occurs.

## Debug

Use RTLogPrintf(string, args) to print debug message. The debug will go into .log files in VirtualBox folder.

You can use `cleanlog.sh` script to clean all logs and `printlog.sh` to print them in the console.

## VM

There is not script for VM creation/management yet. Please create a VM called ProjetLong with 2CPU Cores and 8Gb RAM.

Load `e1k.c`, `e1k_utils.h` and `Makefile` the VM.

Use 

> $ make

and

> # rmmod e1000; insmod e1k.ko

to load fake driver. 

## Note

Some scripts will arrive to make it easier for users, on VM and VMM.
