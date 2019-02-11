# e1000_vulnerability_exploit

## Installation

> $ ./install.sh

Only own version build are supported yet. Please choose *own* and *debug* to build your debug version.

Warning : During the process an error can occur, especially during the sources compilation. You can have something like "Exit with error status 2."

Please contact us at nicolas.dureisseix@etu.enseeiht.fr if an error occurs.

## Debug

Use RTLogPrintf(string, args) to print debug message. The debug will go into .log files in VirtualBox folder.

Look into the files :

* src/VBox/Devices/Network/DevE1000 .cpp / .h ;

* src/VBox/Devices/Network/DevEEPROM .cpp / .h.

You can use `cleanlog` script to clean all logs and `printlog` to print them in the console.

## VM

There is not script for VM creation/management yet. Please create a VM called ProjetLong with 2CPU Cores and 8Gb RAM.

Download `fake_driver` folder into the VM and run `load_fake_driver`. Use `reload_fake_driver` if you have already load the driver and you want to apply changes.

## Note

Some scripts will arrive to make it easier for users, on VM and VMM.
