#!/bin/bash

echo ""
echo "Welcome to our user-friendly script to build VirtualBox locally !"
echo "/!\ For the moment, if an error message appears during the process please stop it and send the log to nicolas.dureisseix@etu.enseeiht.fr"
echo ""
echo "You will need an internet connection during this process."
echo ""
echo ""


echo "--------------------------------------------------------------------------"
echo "Downloading source code in " `pwd`/VirtualBox-5.2.10
echo "--------------------------------------------------------------------------"

wget -nv --show-progress https://download.virtualbox.org/virtualbox/5.2.10/VirtualBox-5.2.10.tar.bz2
sudo apt-get install -y -q pv
pv VirtualBox-5.2.10.tar.bz2 | tar -jx
rm VirtualBox-5.2.10.tar.bz2

if [[ ! -e /etc/debian_version ]]; then
	echo "/!\ Sorry, only Debian-based systems are supported by this script ..."
	exit 1;
fi

echo "--------------------------------------------------------------------------"
echo "Downloading required packages"
echo "--------------------------------------------------------------------------"
echo "+ Common packages ..."
sudo apt-get install -y	-q					\
				kbuild						\
				yasm						\
				gcc-7						\
				g++-7						\
				bcc							\
				acpica-tools				\
				xsltproc					\
				uuid-dev					\
				zlib1g-dev					\
				libidl-dev					\
                libsdl1.2-dev				\
				libxcursor-dev				\
				libasound2-dev				\
				libstdc++5					\
                libpulse-dev				\
				libxml2-dev					\
				libxslt1-dev				\
				libcurl4-openssl-dev		\
                qt5-qmake					\
				qt5-default					\
				qtbase5-dev					\
				qttools5-dev-tools			\
				libcap-dev					\
                libxmu-dev					\
				mesa-common-dev				\
				libglu1-mesa-dev			\
                linux-libc-dev				\
				libvpx-dev					\
				libssl-dev					\
				libpam0g-dev				\
                libxrandr-dev				\
				libxinerama-dev				\
				libqt4-opengl-dev			\
				makeself					\
                libdevmapper-dev			\
				default-jdk					\
				python						\
				python-dev					\
				libqt5x11extras5			\
				libqt5x11extras5-dev		\
                texlive-latex-base			\
				texlive-latex-extra			\
				texlive-latex-recommended	\
                texlive-fonts-extra			\
				texlive-fonts-recommended

if (uname -i | grep -q x86_64); then
	echo "+ 64-bit platform packages ..."
	sudo apt-get install -y	-q			\
					lib32z1				\
					libc6-dev-i386		\
					lib32gcc1			\
					gcc-7-multilib		\
					lib32stdc++6		\
					g++-7-multilib

	echo "+ 64-bit platform symbolic linking ..."
	sudo ln -s	libX11.so.6		/usr/lib32/libX11.so
	sudo ln -s 	libXTrap.so.6	/usr/lib32/libXTrap.so
	sudo ln -s	libXt.so.6		/usr/lib32/libXt.so
	sudo ln -s 	libXtst.so.6	/usr/lib32/libXtst.so
	sudo ln -s 	libXmu.so.6		/usr/lib32/libXmu.so
	sudo ln -s 	libXext.so.6	/usr/lib32/libXext.so
fi

echo "--------------------------------------------------------------------------"
echo "Building VirtualBox"
echo "--------------------------------------------------------------------------"

cd VirtualBox-5.2.10/

until [[ $VBOX_BUILD_KIND =~ (debug|release) ]]; do
	read -rp "What kind of VirtualBox do you want to build ? [debug/release]: " -e VBOX_BUILD_KIND
done

sed -i -e 's/CC="gcc"/CC="gcc-7"/g' configure
sed -i -e 's/CXX="g++"/CXX="g++-7"/g' configure

if [[ $VBOX_BUILD_KIND = "debug" ]];
	then	./configure --build-debug --disable-hardening
	else	./configure --disable-hardening
fi

source ./env.sh

sed -i -e 's/VBOX_JAVAC_OPTS   = -encoding UTF-8 -source 1.5 -target 1.5 -Xlint:unchecked/VBOX_JAVAC_OPTS   = -encoding UTF-8 -source 1.6 -target 1.6 -Xlint:unchecked/g' Config.kmk

if [[ $VBOX_BUILD_KIND = "debug" ]];
	then    kmk BUILD_TYPE=debug
    else    kmk all
fi

cd out/linux.amd64/$VBOX_BUILD_KIND/bin/src
make
sudo make install
cd ..
sudo modprobe vboxdrv

echo ""
echo ""
echo "VirtualBox is ready !"
echo "Launch it thanks to : sudo ./VirtualBox"
echo "./VirtualBox is located at" `pwd`

until [[ $VM_DISK_DL =~ (Y|n) ]]; do
	read -rp "Do you want to download an Ubuntu 18.10 image disk ? [Y/n]: " -e VM_DISK_DL
done

if [[ $VM_DISK_DL = "Y" ]]; then
	cd ../../../../..
	wget -nv --show-progress https://sourceforge.net/projects/osboxes/files/v/vb/55-U-u/18.10/181064.7z
	7z e 181064.7z
	rm 181064.7z
	rm -r 64bit/
	cd out/linux.amd64/$VBOX_BUILD_KIND/bin
fi

VM="ProjetLong"
until [[ $VM_CREATION =~ (Y|n) ]]; do
	read -rp "Do you want to create a VM called "$VM" ? [Y/n]: " -e VM_CREATION
done

if [[ $VM_CREATION = "Y" ]]; then
	sudo ./VBoxManage createvm --name $VM --ostype "Ubuntu_64" --register
	sudo ./VBoxManage storagectl $VM --name "SATA Controller" --add sata --controller IntelAHCI
	sudo ./VBoxManage storageattach $VM --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium ../../../../../Ubuntu*.vdi
	sudo ./VBoxManage modifyvm $VM --memory 8192 --cpus 2 --vram 32
fi

# TODO :
# - check command if an error occured
# - make a file for environnement variable (VM Name ...)
