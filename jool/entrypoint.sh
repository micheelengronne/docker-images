#!/bin/bash

set -Eeuo pipefail

echo "This script expects that the kernel-headers from the host are mounted in /usr/src"
ln -s /usr/src/linux-headers-$(uname -r)  /lib/modules/$(uname -r)/build

cd /usr/local/src/build
dkms build jool

cp /var/lib/dkms/jool/$JOOL_VERSION/$(uname -r)/$(uname -m)/module/jool_common.ko.zst /lib/modules/$(uname -r)/extra/jool/
cp /var/lib/dkms/jool/$JOOL_VERSION/$(uname -r)/$(uname -m)/module/jool.ko.zst /lib/modules/$(uname -r)/extra/jool/
cp /var/lib/dkms/jool/$JOOL_VERSION/$(uname -r)/$(uname -m)/module/jool_siit.ko.zst /lib/modules/$(uname -r)/extra/jool/

depmod -a

echo 'jool and jool_siit kernel modules are compiled'
modprobe jool
echo 'jool kernel module is enabled'
modprobe jool_siit
echo 'jool_siit kernel module is enabled'

# Set the python script as a CMD
"$@"
