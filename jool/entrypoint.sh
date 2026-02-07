#!/bin/bash

set -Eeuo pipefail

cd /usr/local/src/build/jool
./configure
make
cp src/mod/common/*.ko /lib/modules/$(uname -r)/extra/jool/
cp src/mod/siit/*.ko /lib/modules/$(uname -r)/extra/jool/
cp src/mod/nat64/*.ko /lib/modules/$(uname -r)/extra/jool/

depmod -a

echo 'jool and jool_siit kernel modules are compiled'
modprobe jool
echo 'jool kernel module is enabled'
modprobe jool_siit
echo 'jool_siit kernel module is enabled'

# Set the python script as a CMD
"$@"
