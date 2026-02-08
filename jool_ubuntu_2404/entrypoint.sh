#!/bin/bash

set -Eeuo pipefail

apt-get update
apt-get install -y linux-headers-$(uname -r) --no-install-recommends
echo 'jool and jool_siit kernel modules are compiled'
modprobe jool
echo 'jool kernel module is enabled'
modprobe jool_siit
echo 'jool_siit kernel module is enabled'

# Set the python script as a CMD
"$@"
