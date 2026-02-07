#!/bin/bash

set -Eeuo pipefail

apt-get update
arch=$(uname -m)

if [ "$arch" = "x86_64" ]; then
    apt-get install -y linux-headers-amd64 --no-install-recommends
elif [ "$arch" = "aarch64" ]; then
    apt-get install -y linux-headers-arm64 --no-install-recommends
else
    echo "other architecture not supported: $(uname -m)"
    exit 250
fi
echo 'jool and jool_siit kernel modules are compiled'
modprobe jool
echo 'jool kernel module is enabled'
modprobe jool_siit
echo 'jool_siit kernel module is enabled'

# Set the python script as a CMD
"$@"
