#!/bin/bash

set -Eeuo pipefail

rmmod jool_common
rmmod jool
rmmod jool_siit

apt-get update
apt-get install -y linux-headers-$(uname -r) --no-install-recommends
echo 'jool kernel module is compiled'
modprobe jool
echo 'jool kernel module is enabled'

if [[ $(/usr/bin/jool instance display) != *${JOOL_INSTANCE:-default}* ]];
then
    /usr/bin/jool instance add ${JOOL_INSTANCE:-default} --netfilter --pool6 64:ff9b::/96;
fi

echo "jool ${JOOL_INSTANCE:-default} instance configured"
