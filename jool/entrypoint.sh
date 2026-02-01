#!/bin/bash

set -Eeuo pipefail

rmmod jool_common || true
rmmod jool || true
rmmod jool_siit || true

apt-get update
apt-get install -y linux-headers-$(uname -r) --no-install-recommends
echo 'jool and jool_siit kernel modules are compiled'
modprobe jool
echo 'jool kernel module is enabled'
modprobe jool_siit
echo 'jool_siit kernel module is enabled'

# Reattach the nat64 instance
if [[ $(/usr/bin/jool instance display) == *${JOOL_INSTANCE:-defaultnat64}* ]];
then
    /usr/bin/jool instance remove ${JOOL_INSTANCE:-defaultnat64}
fi

/usr/bin/jool instance add ${JOOL_INSTANCE:-defaultnat64} --netfilter --pool6 ${JOOL_POOL6:-'64:ff9b::/96'}

echo "jool ${JOOL_INSTANCE:-defaultnat64} instance configured"

# Reattach the nat46 instance
if [[ $(/usr/bin/jool_siit instance display) == *${JOOL_INSTANCE_SIIT:-defaultnat46}* ]];
then
    /usr/bin/jool_siit instance remove ${JOOL_INSTANCE_SIIT:-defaultnat46}
fi

/usr/bin/jool_siit instance add ${JOOL_INSTANCE_SIIT:-defaultnat46} --netfilter --pool6 ${JOOL_POOL6:-'64:ff9b::/96'}

echo "jool ${JOOL_INSTANCE_SIIT:-defaultnat46} instance configured"
