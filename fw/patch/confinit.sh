#!/bin/bash

CONF_FILE="nat.conf"

## Execution ##

read -d '' sql << EOF
{
"lanIface":"enp0s8",
"wanIface":"enp0s3",
"lanIpMin":"192.168.217.0",
"lanIpNetmask":"255.255.255.0",
"wanIpMin":"10.0.2.0",
"wanIpNetmask":"255.255.255.0",
"defualtGateway":"10.0.2.2"
}
EOF

echo "$sql" > $CONF_FILE