CONF_FILE="nat.conf"

## Execution ##

read -d '' sql << EOF
{
"lanIface":"enp0s3",
"wanIface":"enp0s8",
"lanIpMin":"192.168.56.0",
"lanIpNetmask":"255.255.255.0",
"wanIpMin":"192.168.1.0",
"wanIpNetmask":"255.255.255.0",
"defualtGateway":"192.168.1.1"
}
EOF

echo "$sql" > $CONF_FILE