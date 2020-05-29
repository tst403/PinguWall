#!/bin/bash

# Functions

# Parameters:
#
# Return:
function init () {
    chmod +x *.sh

    > vm.config
    > server.config

    chmod 644 vm.config
    chmod 644 server.config
}

# Variables

VM_WARE="VirtualBoxVM"
VM_NAME=''
SNAPSHOT_NAME=''

# Code section

init

read -p "Enter VM-Name: " VM_NAME
read -p "Enter Cleaned snapshot-name: " SNAPSHOT_NAME

echo "VM-Name $VM_NAME"             >>vm.config
echo "snapshot-name $SNAPSHOT_NAME" >>vm.config

./init.sh