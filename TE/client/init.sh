#!/bin/bash

# Variables

VM_CONFIG_FILENAME="vm.config"
VM_NAME=''
VM_IP=''
SNAPSHOT_NAME=''
SERVER_IP=''
TE_USER='te'
SSH_KEY_PATH='/home/dindibo4/.ssh/id_rsa'
WAIT_TIME=10

# Functions

# Parameters: 
# 1 - Server IP
# 2 - Command to execute
# Return:
function executeRemoteCommand () {
    ssh -l $TE_USER -i $SSH_KEY_PATH $1 '$2'
}

# Code section

VM_NAME=`cat $VM_CONFIG_FILENAME | grep -i VM-Name | cut -d ' ' -f 2-`
SNAPSHOT_NAME=`cat $VM_CONFIG_FILENAME | grep -i snapshot-name | cut -d ' ' -f 2-`

# Revert to snapshot
VBoxManage snapshot $VM_NAME restore $SNAPSHOT_NAME 2> /dev/null

# Start VM Headlessly
VBoxManage startvm $VM_NAME --type headless

sleep $WAIT_TIME

# Get VM IP
SERVER_IP=`VBoxManage guestproperty enumerate UbuntuMate-VM | grep /VirtualBox/GuestInfo/Net/0/V4/IP | cut -d ',' -f2 | cut -d ' ' -f3`

executeRemoteCommand $SERVER_IP ls
