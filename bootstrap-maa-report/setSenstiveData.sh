#!/bin/bash

export TF_VAR_appadminUsername=`cat /Users/s.kondla/.secrets/sensitive.txt|grep appadminUsername|awk '{print $2}'`
export TF_VAR_appadminPassword=`cat /Users/s.kondla/.secrets/sensitive.txt|grep appadminPassword|awk '{print $2}'`
export TF_VAR_adminPublicKey=`cat ~/.ssh/app1_key.pub`
export TF_VAR_backendPoolId="/subscriptions/xxxxxxxx-23sdsd-23333yyyds-ccss3-sshgtu345/resourceGroups/app1-conf-compute/providers/Microsoft.Network/loadBalancers/app1-lb/backendAddressPools/app1-lbbepool"
export TF_VAR_confidentialDiskEncryptionSetId="App1-HSM-Encryption-Set"
export TF_VAR_resource_group_name="app1-conf-compute"
export TF_VAR_resource_group_name_des="cc-app1-rg"
export TF_VAR_storage_account="confcomputesa"
export TF_VAR_virtual_network_name="app1-vnet1"
export TF_VAR_vnet_resource_group="app1-conf-compute"
