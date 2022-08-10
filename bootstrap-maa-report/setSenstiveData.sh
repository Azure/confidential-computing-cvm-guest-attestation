#!/bin/bash

export TF_VAR_appadminUsername=`cat /Users/appuser1/.secrets/sensitive.txt|grep appadminUsername|awk '{print $2}'`
export TF_VAR_appadminPassword=`cat /Users/appuser1/.secrets/sensitive.txt|grep appadminPassword|awk '{print $2}'`
export TF_VAR_adminPublicKey=`cat ~/.ssh/app1_maa_key.pub`
export TF_VAR_backendPoolId="/subscriptions/xxxxxxx-yyyyyyy-23dddddd34-zzzzzz332sgm/resourceGroups/app1-conf-compute/providers/Microsoft.Network/loadBalancers/app1-lb/backendAddressPools/app1-lbbepool"
export TF_VAR_confidentialDiskEncryptionSetId="app1-mhsm-disk-encryption-set"
export TF_VAR_resource_group_name="app1-conf-compute"
export TF_VAR_resource_group_name_des="des-app1-cc"
export TF_VAR_storage_account="app1sa"
export TF_VAR_virtual_network_name="app1-vnet1"
export TF_VAR_vnet_resource_group="app1-conf-compute"
