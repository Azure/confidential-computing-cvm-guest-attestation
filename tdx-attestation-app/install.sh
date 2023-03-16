#!/bin/bash

# Install required packages
sudo apt-get install build-essential -y
sudo apt-get install libcurl4-openssl-dev -y
sudo apt-get install cmake -y
sudo apt-get install libjsoncpp-dev -y
sudo apt-get install libboost-all-dev -y

# Install GuestAttestation Debian Package
sudo dpkg -i package/azguestattestation1_1.0.3_amd64.deb

# Give user permission to get report from tdx driver
sudo chmod og=rw /dev/tdx_guest