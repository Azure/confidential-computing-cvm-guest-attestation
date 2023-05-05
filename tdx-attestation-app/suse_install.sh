#!/bin/bash

# sudo rpm --import https://packman.inode.at/keys/packman.key
sudo zypper ar -cfp 90 https://ftp.fau.de/packman/suse/openSUSE_Tumbleweed/ packman
sudo zypper addrepo -f https://download.opensuse.org/distribution/leap/15.5/repo/oss/ openSUSE-0ss

# Update
sudo zypper --gpg-auto-import-keys refresh

# Install required packages
sudo zypper install -y -t pattern devel_basis
sudo zypper install -y cmake
sudo zypper install -y nlohmann_json-devel
sudo zypper install -y libcurl4
sudo zypper install -y libcurl-devel
sudo zypper install -y libboost_headers1_75_0-devel

# Install GuestAttestation Debian Package
sudo rpm --nosignature -i package/azguestattestation1-1.0.5-2.x86_64.rpm

# Update the Linker cache
sudo ldconfig