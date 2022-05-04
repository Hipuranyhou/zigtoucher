#!/bin/bash

#################################################################
#                                                               #
#   This script expects and was tested on Ubuntu 20.04.3 LTS.   #
#   It prepares the system for and installs zigtoucher.         #
#                                                               #
#                 !!! DO NOT RUN AS ROOT !!!                    #
#                                                               #
#################################################################

print_status() {
        if [ ! -t 1 -o -z "$(tput colors)" ]; then
                echo "${1}"
        fi
        echo "$(tput rev)$(tput bold) ${1} $(tput sgr0)"
}

warn() {
        if [ ! -t 1 -o -z "$(tput colors)" ]; then
                echo "${1}"
        fi
        echo
        echo "$(tput setaf 3)$(tput bold) ${1} $(tput sgr0)"
        echo
}

confirm() {
        read -p "${1} Do you want to continue [Y/n]? " confirmation
        confirmation=${confirmation:-y}
        if [ "${confirmation}" == "y" -o "${confirmation}" == "Y" ]; then
                true
        else
                false
        fi
}

# make sure we are up to date
print_status "apt update"
if confirm "Update system packages?"; then
        sudo apt update && sudo apt upgrade
else
        warn "Packages may be not up to date."
fi

# install dependencies
print_status "Installing dependencies"
sudo apt install -y \
        git \
        build-essential \
        cmake \
        doxygen \
        graphviz \
        ipython3 \
        libgcrypt20 \
        libgcrypt20-dev \
        liborc-0.4-0 \
        liborc-0.4-dev \
        libpcap0.8 \
        libpcap0.8-dev \
        libuhd-dev \
        libuhd3.15.0 \
        libx11-dev \
        python3-autopep8 \
        python3-crypto \
        python3-cryptography \
        python3-dev \
        python3-matplotlib \
        python3-pyx \
        python3-setuptools \
        python3-tabulate \
        python3-termcolor \
        python3-xdg \
        python3-yaml \
        swig \
        uhd-host \
        wireshark \
        wireshark-dev

# consts
readonly ZIGTOUCHER_SETUP_BASE_DIR="$(pwd)"
readonly ZIGTOUCHER_SETUP_BUILD_DIR="${ZIGTOUCHER_SETUP_BASE_DIR}/build"
readonly ZIGTOUCHER_GLOBAL_CONF_DIR="/usr/local/etc/zigtoucher"
readonly ZIGTOUCHER_USER_CONF_DIR="${XDG_CONFIG_HOME:-${HOME}/.config}/zigtoucher"

# setup work dir
cd "${ZIGTOUCHER_SETUP_BASE_DIR}"
mkdir -p "${ZIGTOUCHER_SETUP_BUILD_DIR}"

# setup scapy-radio
print_status "Getting scapy-radio"
cd "${ZIGTOUCHER_SETUP_BUILD_DIR}"
git clone https://github.com/Hipuranyhou/scapy-radio.git
cd scapy-radio
git checkout maint-3.8
print_status "Customizing scapy-radio"
cp "${ZIGTOUCHER_SETUP_BASE_DIR}/setup/grc/zigtoucher.grc" gnuradio/grc
echo "https://github.com/bastibl/gr-foo.git" >>gnuradio/blocks.txt
echo "https://github.com/bastibl/gr-ieee802-15-4.git" >>gnuradio/blocks.txt
echo "https://github.com/Hipuranyhou/gr-zigbee.git" >>gnuradio/blocks.txt
cp "${ZIGTOUCHER_SETUP_BASE_DIR}/setup/patch/scapy/zll.patch" patch/scapy
print_status "Installing scapy-radio"
./install.sh

# setup our tool
print_status "Installing zigtoucher"
cd "${ZIGTOUCHER_SETUP_BASE_DIR}"
sudo python3 setup/setup.py install

# configuration files
print_status "Installing zigtoucher configuration files"
cd "${ZIGTOUCHER_SETUP_BASE_DIR}"
sudo mkdir -p "${ZIGTOUCHER_GLOBAL_CONF_DIR}"
mkdir -p "${ZIGTOUCHER_USER_CONF_DIR}"
sudo cp setup/config/zigtoucher.yml "${ZIGTOUCHER_GLOBAL_CONF_DIR}"
cp setup/config/zigtoucher.yml "${ZIGTOUCHER_USER_CONF_DIR}"

# setup uhd
print_status "Setting up uhd"
cd "${ZIGTOUCHER_SETUP_BASE_DIR}"
sudo groupadd usrp >/dev/null 2>&1
if confirm "Set rtprio for group usrp in /etc/security/limits.conf?"; then
        sudo usermod -aG usrp "${USER}"
        echo '@usrp - rtprio  99' | sudo tee -a /etc/security/limits.conf >/dev/null
else
        warn "Please disable realtime priority in the provided GRC file."
fi
sudo uhd_images_downloader

# setup python
print_status 'Setting up .bashrc (PYTHONPATH)'
cd "${ZIGTOUCHER_SETUP_BASE_DIR}"
if confirm "Set PYTHONPATH=/usr/local/lib/python3/dist-packages in bashrc?"; then
        echo "export PYTHONPATH=/usr/local/lib/python3/dist-packages" >>"${HOME}/.bashrc"
        . "${HOME}/.bashrc"
else
        warn "Please add /usr/local/lib/python3/dist-packages to PYTHONPATH."
fi

# ask for reboot for all updates and user group changes to take effect
print_status "Reboot"
cd "${ZIGTOUCHER_SETUP_BASE_DIR}"
if confirm "Reboot for all changes to take effect?"; then
        reboot
fi
