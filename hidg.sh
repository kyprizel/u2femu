#!/bin/bash

N="usb0"

modprobe -r g_ether


modprobe -r g_cdc
modprobe libcomposite
modprobe usb_f_acm
modprobe usb_f_hid
modprobe usb_f_rndis
modprobe usb_f_ecm
modprobe usb_f_serial

sleep 1s

cd /sys/kernel/config/usb_gadget/

mkdir -p usb_armory
cd usb_armory

echo 0x1050 > idVendor # Yubico?
echo 0x0407 > idProduct # Multifunction Composite Gadget
echo 0x0100 > bcdDevice # v1.0.0
echo 0x0200 > bcdUSB # USB2

mkdir -p strings/0x409
echo "fedcba9876543210" > strings/0x409/serialnumber
echo "InversePath" > strings/0x409/manufacturer
echo "USBArmory U2F" > strings/0x409/product

mkdir -p functions/acm.$N
mkdir -p functions/ecm.$N
mkdir -p functions/hid.$N
#mkdir -p functions/mass_storage.$N

HOST="1a:55:89:a2:69:42" # "HostPC"
SELF="1a:55:89:a2:69:41" # "BadUSB"
echo $HOST > functions/ecm.$N/host_addr
echo $SELF > functions/ecm.$N/dev_addr

# https://github.com/crmulliner/hidemulation
echo 0 > functions/hid.usb0/protocol
echo 0 > functions/hid.usb0/subclass
echo 64 > functions/hid.usb0/report_length
echo -ne "\x06\xd0\xf1\x09\x01\xa1\x01\x09\x20\x15\x00\x26\xff\x00\x75\x08\x95\x40\x81\x02\x09\x21\x15\x00\x26\xff\x00\x75\x08\x95\x40\x91\x02\xc0" > functions/hid.usb0/report_desc

C=1
mkdir -p configs/c.$C/strings/0x409
echo "Config $C: ECM network" > configs/c.$C/strings/0x409/configuration
echo 250 > configs/c.$C/MaxPower
ln -s functions/acm.$N configs/c.$C/
ln -s functions/ecm.$N configs/c.$C/
ln -s functions/hid.$N configs/c.$C/

ls /sys/class/udc > UDC

chmod 666 /dev/hidg0

ifconfig usb0 10.0.0.1 netmask 255.255.255.252 up
route add -net default gw 10.0.0.2
