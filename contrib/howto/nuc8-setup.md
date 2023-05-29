## Setup Intel NUC8 Demo Unit

### Bill of Materials
- [Intel® NUC 8 Rugged Kit NUC8CCHKRN](https://ark.intel.com/content/www/us/en/ark/products/214634/intel-nuc-8-rugged-kit-nuc8cchkrn.html)
- [2TB M.2 SSD](https://www.newegg.com/samsung-970-evo-plus-2tb/p/N82E16820147744?Description=2tb%20m.2&cm_re=2tb_m.2-_-20-147-744-_-Product)
- [Discovery kit with STM32F413ZH MCU](https://www.st.com/en/evaluation-tools/32f413hdiscovery.html)

### Boot Media
- [How to write/create a Ubuntu .iso to a bootable USB device on Linux using dd command](https://www.cyberciti.biz/faq/creating-a-bootable-ubuntu-usb-stick-on-a-debian-linux/)
- [How to Install Ubuntu 22.04 LTS (Jammy Jellyfish) On UEFI and Legacy BIOS System](https://www.itzgeek.com/how-tos/linux/ubuntu-how-tos/how-to-install-ubuntu-22-04-lts.html)

### Physical Setup
- Install SSD in Mini-PC
- Install Rubber Feet
- Attach Display temporarily
- Attach Keyboard temporarily

### Setup BIOS
Press `F2` during boot.

Change to:  `Power` -> `Secondary Power Settings` -> `After power failure: Last State`

### Ubuntu Installation Boot

The Boot Menu key is F10 if you are already running something else.

#### Partition the onboard disk:

1. Choose "Minimal Installation", no third-party drivers
1. "Erase disk and install Ubuntu"
1. "Advanced Partitioning Tool"

Format the onboard SSD ("mmcblk0"), create a single primary partition using all
available space. Set the `Use as:` to "do not use the partition" (it will be
modified later when we setup the mirror).  Note the size of this
created partition, it will be used in the next step.

#### Partition the SSD ("nvme0"):

| Partition| Size |
| -------- | -------- |
| Reserved BIOS boot area | 1 MB |
| EFI | 1 GB |
| swap | 64G |
| explicit-unused | same-size-as-onboard-unused-above |
| / | remaining-space |

Install Desktop [mininal, I think]

Create a user named `user`

[lots missing here, getting on local network, etc]
    
### Setup System

Update `/etc/sudoers` so you don't need passwd:
```
--- sudoers~	2022-02-08 00:41:40.000000000 -0800
+++ sudoers	2022-11-15 13:02:56.031830429 -0800
@@ -47,7 +47,8 @@
 %admin ALL=(ALL) ALL
 
 # Allow members of group sudo to execute any command
-%sudo	ALL=(ALL:ALL) ALL
+# %sudo	ALL=(ALL:ALL) ALL
+%sudo	ALL=(ALL:ALL) NOPASSWD: ALL
 
 # See sudoers(5) for more information on "@include" directives:
```

Update system and basics
```
sudo apt update
sudo apt upgrade
sudo apt install openssh-server -y
sudo apt install dbus-x11 -y
sudo apt install sqlite -y
sudo apt install vim -y
sudo apt install lowdown -y
sudo apt install lm-sensors -y
sudo apt install gitk -y
```

Consider setting up `user`'s `~/.ssh` to allow remot login.

To turn off the wireless network interface and only use the wired network (optional):
```
nmcli connection show

sudo nmcli device connect enp2s0
sudo nmcli connection modify enp2s0 connection.autoconnect yes

sudo nmcli radio wifi off
sudo nmcli connection modify 'Your ESSID' connection.autoconnect no
```

Consider disabling X windows (optional0:
```
sudo systemctl stop display-manager
sudo systemctl disable display-manager
```

Enable sysstat to track system resources:
```
sudo apt install sysstat -y
sudo vim /etc/default/sysstat
> ENABLED="true"
sudo systemctl enable sysstat
sudo systemctl start sysstat
```

Setup mirror:
```
sudo apt install mdadm -y
sudo lsblk # find the matching unused partitions
sudo mdadm --create --verbose /dev/md0 --level=1 --raid-devices=2 \
    /dev/mmcblk0p1 \
    /dev/nvme0n1p4
sudo mkfs.ext4 -F /dev/md0
sudo mkdir -p /mnt/md0
sudo mount /dev/md0 /mnt/md0
sudo mdadm --detail --scan | sudo tee -a /etc/mdadm/mdadm.conf
sudo update-initramfs -u
echo '/dev/md0 /mnt/md0 ext4 defaults,nofail,discard 0 0' | sudo tee -a /etc/fstab
```

#### Move CLN onto the mirror

This must be done later, after the `cln` user has been created and
it's home directory populated ...

Transplant ~cln onto the mirror:
```
sudo mkdir -p /mnt/md0/home
sudo rsync -av /home/cln /mnt/md0/home/
sudo mv /home/cln /home/cln.old
cd /home && sudo ln -s /mnt/md0/home/cln
# make sure ~cln is a happy place
sudo rm -rf /home/cln.old
```
