# Assistant for securely decrypting zfs drives automatically on boot

[![Lint status](https://github.com/sophonet/zfskeyprovider/actions/workflows/check.yml/badge.svg)](https://github.com/sophonet/zfskeyprovider/actions/workflows/check.yml)

## Concept

ZFS has the ability to encrypt content on hard drives, which is an important aspect when
storing personal data. In that case, when a device holding the data (for example a NAS)
is stolen, the stored data cannot be read by third parties.

During boot, the NAS system has to know the zfs encryption key in order to decrypt file systems
for further use. Entering information manually is cumbersome, since it requires an administrator
to log on the the NAS and run a couple of commands interactively. This is especially difficult
if the administrator cannot access the NAS system, e.g. while traveling.

This repository provides a solution for automatically decrypting ZFS drives on boot by utilizing
a second device providing an encrypted version of the key.

The zfs system, during boot, retrieves the encrypted key,
decrypts it with a local private key and uses the output (the unencrypted zfs key)
for decrypting the zfs filesystems.

The encrypted key could be stored on a public web site. However if the main system (e.g. the NAS) is stolen,
it should be deleted as soon as possible since otherwise the combination of the local SSL key on the NAS
and the publicly accessible encrypted key might be used to retrieve the zfs key used for encrypting
personal data.

This repository provides functionality for a custom web server e.g. running in the same local network. 
Both, the device running the web server and the NAS itself keep the encrypted password in /dev/shm
(shared memory), so the information is gone after power off, hence, the key is not available anymore if
the devices are stolen.

The device running the web service presents a form for entering the encrypted
key if it is not yet known, e.g. after powering up.

In order to further simplify the setup, the web service is also running on the NAS itself. Both services are identical
and first try to retrieve the encrypted key from the other system. Therefore, entering the encrypted key manually
via a web form is only necessary if both devices are turned off at the same time. In that case, the web server of the
secondary device should first be contacted to enter the encrypted key via a form. After that, the NAS should be turned on/
rebooted such that it can retrieve the key for decrypting filesystems.

An attacker therefore must be able to retrieve the encrypted key from one of the two systems while the devices are
running and therefore "steal" one of the IP addresses and additionally get hold of the SSL key locally stored on the NAS,
or hack into the NAS and inspect the password file in /dev/shm while it is running. For a home server, this is
an extremely unlikely situation.

In order to avoid special characters, encrypted zfs key is base64 encoded.

Remark: The secondary device might also be an arduino low power device. A template remote_system_arduino/main.cpp might be used for that purpose. However, it does not implement the functionality of initial retrieval of the encrypted password on initialization as well as restricting the /password route to a particular IP address, since development has stopped. In order to avoid storing the WPA key for WiFi on the system, an initial captive portal is started asking for information for connecting to the home network. The source file targets an ESP32 and has been
compiled with the PlatformIO extension of Visual Studio Code.

## Preparation

Note: The steps below might be automated via ansible - see https://github.com/sophonet/zfskeyprovider-role

### Prerequisites:

1. A good password for encrypting zfs filesystems, e.g. an automatically generated random character sequence. This password shall be stored in the file /dev/shm/zfspwd on the NAS. Additionally a copy shall be stored in a password manager or similar, since it shall not be lost.
2. An SSL public/private keypair:

```
openssl genpkey -algorithm RSA -out private_key.pem
openssl rsa -pubout -in private_key.pem -out public_key.pem
```
3. A running ZFS system (see e.g. https://openzfs.github.io/openzfs-docs/Getting%20Started/Debian/index.html and additional hints for UEFI boot https://forums.debian.net/viewtopic.php?t=154555:)

### Create encrypted file systems

```
zfs create -o encryption=on -o keylocation=file:///dev/shm/zfspwd -o keyformat=passphrase *zfspool*/*zfsfilename*
```

### Generate base64-encoded encrypted password

```
openssl pkeyutl -encrypt -pubin -inkey public.key -in /dev/shm/zfspwd -out encrypted.bin
base64 encrypted.bin > encrypted.b64
```

### Installation on secondary Linux device

1. Copy zfskeyprovider.py to /usr/local/bin on secondary device and adjust the IP address
   at the top (```partner_host```) to the one of the NAS
2. Copy zfskeyprovider.service to /etc/systemd/system and run
```
systemctl daemon-reload
systemctl enable --now zfskeyprovider
```
3. Enter the base64-encoded encrypted key (content of encrypted.b64) in webserver on port 8080

### Installation on primary device (NAS)

1. Follow steps 1. and 2. above for primary device, i.e. enter IP address of secondary device as
   ```partner_host```
2. Copy zfs-load-key.service to /etc/systemd/system and replace REMOTEIP with address of secondary device
3. Ensure that the private ssl key from prerequisites is root-only readable and can be found at ```/etc/ssl/private/private_key.pem``` (or adjust the path in the service script)
4. Run the ```daemon-reload``` and ```enable --now``` commands from step 3 above accordingly for the zfs-load-key.service
