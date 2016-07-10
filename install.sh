#!/bin/sh

cp -i integrityd-file.yaml /etc/
cp -i integrityd-file-checksum.py /usr/local/share/
cp -i integrityd-file.py /usr/local/sbin/
cp -i integrityd-file.service /etc/systemd/system/

cp -i integrityd-log.yaml /etc/
cp -i integrityd-log.py /usr/local/sbin/
cp -i integrityd-log.service /etc/systemd/system/

