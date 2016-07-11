#!/bin/sh

newercp () {
	sourcefile=$1
	destdir=$2
	dest="$destdir/$sourcefile"
	if [ -f "$dest" -a "$sourcefile" -ot "$dest" ]; then return; fi
	cp -i "$sourcefile" "$destdir"
}

[ -f /etc/integrityd-file.yaml ] || newercp integrityd-file.yaml /etc/
newercp integrityd-file-checksum.py /usr/local/share/
newercp integrityd-file.py /usr/local/sbin/
newercp integrityd-file.service /etc/systemd/system/

[ -f /etc/integrityd-log.yaml ] || newercp integrityd-log.yaml /etc/
newercp integrityd-log.py /usr/local/sbin/
newercp integrityd-log.service /etc/systemd/system/

