#!/usr/bin/env python3.4
#    Log Anomaly monitoring and reporting daemon - checksum helper
#    Copyright (C) 2011,2016  Glen Pitt-Pladdy
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#
# For effective checksumming (eg. avoid impacting cache we need Python 3.3+
# Since many needed modules are not widely distributed beyond 2.7 yet this
# part has been separated to allow capabilities in 3.3+ to be used.
#
# See: https://www.pitt-pladdy.com/blog/
#


# takes a path on STDIN
# outputs SHA1 (or NULL) and path on STDOUT

# commands can be sent to set tihngs like burst size and read rate:
#	send a \n
#	send the command terminated by \n


import sys
import os
import hashlib
import time


block = 4096


# WARNING: the moment we access sys.argv[1] or other arrgs sys.stdin goes non-blocking
# to work round this we use a "\nfield value\n" command
#sys.stderr.write ( "%s\n" % str(sys.argv) )
#sys.stderr.write ( "%s\n" % sys.argv[0] )
#sys.stderr.write ( "%s\n" % sys.argv[1] )
#sys.stderr.write ( "%d\n" % len(sys.argv) )
#if len(sys.argv) != 3:
#	sys.exit ( "Usage: %s <burst bytes> <byterate / second>\n" % sys.argv[0] )
#burst = int(sys.argv[1])
#rate = int(sys.argv[2])
burst=131072
rate=262144


blockburst = int(burst/block)
bursttime = 1.0 / ( rate / block ) * blockburst


while True:
	node = sys.stdin.readline().rstrip ( "\n" )
	if node == '':	# command incoming
		command,value = sys.stdin.readline().rstrip ( "\n" ).split()
#		sys.stderr.write ( "%s :: %s\n" % (command,value) )
		if command == 'burst':
			burst = int(value)
		elif command == 'byterate':
			rate = int(value)
		continue
	try:
		starttime = time.time () 
		with open ( node, 'rb' ) as f:
#			os.posix_fadvise ( f.fileno(), 0, 0, os.POSIX_FADV_DONTNEED )	# avoid displacing other items in cache
			os.posix_fadvise ( f.fileno(), 0, 0, os.POSIX_FADV_NOREUSE )	# avoid displacing other items in cache
			sha = hashlib.sha1 ()
			data = ' '
			blockcount = 0
			while len(data) > 0:
				data = f.read ( 4096 )
				sha.update ( data )
				blockcount += 1
				# check on progress
				if blockcount >= blockburst:
					now = time.time ()
					delay = bursttime - ( now - starttime )
					if delay > 0.0:
						time.sleep ( delay )
						starttime += bursttime
					else:
						# we're slipping - keep slipping
						starttime = now
					blockcount = 0
					
					
#			sys.stderr.write ( "%s\t%s\n" % (sha.hexdigest(),node) )
			print ( sha.hexdigest(), node )
			sys.stdout.flush()
	except FileNotFoundError:
		print ( "NULL", node )
		sys.stdout.flush()

