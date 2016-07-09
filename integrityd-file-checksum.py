#!/usr/bin/env python3.4
# takes a path on STDIN
# outputs SHA1 (or NULL) and path on STDOUT


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

