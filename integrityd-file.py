#!/usr/bin/env python


import sys
import os
import yaml
import sqlite3
import time
import re
import hashlib
import subprocess
import random
#import socket
import syslog
import struct
# see https://www.python.org/dev/peps/pep-3143/#example-usage
import daemon
import daemon.pidlockfile





# main class for tracking node changes
class filecheck:
	def __init__ ( self ):
		self.lastfiletime = 0
		self.reitterate = False
		# get the checksum helper (Python 3) up
		self.checksum = subprocess.Popen ( config['common']['checksumhelper'], bufsize=0, universal_newlines=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE )
		# we start in fast mode
		self.fastmode = None
		self._setfastmode ( True )
		# get the database up
		self.db = sqlite3.connect ( config['common']['database'] )
		self.db.row_factory = sqlite3.Row
		self.dbcur = self.db.cursor()
		# put the tables in we need (if we need them)
		self.dbcur.execute ( """
CREATE TABLE IF NOT EXISTS `NodeInfo` (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	Path TEXT NOT NULL UNIQUE,
	Parent INTEGER REFERENCES NodeInfo(id),
	LastChecked INT UNSIGNED NOT NULL DEFAULT 0,
	ForceCheck BOOL NOT NULL DEFAULT 1,
	Type CHAR(10) NOT NULL,
	UID INT UNSIGNED NOT NULL,
	GID INT UNSIGNED NOT NULL,
	Links INT UNSIGNED NOT NULL,
	Inode INT UNSIGNED NOT NULL,
	Perms CHAR(10),
	CTime INT UNSIGNED NOT NULL,
	MTime INT UNSIGNED NOT NULL,
	Size INT UNSIGNED,
	SHA1 CHAR(40),
	LinkDest TEXT
)""" )
		self.dbcur.execute ( """CREATE INDEX IF NOT EXISTS NodeInfo_Path ON NodeInfo(Path)""" )
		self.dbcur.execute ( """CREATE INDEX IF NOT EXISTS NodeInfo_Path ON NodeInfo(Parent)""" )
		self.dbcur.execute ( """CREATE INDEX IF NOT EXISTS NodeInfo_LastChecked ON NodeInfo(LastChecked)""" )
		self.dbcur.execute ( """CREATE INDEX IF NOT EXISTS NodeInfo_ForceCheck ON NodeInfo(ForceCheck)""" )
		self.db.commit ();
		# make sure the database is not accessible by others
		os.chmod ( config['common']['database'], 0600 )
		# remove paths without parents that aren't areas we watch, cycling through to catch all children
		deleted = 1	# make sure we run on the first cycle
		while deleted > 0:
			todelete = []
			self.dbcur.execute ( "SELECT id,Path FROM NodeInfo WHERE Parent IS NULL" )
			for row in self.dbcur:
				if row['Path'] not in config['filecheck']['areas']:
					todelete.append ( row['id'] )
					syslog.syslog ( 'Clean up unmonitored path: %s' % row['Path'] )
			for id in todelete:
				self.dbcur.execute ( "UPDATE NodeInfo SET Parent = NULL WHERE Parent = ?", [id] )
				self.dbcur.execute ( "DELETE FROM NodeInfo WHERE id = ?", [id] )
			deleted = len(todelete)
		# add starting records if needed
		for path in config['filecheck']['areas']:
			self.dbcur.execute ( "SELECT COUNT(*) FROM NodeInfo WHERE Path = ?", [path] )
			if self.dbcur.fetchone()['COUNT(*)'] == 0:
				self.dbcur.execute ( "INSERT INTO NodeInfo (Path,LastChecked,Type,UID,GID,Links,Inode,CTime,MTime) VALUES (?,0,'New',0,0,0,0,0,0)", [path] )
		self.db.commit ();

	def __del__ ( self ):
		self.checksum.terminate()
		self.checksum.wait()

	def _setfastmode ( self, state ):
		if state != ( self.fastmode > 0 ):
			# state change
			command = "\nburst %d\n" % int(config['common']['burst'])
			self.filetime = 1.0 / config['common']['filerate']
			if state:
				self.fastmode = int(time.time())	# this is the epoch when a fast cycle is started - LastChecked after this means cycle complete
				command += "\nbyterate %d\n" % (int(config['common']['byterate'])*int(config['common']['fastmode']))
				self.filetime /= config['common']['fastmode']
			else:
				self.fastmode = 0	# disabled
				command += "\nbyterate %d\n" % int(config['common']['byterate'])
			if command != '':
				self.checksum.stdin.write ( command )
		elif state:
			# reset timer
			self.fastmode = int(time.time())	# this is the epoch when a fast cycle is started - LastChecked after this means cycle complete

	def _time2str ( self, epoch ):
		return time.strftime ( '%a, %d %b %Y %H:%M:%S %Z', time.localtime ( epoch ) )

	def _sha1file ( self, node ):
#		print '',node['Path']
		try:
			self.checksum.stdin.write ( "%s\n" % node['Path'] )
			out = self.checksum.stdout.readline ().rstrip ( '\n' )
#			print out
			out = out.split ( ' ', 1 )
			if out[1] != node['Path']:
				raise Exception ( 'Mismatched data for: %s' % str(out) )
			if out[0] == 'NULL': out[0] = None
#			print out[0]
#			print '',out[0]
			return out[0]
		except IOError:
			if self.checksum.poll():
				err = self.checksum.stderr.readline ()
				syslog.syslog ( 'Checksum Helper Died: %s' % err )
			raise Exception ( 'Checksum Helper Died' )

	def _checkexclude ( self, path ):
		parts = path.split ( os.sep )
		if parts[0] == '': parts.pop ( 0 )
		ptr = excludes
		excluded = False
		for part in parts:
			if part in ptr['branch']:
				ptr = ptr['branch'][part]
				if ptr['leaf']:
					excluded = True
					break
		return excluded
				

	def _checknode ( self, node ):
#		print node['Path']
		nodenow = {}
		for field in node.keys(): nodenow[field] = node[field]
		# check exclusion
		if self._checkexclude( node['Path'] ):
			syslog.syslog ( "remove excluded record: %s" % node['Path'] )
			# remove from database
			self.dbcur.execute ( "DELETE FROM NodeInfo WHERE id = ?", [node['id']] )
			return
		# inspect element
		try:
			if os.path.islink ( node['Path'] ):
				stat = os.lstat ( node['Path'] )
				nodenow['Type'] = 'Symlink'
				nodenow['LinkDest'] = os.readlink ( node['Path'] )
				nodenow['SHA1'] = None
			else:
				if os.path.isfile ( node['Path'] ):
					nodenow['Type'] = 'File'
					nodenow['SHA1'] = self._sha1file ( nodenow )
#					print nodenow['SHA1']
				elif os.path.isdir ( node['Path'] ):
					nodenow['Type'] = 'Directory'
					nodenow['SHA1'] = None
					below = sorted ( os.listdir ( node['Path'] ) )
					data = "\n".join ( [ item.encode('utf-8') for item in below ] )
					nodenow['SHA1'] = hashlib.sha1 ( data ).hexdigest()
					for subnode in below:
						subpath = os.path.join(node['Path'],subnode)
						if self._checkexclude( subpath ):
							continue	# skip excluded
						self.dbcur.execute ( "INSERT OR IGNORE INTO NodeInfo (Path,Parent,LastChecked,ForceCheck,Type,UID,GID,Links,Inode,CTime,MTime) VALUES (?,?,0,1,'New',0,0,0,0,0,0)", [subpath,nodenow['id']] )
				else:
					# sockets, pipes, devices etc.
					# don't read these, but do stat them
					nodenow['Type'] = 'Other'
					nodenow['SHA1'] = None
				stat = os.stat ( node['Path'] )
				nodenow['LinkDest'] = None
		except OSError, e:
			# check for deletion (handle)
			if e.strerror == 'No such file or directory':
				syslog.syslog ( syslog.LOG_WARNING, 'Deleted %s: %s' % ( node['Type'], node['Path'] ) )
				parents = [ node['id'] ]
				while len(parents) > 0:
					todelete = []
					for parent in parents:
						self.dbcur.execute ( 'SELECT id,Path,Type FROM NodeInfo WHERE Parent = ?', [parent] )
						for row in self.dbcur:
							self.reitterate = True	# we have made changes that may impact running list
							todelete.append ( row['id'] )
							syslog.syslog ( syslog.LOG_WARNING, '+Deleted %s: %s' % ( row['Type'], row['Path'] ) )
						self.dbcur.execute ( 'DELETE FROM NodeInfo WHERE id = ?', [parent] )
					parents = todelete
				return
			etype, evalue, etrace = sys.exc_info()
			raise etype, evalue, etrace
#			syslog.syslog ( str(dir(e)) )
#			syslog.syslog ( str(e.filename) )
#			syslog.syslog ( e.strerror )
#			syslog.syslog ( str([etype,evalue]) )
#			syslog.syslog ( "----" )
#			return
#		nodenow['Parent'] = No Change
		nodenow['LastChecked'] = int(time.time())
		nodenow['ForceCheck'] = 0
		nodenow['UID'] = stat.st_uid
		nodenow['GID'] = stat.st_gid
		nodenow['Links'] = stat.st_nlink
		nodenow['Inode'] = stat.st_ino
		nodenow['Perms'] = '%04o' % stat.st_mode
		nodenow['CTime'] = int(stat.st_ctime)
		nodenow['MTime'] = int(stat.st_mtime)
		nodenow['Size'] = stat.st_size
#		print nodenow['SHA1']

		# analyse changes
		changed = False
		changedfields = []
		if node['Type'] == 'New':
			# new node, no need to get into details
			changed = True
			if not args['init']: syslog.syslog ( syslog.LOG_WARNING, 'New %s: %s' % ( nodenow['Type'], nodenow['Path'] ) )
			changedfields = nodenow.keys()
		else:
			for field in node.keys():
				if field in ['Path','Parent','ForceCheck','LastChecked']:
					# skip these
					pass
				elif nodenow[field] != node[field]:
						changed = True
						changedfields.append ( field )
			if changed:
				syslog.syslog ( syslog.LOG_WARNING, 'Changed %s: %s' % ( nodenow['Type'], nodenow['Path'] ) )
				shortpath = re.sub ( r'^.+?(.{1,20})$', r'... \1', nodenow['Path'] )
				for field in changedfields:
					if field in ['CTime','MTime']:
						syslog.syslog ( syslog.LOG_WARNING, '    %s: %s :: %s => %s' % ( shortpath, field, self._time2str(node[field]), self._time2str(nodenow[field]) ) )
					else:
						syslog.syslog ( syslog.LOG_WARNING, '    %s: %s :: %s => %s' % ( shortpath, field, node[field], nodenow[field] ) )
				syslog.syslog ( syslog.LOG_WARNING, '    %s: LastChecked :: %s' % (shortpath, self._time2str(node['LastChecked'])) )
		if changed:
			# changed and directory, set mustcheck on all subnodes
			if nodenow['Type'] == 'Directory':
				self.dbcur.execute ( "UPDATE NodeInfo SET ForceCheck = 1 WHERE Parent = ?", [nodenow['id']] )
		# update database with new data
		changedfields.append ( 'LastChecked' )
		if nodenow['ForceCheck'] != node['ForceCheck']: changedfields.append ( 'ForceCheck' )
		items = ', '.join ( [ '%s = ?' % field for field in changedfields ] )
		values = [ nodenow[field] for field in changedfields ]
		values.append ( nodenow['id'] )
		self.dbcur.execute ( "UPDATE NodeInfo SET %s WHERE id = ?" % items, values )
		if changed:
			# switch to fastmode if needed
			self._setfastmode ( True )
			if self.fastmode == 0:
				syslog.syslog ( 'FastMode Start' )



	# do a cycle of "number" items
	def cycle ( self, number ):
		# get nodes for this cycle up to number
		# TODO possibly prioritise directories - a delta there means something in them has changed TODO
		self.dbcur.execute ( "SELECT * FROM NodeInfo WHERE ForceCheck = 1 LIMIT ?", [number] )
#		self.dbcur.execute ( "SELECT * FROM NodeInfo WHERE ForceCheck = 1 ORDER BY RANDOM() LIMIT ?", [number] )
		nodes = [ row for row in self.dbcur ]
		if len(nodes) < number:
			self.dbcur.execute ( "SELECT * FROM NodeInfo ORDER BY LastChecked LIMIT ?", [number-len(nodes)] )
			for row in self.dbcur: nodes.append ( row )
		# randomise order for security (attacker can't mitigate by guessing what's next)
		random.shuffle ( nodes )

		# we have our batch - check all the nodes
		for node in nodes:
			if self.reitterate:
				# something changed that impacts this cycle - break so we re-query
				self.reitterate = False
				break
			now = time.time()
			delay = self.filetime - ( now - self.lastfiletime )
			self.lastfiletime = self.lastfiletime + self.filetime
			if delay > 0.0:
				time.sleep ( delay )
			else:
				self.lastfiletime = now
			self._checknode ( node )
		self.db.commit ();

		# check if we should drop out of fastmode
		self.dbcur.execute ( 'SELECT MIN(LastChecked) FROM NodeInfo' )
		if self.fastmode > 0 and self.dbcur.fetchone()['MIN(LastChecked)'] > self.fastmode:
			self._setfastmode ( False )	# drop out of fastmode
			self.dbcur.execute ( 'SELECT MAX(LastChecked)-MIN(LastChecked) as CycleTime FROM NodeInfo' )
			syslog.syslog ( 'FastMode Complete with CycleTime = %d' % self.dbcur.fetchone()['CycleTime'] )








# get logging up
syslog.openlog ( logoption=syslog.LOG_PID, facility=syslog.LOG_DAEMON )
syslog.syslog ( 'Starting up with args: %s' % (str(sys.argv[1:]) if len(sys.argv) > 1 else 'None') )

# arguments - config file, else looks for a few options
# optional argument of --init doesn't report new files until all known new files are captured, then exits
args = { 'init': False }
configfile = None
if len(sys.argv) > 1:
	for arg in range (1,len(sys.argv)):
		if sys.argv[arg] == '--init':
			args['init'] = True
			syslog.syslog ( "Started in init mode - changes will not be logged" )
		else:
			configfile = sys.argv[arg]
if configfile == None:
	if os.path.isfile ( '/etc/integrityd-file.yaml' ):
		configfile = '/etc/integrityd-file.yaml'
	elif os.path.isfile ( 'integrityd-file.yaml' ):
		configfile = 'integrityd-file.yaml'
syslog.syslog ( 'Using config: %s' % configfile )

if not os.path.isfile ( configfile ):
	sys.exit ( "FATAL - can't find a config file (might be the command line argument)\n" )

# read in conf
with open ( configfile, 'r' ) as f:
	config = yaml.load ( f )
	f.close ()

# if not specified in the config, add checksum helper
if 'checksumhelper' not in config['common']:
	paths = [	# where to search
			os.path.abspath ( os.path.join ( os.path.dirname ( sys.argv[0] ), 'integrityd-file-checksum.py' ) ),
			'/usr/local/share/integrityd-file-checksum.py',
		]
	for path in paths:
		if os.path.isfile ( path ):
			config['common']['checksumhelper'] = path
			break

# break up excludes
excludes = { 'branch': {} }
for path in config['filecheck']['exclude']:
	ptr = excludes
	parts = path.split ( os.sep )
	if parts[0] == '': parts.pop ( 0 )
	for part in parts:
		ptr = ptr['branch']
		if part not in ptr:
			ptr[part] = {
					'leaf': False,
					'branch': {},
				}
		ptr = ptr[part]
	ptr['leaf'] = True




def rundaemon():
	try:
		syslog.syslog ( 'starting daemon' )
		check = filecheck ()
		syslog.syslog ( 'entering loop' )
		while True:
			check.cycle ( 100 )
	except Exception:	# catch excptions, but not all else we catch daemon terminating
		etype, evalue, etrace = sys.exc_info()
		import traceback
		syslog.syslog ( syslog.LOG_ERR, 'exception: %s' % '!! '.join ( traceback.format_exception ( etype, evalue, etrace ) ) )
	syslog.syslog ( 'exiting' )

# sort out class that actually does the work
if args['init']:
	syslog.syslog ( 'starting init' )
	check = filecheck ()
	newnodes = True
	while check.fastmode > 0 and newnodes:
		check.cycle ( 100 )
		check.dbcur.execute ( "SELECT COUNT(*) FROM NodeInfo WHERE Type = 'New'" )
		if check.dbcur.fetchone()['COUNT(*)'] == 0: newnodes = False
	syslog.syslog ( 'init complete' )
else:
	# regular daemon startup
	with daemon.DaemonContext( umask=0o077, pidfile=daemon.pidlockfile.PIDLockFile('/run/integrityd-file.pid') ):
		rundaemon()



