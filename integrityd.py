#!/usr/bin/env python


import sys
import os
import yaml
import sqlite3
import time
import re






# one argument - config file, else looks for a few options
configfile = None
if len(sys.argv) > 1:
	configfile = sys.argv[1]
elif os.path.isfile ( '/etc/integrityd.yaml' ):
	configfile = '/etc/integrityd.yaml'
elif os.path.isfile ( 'integrityd.yaml' ):
	configfile = 'integrityd.yaml'

if not os.path.isfile ( configfile ):
	sys.exit ( "FATAL - can't find a config file (might be the command line argument)\n" )

# read in conf
with open ( configfile, 'r' ) as f:
	config = yaml.load ( f )
	f.close ()


# get database up
db = sqlite3.connect ( config['common']['database'] )
db.row_factory = sqlite3.Row
dbcur = db.cursor()

# put the tables in we need (if we need them)
dbcur.execute ( """
CREATE TABLE IF NOT EXISTS `LogPosition` (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    Host CHAR(40) NOT NULL,
    LogFile TEXT NOT NULL UNIQUE,
    Inode INT UNSIGNED NOT NULL,
    Position INT UNSIGNED NOT NULL
)""" )
dbcur.execute ( """CREATE INDEX IF NOT EXISTS LogPosition_LogFile ON LogPosition(LogFile)""" )
dbcur.execute ( """
CREATE TABLE IF NOT EXISTS `LogReport` (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    Host CHAR(40) NOT NULL,
    LogFile TEXT NOT NULL,
    Line TEXT NOT NULL,
    Priority CHAR(20) NOT NULL,
    Time INT UNSIGNED NOT NULL DEFAULT 0
)""" )
dbcur.execute ( """CREATE INDEX IF NOT EXISTS LogReport_Priority ON LogReport(Priority)""" )





# generic timer
class timer:
	def __init__ ( self, interval ):
		self.interval = interval
		self.next = 0.0
	def timer ( self ):
		now = time.time ()
		if now >= self.next:
			self.next = now + self.interval
			return True
		return False
	def ramaining ( self ):
		return self.next - time.time ()



class logrules:
	def __init__ ( self ):
		global dbcur
		self.dirstate = {}	# holds last change times of paths we track
		self.rules = {}	# holds paths, files below those and lists of rules in those files
		self.hosts = {}	# holds the host, categories and list of paths relevant to the catoegory
		self.hostorder = ['__HOST__']	# hosts in configuration order (which we send reports in)
		self.logpositions = {}
		self.logfiles = {}	# lists by host
		self.checktimer = timer ( config['logcheck']['checkinterval'] )
		self.rulesupdatetimer = timer ( config['logcheck']['rulesfreshness'] )
		self.holdofftime = 0	# startup with no holdoff
		# populate host configs we work against
		for host in config['logcheck']['hosts']:
			hostconfig = {
					'cracking': [],
					'cracking.ignore': [],
					'violations': [],
					'violations.ignore': [],
					'ignore': [],
				}
			# figure out bases we are using
			basemode = config['logcheck']['basemode']
			if 'basemode' in host: basemode = host['basemode']
			baserules = config['logcheck']['baserules']
			if 'baserules' in host: baserules = host['baserules']
			# add bases - these have to have the full set of directories
			for category in ['cracking','cracking.ignore','violations','violations.ignore']:
				hostconfig[category].append ( os.path.join ( baserules, '%s.d' % category ) )
			hostconfig['ignore'].append ( os.path.join ( baserules, 'ignore.d.paranoid' ) )
			if basemode in ['workstation','server']:
				hostconfig['ignore'].append ( os.path.join ( baserules, 'ignore.d.server' ) )
			if basemode in ['workstation']:
				hostconfig['ignore'].append ( os.path.join ( baserules, 'ignore.d.workstation' ) )
			# now add local rules, assuming they are all ignores if there are no dirs
			gotrules = False
			for category in ['cracking','cracking.ignore','violations','violations.ignore']:
				if os.path.isdir ( os.path.join ( host['localrules'], '%s.d' % category ) ):
					hostconfig[category].append ( os.path.join ( host['localrules'], '%s.d' % category ) )
					gotrules = True
			localmode = basemode
			if 'localmode' in host: localmode = host['localmode']
			if os.path.isdir ( os.path.join ( host['localrules'], 'ignore.d.paranoid' ) ):
				hostconfig['ignore'].append ( os.path.join ( host['localrules'], 'ignore.d.paranoid' ) )
				gotrules = True
			if localmode in ['workstation','server']:
				if os.path.isdir ( os.path.join ( host['localrules'], 'ignore.d.server' ) ):
					hostconfig['ignore'].append ( os.path.join ( host['localrules'], 'ignore.d.server' ) )
					gotrules = True
			if localmode in ['workstation']:
				if os.path.isdir ( os.path.join ( host['localrules'], 'ignore.d.workstation' ) ):
					hostconfig['ignore'].append ( os.path.join ( host['localrules'], 'ignore.d.workstation' ) )
					gotrules = True
			# if we didn't get any of the dirs, then assme the directory given is an ignore directory
			if not gotrules: hostconfig['ignore'].append ( host['localrules'] )
			# we should now have all the config for this host
			self.hosts[host['name']] = hostconfig
			self.logfiles[host['name']] = host['logfiles']
			self.hostorder.append ( host['name'] )
		# populate directory states
		for host in self.hosts:
			for check in self.hosts[host]:
				for path in self.hosts[host][check]:
					if path not in self.dirstate:
						self.dirstate[path] = 0.0	# set zero start time to force files to be checked
		# now update (read) all the rules for the first time
		self.rulesupdate ()
		# read LogPosition from database, cleanup unconfigured logs from database
		cleanup = []
		dbcur.execute ( 'SELECT * FROM LogPosition' )
		for row in dbcur:
			if row['Host'] not in self.logfiles or row['LogFile'] not in self.logfiles[row['Host']]:
				cleanup.append ( row['id'] )
			else:
				if row['Host'] not in self.logpositions: self.logpositions[row['Host']] = {}
				self.logpositions[row['Host']][row['LogFile']] = [ row['Inode'], row['Position'], False ]
		if len(cleanup) > 0:
			for rowid in cleanup:
				dbcur.execute ( 'DELETE FROM LogPosition WHERE id = ?', [ rowid ] )
			db.commit ()
		# trigger mailing cycle - flush whatever is already in the database
		# TODO put a startup message in here from __HOST__ and don't need to check for messages then TODO
		dbcur.execute ( 'SELECT COUNT(*) FROM LogReport' )
		if dbcur.fetchone()['COUNT(*)'] > 0: self._send ()

	# read in a rules file
	def _readrules ( self, path, item ):
		with open ( os.path.join ( path, item ), 'r' ) as f:
#			print 'read: %s' % os.path.join ( path, item )
			lines = f.read().splitlines()
			rules = []
			for line in lines:	# identify comments and blanks
				if line == '' or line[0] == '#': continue
				rules.append ( re.compile ( line ) )
			# all done
			self.rules[path][item] = rules

	# run through rules directories updating them
	def rulesupdate ( self ):
		# TODO log each of these as a host log item TODO
		# we need to check all paths for updates
		for path in self.dirstate:
			if path not in self.rules: self.rules[path] = {}
			for item in os.listdir ( path ):
				if os.path.isfile ( os.path.join ( path, item ) ):
					if os.path.getmtime ( os.path.join ( path, item ) ) >= self.dirstate[path] or path not in self.rules or item not in self.rules[path]:
						# we need to read in this file
						self._readrules ( path, item )
			# check and prune non-existing files
			filesgone = []
			for item in self.rules[path]:
				if not os.path.isfile ( os.path.join ( path, item ) ):
					filesgone.append ( item )
			for item in filesgone:
				print 'delete: %s' % os.path.join ( path, item )
				del self.rules[path][item]

	# read a log file
	def _readlog ( self, logfile, lastinode, lastposition ):
		lines = []
		# open and read the file
		fd = os.open ( logfile, os.O_RDONLY )
		stat = os.fstat ( fd )
		f = os.fdopen ( fd )
		if lastinode != None and stat.st_ino != lastinode:
			# this is not the same file - presume logs rotated so find previous and finish it up
			lastlogfile = None
			for lastfile in os.listdir ( os.path.dirname ( logfile ) ):
				path = os.path.join ( os.path.dirname ( logfile ), lastfile )
				if os.path.isfile ( path ):
					laststat = os.stat ( path )
					if laststat.st_ino == lastinode:
						lastlogfile = path
						break
			if lastlogfile != None:
				# we have a valid previous logfile to read
				lfd = os.open ( lastlogfile, os.O_RDONLY )
				lf = os.fdopen ( lfd )
				if lastposition != None:
					lf.seek ( lastposition )
				for line in lf:
					if line[-1] == '\n':
						lines.append ( line[:-1] )
					else:
						lines.append ( line )
			else:
				# flag and report this TODO
				print "bad - can't find last logfile against %s" % logfile
			# whatever happens, we now have to start again for the current logfile
			lastposition = None
		# we need to seek to the last valid position
		if lastposition != None:
			f.seek ( lastposition )
		for line in f:
			if line[-1] != '\n': break
			lastposition = f.tell ()	# we are only interested in last full line
			lines.append ( line[:-1] )	# we already know we end with \n
		lastinode = stat.st_ino
		if lastposition == None: lastposition = 0	# set position anyway - we don't have one yet
		return ( lastinode, lastposition, lines )

	# filter lines for matches TODO this can be optimised by ordering rules by most frequently matched across all contributing files TODO
	def _matchinglines ( self, rules, lines, includelines=True ):
		outlines = []
		for line in lines:
			if includelines:
				for rule in rules:
					 if rule.search ( line ): outlines.append ( line )
			else:
				includeline = True
				for rule in rules:
					if rule.search ( line ):
						includeline = False
						break
				if includeline: outlines.append ( line )
		return outlines
				
	# given a host return matching items
	def checklogs ( self, host ):
		global dbcur
		report = {
				'cracking': {},
				'violations': {},
				'logs': {},
			}
		if host not in self.logpositions: self.logpositions[host] = {}
		for logfile in self.logfiles[host]:
			if logfile not in self.logpositions[host]: self.logpositions[host][logfile] = [ None, None, False ]
			lastposition, lastinode, lines = self._readlog ( logfile, self.logpositions[host][logfile][0], self.logpositions[host][logfile][1] )
			if lastposition != self.logpositions[host][logfile][0] or lastinode != self.logpositions[host][logfile][1]:
				self.logpositions[host][logfile] = [ lastposition, lastinode, True ]
			# now we need to check these against rules
			for category in ['cracking','violations']:
				report[category][logfile] = []
				matching = []
				for path in self.hosts[host][category]:
					for rules in self.rules[path].values():
						matching.extend ( rules )
				ignoring = []
				for path in self.hosts[host]['%s.ignore' % category]:
					for rules in self.rules[path].values():
						ignoring.extend ( rules )
				report[category][logfile].extend ( self._matchinglines ( ignoring, self._matchinglines ( matching, lines, True ), False ) )
			ignoring = []
			for path in self.hosts[host]['ignore']:
				for rules in self.rules[path].values():
					ignoring.extend ( rules )
			report['logs'][logfile] = []
			report['logs'][logfile].extend ( self._matchinglines ( ignoring, lines, False ) )
		# commit to database
		newlines = []
		timenow = int(time.time())
		for category in report:
			for logfile in report[category]:
				for line in report[category][logfile]:
					newlines.append ( [ host, logfile, line, category, timenow ] )
		changed = False
		if len(newlines) > 0:
			changed = True
			for line in newlines:
				dbcur.execute ( 'INSERT INTO LogReport (Host,LogFile,Line,Priority,Time) VALUES (?,?,?,?,?)', line )
		for logfile in self.logpositions[host]:
			if self.logpositions[host][logfile][2]:
				# something changed
				changed = True
				dbcur.execute ( 'INSERT OR REPLACE INTO LogPosition (Host,LogFile,Inode,Position) VALUES (?,?,?,?)', [ host, logfile, self.logpositions[host][logfile][0], self.logpositions[host][logfile][1] ] )
				# reset for next time
				self.logpositions[host][logfile][2] = False
		if changed: db.commit ()

	# check all the logs in the config
	def checkalllogs ( self ):
		for host in self.logfiles:
			self.checklogs ( host )

	# automated check of everything
	def autocheck ( self ):
		global dbcur
		if self.rulesupdatetimer.timer ():
			self.rulesupdate ()
		if not self.checktimer.timer (): return
		self.checkalllogs ()
		# check if we need to mail out
		mustsend = False
		# query database for number of non-standard logs - immediate send
		dbcur.execute ( 'SELECT COUNT(*) FROM LogReport WHERE Priority != \'logs\'' )
		if dbcur.fetchone()['COUNT(*)'] > 0: mustsend = True
		# query database of oldest standard (logs) message - if it trips the timer then ssend unless in holdoff
		dbcur.execute ( 'SELECT MIN(Time) FROM LogReport WHERE Priority = \'logs\'' )
		oldest = dbcur.fetchone()['MIN(Time)']
		timenow = int(time.time())
		if oldest != None and timenow >= oldest + config['common']['reporttime'] and timenow >= self.holdofftime:
			mustsend = True
		# mail out if needed
		if mustsend: self._send ()


	# TODO check and generate mail subject and text, pass to generic mailing TODO
	def _send ( self ):
		global dbcur
		print "send"
		# TODO
		messagelines = []
		logfile = None
		sententries = []
		# query in order of priority, then host
		for priority in ['cracking','violations','logs']:
			for host in self.hostorder:
				dbcur.execute ( 'SELECT * FROM LogReport WHERE Priority = ? AND Host = ? ORDER BY LogFile,Time', [ priority, host ] )
				for row in dbcur:
					if row['LogFile'] != logfile:
						messagelines.append ( '' )
						messagelines.append ( "%s :: %s" % (priority,row['LogFile']) )
						messagelines.append ( '=' * len("%s :: %s" % (priority,row['LogFile'])) )
						logfile = row['LogFile']
					messagelines.append ( row['Line'] )
					sententries.append ( row['id'] )
		print "\n".join(messagelines)
		# TODO send these
		# nuke used lines
		for rowid in sententries:
			dbcur.execute ( 'DELETE FROM LogReport WHERE id = ?', [rowid] )
		db.commit ()
		# on send set holdoff timer
		self.holdofftime = int(time.time()) + config['common']['reportholdoff']
		







print config

print
rules = logrules ()
print
#		for host in config['logcheck']['hosts']:
while True:
	rules.autocheck ()
	time.sleep ( 5 )	# TODO put a small random component to this







