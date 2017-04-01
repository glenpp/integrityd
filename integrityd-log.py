#!/usr/bin/env python
#    Log Anomaly monitoring and reporting daemon
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
# This is a redesigned version of a combined File & Log integrity tool
# written in Perl. This has been fully redesigned based on the original
# concepts for the Perl version.
#
# See: https://www.pitt-pladdy.com/blog/_20160711-084204_0100_File_integrity_and_log_anomaly_auditing_Updated_like_fcheck_logcheck_/
#


import sys
reload(sys)
sys.setdefaultencoding("utf-8")
import os
import yaml
import sqlite3
import time
import re
import subprocess
import random
import socket
import syslog
# see https://www.python.org/dev/peps/pep-3143/#example-usage
import daemon
# this is in different places in different distros
try:
	import lockfile.pidlockfile as pidlockfile
except ImportError, e:
	if e.args[0] != 'No module named pidlockfile': raise
try:
	import daemon.pidlockfile as pidlockfile
except ImportError, e:
	if e.args[0] != 'No module named pidlockfile': raise









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

# mailer
hostname = socket.gethostname()	# used for subjects etc.
def mail ( subject, lines ):
	global config
	print "sending mail"
	mail = subprocess.Popen ( [ config['common']['mailcommand'], '-s', subject, config['common']['email'] ], stdin=subprocess.PIPE )
	out,err = mail.communicate ( "\n".join(lines) )
	ret = mail.returncode
	print out
	print err
	print ret
	print



class logrules:
	def __init__ ( self ):
		self.dirstate = {}	# holds last change times of paths we track
		self.rules = {}	# holds paths, files below those and lists of rules in those files
		self.hosts = {}	# holds the host, categories and list of paths relevant to the catoegory
		self.hostorder = ['__HOST__']	# hosts in configuration order (which we send reports in)
		self.logpositions = {}
		self.logfiles = {}	# lists by host
		self.checktimer = timer ( config['logcheck']['checkinterval'] )
		self.rulesupdatetimer = timer ( config['logcheck']['rulesfreshness'] )
		self.holdofftime = 0	# startup with no holdoff
		# get the database up
		self.db = sqlite3.connect ( config['common']['database'] )
		self.db.row_factory = sqlite3.Row
		self.dbcur = self.db.cursor()
		# put the tables in we need (if we need them)
		self.dbcur.execute ( """
CREATE TABLE IF NOT EXISTS `LogPosition` (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    Host CHAR(40) NOT NULL,
    LogFile TEXT NOT NULL UNIQUE,
    Inode INT UNSIGNED NOT NULL,
    Position INT UNSIGNED NOT NULL
)""" )
		self.dbcur.execute ( """CREATE INDEX IF NOT EXISTS LogPosition_LogFile ON LogPosition(LogFile)""" )
		self.dbcur.execute ( """
CREATE TABLE IF NOT EXISTS `LogReport` (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    Host CHAR(40) NOT NULL,
    LogFile TEXT NOT NULL,
    Line TEXT NOT NULL,
    Priority CHAR(20) NOT NULL,
    Time INT UNSIGNED NOT NULL DEFAULT 0
)""" )
		self.dbcur.execute ( """CREATE INDEX IF NOT EXISTS LogReport_Priority ON LogReport(Priority)""" )
		self.db.commit ();
		# make sure the database is not accessible by others
		os.chmod ( config['common']['database'], 0600 )
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
			if 'localrules' in host:
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
		self.rulesupdate ( True )
		# read LogPosition from database, cleanup unconfigured logs from database
		cleanup = []
		self.dbcur.execute ( 'SELECT * FROM LogPosition' )
		for row in self.dbcur:
			if row['Host'] not in self.logfiles or row['LogFile'] not in self.logfiles[row['Host']]:
				cleanup.append ( row['id'] )
			else:
				if row['Host'] not in self.logpositions: self.logpositions[row['Host']] = {}
				self.logpositions[row['Host']][row['LogFile']] = [ row['Inode'], row['Position'], False ]
		if len(cleanup) > 0:
			for rowid in cleanup:
				self.dbcur.execute ( 'DELETE FROM LogPosition WHERE id = ?', [ rowid ] )
			self.db.commit ()
		# trigger mailing cycle - flush whatever is already in the database
		self._special ( '%s starting up' % sys.argv[0] )
		self.dbcur.execute ( 'SELECT COUNT(*) FROM LogReport' )
		if self.dbcur.fetchone()['COUNT(*)'] > 0: self._send ()

	# read in a rules file
	def _readrules ( self, path, item ):
		with open ( os.path.join ( path, item ), 'r' ) as f:
#			print 'read: %s' % os.path.join ( path, item )
			lines = f.read().splitlines()
			rules = []
			for line in lines:	# identify comments and blanks
				if line == '' or line[0] == '#': continue
				# TODO this is a very crude change over for translating perl/grep into python TODO
				pyline = line
				pyline = re.sub ( r'\[:alnum:\]', 'a-zA-Z0-9', pyline )
				pyline = re.sub ( r'\[:alpha:\]', 'a-zA-Z', pyline )
				pyline = re.sub ( r'\[:digit:\]', '0-9', pyline )
				pyline = re.sub ( r'\[:lower:\]', 'a-z', pyline )
				pyline = re.sub ( r'\[:space:\]', r'\s', pyline )
				pyline = re.sub ( r'\[:upper:\]', 'A-Z', pyline )
				pyline = re.sub ( r'\[:xdigit:\]', '0-9a-fA-F', pyline )
#				if pyline != line:
#					print
#					print line
#					print pyline
				# generate the compiled expression
				try:
					rules.append ( re.compile ( pyline ) )
				except re.error, e:
					self._special ( 'Bad line in "%s" with "%s" ignored: "%s"' % (os.path.join ( path, item ), e.args[0], line) )
			# all done
			self.rules[path][item] = rules

	# run through rules directories updating them
	def rulesupdate ( self, startup=False ):
		# we need to check all paths for updates
		mtimes = {}	# new/updated directories
		filesgone = []	# deleted files to remove from rules after
		for path in self.dirstate:
			if path not in self.rules: self.rules[path] = {}
			mtime = os.path.getmtime ( path )
			if self.dirstate[path] == mtime: continue	# nothing in the directory has changed
			mtimes[path] = mtime	# store to update later
			for item in os.listdir ( path ):
				if item[0] == '.': continue	# skip hidden files
				if os.path.isfile ( os.path.join ( path, item ) ):
					if os.path.getmtime ( os.path.join ( path, item ) ) >= self.dirstate[path] or item not in self.rules[path]:
						# we need to read in this file
						self._readrules ( path, item )
						if not startup:
							if item not in self.rules[path]:
								self._special ( 'New rule file: %s "%s" "%s"' % (os.path.join(path,item),path,item))	# inform
							else:
								self._special ( 'Updated rule file: %s "%s" "%s"' % (os.path.join(path,item),path,item) )	# inform
			# check and prune non-existing files
			for item in self.rules[path]:
				if not os.path.isfile ( os.path.join ( path, item ) ):
					filesgone.append ( [path,item] )
					if not startup: self._special ( 'Removed rule file: %s "%s" "%s"' % (os.path.join(path,item),path,item) )	# inform
		# update all dirstates
		for path in mtimes:
			self.dirstate[path] = mtimes[path]
		for item in filesgone:
			self._special ( 'Removing rule file: %s "%s" "%s"' % (os.path.join(item[0],item[1]),item[0],item[1]) )	# inform
			del self.rules[item[0]][item[1]]	# TODO this has a key error

	# read a log file
	def _readlog ( self, logfile, lastinode, lastposition ):
		lines = []
		# open and read the file
		fd = os.open ( logfile, os.O_RDONLY )
		stat = os.fstat ( fd )
		f = os.fdopen ( fd )
		if lastinode != None and stat.st_ino != lastinode:
			if 'logrotationalert' in config['logcheck'] and config['logcheck']['logrotationalert']:
				self._special ( "logfile has been rotated %s" % logfile )
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
				# flag and report this
				self._special ( "bad - can't find last logfile against %s" % logfile )
			# whatever happens, we now have to start again for the current logfile
			lastposition = None
		# we need to seek to the last valid position
		if lastposition != None:
			if lastposition > os.path.getsize ( logfile ):
				# assume it's been truncated so start again
				lastposition = None
				if 'logrotationalert' in config['logcheck'] and config['logcheck']['logrotationalert']:
					self._special ( "logfile has been truncated %s" % logfile )
			else:
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
		report = {
				'cracking': {},
				'violations': {},
				'normal': {},
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
			report['normal'][logfile] = []
			report['normal'][logfile].extend ( self._matchinglines ( ignoring, lines, False ) )
		# commit to database
		newlines = []
		timenow = int(time.time())
		for category in report:
			for logfile in report[category]:
				for line in report[category][logfile]:
					lineclean = ''.join([ i if ord(i) <= 126 and ord(i) >= 32 else r'\x%02x' % ord(i) for i in line ])	# clean out non-ascii
					newlines.append ( [ host, logfile, lineclean, category, timenow ] )
		changed = False
		if len(newlines) > 0:
			changed = True
			for line in newlines:
				print line
				self.dbcur.execute ( 'INSERT INTO LogReport (Host,LogFile,Line,Priority,Time) VALUES (?,?,?,?,?)', line )
		for logfile in self.logpositions[host]:
			if self.logpositions[host][logfile][2]:
				# something changed
				changed = True
				self.dbcur.execute ( 'INSERT OR REPLACE INTO LogPosition (Host,LogFile,Inode,Position) VALUES (?,?,?,?)', [ host, logfile, self.logpositions[host][logfile][0], self.logpositions[host][logfile][1] ] )
				# reset for next time
				self.logpositions[host][logfile][2] = False
		if changed: self.db.commit ()

	# log a special message
	def _special ( self, message ):
		self.dbcur.execute ( 'INSERT INTO LogReport (Host,LogFile,Line,Priority,Time) VALUES (?,?,?,?,?)', ['__HOST__','--SPECIAL--',message,'special',int(time.time())] )
		self.db.commit ()

	# check all the logs in the config
	def checkalllogs ( self ):
		for host in self.logfiles:
			self.checklogs ( host )

	# automated check of everything
	def autocheck ( self ):
		if self.rulesupdatetimer.timer ():
			self.rulesupdate ()
		if not self.checktimer.timer (): return
		self.checkalllogs ()
		# check if we need to mail out
		mustsend = False
		# query database for number of non-standard logs - immediate send
		self.dbcur.execute ( 'SELECT COUNT(*) FROM LogReport WHERE Priority != \'normal\'' )
		if self.dbcur.fetchone()['COUNT(*)'] > 0: mustsend = True
		# query database of oldest standard (normal) message - if it trips the timer then ssend unless in holdoff
		self.dbcur.execute ( 'SELECT MIN(Time) FROM LogReport WHERE Priority = \'normal\'' )
		oldest = self.dbcur.fetchone()['MIN(Time)']
		timenow = int(time.time())
		if oldest != None and timenow >= oldest + config['common']['reporttime'] and timenow >= self.holdofftime:
			mustsend = True
		# mail out if needed
		if mustsend: self._send ()


	# TODO check and generate mail subject and text, pass to generic mailing TODO
	def _send ( self ):
		print "send"
		# TODO
		messagelines = []
		logfile = None
		# query in order of priority, then host
		for priority in ['special','cracking','violations','normal']:
			for host in self.hostorder:
				self.dbcur.execute ( 'SELECT * FROM LogReport WHERE Priority = ? AND Host = ? ORDER BY LogFile,Time', [ priority, host ] )
				for row in self.dbcur:
					if row['LogFile'] != logfile:
						messagelines.append ( '' )
						messagelines.append ( "%s :: %s" % (priority,row['LogFile']) )
						messagelines.append ( '=' * len("%s :: %s" % (priority,row['LogFile'])) )
						logfile = row['LogFile']
					messagelines.append ( row['Line'] )
		# prepend context
		messagelines.insert ( 0, '' )
		messagelines.insert ( 0, 'LogReports from %s on %s:' % (sys.argv[0],hostname) )
		# TODO put in cycletime at end TODO maybe actually in mail() function
		# send these
		mail ( 'Log Report for %s' % hostname, messagelines )
		# nuke these entries
		self.dbcur.execute ( 'DELETE FROM LogReport' )
		self.db.commit ()
		# on send set holdoff timer
		self.holdofftime = int(time.time()) + config['common']['reportholdoff']





# get logging up
syslog.openlog ( logoption=syslog.LOG_PID, facility=syslog.LOG_DAEMON )
syslog.syslog ( 'Starting up with args: %s' % (str(sys.argv[1:]) if len(sys.argv) > 1 else 'None') )

# one argument - config file, else looks for a few options
configfile = None
if len(sys.argv) > 1:
	configfile = sys.argv[1]
elif os.path.isfile ( '/etc/integrityd-log.yaml' ):
	configfile = '/etc/integrityd-log.yaml'
elif os.path.isfile ( 'integrityd-log.yaml' ):
	configfile = 'integrityd-log.yaml'
syslog.syslog ( 'Using config: %s' % configfile )

if not os.path.isfile ( configfile ):
	sys.exit ( "FATAL - can't find a config file (might be the command line argument)\n" )

# read in conf
with open ( configfile, 'r' ) as f:
	config = yaml.load ( f )
	f.close ()





def rundaemon():
	try:
		syslog.syslog ( 'starting daemon' )
		rules = logrules ()
		syslog.syslog ( 'entering loop' )
		while True:
			rules.autocheck ()
			time.sleep ( 5.0 + 2.0 * random.random () )
	except Exception:	# catch excptions, but not all else we catch daemon terminating
		etype, evalue, etrace = sys.exc_info()
		import traceback
		syslog.syslog ( syslog.LOG_ERR, 'exception: %s' % '!! '.join ( traceback.format_exception ( etype, evalue, etrace ) ) )
	syslog.syslog ( 'exiting' )

# sort out class that actually does the work
with daemon.DaemonContext( umask=0o077, pidfile=pidlockfile.PIDLockFile('/run/integrityd-log.pid') ):
	rundaemon()
#rundaemon()







