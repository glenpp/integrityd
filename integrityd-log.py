#!/usr/bin/env python3
"""
    Log Anomaly monitoring and reporting daemon
    Copyright (C) 2011,2016  Glen Pitt-Pladdy

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.


This is a redesigned version of a combined File & Log integrity tool
written in Perl. This has been fully redesigned based on the original
concepts for the Perl version.

See: https://www.pitt-pladdy.com/blog/_20160711-084204_0100_File_integrity_and_log_anomaly_auditing_Updated_like_fcheck_logcheck_/

"""


import sys
import os
import sqlite3
import time
import re
import subprocess
import random
import socket
import syslog
import yaml
# see https://www.python.org/dev/peps/pep-3143/#example-usage
import daemon
# this is in different places in different distros
try:
    import lockfile.pidlockfile as pidlockfile
except ImportError as exc:
    if exc.args[0] != 'No module named pidlockfile':
        raise
try:
    import daemon.pidlockfile as pidlockfile
except ImportError as exc:
    if exc.args[0] != "No module named 'daemon.pidlockfile'":
        raise



DEBUG = False   # if True we run in foreground, console output





class Timer:
    """Simple timer for semi-regular intervals
    """
    def __init__(self, interval):
        """Setup timer

        :arg interval: float, interval in seconds
        """
        self.interval = interval
        self.next = 0.0
    def timer(self):
        """Check interval is reached

        :return: True if interval is complete, else False
        """
        now = time.time()
        if now >= self.next:
            self.next = now + self.interval
            return True
        return False
    def ramaining(self):
        """Calculate remaining time in interval

        :return: float, remaining time before end of interval
        """
        return self.next - time.time()

# mailer
HOSTNAME = socket.gethostname()    # used for subjects etc.
def send_mail(subject, lines):
    """Send email

    :arg subject: str, subject of email
    :arg lines:, list, email content as individual lines
    """
    if DEBUG:
        print("sending mail")
    mail_proc = subprocess.Popen(
        [config['common']['mailcommand'], '-s', subject, config['common']['email']],
        stdin=subprocess.PIPE
    )
    out, err = mail_proc.communicate("\n".join(lines).encode('utf-8'))
    ret = mail_proc.returncode
    if DEBUG:
        print(out)
        print(err)
        print(ret)
        print()



class LogRules:
    """Handle log files
    """
    def __init__(self):
        self.dirstate = {}    # holds last change times of paths we track
        self.rules = {}    # holds paths, files below those and lists of rules in those files
        self.hosts = {}    # holds the host, categories and list of paths relevant to the catoegory
        self.hostorder = ['__HOST__']    # hosts in configuration order (which we send reports in)
        self.logpositions = {}
        self.logfiles = {}    # lists by host
        self.checktimer = Timer(config['logcheck']['checkinterval'])
        self.rulesupdatetimer = Timer(config['logcheck']['rulesfreshness'])
        self.holdofftime = 0    # startup with no holdoff
        self.lasterror = {} # the last error we had on a file to avoid excess repeating warnings
        # get the database up
        self.db = sqlite3.connect(config['common']['database'])
        self.db.row_factory = sqlite3.Row
        self.dbcur = self.db.cursor()
        # put the tables in we need (if we need them)
        self.dbcur.execute("""
CREATE TABLE IF NOT EXISTS `LogPosition` (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    Host CHAR(40) NOT NULL,
    LogFile TEXT NOT NULL UNIQUE,
    Inode INT UNSIGNED NOT NULL,
    Position INT UNSIGNED NOT NULL
)""")
        self.dbcur.execute("CREATE INDEX IF NOT EXISTS LogPosition_LogFile ON LogPosition(LogFile)")
        self.dbcur.execute("""
CREATE TABLE IF NOT EXISTS `LogReport` (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    Host CHAR(40) NOT NULL,
    LogFile TEXT NOT NULL,
    Line TEXT NOT NULL,
    Priority CHAR(20) NOT NULL,
    Time INT UNSIGNED NOT NULL DEFAULT 0
)""")
        self.dbcur.execute("CREATE INDEX IF NOT EXISTS LogReport_Priority ON LogReport(Priority)")
        self.db.commit()
        # make sure the database is not accessible by others
        os.chmod(config['common']['database'], 0o600)
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
            if 'basemode' in host:
                basemode = host['basemode']
            baserules = config['logcheck']['baserules']
            if 'baserules' in host:
                baserules = host['baserules']
            # add bases - these have to have the full set of directories
            for category in ['cracking', 'cracking.ignore', 'violations', 'violations.ignore']:
                hostconfig[category].append(os.path.join(baserules, '{}.d'.format(category)))
            hostconfig['ignore'].append(os.path.join(baserules, 'ignore.d.paranoid'))
            if basemode in ['workstation', 'server']:
                hostconfig['ignore'].append(os.path.join(baserules, 'ignore.d.server'))
            if basemode in ['workstation']:
                hostconfig['ignore'].append(os.path.join(baserules, 'ignore.d.workstation'))
            # now add local rules, assuming they are all ignores if there are no dirs
            gotrules = False
            if 'localrules' in host:
                for category in ['cracking', 'cracking.ignore', 'violations', 'violations.ignore']:
                    if os.path.isdir(os.path.join(host['localrules'], '{}.d'.format(category))):
                        hostconfig[category].append(os.path.join(host['localrules'], '{}.d'.format(category)))
                        gotrules = True
                localmode = basemode
                if 'localmode' in host:
                    localmode = host['localmode']
                if os.path.isdir(os.path.join(host['localrules'], 'ignore.d.paranoid')):
                    hostconfig['ignore'].append(os.path.join(host['localrules'], 'ignore.d.paranoid'))
                    gotrules = True
                if localmode in ['workstation', 'server']:
                    if os.path.isdir(os.path.join(host['localrules'], 'ignore.d.server')):
                        hostconfig['ignore'].append(os.path.join(host['localrules'], 'ignore.d.server'))
                        gotrules = True
                if localmode in ['workstation']:
                    if os.path.isdir(os.path.join(host['localrules'], 'ignore.d.workstation')):
                        hostconfig['ignore'].append(os.path.join(host['localrules'], 'ignore.d.workstation'))
                        gotrules = True
                # if we didn't get any of the dirs, then assme the directory given is an ignore directory
                if not gotrules:
                    hostconfig['ignore'].append(host['localrules'])
            # we should now have all the config for this host
            self.hosts[host['name']] = hostconfig
            self.logfiles[host['name']] = host['logfiles']
            self.hostorder.append(host['name'])
        # populate directory states
        for host in self.hosts:
            for check in self.hosts[host]:
                for path in self.hosts[host][check]:
                    if path not in self.dirstate:
                        self.dirstate[path] = 0.0    # set zero start time to force files to be checked
        # now update (read) all the rules for the first time
        self.rulesupdate(True)
        # read LogPosition from database, cleanup unconfigured logs from database
        cleanup = []
        self.dbcur.execute('SELECT * FROM LogPosition')
        for row in self.dbcur:
            if row['Host'] not in self.logfiles or row['LogFile'] not in self.logfiles[row['Host']]:
                cleanup.append(row['id'])
            else:
                if row['Host'] not in self.logpositions:
                    self.logpositions[row['Host']] = {}
                self.logpositions[row['Host']][row['LogFile']] = [row['Inode'], row['Position'], False]
        if cleanup:
            for rowid in cleanup:
                self.dbcur.execute('DELETE FROM LogPosition WHERE id = ?', [rowid])
            self.db.commit()
        # trigger mailing cycle - flush whatever is already in the database
        self._special('{} starting up'.format(sys.argv[0]))
        self.dbcur.execute('SELECT COUNT(*) FROM LogReport')
        if self.dbcur.fetchone()['COUNT(*)'] > 0:
            self._send()

    # read in a rules file
    def _readrules(self, path, item):
        with open(os.path.join(path, item), 'rt') as f_rules:
            lines = f_rules.read().splitlines()
            rules = []
            for line in lines:    # identify comments and blanks
                if line == '' or line[0] == '#':
                    continue
                # TODO this is a very crude change over for translating perl/grep into python TODO
                pyline = line
                pyline = re.sub(r'\[:alnum:\]', 'a-zA-Z0-9', pyline)
                pyline = re.sub(r'\[:alpha:\]', 'a-zA-Z', pyline)
                pyline = re.sub(r'\[:digit:\]', '0-9', pyline)
                pyline = re.sub(r'\[:lower:\]', 'a-z', pyline)
                pyline = re.sub(r'\[:space:\]', r'\s', pyline)
                pyline = re.sub(r'\[:upper:\]', 'A-Z', pyline)
                pyline = re.sub(r'\[:xdigit:\]', '0-9a-fA-F', pyline)
                # generate the compiled expression
                try:
                    rules.append(re.compile(pyline))
                except re.error as exc:
                    self._special('Bad line in "{}" with "{}" ignored: "{}"'.format(os.path.join(path, item), exc.args[0], line))
            # all done
            self.rules[path][item] = rules

    # run through rules directories updating them
    def rulesupdate(self, startup=False):
        # we need to check all paths for updates
        mtimes = {}    # new/updated directories
        filesgone = []    # deleted files to remove from rules after
        for path in self.dirstate:
            if path not in self.rules:
                self.rules[path] = {}
            mtime = os.path.getmtime(path)
            if self.dirstate[path] == mtime:
                continue    # nothing in the directory has changed
            mtimes[path] = mtime    # store to update later
            for item in os.listdir(path):
                if item[0] == '.':
                    continue    # skip hidden files
                if os.path.isfile(os.path.join(path, item)):
                    if os.path.getmtime(os.path.join(path, item)) >= self.dirstate[path] or item not in self.rules[path]:
                        # we need to read in this file
                        self._readrules(path, item)
                        if not startup:
                            if item not in self.rules[path]:
                                self._special('New rule file: {} "{}" "{}"'.format(os.path.join(path, item), path, item))    # inform
                            else:
                                self._special('Updated rule file: {} "{}" "{}"'.format(os.path.join(path, item), path, item))    # inform
            # check and prune non-existing files
            for item in self.rules[path]:
                if not os.path.isfile(os.path.join(path, item)):
                    filesgone.append([path, item])
                    if not startup:
                        self._special('Removed rule file: {} "{}" "{}"'.format(os.path.join(path, item), path, item))    # inform
        # update all dirstates
        for path in mtimes:
            self.dirstate[path] = mtimes[path]
        for item in filesgone:
            self._special('Removing rule file: {} "{}" "{}"'.format(os.path.join(item[0], item[1]), item[0], item[1]))    # inform
            del self.rules[item[0]][item[1]]    # TODO this has a key error


    def _read_lines(self, fd_log, lines):
        """Read whole lines from file

        :arg fd_log: file descriptor, this is the open log file
        :arg lines: list, list to which to append whole log lines (without \n)
        :return: int, bytes in whole lines
        """
        size = 0
        line_buffer = b''
        while b'\n' not in line_buffer:
            chunk = os.read(fd_log, 4096)
            if not chunk:
                # eof
                break
            line_buffer += chunk
            while b'\n' in line_buffer:
                line, line_buffer = line_buffer.split(b'\n', 1)
                size += len(line) + 1   # include \n in count
                lines.append(line.decode('utf-8', errors='ignore'))
                if DEBUG:
                    print("Read line: {}".format(lines[-1]))
        return size


    def _readlog(self, logfile, lastinode, lastposition):
        """Read a log file, continuing on from previous when rotated

        :arg logfile: str, path to log file
        :arg lastinode: int, last inode the file was on
        :arg lastposition: int, last position (for seek) from start of file that was read to
        :return: tuple of:
            int, last inode the file was on (may have changed with rotated file)
            int, last position (for seek) from start of file that was read to
            list, new lines read from file
        """
        lines = []
        # open and read the file
        try:
            fd_log = os.open(logfile, os.O_RDONLY)
        except Exception as exc:
            if logfile not in self.lasterror or self.lasterror[logfile] + config['common']['errornag'] > time.time():
                self._special("Failed opening logfile {} with: {}".format(logfile, exc))
                # set log repeating limit on this file
                self.lasterror[logfile] = time.time()
            return(lastinode, lastposition, lines)
        stat = os.fstat(fd_log)
        # check it's the same file - ie. rotated and read last lines from before if it has
        if lastinode != None and stat.st_ino != lastinode:
            if 'logrotationalert' in config['logcheck'] and config['logcheck']['logrotationalert']:
                self._special("logfile has been rotated {}".format(logfile))
            # this is not the same file - presume logs rotated so find previous and finish it up
            lastlogfile = None
            for lastfile in os.listdir(os.path.dirname(logfile)):
                path = os.path.join(os.path.dirname(logfile), lastfile)
                # files might be changing so be prepared for exceptions
                try:
                    laststat = os.stat(path)
                    if laststat.st_ino == lastinode:
                        lastlogfile = path
                        break
                except FileNotFoundError:
                    pass
            if lastlogfile != None:
                # we have a valid previous logfile to read
                fd_lastlog = os.open(lastlogfile, os.O_RDONLY)
                if lastposition != None:
                    os.lseek(fd_lastlog, lastposition, os.SEEK_SET)
                self._read_lines(fd_lastlog, lines)
                os.close(fd_lastlog)
            else:
                # flag and report this
                self._special("bad - can't find last logfile against {}".format(logfile))
            # whatever happens, we now have to start again for the current logfile
            lastposition = None
        # we need to seek to the last valid position
        if lastposition != None:
            if lastposition > os.path.getsize(logfile):
                # assume it's been truncated so start again
                lastposition = None
                if 'logrotationalert' in config['logcheck'] and config['logcheck']['logrotationalert']:
                    self._special("logfile has been truncated {}".format(logfile))
            else:
                os.lseek(fd_log, lastposition, os.SEEK_SET)
        if lastposition is None:
            lastposition = 0    # we are starting from the beginning
        lastposition += self._read_lines(fd_log, lines)
        os.close(fd_log)
        lastinode = stat.st_ino
        return lastinode, lastposition, lines


    def _matchinglines(self, rules, lines, includelines=True):
        """filter lines for matches
        """
        # TODO this can be optimised by ordering rules by most frequently matched across all contributing files TODO
        outlines = []
        for line in lines:
            if includelines:
                for rule in rules:
                    if rule.search(line):
                        outlines.append(line)
            else:
                includeline = True
                for rule in rules:
                    if rule.search(line):
                        includeline = False
                        break
                if includeline:
                    outlines.append(line)
        return outlines

    # given a host return matching items
    def checklogs(self, host):
        report = {
            'cracking': {},
            'violations': {},
            'normal': {},
        }
        if host not in self.logpositions:
            self.logpositions[host] = {}
        for logfile in self.logfiles[host]:
            if logfile not in self.logpositions[host]:
                self.logpositions[host][logfile] = [None, None, False]
            lastposition, lastinode, lines = self._readlog(logfile, self.logpositions[host][logfile][0], self.logpositions[host][logfile][1])
            if lastposition != self.logpositions[host][logfile][0] or lastinode != self.logpositions[host][logfile][1]:
                self.logpositions[host][logfile] = [lastposition, lastinode, True]
            # now we need to check these against rules
            for category in ['cracking', 'violations']:
                report[category][logfile] = []
                matching = []
                for path in self.hosts[host][category]:
                    for rules in self.rules[path].values():
                        matching.extend(rules)
                ignoring = []
                for path in self.hosts[host]['{}.ignore'.format(category)]:
                    for rules in self.rules[path].values():
                        ignoring.extend(rules)
                report[category][logfile].extend(self._matchinglines(ignoring, self._matchinglines(matching, lines, True), False))
            ignoring = []
            for path in self.hosts[host]['ignore']:
                for rules in self.rules[path].values():
                    ignoring.extend(rules)
            report['normal'][logfile] = []
            report['normal'][logfile].extend(self._matchinglines(ignoring, lines, False))
        # commit to database
        newlines = []
        timenow = int(time.time())
        for category in report:
            for logfile in report[category]:
                for line in report[category][logfile]:
                    lineclean = ''.join([i if ord(i) <= 126 and ord(i) >= 32 else r'\{:02x}'.format(ord(i)) for i in line])    # clean out non-ascii
                    newlines.append([host, logfile, lineclean, category, timenow])
        changed = False
        if newlines:
            changed = True
            for line in newlines:
                print(line)
                self.dbcur.execute('INSERT INTO LogReport (Host,LogFile,Line,Priority,Time) VALUES (?,?,?,?,?)', line)
        for logfile in self.logpositions[host]:
            if self.logpositions[host][logfile][2]:
                # something changed
                changed = True
                self.dbcur.execute('INSERT OR REPLACE INTO LogPosition (Host,LogFile,Inode,Position) VALUES (?,?,?,?)', [host, logfile, self.logpositions[host][logfile][0], self.logpositions[host][logfile][1]])
                # reset for next time
                self.logpositions[host][logfile][2] = False
        if changed:
            self.db.commit()

    # log a special message
    def _special(self, message):
        self.dbcur.execute('INSERT INTO LogReport (Host,LogFile,Line,Priority,Time) VALUES (?,?,?,?,?)', ['__HOST__', '--SPECIAL--', message, 'special', int(time.time())])
        self.db.commit()

    def check_all_logs(self):
        """check all the logs in the config
        """
        for host in self.logfiles:
            self.checklogs(host)

    def autocheck(self):
        """run an iteration of checking everything

        This includes rules updates, log files and mail sending.
        """
        if DEBUG:
            print("autocheck()")
        # update rules if needed
        if self.rulesupdatetimer.timer():
            self.rulesupdate()
        # bail if it's not time to check
        if not self.checktimer.timer():
            return
        # run full set of logs
        if DEBUG:
            print("autocheck() check logs")
        self.check_all_logs()
        # check if we need to mail out
        must_send = False
        # query database for number of non-standard logs - immediate send
        self.dbcur.execute('SELECT COUNT(*) FROM LogReport WHERE Priority != \'normal\'')
        if self.dbcur.fetchone()['COUNT(*)'] > 0:
            if DEBUG:
                print("autocheck() non 'normal' logs found - immediate send")
            must_send = True
        # query database of oldest standard (normal) message - if it trips the timer then ssend unless in holdoff
        self.dbcur.execute('SELECT MIN(Time) FROM LogReport WHERE Priority = \'normal\'')
        oldest = self.dbcur.fetchone()['MIN(Time)']
        timenow = int(time.time())
        if DEBUG:
            print("autocheck() oldest: {}".format(oldest))
            if oldest != None:
                print("autocheck() time until reporttime: {}".format(oldest + config['common']['reporttime'] - timenow))
                print("autocheck() time until holdoff: {}".format(self.holdofftime - timenow))
        if oldest != None and timenow >= oldest + config['common']['reporttime'] and timenow >= self.holdofftime:
            must_send = True
        # mail out iaf needed
        if must_send:
            if DEBUG:
                print("autocheck() sending mail")
            self._send()


    def _send(self):
        """send out anythinng in the queue and clear
        """
        if DEBUG:
            print("_send()")
        messagelines = []
        logfile = None
        # query in order of priority, then host
        for priority in ['special', 'cracking', 'violations', 'normal']:
            for host in self.hostorder:
                self.dbcur.execute('SELECT * FROM LogReport WHERE Priority = ? AND Host = ? ORDER BY LogFile,Time', [priority, host])
                for row in self.dbcur:
                    if row['LogFile'] != logfile:
                        messagelines.append('')
                        messagelines.append("{} :: {}".format(priority, row['LogFile']))
                        messagelines.append('=' * len("{} :: {}".format(priority, row['LogFile'])))
                        logfile = row['LogFile']
                    messagelines.append(row['Line'])
        # prepend context
        messagelines.insert(0, '')
        messagelines.insert(0, 'LogReports from {} on {}:'.format(sys.argv[0], HOSTNAME))
        # TODO put in cycletime at end TODO maybe actually in send_mail() function
        # send these
        send_mail('Log Report for {}'.format(HOSTNAME), messagelines)
        # nuke these entries
        self.dbcur.execute('DELETE FROM LogReport')
        self.db.commit()
        # on send set holdoff timer
        self.holdofftime = int(time.time()) + config['common']['reportholdoff']





# get logging up
syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_DAEMON)
syslog.syslog('Starting up with args: {}'.format(str(sys.argv[1:]) if len(sys.argv) > 1 else 'None'))

# one argument - config file, else looks for a few options
configfile = None
if len(sys.argv) > 1:
    configfile = sys.argv[1]
elif os.path.isfile('/etc/integrityd-log.yaml'):
    configfile = '/etc/integrityd-log.yaml'
elif os.path.isfile('integrityd-log.yaml'):
    configfile = 'integrityd-log.yaml'
syslog.syslog('Using config: {}'.format(configfile))

if not os.path.isfile(configfile):
    sys.exit("FATAL - can't find a config file (might be the command line argument)\n")

# read in conf
with open(configfile, 'rt') as f_config:
    config = yaml.load(f_config)





def rundaemon():
    """main loop with exception logging
    """
    try:
        syslog.syslog('starting daemon')
        rules = LogRules()
        syslog.syslog('entering loop')
        while True:
            rules.autocheck()
            time.sleep(5.0 + 2.0 * random.random())
    except Exception:    # catch excptions, but not all else we catch daemon terminating
        etype, evalue, etrace = sys.exc_info()
        import traceback
        syslog.syslog(syslog.LOG_ERR, 'exception: {}'.format('!! '.join(traceback.format_exception(etype, evalue, etrace))))
        if DEBUG:
            raise
    syslog.syslog('exiting')


def main():
    # sort out class that actually does the work
    if DEBUG:
        # foreground
        rundaemon()
    else:
        # normal (daemon)
        with daemon.DaemonContext(umask=0o077, pidfile=pidlockfile.PIDLockFile('/run/integrityd-log.pid')):
            rundaemon()




if __name__ == '__main__':
    main()

