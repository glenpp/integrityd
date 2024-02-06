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
import signal
import warnings
import logging
import logging.handlers
import hashlib
import fnmatch
import textwrap
import yaml


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
def send_mail(config, subject, lines):
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
    """Handle log files"""

    def __init__(self, logger, config):
        self.logger = logger
        self.config = config
        self.rules_stat = {}    # directory -> filename -> dict of key stat for checking changes
        self.rules = {}    # holds paths, files below those and lists of rules in those files
        self.hosts = {}    # holds the host, categories and list of paths relevant to the catoegory
        self.hostorder = ['__HOST__']    # hosts in configuration order (which we send reports in)
        self.logpositions = {}
        self.logfiles = {}    # lists by host
        self.logfiles_transient = {}    # lists by host - for logfiles (also in above) to be ignored if not available
        self.checktimer = Timer(self.config['logcheck']['checkinterval'])
        self.rulesupdatetimer = Timer(self.config['logcheck']['rulesfreshness'])
        self.holdofftime = 0    # startup with no holdoff
        self.lasterror = {} # the last error we had on a file to avoid excess repeating warnings
        # unused rule reporting cycle
        report_unused_cycle = self.config['common'].get('report_unused_cycle_days')
        self.unused_report_timer = None
        if report_unused_cycle:
            report_unused_cycle *= 86400    # in seconds
            self.unused_report_timer = Timer(report_unused_cycle)
            self.unused_report_timer.timer()    # avoid triggering on first cycle
        # get the database up
        self.db = sqlite3.connect(self.config['common']['database'])
        self.db.row_factory = sqlite3.Row
        self.dbcur = self.db.cursor()
        # put the tables in we need (if we need them)
        self.dbcur.execute(textwrap.dedent("""\
            CREATE TABLE IF NOT EXISTS `LogPosition` (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                Host CHAR(40) NOT NULL,
                LogFile TEXT NOT NULL UNIQUE,
                Inode INT UNSIGNED NOT NULL,
                Position INT UNSIGNED NOT NULL
            )"""))
        self.dbcur.execute("CREATE INDEX IF NOT EXISTS LogPosition_LogFile ON LogPosition(LogFile)")
        self.dbcur.execute(textwrap.dedent("""\
            CREATE TABLE IF NOT EXISTS `LogReport` (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                Host CHAR(40) NOT NULL,
                LogFile TEXT NOT NULL,
                Line TEXT NOT NULL,
                Priority CHAR(20) NOT NULL,
                Time INT UNSIGNED NOT NULL DEFAULT 0
            )"""))
        self.dbcur.execute("CREATE INDEX IF NOT EXISTS LogReport_Priority ON LogReport(Priority)")
        # track usage of indiviual rules
        self.dbcur.execute(textwrap.dedent("""\
            CREATE TABLE IF NOT EXISTS `RulesStatsFiles` (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                RulesPath TEXT NOT NULL,
                RulesFilename TEXT NOT NULL
            )"""))
        self.dbcur.execute("CREATE UNIQUE INDEX IF NOT EXISTS RulesStatsFiles_path ON RulesStatsFiles(RulesPath, RulesFilename)")
        self.dbcur.execute(textwrap.dedent("""\
            CREATE TABLE IF NOT EXISTS `RulesStatsLines` (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                RulesStatsFile_id INT UNSIGNED NOT NULL,
                LineSHA1 CHAR(40) NOT NULL,
                LineNum INT UNSIGNED NOT NULL,
                Added INT UNSIGNED NOT NULL,
                MatchedLast INT UNSIGNED,
                MatchedCount INT UNSIGNED NOT NULL,
                FOREIGN KEY(RulesStatsFile_id) REFERENCES RulesStatsFiles(id)
            )"""))
        self.dbcur.execute("CREATE UNIQUE INDEX IF NOT EXISTS RulesStatsLines_sha1 ON RulesStatsLines(RulesStatsFile_id, LineSHA1)")
        self.dbcur.execute("VACUUM")
        self.db.commit()
        # make sure the database is not accessible by others
        os.chmod(self.config['common']['database'], 0o600)
        # populate host configs we work against
        for host in self.config['logcheck']['hosts']:
            hostconfig = {
                'cracking': [],
                'cracking.ignore': [],
                'violations': [],
                'violations.ignore': [],
                'ignore': [],
                '_baserules': None,
            }
            # figure out bases we are using
            basemode = self.config['logcheck']['basemode']
            if 'basemode' in host:
                basemode = host['basemode']
            baserules = self.config['logcheck']['baserules']
            if 'baserules' in host:
                baserules = host['baserules']
            hostconfig['_baserules'] = baserules
            # add bases - these have to have the full set of directories
            for category in ['cracking', 'cracking.ignore', 'violations', 'violations.ignore']:
                hostconfig[category].append(os.path.join(baserules, f'{category}.d'))
            hostconfig['ignore'].append(os.path.join(baserules, 'ignore.d.paranoid'))
            if basemode in ['workstation', 'server']:
                hostconfig['ignore'].append(os.path.join(baserules, 'ignore.d.server'))
            if basemode in ['workstation']:
                hostconfig['ignore'].append(os.path.join(baserules, 'ignore.d.workstation'))
            # now add local rules, assuming they are all ignores if there are no dirs
            if 'localrules' in host:
                localmode = host.get('localmode', basemode)
                localrules = host['localrules']
                if not isinstance(localrules, list):
                    localrules = [localrules]
                    self._special('Bad config "localrules" should be list of rules directories (was string)')
                for rule_dir in localrules:
                    gotrules = False
                    for category in ['cracking', 'cracking.ignore', 'violations', 'violations.ignore']:
                        if os.path.isdir(os.path.join(rule_dir, f'{category}.d')):
                            hostconfig[category].append(os.path.join(rule_dir, f'{category}.d'))
                            gotrules = True
                    if os.path.isdir(os.path.join(rule_dir, 'ignore.d.paranoid')):
                        hostconfig['ignore'].append(os.path.join(rule_dir, 'ignore.d.paranoid'))
                        gotrules = True
                    if localmode in ['workstation', 'server']:
                        if os.path.isdir(os.path.join(rule_dir, 'ignore.d.server')):
                            hostconfig['ignore'].append(os.path.join(rule_dir, 'ignore.d.server'))
                            gotrules = True
                    if localmode in ['workstation']:
                        if os.path.isdir(os.path.join(rule_dir, 'ignore.d.workstation')):
                            hostconfig['ignore'].append(os.path.join(rule_dir, 'ignore.d.workstation'))
                            gotrules = True
                    # if we didn't get any of the dirs, then assme the directory given is an ignore directory
                    if not gotrules:
                        hostconfig['ignore'].append(rule_dir)
            # we should now have all the config for this host
            self.hosts[host['name']] = hostconfig
            self.logfiles[host['name']] = host['logfiles'] + host.get('logfiles_transient', [])
            self.logfiles_transient[host['name']] = host.get('logfiles_transient', [])
            self.hostorder.append(host['name'])
        # populate directory states
        for host in self.hosts:
            for check in self.hosts[host]:
                if check == '_baserules':
                    continue
                for path in self.hosts[host][check]:
                    self.rules_stat.setdefault(path, {})    # set empty to force files to be checked TODO can we get() when used rather?
        # prepopulate existing stats for all the rules
        self.dbcur.execute('SELECT * FROM RulesStatsLines INNER JOIN RulesStatsFiles ON RulesStatsLines.RulesStatsFile_id = RulesStatsFiles.id')
        for row in self.dbcur:
            if row['RulesPath'] not in self.rules:
                self.rules[row['RulesPath']] = {}
            if row['RulesFilename'] not in self.rules[row['RulesPath']]:
                self.rules[row['RulesPath']][row['RulesFilename']] = {}
            self.rules[row['RulesPath']][row['RulesFilename']][row['LineSHA1']] = {
                'count': row['MatchedCount'],
                'last_used': -1 if row['MatchedLast'] is None else row['MatchedLast'],
                'time_added': row['Added'],
            }
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
        self._special(f'{sys.argv[0]} starting up')
        self.dbcur.execute('SELECT COUNT(*) FROM LogReport')
        if self.dbcur.fetchone()['COUNT(*)'] > 0:
            self._send()

    def store_stats(self):
        """Store stats generated to database (make persistant)
        """
        # work out all basepaths - these will be ignored, only custom rules reported TODO
        # TODO or should we mark these at load time
        basepaths = [hostconfig['_baserules'] for hostconfig in self.hosts.values()]
        # prune gone away files from stats
        prune_files = []
        self.dbcur.execute('SELECT * FROM RulesStatsFiles')
        for row in self.dbcur:
            # check for a missing path/directory
            if row['RulesPath'] not in self.rules:
                prune_files.append(row['id'])
                continue
            # see if this is below one of the basepaths - always has extra category dir
            if os.path.dirname(row['RulesPath'].rstrip(os.sep)) in basepaths:
                prune_files.append(row['id'])
                continue
            # check for a missing file
            if row['RulesFilename'] not in self.rules[row['RulesPath']]:
                prune_files.append(row['id'])
                continue
        for prune_id in prune_files:
            self.dbcur.execute('DELETE FROM RulesStatsLines WHERE RulesStatsFile_id = ?', [prune_id])
            self.dbcur.execute('DELETE FROM RulesStatsFiles WHERE id = ?', [prune_id])
        # prune gone away rules from stats
        prune_sha1s = []
        self.dbcur.execute('SELECT * FROM RulesStatsLines INNER JOIN RulesStatsFiles ON RulesStatsLines.RulesStatsFile_id = RulesStatsFiles.id')
        for row in self.dbcur:
            rules = self.rules[row['RulesPath']][row['RulesFilename']]
            if row['LineSHA1'] not in rules:
                prune_sha1s.append(row['id'])
        for prune_id in prune_sha1s:
            self.dbcur.execute('DELETE FROM RulesStatsFiles WHERE id = ?', [prune_id])
        # done pruning
        self.db.commit()
        # update stats
        for path in self.rules:
            # see if this is below one of the basepaths - always has extra category dir
            if os.path.dirname(path.rstrip(os.sep)) in basepaths:
                continue
            # process each file
            for item in self.rules[path]:
                self.dbcur.execute('SELECT id FROM RulesStatsFiles WHERE RulesPath = ? AND RulesFilename = ?', [path, item])
                file_id = self.dbcur.fetchone()
                file_id = None if file_id is None else file_id['id']
                if file_id is None:
                    self.dbcur.execute('INSERT INTO RulesStatsFiles (RulesPath, RulesFilename) VALUES (?, ?)', [path, item])
                    file_id = self.dbcur.lastrowid
                for sha1, stats in self.rules[path][item].items():
                    self.dbcur.execute('SELECT COUNT(*) FROM RulesStatsLines WHERE RulesStatsFile_id = ? AND LineSHA1 = ?', [file_id, sha1])
                    if self.dbcur.fetchone()['COUNT(*)']:
                        # update
                        self.dbcur.execute(
                            'UPDATE RulesStatsLines SET LineNum = ?, Added = ?, MatchedLast = ?, MatchedCount = ? WHERE RulesStatsFile_id = ? AND LineSHA1 = ?',
                            [
                                stats['line_number'], stats['time_added'], stats['last_used'] if stats['last_used'] > 0 else None, stats['count'],
                                file_id, sha1,
                            ]
                        )
                    else:
                        # insert
                        self.dbcur.execute(
                            'INSERT INTO RulesStatsLines (RulesStatsFile_id, LineSHA1, LineNum, Added, MatchedLast, MatchedCount) VALUES (?, ?, ?, ?, ?, ?)',
                            [
                                file_id, sha1,
                                stats['line_number'], stats['time_added'], stats['last_used'] if stats['last_used'] > 0 else None, stats['count'],
                            ]
                        )
                self.db.commit()

    def report_unused(self):
        """Report (log) patterns that have not been used for the configured period
        """
        report_time = self.config['common'].get('report_unused_rules_days')
        if not report_time:
            # we don't report
            return
        report_time *= 86400    # in seconds
        # work out all basepaths - these will be ignored, only custom rules reported
        basepaths = [hostconfig['_baserules'] for hostconfig in self.hosts.values()]
        time_now = int(time.time())
        #newest = time_now - 7200
        newest = time_now - report_time
        report_patterns = []
        for path in self.rules:
            # see if this is below one of the basepaths - always has extra category dir
            if os.path.dirname(path.rstrip(os.sep)) in basepaths:
                continue
            # work out ignores
            for item in self.rules[path]:
                full_path = os.path.join(path, item)
                ignore = False
                for pattern in self.config['common'].get('unused_rules_ignore', []):
                    if fnmatch.fnmatchcase(full_path, pattern):
                        ignore = True
                        break
                if ignore:
                    continue
                # check there are items to report
                for sha1, stats in self.rules[path][item].items():
                    if stats['time_added'] > newest:
                        continue    # too new
                    if stats['last_used'] >= newest:
                        continue
                    # we got an item that should be reported
                    report_patterns.append(
                        [
                            "stats %s: line %d, sha1 %s added %s last used %s count %d",
                            os.path.join(path, item),
                            stats['line_number'],
                            sha1,
                            time.strftime('%Y-%m-%d', time.localtime(stats['time_added'])),
                            #time.strftime('%Y-%m-%d', time.localtime(stats['last_used'])) if stats['last_used'] > 0 else 'NEVER',
                            '{:0.1f} days'.format((time_now - stats['last_used']) / 86400) if stats['last_used'] > 0 else 'NEVER',
                            stats['count'],
                        ]
                    )
        if report_patterns:
            self.logger.info("unused rules report start ----------------")
            for report_log in report_patterns:
                self.logger.info(*report_log)
            self.logger.info("unused rules report end ------------------")
        else:
            self.logger.info("unused rules report: no unused rules")



    # read in a rules file
    def _readrules(self, path, item):
        """Read in a rules file

        :param path: str, path to rules directory
        :param item: str, filename of individual file
        """
        time_now = int(time.time())
        file_path = os.path.join(path, item)
        with open(file_path, 'rt') as f_rules:
            try:
                lines = f_rules.read().splitlines()
            except UnicodeDecodeError as exc:
                self.logger.exception("Failed reading %s || %s | %s", file_path, path, item)
                raise

            rules = {}
            existing_rules = self.rules.get(path, {}).get(item, {})
            for line_number, line in enumerate(lines):  # identify comments and blanks
                if not line or line.startswith('#'):
                    continue
                sha1 = hashlib.sha1((file_path + '\0' + line).encode('utf-8')).hexdigest()
                # TODO this is a very crude change over for translating perl/posix into python TODO
                # see https://www.regular-expressions.info/posixbrackets.html
                pyline = line
                pyline = pyline.replace('[:alnum:]', 'a-zA-Z0-9')
                pyline = pyline.replace('[:alpha:]', 'a-zA-Z')
                pyline = pyline.replace('[:blank:]', r' \t')
                # pyline = pyline.replace('[:cntrl:]', '')  # TODO
                pyline = pyline.replace('[:digit:]', r'\d')
                pyline = pyline.replace('[:graph:]', '\x00-\x7f')
                pyline = pyline.replace('[:lower:]', 'a-z')
                # pyline = pyline.replace('[:rint:]', '')  # TODO
                # pyline = pyline.replace('[:punct:]', '')  # TODO
                pyline = pyline.replace('[:space:]', r'\s')
                pyline = pyline.replace('[:upper:]', 'A-Z')
                pyline = pyline.replace('[:word:]', r'\w')
                pyline = pyline.replace('[:xdigit:]', '0-9a-fA-F')
                # generate the compiled expression
                try:
                    rule = existing_rules.get(
                        sha1,
                        {
                            'count': 0,
                            'last_used': -1,
                            'time_added': time_now,
                        }
                    )
                    # always use latest file contents
                    rule['line_number'] = line_number + 1   # human number
                    with warnings.catch_warnings():
                        warnings.filterwarnings('error')
                        try:
                            rule['regex'] = re.compile(pyline)
                        except Warning as wrn:
                            self._special(
                                'Bad line {} in "{}" (warning: {}) ignored: "{}"'.format(
                                    line_number + 1,
                                    os.path.join(path, item),
                                    wrn,
                                    line
                                )
                            )
                            continue
                    # sanity check
                    if rule['regex'].search('') or len(pyline) <= 3:
                        # this should not match anything - we have a wildcard line
                        self._special(
                            'Bad line {} in "{}" (broad matching) ignored: "{}"'.format(
                                line_number + 1,
                                os.path.join(path, item),
                                line
                            )
                        )
                        continue
                    # use it
                    rules[sha1] = rule
                except re.error as exc:
                    self._special(
                        'Bad line {} in "{}" with "{}" ignored: "{}"'.format(
                            line_number + 1,
                            os.path.join(path, item),
                            exc.args[0],
                            line
                        )
                    )
            # all done
            self.rules[path][item] = rules

    def rulesupdate(self, startup=False):
        """
        Update rules files in all directories if they change

        :param startup: bool, default false, initial startup cycle
        """
        # we need to check all paths for updates
        mtimes = {}    # new/updated directories
        files_gone = []    # deleted files to remove from rules after
        for path in self.rules_stat:
            self.rules.setdefault(path, {})
            for item in os.listdir(path):
                if item.startswith('.'):
                    continue    # skip hidden files
                if not os.path.isfile(os.path.join(path, item)):
                    # we only do files
                    continue
                file_stat = os.stat(os.path.join(path, item))
                file_info = {
                    'mtime': file_stat.st_mtime_ns,
                    'size': file_stat.st_size,
                }
                if file_info != self.rules_stat[path].get(item) or startup:
                    # we need to read in this file
                    self._readrules(path, item)
                    if not startup:
                        if item not in self.rules[path]:
                            self._special('New rule file: {} "{}" "{}"'.format(os.path.join(path, item), path, item))    # inform
                        else:
                            self._special('Updated rule file: {} "{}" "{}"'.format(os.path.join(path, item), path, item))    # inform
                self.rules_stat[path][item] = file_info
            # check and prune non-existing files
            for item in self.rules[path]:
                if not os.path.isfile(os.path.join(path, item)):
                    files_gone.append([path, item])
                    if not startup:
                        self._special('Removed rule file: {} "{}" "{}"'.format(os.path.join(path, item), path, item))    # inform
        # cleanup items gone away
        for item in files_gone:
            self._special('Removing rule file: {} "{}" "{}"'.format(os.path.join(item[0], item[1]), item[0], item[1]))    # inform
            if item[0] in self.rules and item[1] in self.rules[item[0]]:
                del self.rules[item[0]][item[1]]
            if item[0] in self.rules_stat and item[1] in  self.rules_stat[item[0]]:
                del self.rules_stat[item[0]][item[1]]
        paths_gone = []
        for path in self.rules:
            if path not in self.rules_stat:
                paths_gone.append(path)
        for path in paths_gone:
            self._special(f'Removing rule path: {path}')
            del self.rules[path]

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
                    print(f"Read line: {lines[-1]}")
        return size


    def _readlog(self, logfile, lastinode, lastposition, transient=False):
        """Read a log file, continuing on from previous when rotated

        :param logfile: str, path to log file
        :param lastinode: int, last inode the file was on
        :param lastposition: int, last position (for seek) from start of file that was read to
        :param transient: bool, if the file is not always available and should be ignored
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
            if transient and exc.__class__ is FileNotFoundError:
                pass    # skip
            elif logfile not in self.lasterror or self.lasterror[logfile] + self.config['common']['errornag'] > time.time():
                self.logger.exception("Failed opening logfile: %s", logfile)    # TODO capture any problems for now
                self._special(f"Failed opening logfile \"{logfile}\" with: {exc}")
                # set log repeating limit on this file
                self.lasterror[logfile] = time.time()
            return(lastinode, lastposition, lines)
        stat = os.fstat(fd_log)
        # check it's the same file - ie. rotated and read last lines from before if it has
        if lastinode is not None and stat.st_ino != lastinode:
            if 'logrotationalert' in self.config['logcheck'] and self.config['logcheck']['logrotationalert']:
                self._special(f"logfile has been rotated {logfile}")
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
            if lastlogfile is not None:
                # we have a valid previous logfile to read
                fd_lastlog = os.open(lastlogfile, os.O_RDONLY)
                if lastposition is not None:
                    os.lseek(fd_lastlog, lastposition, os.SEEK_SET)
                self._read_lines(fd_lastlog, lines)
                os.close(fd_lastlog)
            else:
                # flag and report this
                self._special(f"bad - can't find last logfile against {logfile}")
            # whatever happens, we now have to start again for the current logfile
            lastposition = None
        # we need to seek to the last valid position
        if lastposition is not None:
            if lastposition > stat.st_size:
                # assume it's been truncated so start again
                lastposition = None
                if 'logrotationalert' in self.config['logcheck'] and self.config['logcheck']['logrotationalert']:
                    self._special(f"logfile has been truncated {logfile}")
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

        :param rules: list, each item dict containing matching info
        :param lines: list, log lines to process (each str)
        :param includelines: bool, return matching lines (else non-matching lines)
        :return: list, matched lines
        """
        time_now = int(time.time())
        # TODO this can be optimised by ordering rules by most frequently matched across all contributing files TODO
        outlines = []
        if includelines:
            # return matching lines
            for line in lines:
                for rule in rules:
                    if rule['regex'].search(line):
                        outlines.append(line)
                        rule['count'] += 1
                        rule['last_used'] = time_now
        else:
            # return non-matching lines
            for line in lines:
                includeline = True
                for rule in rules:
                    if rule['regex'].search(line):
                        rule['count'] += 1
                        rule['last_used'] = time_now
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
            lastposition, lastinode, lines = self._readlog(logfile,
                                                           self.logpositions[host][logfile][0],
                                                           self.logpositions[host][logfile][1],
                                                           logfile in self.logfiles_transient[host])
            if lastposition != self.logpositions[host][logfile][0] or lastinode != self.logpositions[host][logfile][1]:
                self.logpositions[host][logfile] = [lastposition, lastinode, True]
            # now we need to check these against rules
            for category in ['cracking', 'violations']:
                report[category][logfile] = []
                matching = []
                for path in self.hosts[host][category]:
                    for rules in self.rules[path].values():
                        matching.extend(rules.values())
                ignoring = []
                for path in self.hosts[host][f'{category}.ignore']:
                    for rules in self.rules[path].values():
                        ignoring.extend(rules.values())
                report[category][logfile].extend(self._matchinglines(ignoring, self._matchinglines(matching, lines, True), False))
            ignoring = []
            for path in self.hosts[host]['ignore']:
                for rules in self.rules[path].values():
                    ignoring.extend(rules.values())
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
        self.logger.debug("autocheck()")
        # update rules if needed
        if self.rulesupdatetimer.timer():
            self.rulesupdate()
        # bail if it's not time to check
        if not self.checktimer.timer():
            return
        # check reporting of unused rules
        if self.unused_report_timer is not None:
            if self.unused_report_timer.timer():
                self.logger.debug("autocheck() unused rule reporting")
                # run store and reporting
                self.store_stats()
                self.report_unused()
        # run full set of logs
        self.logger.debug("autocheck() check logs")
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
            print(f"autocheck() oldest: {oldest}")
            if oldest != None:
                print("autocheck() time until reporttime: {}".format(oldest + self.config['common']['reporttime'] - timenow))
                print("autocheck() time until holdoff: {}".format(self.holdofftime - timenow))
        if oldest is not None and timenow >= oldest + self.config['common']['reporttime'] and timenow >= self.holdofftime:
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
        # query in order of priority, then host
        for priority in ['special', 'cracking', 'violations', 'normal']:
            logfile = None
            for host in self.hostorder:
                self.dbcur.execute(
                    'SELECT * FROM LogReport WHERE Priority = ? AND Host = ? ORDER BY LogFile,Time',
                    [priority, host]
                )
                file_count = 0
                insert_count = None
                for row in self.dbcur:
                    if row['LogFile'] != logfile:
                        if insert_count is not None and file_count >= self.config['common']['report_file_line_limit']:
                            messagelines.insert(insert_count, f"LIMITED - {self.config['common']['report_file_line_limit']} of {file_count}")
                        file_count = 0
                        messagelines.append('')
                        messagelines.append(f"{priority} :: {row['LogFile']}")
                        messagelines.append('=' * len(f"{priority} :: {row['LogFile']}"))
                        insert_count = len(messagelines)
                        logfile = row['LogFile']
                    if file_count < self.config['common']['report_file_line_limit']:    # TODO default or skip?
                        messagelines.append(row['Line'])
                    file_count += 1
        if insert_count is not None and file_count >= self.config['common']['report_file_line_limit']:
            messagelines.insert(insert_count, f"LIMITED - {self.config['common']['report_file_line_limit']} of {file_count}")
        # prepend context
        messagelines.insert(0, '')
        messagelines.insert(0, f'LogReports from {sys.argv[0]} on {HOSTNAME}:')
        # TODO put in cycletime at end TODO maybe actually in send_mail() function
        # send these
        send_mail(self.config, f'Log Report for {HOSTNAME}', messagelines)
        # nuke these entries
        self.dbcur.execute('DELETE FROM LogReport')
        self.db.commit()
        # on send set holdoff timer
        self.holdofftime = int(time.time()) + self.config['common']['reportholdoff']







class RunDaemon:
    """Main loop handler
    """
    def __init__(self, logger, config):
        """Constructor

        :param logger: logging object, passed through to log
        :param config: dict, loaded config file
        """
        self.logger = logger
        self.config = config
        self.running = True

    def loop(self):
        """Run main loop to check logs
        """
        rules = None
        try:
            self.logger.info("starting daemon")
            rules = LogRules(self.logger, self.config)
            self.logger.info("entering loop")
            while self.running:
                rules.autocheck()
                delay = 5.0 + 2.0 * random.random() # TODO make cycle configurable
                while self.running and delay > 0.0:
                    time.sleep(max(1.0, delay))
                    delay -= 1.0
        except Exception:   # pylint: disable=broad-except
            self.logger.exception("Exception caught")
        if rules is not None:
            rules.store_stats()
            rules.report_unused()

    def stop(self, *args):
        """Set loop to exit
        """
        self.running = False



def main():
    # get logging up
    logger = logging.getLogger('integrityd-log')
    log_level = logging.INFO
    if DEBUG:
        log_level = logging.DEBUG
    logger.setLevel(log_level)
    syslog_handler = logging.handlers.SysLogHandler(
        address='/dev/log',
        facility=logging.handlers.SysLogHandler.LOG_DAEMON
    )
    syslog_handler.setFormatter(
        logging.Formatter(
            # TODO should this depend on debug mode?
            '%(name)s[%(process)d]: [%(levelname)s] %(message)s (%(filename)s:%(lineno)d)'
        )
    )
    syslog_handler.setLevel(log_level)
    logger.addHandler(syslog_handler)
    logger.info("Starting up with args: %s", str(sys.argv[1:]) if len(sys.argv) > 1 else 'None')

    # one argument - config file, else looks for a few options
    configfile = None
    if len(sys.argv) > 1:
        configfile = sys.argv[1]
    elif os.path.isfile('/etc/integrityd-log.yaml'):
        configfile = '/etc/integrityd-log.yaml'
    elif os.path.isfile('integrityd-log.yaml'):
        configfile = 'integrityd-log.yaml'
    if not os.path.isfile(configfile):
        logger.error("Can't find a config file (might be the command line argument)")
        sys.exit("FATAL - can't find a config file (might be the command line argument)\n")
    # read in conf
    logger.info("reading config from: %s", configfile)
    with open(configfile, 'rt') as f_config:
        config = yaml.safe_load(f_config)

    # with systemd just let it handle things
    runner = RunDaemon(logger, config)
    signal.signal(signal.SIGTERM, runner.stop)
    runner.loop()
    logger.info("exiting")


if __name__ == '__main__':
    main()
