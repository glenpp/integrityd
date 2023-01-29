#!/usr/bin/env python3
"""
    File Integrity monitoring and logging daemon
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
import random
import signal
import logging
import logging.handlers
import hashlib
import textwrap
import yaml


DEBUG = False   # if True we run in foreground, console output


# main class for tracking node changes
class FileCheck:
    def __init__(self, logger, config, init=False):
        self.logger = logger
        self.config = config
        self.init = init
        self.file_target_time = 0   # time when next file should be processed
        self.per_file_time = None   # set by _setfastmode()
        self.reitterate = False
        self._running = True
        # checksum properties
        self.block_size = 4096
        self.byterate_current = float(config['common']['byterate'])
        self.block_burst = int(float(config['common']['burst']) / self.block_size)
        self.burst_time = 1.0 / (self.byterate_current / self.block_size) * self.block_burst
        # we start in fast mode
        self.fastmode = 0   # start off
        self._setfastmode(True) # transition to on
        # track how frequently we sent cycle time info
        self.nextcycletime = time.time() + config['common']['cycletimeinterval']    # count from startup so we don't report immediately
        self.fastmodeend = self.nextcycletime    # sane to prevent reporting inline with cycle time
        # get the database up
        self.db = sqlite3.connect(self.config['common']['database'])
        self.db.row_factory = sqlite3.Row
        self.dbcur = self.db.cursor()
        # put the tables in we need (if we need them)
        self.dbcur.execute(textwrap.dedent("""\
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
            )"""))
        self.dbcur.execute('CREATE INDEX IF NOT EXISTS NodeInfo_Path ON NodeInfo(Path)')
        self.dbcur.execute('CREATE INDEX IF NOT EXISTS NodeInfo_Path ON NodeInfo(Parent)')
        self.dbcur.execute('CREATE INDEX IF NOT EXISTS NodeInfo_LastChecked ON NodeInfo(LastChecked)')
        self.dbcur.execute('CREATE INDEX IF NOT EXISTS NodeInfo_ForceCheck ON NodeInfo(ForceCheck)')
        self.dbcur.execute("VACUUM")
        self.db.commit()
        # make sure the database is not accessible by others
        os.chmod(self.config['common']['database'], 0o600)
        # remove paths without parents that aren't areas we watch, cycling through to catch all children
        deleted = 1    # make sure we run on the first cycle
        while deleted > 0:
            todelete = []
            self.dbcur.execute("SELECT id,Path FROM NodeInfo WHERE Parent IS NULL")
            for row in self.dbcur:
                if row['Path'] not in self.config['filecheck']['areas']:
                    todelete.append(row['id'])
                    self.logger.info('Clean up unmonitored path: {}'.format(row['Path']))
            for rowid in todelete:
                self.dbcur.execute("UPDATE NodeInfo SET Parent = NULL WHERE Parent = ?", [rowid])
                self.dbcur.execute("DELETE FROM NodeInfo WHERE id = ?", [rowid])
            deleted = len(todelete)
        # add starting records if needed
        for path in self.config['filecheck']['areas']:
            self.dbcur.execute("SELECT COUNT(*) FROM NodeInfo WHERE Path = ?", [path])
            if self.dbcur.fetchone()['COUNT(*)'] == 0:
                self.dbcur.execute("INSERT INTO NodeInfo (Path,LastChecked,Type,UID,GID,Links,Inode,CTime,MTime) VALUES (?,0,'New',0,0,0,0,0,0)", [path])
        self.db.commit()
        # break up excludes
        self.excludes = {'branch': {}}
        if 'exclude' in self.config['filecheck']:
            for path in self.config['filecheck']['exclude']:
                parts = path.split(os.sep)
                if parts[0] == '':
                    parts.pop(0)
                if parts[-1] == '':
                    parts.pop()
                ptr = self.excludes
                for part in parts:
                    ptr = ptr['branch']
                    if part not in ptr:
                        ptr[part] = {
                            'leaf': False,
                            'branch': {},
                        }
                    ptr = ptr[part]
                ptr['leaf'] = True
        # break up noinodes
        self.noinodes = {'branch': {}}
        if 'noinode' in self.config['filecheck']:
            for path in self.config['filecheck']['noinode']:
                parts = path.split(os.sep)
                if parts[0] == '':
                    parts.pop(0)
                if parts[-1] == '':
                    parts.pop()
                ptr = self.noinodes
                for part in parts:
                    ptr = ptr['branch']
                    if part not in ptr:
                        ptr[part] = {
                            'leaf': False,
                            'branch': {},
                        }
                    ptr = ptr[part]
                ptr['leaf'] = True
        # brek up notime
        self.notime = {'branch': {}}
        if 'notime' in self.config['filecheck']:
            for path in self.config['filecheck']['notime']:
                parts = path.split(os.sep)
                if parts[0] == '':
                    parts.pop(0)
                if parts[-1] == '':
                    parts.pop()
                ptr = self.notime
                for part in parts:
                    ptr = ptr['branch']
                    if part not in ptr:
                        ptr[part] = {
                            'leaf': False,
                            'branch': {},
                        }
                    ptr = ptr[part]
                ptr['leaf'] = True



    def _setfastmode(self, state):
        if state != (self.fastmode > 0):
            # state change
            self.per_file_time = 1.0 / self.config['common']['filerate']
            if state:
                self.fastmode = int(time.time())    # this is the epoch when a fast cycle is started - LastChecked after this means cycle complete
                self.byterate_current = float(self.config['common']['byterate']) * self.config['common']['fastmode']
                self.per_file_time /= self.config['common']['fastmode']
            else:
                self.fastmode = 0    # disabled
                self.byterate_current = float(self.config['common']['byterate'])
            self.burst_time = 1.0 / (self.byterate_current / self.block_size) * self.block_burst
        elif state:
            # already in fast mode - reset timer
            self.fastmode = int(time.time())    # this is the epoch when a fast cycle is started - LastChecked after this means cycle complete

    def _time2str(self, epoch):
        return time.strftime('%a, %d %b %Y %H:%M:%S %Z', time.localtime(epoch))

    def _sha1file(self, node):
        """Checksum a single node (file)

        :return: str|None|False, sha1 hex checksum, None on no fail, False on rapid exit
        """
        if DEBUG:
            print("_sha1file({})".format(node))
        try:
            starttime = time.time()
            sha = hashlib.sha1()
            with open(node['Path'], 'rb') as f_check:
                # Caching:
                # This risks filling caches with what we're reading here, displacing potentially higher value items.
                #
                # To work this out trials of FADV options where mode. The lowest option was:
                #   * on opening the file POSIX_FADV_NOREUSE
                #   * before closing the file os.POSIX_FADV_DONTNEED
                #
                # Differences seem small, but this none the less is the lowest cache option consistently in 3 tests
                #
                # See:
                #   man 2 posix_fadvise
                #   https://stackoverflow.com/questions/15266115/read-file-without-disk-caching-in-linux
                os.posix_fadvise(f_check.fileno(), 0, 0, os.POSIX_FADV_NOREUSE)
                data = ' '  # we start with something as the "last read" to ensure the loop starts
                blockcount = 0
                while data:
                    if not self._running:
                        return False
                    data = f_check.read(self.block_size)
                    sha.update(data)
                    blockcount += 1
                    # check on progress
                    if blockcount >= self.block_burst:
                        now = time.time()
                        delay = self.burst_time - (now - starttime)
                        if delay > 0.0:
                            time.sleep(delay)
                            starttime += self.burst_time
                        else:
                            # we're slipping - keep slipping
                            starttime = now
                        blockcount = 0
                os.posix_fadvise(f_check.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)
            return sha.hexdigest()
        except FileNotFoundError:
            return None

    def _checkexclude(self, path):
        parts = path.split(os.sep)
        if parts[0] == '':
            parts.pop(0)
        ptr = self.excludes
        excluded = False
        for part in parts:
            if part in ptr['branch']:
                ptr = ptr['branch'][part]
                if ptr['leaf']:
                    excluded = True
                    break
        return excluded

    def _checknoinode(self, path):
        """Check that the path matches an exclusion or object below
        """
        parts = path.split(os.sep)
        if parts[0] == '':
            parts.pop(0)
        ptr = self.noinodes
        match = False
        for part in parts:
            if part in ptr['branch']:
                ptr = ptr['branch'][part]
                if ptr['leaf']:
                    match = True
                    break
        return match

    def _checknotime(self, path):
        """Check that the path exactly matches an exclusion

        Unlike others where this needs an exact match so does not apply to objects below the node (directory)
        """
        parts = path.split(os.sep)
        if parts[0] == '':
            parts.pop(0)
        ptr = self.notime
        match = False
        while parts:
            part = parts.pop(0)
            if part in ptr['branch']:
                ptr = ptr['branch'][part]
                if ptr['leaf'] and not parts:
                    match = True
                    break
        return match


    def _checknode(self, node):
        """Check one specific node
        """
#        print node['Path']
        nodenow = {}
        for field in node.keys():
            nodenow[field] = node[field]
        # check exclusion
        if self._checkexclude(node['Path']):
            self.logger.info("remove excluded record: {}".format(node['Path']))
            # remove from database
            self.dbcur.execute("DELETE FROM NodeInfo WHERE id = ?", [node['id']])
            return
        # inspect element
        try:
            if os.path.islink(node['Path']):
                stat = os.lstat(node['Path'])
                nodenow['Type'] = 'Symlink'
                nodenow['LinkDest'] = os.readlink(node['Path'])
                nodenow['SHA1'] = None
            else:
                if os.path.isfile(node['Path']):
                    nodenow['Type'] = 'File'
                    nodenow['SHA1'] = self._sha1file(nodenow)
                    if not self._running:
                        return
#                    print nodenow['SHA1']
                elif os.path.isdir(node['Path']):
                    nodenow['Type'] = 'Directory'
                    nodenow['SHA1'] = None
                    below = sorted(os.listdir(node['Path']))
                    data = "\n".join(below)
                    nodenow['SHA1'] = hashlib.sha1(data.encode('utf-8')).hexdigest()
                    for subnode in below:
                        subpath = os.path.join(node['Path'], subnode)
                        if self._checkexclude(subpath):
                            continue    # skip excluded
                        self.dbcur.execute("INSERT OR IGNORE INTO NodeInfo (Path,Parent,LastChecked,ForceCheck,Type,UID,GID,Links,Inode,CTime,MTime) VALUES (?,?,0,1,'New',0,0,0,0,0,0)", [subpath, nodenow['id']])
                else:
                    # sockets, pipes, devices etc.
                    # don't read these, but do stat them
                    nodenow['Type'] = 'Other'
                    nodenow['SHA1'] = None
                stat = os.stat(node['Path'])
                nodenow['LinkDest'] = None
        except (OSError, NotADirectoryError) as exc:
            # check for deletion (handle it)
            if exc.strerror in ['No such file or directory', 'Not a directory']:
                self.logger.warning('Deleted {}: {}'.format(node['Type'], node['Path']))
                parents = [node['id']]
                while parents:
                    todelete = []
                    for parent in parents:
                        self.dbcur.execute('SELECT id,Path,Type FROM NodeInfo WHERE Parent = ?', [parent])
                        for row in self.dbcur:
                            self.reitterate = True    # we have made changes that may impact running list
                            todelete.append(row['id'])
                            self.logger.warning('+Deleted {}: {}'.format(row['Type'], row['Path']))
                        self.dbcur.execute('DELETE FROM NodeInfo WHERE id = ?', [parent])
                    parents = todelete
                return
            # not handled message - re-raise
            raise exc
#            return
#        nodenow['Parent'] = No Change
        nodenow['LastChecked'] = int(time.time())
        nodenow['ForceCheck'] = 0
        nodenow['UID'] = stat.st_uid
        nodenow['GID'] = stat.st_gid
        nodenow['Links'] = stat.st_nlink
        if self._checknoinode(node['Path']):
            nodenow['Inode'] = 0    # pretend it's zero on areas with no inodes
        else:
            nodenow['Inode'] = stat.st_ino
        nodenow['Perms'] = '%04o' % stat.st_mode
        if self._checknotime(node['Path']):
            nodenow['CTime'] = 0    # pretend it's zero on nodes with no times
            nodenow['MTime'] = 0    # pretend it's zero on nodes with no times
        else:
            nodenow['CTime'] = int(stat.st_ctime)
            nodenow['MTime'] = int(stat.st_mtime)
        nodenow['Size'] = stat.st_size
#        print nodenow['SHA1']

        # analyse changes
        changed = False
        changedfields = []
        if node['Type'] == 'New':
            # new node, no need to get into details
            changed = True
            if not self.init:
                self.logger.warning('New {}: {}'.format(nodenow['Type'], nodenow['Path']))
            changedfields = list(nodenow.keys())
        else:
            for field in node.keys():
                if field in ['Path', 'Parent', 'ForceCheck', 'LastChecked']:
                    # skip these
                    pass
                elif nodenow[field] != node[field]:
                    changed = True
                    changedfields.append(field)
            if changed:
                self.logger.warning('Changed {}: {}'.format(nodenow['Type'], nodenow['Path']))
                shortpath = re.sub(r'^.+?(.{1,20})$', r'... \1', nodenow['Path'])
                for field in changedfields:
                    if field in ['CTime', 'MTime']:
                        self.logger.warning('    {}: {} :: {} => {}'.format(shortpath, field, self._time2str(node[field]), self._time2str(nodenow[field])))
                    else:
                        self.logger.warning('    {}: {} :: {} => {}'.format(shortpath, field, node[field], nodenow[field]))
                self.logger.warning('    {}: LastChecked :: {}'.format(shortpath, self._time2str(node['LastChecked'])))
        if changed:
            # changed and directory, set mustcheck on all subnodes
            if nodenow['Type'] == 'Directory':
                self.dbcur.execute("UPDATE NodeInfo SET ForceCheck = 1 WHERE Parent = ?", [nodenow['id']])
        # update database with new data
        changedfields.append('LastChecked')
        if nodenow['ForceCheck'] != node['ForceCheck']:
            changedfields.append('ForceCheck')
        items = ', '.join(['%s = ?' % field for field in changedfields])
        values = [nodenow[field] for field in changedfields]
        values.append(nodenow['id'])
        self.dbcur.execute("UPDATE NodeInfo SET {} WHERE id = ?".format(items), values)
        if changed:
            # switch to fastmode if needed
            self._setfastmode(True)
            if self.fastmode == 0:
                self.logger.info('FastMode Start')



    def cycle(self, number):
        """Do a cycle of "number" items

        :arg number: int, how many nodes to visit/check in this cycle
        """
        # get nodes for this cycle up to number
        # TODO possibly prioritise directories - a delta there means something in them has changed TODO
        self.dbcur.execute("SELECT * FROM NodeInfo WHERE ForceCheck = 1 LIMIT ?", [number])
#        self.dbcur.execute("SELECT * FROM NodeInfo WHERE ForceCheck = 1 ORDER BY RANDOM() LIMIT ?", [number])
        nodes = [row for row in self.dbcur]
        if len(nodes) < number:
            self.dbcur.execute("SELECT * FROM NodeInfo ORDER BY LastChecked LIMIT ?", [number-len(nodes)])
            for row in self.dbcur:
                nodes.append(row)
        # randomise order for security (attacker can't mitigate by guessing what's next)
        random.shuffle(nodes)

        # we have our batch - check all the nodes
        for node in nodes:
            if self.reitterate:
                # something changed that impacts this cycle - break so we re-query
                self.reitterate = False
                break
            now = time.time()
            self.file_target_time = max(now, self.file_target_time + self.per_file_time) # for this (next) file
            # delay in small steps to allow for clean stop
            while self._running:
                delay = min(1.0, self.file_target_time -  time.time())
                if delay <= 0.0:
                    break
                time.sleep(delay)
            if not self._running:
                # end loop if we are stopping
                break
            self._checknode(node)
        self.db.commit()

        # check if we should drop out of fastmode
        if self.fastmode > 0:
            self.dbcur.execute('SELECT MIN(LastChecked) FROM NodeInfo')
            if self.dbcur.fetchone()['MIN(LastChecked)'] > self.fastmode:
                self._setfastmode(False)    # drop out of fastmode
                self.dbcur.execute('SELECT MAX(LastChecked)-MIN(LastChecked) as CycleTime FROM NodeInfo')
                self.logger.info('FastMode Complete with CycleTime = {:d}'.format(self.dbcur.fetchone()['CycleTime']))
                # next regular cycle can start from now
                self.fastmodeend = time.time()
                self.nextcycletime = self.fastmodeend + self.config['common']['cycletimeinterval']
        elif time.time() >= self.nextcycletime:
            # check we've cleared the end of the FastMode cycle - only report once we're clear of fastmode
            self.dbcur.execute('SELECT MIN(LastChecked) FROM NodeInfo')
            if self.dbcur.fetchone()['MIN(LastChecked)'] > self.fastmodeend:
                # regular reporting
                self.dbcur.execute('SELECT MAX(LastChecked)-MIN(LastChecked) as CycleTime FROM NodeInfo')
                self.logger.info('RegularMode CycleTime = %d' % self.dbcur.fetchone()['CycleTime'])
                # next cycle
                self.nextcycletime += self.config['common']['cycletimeinterval']


    def stop(self):
        # allow loops to exit cleanly
        self._running = False




class RunDaemon:
    def __init__(self, logger, config):
        self.logger = logger
        self.config = config
        self.check = None
        self.running = True

    def loop(self):
        try:
            self.logger.info("starting daemon")
            self.check = FileCheck(self.logger, self.config)
            self.logger.info("entering loop")
            while self.running:
                self.check.cycle(100)
        except Exception:   # pylint: disable=broad-except
            self.logger.exception("Exception caught")

    def stop(self, *_):
        self.check.stop()
        self.running = False



def main():
    # get logging up
    logger = logging.getLogger('integrityd-file')
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


    # arguments - config file, else looks for a few options
    # optional argument of --init doesn't report new files until all known new files are captured, then exits
    args = {'init': False}
    configfile = None
    if len(sys.argv) > 1:
        for arg in range(1, len(sys.argv)):
            if sys.argv[arg] == '--init':
                args['init'] = True
                logger.info("Started in init mode - changes will not be logged")
            else:
                configfile = sys.argv[arg]
    if configfile is None:
        if os.path.isfile('/etc/integrityd-file.yaml'):
            configfile = '/etc/integrityd-file.yaml'
        elif os.path.isfile('integrityd-file.yaml'):
            configfile = 'integrityd-file.yaml'
    if not os.path.isfile(configfile):
        logger.error("Can't find a config file (might be the command line argument)")
        sys.exit("FATAL - can't find a config file (might be the command line argument)\n")
    # read in conf
    logger.info("reading config from: %s", configfile)
    with open(configfile, 'rt') as f_config:
        config = yaml.safe_load(f_config)

    # if not specified in the config, add cycletime interval
    if 'cycletimeinterval' not in config['common']:
        config['common']['cycletimeinterval'] = 86400    # once every 24 hours


    # sort out class that actually does the work
    if args['init']:
        logger.info('starting init')
        check = FileCheck(logger, config)
        newnodes = True
        while check.fastmode > 0 and newnodes:
            check.cycle(100)
            check.dbcur.execute("SELECT COUNT(*) FROM NodeInfo WHERE Type = 'New'")
            if check.dbcur.fetchone()['COUNT(*)'] == 0:
                newnodes = False
        logger.info('init complete')
    else:
        # with systemd just let it handle things
        runner = RunDaemon(logger, config)
        signal.signal(signal.SIGTERM, runner.stop)
        runner.loop()
        logger.info("exiting")




if __name__ == '__main__':
    main()
