# File integrity and log anomaly auditing Updated (like fcheck/logcheck)

About 5 years ago I wrote and then spent another year refining my original combined File Integrity and Log Anomaly monitoring daemon. This was due to security concerns with the periodically run tools (generally from cron) and the high impact they had on systems by reading loads of files quickly on each run. The impact is particularly bad when you've got virtualisation and all the guests kick off together. The long periods between and known schedule meant anyone up to anything malicious could easily defeat these just by choosing their timing carefully.

I solved these problems by creating a daemon that trickled along in the background with low impact, and by randomising the path it took when checking files. Although never perfect, this makes it highly unpredictable for anyone trying to hide malicious activity while being able to alert quickly about log anomalies. I also made provision for understanding OpenVz containers which where the established container technology at that time.

The experience gained has been very useful and a lot has changed since then in both the way that systems are architected, mainstream technologies and the direction things are going.

## Why this approach?

The vast majority of tools of this type are (despite what vendors will say) orientated to and used in a reactive manner. They may produce colourful graphs and allow you to check what happened, but they're not going to tell you about tiny things that you haven't seen before that could be important in the long run (proactive).

What I aim for is to exclude normal healthy system activity (noise) so that anything abnormal is reported. This does require good quality configuration (possibly automated) and diligent operations to maintain the health of systems. While some may not recognise the value of this in reducing end-to-end costs and would prefer to quietly ignore problems until they are forced to act, those that are interested in tools like this would see the value.

## What's changed

This iteration of the tools is a massive change, essentially a complete rewrite (though largely same refinements, approach and database schema). The main changes are:

**Ported from Perl to Python:** This is a more modern language, far more readable and can leverage a huge number of high quality modules / classes to build on.

**Separation of File Integrity and Log Anomaly functions:** With Cloud Computing taking over, centralised logging has become commonplace. This means that there are many cases where it is unnecessary (and safer) to only run File Integrity on an instance/host and centrally inspect log files for anomalies separately.

**Support for systemd:** Love it or hate it, major distros are using systemd so this now ships with systemd unit files rather than the init script of the previous version.

**File Integrity logging:** Previously all reporting was by email which is often a sensible way of distributing alerts (they could be processed to SMS etc. if needed). With separation of functions, it makes much more sense that File Integrity is reported via syslog so that it makes its way to the centralised mechanisms for handling logging and reporting. The Log Anomaly part of this tool can then report on the changes by email or whatever other log processing you use.

**Base and local log rules:** Originally I used the logcheck database of regular expressions to exclude normal log activity. This is an excellent baseline, but it meant editing and adding to this database as well as maintaining a full database for every different scenario (eg. host doing different work). This version allows a base ruleset (again the logcheck database is the aim) and then a separate set of additional rules for each host or group of logs. This makes things a lot more manageable and safer.

## Install

Both parts of this can be used separately if needed, or combine them for stand-alone hosts.
While there is a simple install/update script (targeted for Debian based systems) you should fully read this posting before proceeding.

Many Python modules used will already exist on systems, but if you find you are missing one you will get an error about "import \*\*\*\*" and typically under Debian/Ubuntu and derived distros will need to install a package with the corresponding name "python3-\*\*\*\*"

### File Integrity Monitor

This is the more complicated tool since with the limited distribution of Python 3.4 modules at this time and big benefits of Python 3.3+ for the checksumming functionality, I've split this into two scripts. The main script is Python 2.7 to take advantage of the many modules available, and the checksumming is Python 3.4 to leverage new low-level controls to reduce impact on the system.

The main daemon is **integrityd-file.py** which would typically go in /usr/local/sbin for a local install. This should be made executable (chmod +x).

The configuration file **integrityd-file.yaml** would go in /etc and should be updated to match the system.

The systemd unit file **integrityd-file.service** would normally go in /etc/systemd/system/ for local configuration.

When started the daemon will create a Sqlite3 database in the location in the config and start reporting on changed files in the areas set in the config. This is annoying on the first run as every file is reported as being "New" so you can manually run an initialisation which will run in the foreground and not report anything new, but will still report anything existing which has changed.

```
# integrityd-file.py --init
```

Once that finishes you can enable the daemon to start at boot and start it off:

```
# systemctl enable integrityd-file
# systemctl start integrityd-file
```

Keep an eye on the logs an you should see any changes reported.

If you want to change the configuration you need to restart the daemon. On start the daemon runs in "fast mode" until the first pass is complete, and then drops down to the normal configured speeds from the configuration files. When a change is detected the daemon will switch back to fast mode until it has a clean cycle with no changes.

### Log Anomaly monitor

Similarly to the File Integrity monitor, this has a main daemon **integrityd-log.py** which would be put in /usr/local/sbin/ for local installs.

The configuration file **integrityd-log.yaml** again goes in /etc. This will need editing to reflect the configuration of the system and different groups of logs and rules. It's assumed you will use the logcheck databse (on Debian/Ubuntu and derived distros install the "logcheck-database" package) as the base rules, and then you can create your own local rules specific to the host / logfiles in each group. These may be under /etc/integrityd/localrules-somehostname/ and are just sets of regex to match and eliminate items from the logs.

There is also the systemd unit file **integrityd-log.service** which as before goes in /etc/systemd/system/ for local installs.

At this point you can enable and start the daemon:

```
# systemctl enable integrityd-log
# systemctl start integrityd-log
```

You should almost immediately get an email sent (to the configured address) on startup and follwed by log entries. When started the daemon will create a Sqlite3 database in the location in the config.

The rules can be updated dynamically and the daemon will automatically check for changes and load the new rules. Currently some errors in rules may cause the daemon to fail with an exception (manually check the logs) and you should also get an email reporting any changes to rules.

Since when you start you're likely to be seeing a lot of normal activity reported, you need to immediately spend time updating rules to quiet down the emails. As you refine your rules you will see less and less normal healthy activity reported and be operating much more as an anomaly detector.
