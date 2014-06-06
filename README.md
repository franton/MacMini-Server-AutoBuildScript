Casper Distribution Server Automated Build Script
=================================================

Version 1.1 - 28th April

This script is meant to be run as part of a Casper Imaging workflow and will happily set up
an OS X 10.9 Server with the following services:

1) Casper AFP/HTTPS Distribution Point

2) Casper rsync to other servers

3) Netboot Server (both NFS and HTTP based)

4) SNMP Monitoring


The process can take a few hours depending on your network connection. Yes, HOURS. This is because
the script will attempt to rsync your new server with your primary Casper server including Netboot image.

Six plus hours over 100Mb network are not unheard of for this.

I HIGHLY encourage you to go through the script for your own customisations. I've sanitised the script to
remove all references from where I work ;)

Areas for Improvement
=====================

1) Make this thing get Server.app to do it's first run process for us instead of relying on a monolithic image!

2) Admin password for root and admin accounts should really be passed to this script for security rather than baked in. (Ick but it is a v.1 release).

Current Known Issues
====================

1) Netboot service does not start up again. Currently requires manual start.

2) SNMP service also does not start up again. Same as 1)

3) HTTP service alias info is not being set up. Serveradmin appears to be igoring the data being passed to it.
