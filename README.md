Casper Distribution Server Automated Build Script
=================================================

Version 2.0 - 29th October 2015.

This script is meant to be run as part of a Casper Imaging workflow and will happily set up
an OS X Server with the following services:

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

1) Admin password for root and admin accounts should really be passed to this script for security rather than baked in.

3) Feedback on screen outside of the Console logs would be nice. Loceee's cocoadialog integration is forthcoming.

Current Known Issues
====================

1) Netboot service does not start up again. Currently requires manual start.

2) SNMP service also does not start up again. Same as 1)

3) HTTP service alias info is not being set up. Serveradmin appears to be igoring the data being passed to it.
