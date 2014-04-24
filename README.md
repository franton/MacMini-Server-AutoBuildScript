Casper AFP/Netboot Distribution Server Automated Build Script
=============================================================

Version 1.0 - First Release - 24th April

Firstly, I am SERIOUSLY hacked off at GitHub. For some reason it kept screwing my commits 
to the point where the master copy I had of this script was corrupted with an mangled earlier version.

Sigh.

This script is meant to be run as part of a Casper Imaging workflow and will happily set up
an OS X 10.9 Server with the following services:

1) Casper AFP Distribution Point
2) Casper AFP rsync to other servers
3) Netboot Server (both NFS and HTTP based)
4) SNMP Monitoring

The process can take a few hours depending on your network connection. Yes, HOURS. This is because
the script will attempt to rsync your new server with your primary Casper server including Netboot image.

Six plus hours over 100Mb network are not unheard of for this, especially given all the software I work with.

I HIGHLY encourage you to go through the script for your own customisations. I've sanitised the script to
remove all references from where I work ;)