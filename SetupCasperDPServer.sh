#!/bin/bash

# Script to automate setup and config of a Casper file distribution OS X Server

# Author  : r.purves@arts.ac.uk
# Version : 0.1 - 10-04-2014 - Initial Version
# Version : 0.2 – 15-04-2014 – Added command= line to use validate-rsync script on root ssh access
# Version : 0.3 - 16-04-2014 - Found major bugs in code. Removed AppleRAID code for safety. Added serveradmin account to share ACL.
# Version : 0.4 - 17-04-2014 - Fixed bugs to do with SSH enabling for appropriate users. Added code to auto add servers to known_hosts file.
# Version : 0.5 - 18-04-2014 - Added check to initial rsync. Primary server will now not attempt to replicate from itself!
# Version : 0.6 - 22-04-2014 - Massively overhauled known_hosts code to make it more elegant and use existing commands rather than directly messing with files.
# Version : 0.7 - 23-04-2014 - Moved IP address code to back of script for non server VLAN builds. And now sets up user dock!
# Version : 0.8 - 24-04-2014 - Everything works as expected! Now added code to set admin account desktop background and fixed rsync script generation.
# Version : 1.0 - 24-04-2014 - Initial Release.
# Version : 1.1 - 29-04-2014 - Now enables CasperShare to be shared via HTTP alias as well as AFP

# Set variables here

MacModel=$( ioreg -l | awk '/product-name/ { split($0, line, "\""); printf("%s\n", line[4]); }' )
PrefModel=$( defaults read /Library/Preferences/SystemConfiguration/preferences.plist Model )
errorcode=1
SERVERPW=password
LOG=/var/log/server-build.log
computername=$( scutil --get ComputerName )
DU=/usr/local/scripts/dockutil.py

# Set System Timezone to avoid clock sync issues and record imaging time.

systemsetup -settimezone Europe/London
systemsetup -setusingnetworktime on
systemsetup -setnetworktimeserver timeserver.com
/usr/sbin/ntpd -g -q
echo "OS X Server Build - started at "$( date ) >> $LOG

# Set energy saving settings to never sleep

echo "" >> $LOG
echo $( date )" - Disabling sleep settings" >> $LOG
/usr/bin/pmset -a sleep 0 >> $LOG
/usr/bin/pmset -a displaysleep 0 >> $LOG
/usr/bin/pmset -a disksleep 0 >> $LOG

# Hiding under UID500 users and setting login window to username/password entry.

echo "" >> $LOG
echo $( date )" - Hiding admin users and setting login window settings" >> $LOG
defaults write /Library/Preferences/com.apple.loginwindow Hide500Users -bool true
defaults write /Library/Preferences/com.apple.loginwindow SHOWFULLNAME -bool true

# Disable auto check for Software Updates

echo "" >> $LOG
echo $( date )" - Disabling Apple Software Update Checking" >> $LOG
softwareupdate --schedule off >> $LOG

# Create Server local admin account

echo "" >> $LOG
echo $( date )" - Creating serveradmin account" >> $LOG
jamf createAccount -username serveradmin -realname serveradmin -password $SERVERPW -home /Users/serveradmin -shell /bin/bash -admin >> $LOG

# Save last imaged time

touch /usr/lastimaged
echo "`date`" > /usr/lastimaged

# Disable spotlight indexing

echo "" >> $LOG
echo $( date )" - Disabling spotlight indexing" >> $LOG
mdutil -i off / >> $LOG
mdutil -d / >> $LOG

# Disable iCloud popup.

echo "" >> $LOG
echo $( date )" - Disabling iCloud popups" >> $LOG
mv -f -v /System/Library/CoreServices/Setup\ Assistant.app/Contents/SharedSupport/MiniLauncher /System/Library/CoreServices/Setup\ Assistant.app/Contents/SharedSupport/MiniLauncher.backup >> $LOG

# Enable ARD for remote access for all users.

echo "" >> $LOG
echo $( date )" - Enabling Apple Remote Management" >> $LOG
/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -access -on -restart -agent -privs -all >> $LOG

# Make sure the computer has enrolled

echo "" >> $LOG
echo $( date )" - Checking to see if JAMF enroll.sh is still running" >> $LOG

while [ -d '/Library/Application Support/JAMF/FirstRun/Enroll' ]
do
   echo $( date )" - Computer enrolment into JSS in progress."
   sleep 5
done

# Set up error trapping function for multiple jamf binary processes

function multiplejamf {
	# Check to see if jamf binary is running, and wait for it to finish.
	# Trying to avoid multiple triggers running at once at the expense of time taken.
	# There are two existing jamf processes running at all times. More than that is bad for us!

	TEST=$( pgrep jamf | wc -l )

	while [ $TEST -gt 2 ]
	do
		/bin/echo "Waiting for existing jamf processes to finish ..." >> $LOG
		sleep 3
		TEST=$( pgrep jamf | wc -l )
	done
}

# Fix the incorrect model name in /Library/Preferences/SystemConfiguration/preferences.plist
# Also make sure the .plist is in the correct format

echo "" >> $LOG
echo $( date )" - Fixing network settings and interfaces" >> $LOG

if [[ "$PrefModel" != "$MacModel" ]];
then
  /bin/echo $AdminPW | sudo -S defaults write /Library/Preferences/SystemConfiguration/preferences.plist Model $MacModel
  /bin/echo $AdminPW | sudo -S plutil -convert xml1 /Library/Preferences/SystemConfiguration/preferences.plist
fi

# Fix the incorrect network service names
# Script lovingly stolen from https://jamfnation.jamfsoftware.com/discussion.html?id=3422

# Detect new network hardware
networksetup -detectnewhardware

# List all network services and read one by one
networksetup -listallnetworkservices | tail -n +2 | while read service
do

# Remove asterisk from string for renaming disabled services
	service=${service#*\*}

# Use filter to select next line which has the hardware port defined
	filter=false

# Display network services
	networksetup -listnetworkserviceorder | while read serviceorder
	do
		if [[ ${filter} == true ]]
		then
			# Grab hardware port
			hardwareport=`echo ${serviceorder} | sed -e 's/(Hardware Port: //;s/, Device:.*//'`
			
			# Check if service name if different
			if [[ ${service} != ${hardwareport} ]]
			then
				# Rename the network service
				networksetup -renamenetworkservice "${service}" "${hardwareport}"
				echo -e "Renamed network service \"${service}\" to \"${hardwareport}\""
			fi
		fi

		if [[ ${serviceorder} == *${service} ]]
		then		
			# Got the line with the service. Set the filter to true to grab the next line which contains the hardware port
			filter=true
			else
			filter=false
		fi
	done
done

# Set the building to put the computer in the Unmanaged building

echo "" >> $LOG
echo $( date )" - Configuring JSS record for server" >> $LOG
	
multiplejamf	
jamf recon -building Unmanaged >> $LOG
	
# Now set the department details to the Casper Distribution Point department.
	
multiplejamf
jamf recon -department CasperDP >> $LOG

# Refresh the MCX Settings

echo "" >> $LOG
echo $( date )" - Refreshing computer level MCX settings" >> $LOG
	
multiplejamf
jamf mcx >> $LOG

# Install server specific configuration.

multiplejamf
jamf policy -trigger CasperServer >> $LOG

# Final recon to make sure Inventory is up to date.

multiplejamf
jamf recon

# Enable root user for rsync purposes

echo "" >> $LOG
echo $( date )" - Enabling root account" >> $LOG
dsenableroot -u serveradmin -p $SERVERPW -r $SERVERPW

# Enable SSH access for root and serveradmin users

echo "" >> $LOG
echo $( date )" - Enabling SSH access" >> $LOG
dseditgroup -o delete -t group com.apple.access_ssh >> $LOG
dseditgroup -o create -q com.apple.access_ssh >> $LOG
dseditgroup -o edit -a caspermgt -t user com.apple.access_ssh >> $LOG
dseditgroup -o edit -a root -t user com.apple.access_ssh >> $LOG
dseditgroup -o edit -a serveradmin -t user com.apple.access_ssh >> $LOG

# Create CasperAdmin and CasperInstall accounts. These must not have user folders or user shells!

echo "" >> $LOG
echo $( date )" - Creating casperadmin account" >> $LOG
dscl . create /Users/casperadmin
dscl . create /Users/casperadmin UserShell /usr/bin/false
dscl . create /Users/casperadmin RealName casperadmin
dscl . create /Users/casperadmin UniqueID 502
dscl . create /Users/casperadmin PrimaryGroupID 20
dscl . passwd /Users/casperadmin password

echo "" >> $LOG
echo $( date )" - Creating casperinstall account" >> $LOG
dscl . create /Users/casperinstall
dscl . create /Users/casperinstall UserShell /usr/bin/false
dscl . create /Users/casperinstall RealName casperinstall
dscl . create /Users/casperinstall UniqueID 503
dscl . create /Users/casperinstall PrimaryGroupID 20
dscl . passwd /Users/casperinstall password

# Create caspershare folder and set ACL permissions for casperadmin, casperinstall and serveradmin users.

mkdir /CasperShare
chmod -R +a "serveradmin allow list,add_file,search,add_subdirectory,delete_child,readattr,writeattr,readextattr,writeextattr,readsecurity,file_inherit,directory_inherit" /CasperShare
chmod -R +a "casperadmin allow list,add_file,search,add_subdirectory,delete_child,readattr,writeattr,readextattr,writeextattr,readsecurity,file_inherit,directory_inherit" /CasperShare
chmod -R +a "casperinstall allow list,search,readattr,readextattr,readsecurity,file_inherit,directory_inherit" /CasperShare
chmod -R +a "_www allow list,add_file,search,add_subdirectory,delete_child,readattr,writeattr,readextattr,writeextattr,readsecurity,file_inherit,directory_inherit" /CasperShare

# Create SSH folder for root user

mkdir /var/root/.ssh >> $LOG
chown root:wheel /var/root/.ssh >> $LOG
chmod 700 /var/root/.ssh >> $LOG

# Create SSH key

touch /var/root/.ssh/rsync-key >> $LOG
cat > /var/root/.ssh/rsync-key << ENDRSAKEY
-----BEGIN RSA PRIVATE KEY-----
key goes here
-----END RSA PRIVATE KEY-----
ENDRSAKEY

touch /var/root/.ssh/rsync-key.pub >> $LOG
cat > /var/root/.ssh/rsync-key.pub << ENDRSAKEY
ssh-rsa key goes here mac_root
ENDRSAKEY

# Lock down SSH access to rsync service only

echo "" >> $LOG
echo $( date )" - Lock root ssh to rsync command" >> $LOG

touch /var/root/.ssh/authorized_keys
cat > /var/root/.ssh/authorized_keys << ENDAUTHKEY
command="/usr/local/scripts/validate-rsync" ssh-rsa key goes here mac_root
ENDAUTHKEY

chown root:wheel /var/root/.ssh/authorized_keys >> $LOG
chmod 644 /var/root/.ssh/authorized_keys >> $LOG

# Make and lock down working folder

echo "" >> $LOG
echo $( date )" - Create scripts folder, ssh key and validate-rsync file" >> $LOG

mkdir /usr/local/
mkdir /usr/local/scripts
chown root:wheel /usr/local/scripts

# Create SSH validation script

touch /usr/local/scripts/validate-rsync

cat > /usr/local/scripts/validate-rsync << ENDVALIDATE
#!/bin/sh
case "\$SSH_ORIGINAL_COMMAND" in
rsync\ --server*)
\$SSH_ORIGINAL_COMMAND
;;
*)
echo "Rejected"
;;
esac
ENDVALIDATE

# Set the correct permissions and owner on the files we just created

chown root:wheel /usr/local/scripts/validate-rsync >> $LOG
chmod 755 /usr/local/scripts/validate-rsync >> $LOG

chown root:wheel /usr/local/scripts/authorized_keys >> $LOG
chmod 755 /usr/local/scripts/authorized_keys >> $LOG

chown root:wheel /var/root/.ssh/rsync-key >> $LOG
chmod 600 /var/root/.ssh/rsync-key >> $LOG

chown root:wheel /var/root/.ssh/rsync-key.pub >> $LOG
chmod 600 /var/root/.ssh/rsync-key.pub >> $LOG

# Add servers to /var/root/.ssh/known_hosts file.

echo "" >> $LOG
echo $( date )" - Adding current casper dp servers to known_hosts file" >> $LOG

[ -e /var/root/.ssh/known_hosts ] || touch /var/root/.ssh/known_hosts
for host in \
    server1 \
    server2 \
    server3 \
; do
    ssh-keygen -R $host -f /var/root/.ssh/known_hosts
    ssh -q -o StrictHostKeyChecking=no -o BatchMode=yes -o UserKnownHostsFile=/var/root/.ssh/known_hosts $host echo '' || true
done

chown root:wheel /var/root/.ssh/known_hosts
chmod 755 /var/root/.ssh/known_hosts

# Create rsync script for specific server computernames.
# There's a lot of \ being used in places. That's to stop the cat command expanding variables/commands out and breaking the generated files.

case $computername in

server1 )
echo "" >> $LOG
echo $( date )" - Creating rsync scripts for server: "$computername >> $LOG

mkdir /usr/local/scripts >> $LOG
touch /usr/local/scripts/casper-sync.sh >> $LOG

cat  > /usr/local/scripts/casper-sync.sh << CASPER-SYNC
#!/bin/sh

# rsync script for server1
# implemented   : r.purves@arts.ac.uk

LOGS=/var/log/casper-sync.log
LOCKS=/var/run/casper-sync.lck
TEST=""
TEST=\`/bin/ps -ef \\
     |/usr/bin/grep casper-sync \\
     |/usr/bin/grep -v grep \\
     |/usr/bin/grep -v casper-sync.log \\
     |/usr/bin/wc -l\`

if [ \$TEST -gt 2 ]; then
echo "\`date\` Another rsync instance running .... exiting" >> \$LOGS;
exit 0;
else
   echo "Starting rsync at \`date\`" >> \$LOGS;
   while true ; do
    if [ ! -e \$LOCKS ] ;then
        touch \$LOCKS ;

# Sync server2 first

# Sync CasperShare
        
        echo "Syncing server server2" >> \$LOGS;
        /usr/bin/rsync -a4hxvz --delete-after --force  --bwlimit=100000 -e "ssh -i /var/root/.ssh/rsync-key" /CasperShare/ root@server2:/CasperShare >> \$LOGS 2>&1

# Sync Netboot image

        echo "Syncing netboot image server2" >> \$LOGS;
        /usr/bin/rsync -a4hxvz --delete-after --force  --bwlimit=100000 -e "ssh -i /var/root/.ssh/rsync-key" /Library/NetBoot/NetBootSP0/ root@server2:/Library/NetBoot/NetBootSP0/ >> \$LOGS 2>&1

# Start external sync from server2
# Background this so that the rest of the rsync will finish while this works. They "should" be ok for this.

		echo "Starting sync from server2 outward" >> \$LOGS;
		nohup ssh -i /var/root/.ssh/rsync-key root@server2 /usr/local/scripts/casper-sync-2.sh &;

# All done for this server!
        
        /bin/rm \$LOCKS ;
        echo "Sync finished at \`date\`" >> \$LOGS ;
        exit 0;
    else
        sleep 60 ;
    fi;
   done;
fi;
CASPER-SYNC

touch /Library/LaunchDaemons/com.casper-rsync.plist

cat > /Library/LaunchDaemons/com.casper-rsync.plist << CASPER-SYNC-LAUNCHD
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>com.casper-rsync</string>
	<key>ProgramArguments</key>
	<array>
		<string>/usr/local/scripts/casper-sync.sh</string>
	</array>
	<key>StartInterval</key>
	<integer>900</integer>
</dict>
</plist>
CASPER-SYNC-LAUNCHD

chown root:staff /usr/local/scripts/casper-sync.sh >> $LOG
chmod 700 /usr/local/scripts/casper-sync.sh >> $LOG

chown root:wheel /Library/LaunchDaemons/com.casper-rsync.plist >> $LOG
chmod 644 /Library/LaunchDaemons/com.casper-rsync.plist >> $LOG
;;

server2 )
echo "" >> $LOG
echo $( date )" - Creating rsync scripts for server: "$computername >> $LOG

mkdir /usr/local/scripts >> $LOG
touch /usr/local/scripts/casper-sync.sh >> $LOG

cat > /usr/local/scripts/casper-sync.sh << CASPER-SYNC
#!/bin/sh

# rsync script for server2
# implemented   : r.purves@arts.ac.uk

LOGS=/var/log/casper-sync.log
LOCKS=/var/run/casper-sync.lck
TEST=""
TEST=\`/bin/ps -ef \\
     |/usr/bin/grep casper-sync \\
     |/usr/bin/grep -v grep \\
     |/usr/bin/grep -v casper-sync.log \\
     |/usr/bin/wc -l\`

if [ \$TEST -gt 2 ]; then
echo "\`date\` Another process running .... exiting" >> \$LOGS;
exit 0;
else
   echo "Starting rsync at \`date\`" >> \$LOGS;
   while true ; do
    if [ ! -e \$LOCKS ] ;then
        touch \$LOCKS ;

# Sync server3 first

# Sync CasperShare
        
        echo "Syncing server server3" >> \$LOGS;
        /usr/bin/rsync -a4hxvz --delete-after --force  --bwlimit=100000 -e "ssh -i /var/root/.ssh/rsync-key" /CasperShare/ root@server3:/CasperShare >> \$LOGS 2>&1

# Sync Netboot image

        echo "Syncing netboot image server3" >> \$LOGS;
        /usr/bin/rsync -a4hxvz --delete-after --force  --bwlimit=100000 -e "ssh -i /var/root/.ssh/rsync-key" /Library/NetBoot/NetBootSP0/ root@server3:/Library/NetBoot/NetBootSP0/ >> \$LOGS 2>&1

# All done for this server!
        
        /bin/rm \$LOCKS ;
        echo "Sync finished at \`date\`" >> \$LOGS ;
        exit 0;
    else
        sleep 60 ;
    fi;
   done;
fi;
CASPER-SYNC

chown root:staff /usr/local/scripts/casper-sync.sh >> $LOG
chmod 700 /usr/local/scripts/casper-sync.sh >> $LOG
;;

esac

# Make sure the five services we need are off

echo "" >> $LOG
echo $( date )" - Stopping services before configuration" >> $LOG

serveradmin stop afp
serveradmin stop smb
serveradmin stop web
serveradmin stop nfs
serveradmin stop netboot
serveradmin stop sharing
serveradmin settings info:enableSNMP = no

# Initial Sync of CasperShare

# Is this the primary server? If so, sync from secondary server

echo "" >> $LOG
if [ "$computername" == "server1" ]
then
	echo $( date )" - Initial CasperShare sync from server2" >> $LOG
	/usr/bin/rsync -a4hxvz --delete-after --force -e "ssh -i /var/root/.ssh/rsync-key" root@server2:/CasperShare/ /CasperShare >> $LOG
else
	echo $( date )" - Initial CasperShare sync from server1" >> $LOG
	/usr/bin/rsync -a4hxvz --delete-after --force -e "ssh -i /var/root/.ssh/rsync-key" root@server1:/CasperShare/ /CasperShare >> $LOG
fi

# Sync Netboot image

# Is this the primary server? If so, sync from secondary server

echo "" >> $LOG

if [ "$computername" == "server1" ]
then
	echo "Initial netboot image sync from server server2" >> $LOG;
	/usr/bin/rsync -a4hxvz --delete-after --force -e "ssh -i /var/root/.ssh/rsync-key" root@server2:/Library/NetBoot/NetBootSP0/ /Library/NetBoot/NetBootSP0/ >> $LOG
else
	echo "Initial netboot image sync from server server1" >> $LOG;
	/usr/bin/rsync -a4hxvz --delete-after --force -e "ssh -i /var/root/.ssh/rsync-key" root@server1:/Library/NetBoot/NetBootSP0/ /Library/NetBoot/NetBootSP0/ >> $LOG
fi

# Set IP address depending on server computername

echo "" >> $LOG
echo $( date )" - Server computer name set to: "$computername >> $LOG

case $computername in

server1 )
echo $( date )" - Setting IP address to x.x.x.x" >> $LOG
networksetup -setmanual Ethernet x.x.x.x 255.255.255.0 x.x.x.x
;;

server2 )
echo $( date )" - Setting IP address to x.x.x.x" >> $LOG
networksetup -setmanual Ethernet x.x.x.x 255.255.255.0 x.x.x.x
;;

server3 )
echo $( date )" - Setting IP address to x.x.x.x" >> $LOG
networksetup -setmanual Ethernet x.x.x.x 255.255.255.0 x.x.x.x
;;

esac

# Force DNS and Search Domain server settings

echo "" >> $LOG
echo $( date )" - Setting DNS and Search Domain information" >> $LOG
networksetup -setdnsservers Ethernet x.x.x.x x.x.x.x >> $LOG
networksetup -setsearchdomains Ethernet domain.local domain.co.uk >> $LOG

# Set proxy server environment variables so JAMF binary can see out

echo "" >> $LOG
echo $( date )" - Setting proxy cache settings" >> $LOG
echo "export HTTP_PROXY="proxy.cache:3128"" >> /etc/profile
echo "export http_proxy="proxy.cache:3128"" >> /etc/profile
echo "export HTTP_PROXY="proxy.cache:3128"" >> /etc/bashrc
echo "export http_proxy="proxy.cache:3128"" >> /etc/bashrc

# Now set proxy server so rest of system can see out

networksetup -setwebproxy Ethernet proxy.cache 3128 >> $LOG
networksetup -setsecurewebproxy Ethernet proxy.cache 3128 >> $LOG

# Default AFP share configuration

echo "" >> $LOG
echo $( date )" - Configuring AFP service" >> $LOG

cat << SERVERADMIN_AFP | sudo /Applications/Server.app/Contents/ServerRoot/usr/sbin/serveradmin settings
afp:attemptAdminAuth = no
afp:maxGuests = -1
afp:afpTCPPort = 548
afp:clientSleepTime = 24
afp:replyCacheQuantum = 32
afp:maxConnections = -1
afp:sendGreetingOnce = no
afp:reconnectTTLInMin = 1440
afp:clientSleepOnOff = yes
afp:loginGreeting = ""
afp:errorLogPath = "/Library/Logs/AppleFileService/AppleFileServiceError.log"
afp:errorLogTime = 14
afp:activityLogTime = 7
afp:errorLogSize = 1000
afp:kerberosPrincipal = "afpserver"
afp:recon1SrvrKeyTTLHrs = 168
afp:idleDisconnectOnOff = no
afp:reconnectFlag = "no_admin_kills"
afp:activityLog = yes
afp:reconnectKeyLocation = "/private/etc/AFP.conf"
afp:loginGreetingTime = 1315436086
afp:adminGetsSp = yes
afp:fullServerMode = yes
afp:idleDisconnectMsg = ""
afp:updateHomeDirQuota = yes
afp:activityLogPath = "/Library/Logs/AppleFileService/AppleFileServiceAccess.log"
afp:authenticationMode = "standard_and_kerberos"
afp:admin31GetsSp = no
afp:shutdownThreshold = 3
afp:TCPQuantum = 1048576
afp:allowSendMessage = yes
afp:idleDisconnectTime = 10
afp:loggingAttributes:logOpenFork = yes
afp:loggingAttributes:logDelete = yes
afp:loggingAttributes:logCreateDir = yes
afp:loggingAttributes:logLogin = yes
afp:loggingAttributes:logLogout = yes
afp:loggingAttributes:logCreateFile = yes
afp:tickleTime = 30
afp:specialAdminPrivs = no
afp:noNetworkUsers = no
afp:idleDisconnectFlag:adminUsers = yes
afp:idleDisconnectFlag:registeredUsers = yes
afp:idleDisconnectFlag:usersWithOpenFiles = yes
afp:idleDisconnectFlag:guestUsers = yes
afp:recon1TokenTTLMins = 10080
afp:guestAccess = yes
afp:allowRootLogin = no
afp:activityLogSize = 1000
afp:afpServerEncoding = 0
afp:createHomeDir = yes
afp:reconnectTTLInMin=120
SERVERADMIN_AFP

# Default SMB share configuration

echo "" >> $LOG
echo $( date )" - Configuring SMB service" >> $LOG

cat << SERVERADMIN_SMB | sudo /Applications/Server.app/Contents/ServerRoot/usr/sbin/serveradmin settings
smb:EnabledServices:_array_index:0 = "disk"
smb:Workgroup = "WORKGROUP"
smb:AllowGuestAccess = no
smb:DOSCodePage = "850"
SERVERADMIN_SMB

# Default Web configuration for HTTPS distribution

echo "" >> $LOG
echo $( date )" - Configuring HTTP service" >> $LOG

cat << SERVERADMIN_WEB | sudo /Applications/Server.app/Contents/ServerRoot/usr/sbin/serveradmin settings
web:defaultSite:aliases:_array_index:0:matchType = 0
web:defaultSite:aliases:_array_index:0:fileSystemPath = "/CasperShare"
web:defaultSite:aliases:_array_index:0:urlPathOrRegularExpression = "/CasperShare"
SERVERADMIN_WEB

# Default Netboot configuration

echo "" >> $LOG
echo $( date )" - Configuring Netboot service" >> $LOG

cat << SERVERADMIN_NETBOOT | sudo /Applications/Server.app/Contents/ServerRoot/usr/sbin/serveradmin settings
netboot:netBootFiltersRecordsArray = _empty_array
netboot:netBootStorageRecordsArray:_array_index:0:sharepoint = yes
netboot:netBootStorageRecordsArray:_array_index:0:clients = yes
netboot:netBootStorageRecordsArray:_array_index:0:volType = "hfs"
netboot:netBootStorageRecordsArray:_array_index:0:okToDeleteSharepoint = no
netboot:netBootStorageRecordsArray:_array_index:0:readOnlyShare = no
netboot:netBootStorageRecordsArray:_array_index:0:path = "/"
netboot:netBootStorageRecordsArray:_array_index:0:okToDeleteClients = yes
netboot:netBootStorageRecordsArray:_array_index:0:volName = "Macintosh HD"
netboot:netBootPortsRecordsArray:_array_index:0:deviceAtIndex = "en0"
netboot:netBootPortsRecordsArray:_array_index:0:isEnabledAtIndex = yes
netboot:netBootPortsRecordsArray:_array_index:0:nameAtIndex = "Ethernet"
netboot:logging_level = "HIGH"
netboot:filterEnabled = no
netboot:netBootImagesRecordsArray:_array_index:0:BootFile = "booter"
netboot:netBootImagesRecordsArray:_array_index:0:EnabledMACAddresses = _empty_array
netboot:netBootImagesRecordsArray:_array_index:0:RootPath = "NetBoot.dmg"
netboot:netBootImagesRecordsArray:_array_index:0:IsDefault = yes
netboot:netBootImagesRecordsArray:_array_index:0:Kind = "1"
netboot:netBootImagesRecordsArray:_array_index:0:EnabledSystemIdentifiers = _empty_array
netboot:netBootImagesRecordsArray:_array_index:0:Type = "HTTP"
netboot:netBootImagesRecordsArray:_array_index:0:Language = "Default"
netboot:netBootImagesRecordsArray:_array_index:0:DisabledMACAddresses = _empty_array
netboot:netBootImagesRecordsArray:_array_index:0:BackwardCompatible = no
netboot:netBootImagesRecordsArray:_array_index:0:IsEnabled = yes
netboot:netBootImagesRecordsArray:_array_index:0:IsInstall = no
netboot:netBootImagesRecordsArray:_array_index:0:Architectures = "4"
netboot:netBootImagesRecordsArray:_array_index:0:SupportsDiskless = yes
netboot:netBootImagesRecordsArray:_array_index:0:pathToImage = "/Library/NetBoot/NetBootSP0/Casper Netboot.nbi/NBImageInfo.plist"
netboot:netBootImagesRecordsArray:_array_index:0:imageType = "netboot"
netboot:afpUsersMax = "50"
SERVERADMIN_NETBOOT

# Default Sharing configuration

echo "" >> $LOG
echo $( date )" - Configuring Sharing service" >> $LOG

cat << SERVERADMIN_SHARING | sudo /Applications/Server.app/Contents/ServerRoot/usr/sbin/serveradmin settings
sharing:sharePointList:_array_id:/CasperShare:smbName = "CasperShare"
sharing:sharePointList:_array_id:/CasperShare:afpIsGuestAccessEnabled = no
sharing:sharePointList:_array_id:/CasperShare:webDAVName = "CasperShare"
sharing:sharePointList:_array_id:/CasperShare:smbDirectoryMask = "0755"
sharing:sharePointList:_array_id:/CasperShare:afpName = "CasperShare"
sharing:sharePointList:_array_id:/CasperShare:smbCreateMask = "0644"
sharing:sharePointList:_array_id:/CasperShare:nfsExportRecord = _empty_array
sharing:sharePointList:_array_id:/CasperShare:path = "/CasperShare"
sharing:sharePointList:_array_id:/CasperShare:smbUseStrictLocking = yes
sharing:sharePointList:_array_id:/CasperShare:smbIsGuestAccessEnabled = no
sharing:sharePointList:_array_id:/CasperShare:name = "CasperShare"
sharing:sharePointList:_array_id:/CasperShare:smbInheritPermissions = yes
sharing:sharePointList:_array_id:/CasperShare:ftpName = "CasperShare"
sharing:sharePointList:_array_id:/CasperShare:smbIsShared = yes
sharing:sharePointList:_array_id:/CasperShare:afpIsShared = yes
sharing:sharePointList:_array_id:/CasperShare:isTimeMachineBackup = no
sharing:sharePointList:_array_id:/CasperShare:smbUseOplocks = yes
sharing:sharePointList:_array_id:/CasperShare:mountedOnPath = "/"
sharing:sharePointList:_array_id:/CasperShare:isIndexingEnabled = yes
sharing:sharePointList:_array_id:/Library/NetBoot/NetBootClients0:smbName = "NetBootClients0"
sharing:sharePointList:_array_id:/Library/NetBoot/NetBootClients0:afpIsGuestAccessEnabled = yes
sharing:sharePointList:_array_id:/Library/NetBoot/NetBootClients0:smbDirectoryMask = "755"
sharing:sharePointList:_array_id:/Library/NetBoot/NetBootClients0:ftpIsShared = no
sharing:sharePointList:_array_id:/Library/NetBoot/NetBootClients0:afpName = "NetBootClients0"
sharing:sharePointList:_array_id:/Library/NetBoot/NetBootClients0:smbCreateMask = "644"
sharing:sharePointList:_array_id:/Library/NetBoot/NetBootClients0:ftpIsGuestAccessEnabled = no
sharing:sharePointList:_array_id:/Library/NetBoot/NetBootClients0:nfsExportRecord = _empty_array
sharing:sharePointList:_array_id:/Library/NetBoot/NetBootClients0:path = "/Library/NetBoot/NetBootClients0"
sharing:sharePointList:_array_id:/Library/NetBoot/NetBootClients0:smbUseStrictLocking = yes
sharing:sharePointList:_array_id:/Library/NetBoot/NetBootClients0:smbIsGuestAccessEnabled = no
sharing:sharePointList:_array_id:/Library/NetBoot/NetBootClients0:name = "NetBootClients0"
sharing:sharePointList:_array_id:/Library/NetBoot/NetBootClients0:smbInheritPermissions = yes
sharing:sharePointList:_array_id:/Library/NetBoot/NetBootClients0:ftpName = "NetBootClients0"
sharing:sharePointList:_array_id:/Library/NetBoot/NetBootClients0:smbIsShared = no
sharing:sharePointList:_array_id:/Library/NetBoot/NetBootClients0:afpIsShared = yes
sharing:sharePointList:_array_id:/Library/NetBoot/NetBootClients0:smbUseOplocks = yes
sharing:sharePointList:_array_id:/Library/NetBoot/NetBootClients0:isIndexingEnabled = no
sharing:sharePointList:_array_id:/Library/NetBoot/NetBootClients0:mountedOnPath = "/"
sharing:sharePointList:_array_id:/Library/NetBoot/NetBootSP0:smbName = "NetBootSP0"
sharing:sharePointList:_array_id:/Library/NetBoot/NetBootSP0:afpIsGuestAccessEnabled = no
sharing:sharePointList:_array_id:/Library/NetBoot/NetBootSP0:smbDirectoryMask = "755"
sharing:sharePointList:_array_id:/Library/NetBoot/NetBootSP0:ftpIsShared = no
sharing:sharePointList:_array_id:/Library/NetBoot/NetBootSP0:afpName = "NetBootSP0"
sharing:sharePointList:_array_id:/Library/NetBoot/NetBootSP0:smbCreateMask = "644"
sharing:sharePointList:_array_id:/Library/NetBoot/NetBootSP0:ftpIsGuestAccessEnabled = no
sharing:sharePointList:_array_id:/Library/NetBoot/NetBootSP0:nfsExportRecord:_array_id:/Library/NetBoot/NetBootSP0:path = "/Library/NetBoot/NetBootSP0"
sharing:sharePointList:_array_id:/Library/NetBoot/NetBootSP0:nfsExportRecord:_array_id:/Library/NetBoot/NetBootSP0:mapAllUser = ""
sharing:sharePointList:_array_id:/Library/NetBoot/NetBootSP0:nfsExportRecord:_array_id:/Library/NetBoot/NetBootSP0:mapRootUser = "root"
sharing:sharePointList:_array_id:/Library/NetBoot/NetBootSP0:nfsExportRecord:_array_id:/Library/NetBoot/NetBootSP0:isReadOnly = yes
sharing:sharePointList:_array_id:/Library/NetBoot/NetBootSP0:nfsExportRecord:_array_id:/Library/NetBoot/NetBootSP0:shareAllDirectories = no
sharing:sharePointList:_array_id:/Library/NetBoot/NetBootSP0:path = "/Library/NetBoot/NetBootSP0"
sharing:sharePointList:_array_id:/Library/NetBoot/NetBootSP0:smbUseStrictLocking = yes
sharing:sharePointList:_array_id:/Library/NetBoot/NetBootSP0:smbIsGuestAccessEnabled = no
sharing:sharePointList:_array_id:/Library/NetBoot/NetBootSP0:name = "NetBootSP0"
sharing:sharePointList:_array_id:/Library/NetBoot/NetBootSP0:smbInheritPermissions = yes
sharing:sharePointList:_array_id:/Library/NetBoot/NetBootSP0:ftpName = "NetBootSP0"
sharing:sharePointList:_array_id:/Library/NetBoot/NetBootSP0:smbIsShared = no
sharing:sharePointList:_array_id:/Library/NetBoot/NetBootSP0:afpIsShared = no
sharing:sharePointList:_array_id:/Library/NetBoot/NetBootSP0:smbUseOplocks = yes
sharing:sharePointList:_array_id:/Library/NetBoot/NetBootSP0:isIndexingEnabled = no
sharing:sharePointList:_array_id:/Library/NetBoot/NetBootSP0:mountedOnPath = "/"
SERVERADMIN_SHARING

# Write a snmpd.conf file that will allow monitoring via opsview/cacti

echo "" >> $LOG
echo $( date )" - Configuring v2c SNMP service" >> $LOG

rm /etc/snmp/snmpd.conf
touch /etc/snmp/snmpd.conf

cat > /etc/snmp/snmpd.conf << SNMP_CONF

###########################################################################
#
# snmpd.conf
#
#   - created by the snmpconf configuration program
#
###########################################################################
# SECTION: Access Control Setup
#
#   This section defines who is allowed to talk to your running
#   snmp agent.

# rwuser: a SNMPv3 read-write user
#   arguments:  user [noauth|auth|priv] [restriction_oid]

rwuser  admin  

# rocommunity: a SNMPv1/SNMPv2c read-only access community name
#   arguments:  community [default|hostname|network/bits] [oid]

rocommunity  cacti_monitor #default .1.3.6.1.2.1.1.4

###########################################################################
# SECTION: Extending the Agent
#
#   You can extend the snmp agent to have it return information
#   that you yourself define.

# exec: run a simple command using exec()
#   arguments:  [oid] name /path/to/executable arguments

exec echotest /bin/echo hello world
exec web_status /usr/sbin/serveradmin status web
exec wo_status /usr/sbin/serveradmin status webobjects

###########################################################################
# SECTION: Monitor Various Aspects of the Running Host
#
#   The following check up on various aspects of a host.

# proc: Check for processes that should be running.
#     proc NAME [MAX=0] [MIN=0]
#   
#     NAME:  the name of the process to check for.  It must match
#            exactly (ie, http will not find httpd processes).
#     MAX:   the maximum number allowed to be running.  Defaults to 0.
#     MIN:   the minimum number to be running.  Defaults to 0.
#   
#   The results are reported in the prTable section of the UCD-SNMP-MIB tree
#   Special Case:  When the min and max numbers are both 0, it assumes
#   you want a max of infinity and a min of 1.

proc httpd

# disk: Check for disk space usage of a partition.
#   The agent can check the amount of available disk space, and make
#   sure it is above a set limit.  
#   
#    disk PATH [MIN=100000]
#   
#    PATH:  mount path to the disk in question.
#    MIN:   Disks with space below this value will have the Mib's errorFlag set.
#           Can be a raw integer value (units of kB) or a percentage followed by the %
#           symbol.  Default value = 100000.
#   
#   The results are reported in the dskTable section of the UCD-SNMP-MIB tree

disk / 10000

# load: Check for unreasonable load average values.
#   Watch the load average levels on the machine.
#   
#    load [1MAX=12.0] [5MAX=12.0] [15MAX=12.0]
#   
#    1MAX:   If the 1 minute load average is above this limit at query
#            time, the errorFlag will be set.
#    5MAX:   Similar, but for 5 min average.
#    15MAX:  Similar, but for 15 min average.
#   
#   The results are reported in the laTable section of the UCD-SNMP-MIB tree

load 12 14 14

###########################################################################
# SECTION: System Information Setup
#
#   This section defines some of the information reported in
#   the "system" mib group in the mibII tree.

# syslocation: The [typically physical] location of the system.
#   Note that setting this value here means that when trying to
#   perform an snmp SET operation to the sysLocation.0 variable will make
#   the agent return the "notWritable" error code.  IE, including
#   this token in the snmpd.conf file will disable write access to
#   the variable.
#   arguments:  location_string

syslocation Right here, right now.

# syscontact: The contact information for the administrator
#   Note that setting this value here means that when trying to
#   perform an snmp SET operation to the sysContact.0 variable will make
#   the agent return the "notWritable" error code.  IE, including
#   this token in the snmpd.conf file will disable write access to
#   the variable.
#   arguments:  contact_string

syscontact Administrator <postmaster@example.com>

# sysservices: The proper value for the sysServices object.
#   arguments:  sysservices_number

sysservices 76

#
# Unknown directives read in from other files by snmpconf
#
com2sec local     localhost       public
com2sec mynetwork NETWORK/24      public
group MyRWGroup	v1         local
group MyRWGroup	v2c        local
group MyRWGroup	usm        local
group MyROGroup v1         mynetwork
group MyROGroup v2c        mynetwork
group MyROGroup usm        mynetwork
view all    included  .1.3.6.1.2.1.25.1.1                               80
access MyROGroup ""      any       noauth    exact  all    none   none
access MyRWGroup ""      any       noauth    exact  all    all    none

SNMP_CONF

# Make sure the services we need are re-enabled

echo "" >> $LOG
echo $( date )" - Restarting Services" >> $LOG

serveradmin start afp >> $LOG
serveradmin start smb >> $LOG
serveradmin start sharing >> $LOG
serveradmin start web >> $LOG
serveradmin start nfs >> $LOG
serveradmin start netboot >> $LOG
serveradmin settings info:enableRemoteAdministration = yes >> $LOG
serveradmin settings info:enableSNMP = yes >> $LOG

# Finally set up the admin user dock the way we like it

echo "" >> $LOG
echo $( date )" - Setting up the dock" >> $LOG

# Clear the dock!

$DU --remove all --allhomes

# Now put the right stuff in place!

$DU --add /Applications/Launchpad.app --allhomes
$DU --add /Applications/App\ Store.app --allhomes
$DU --add /Applications/Safari.app --allhomes
$DU --add /Applications/System\ Preferences.app --allhomes
$DU --add /Applications/Server.app --allhomes

$DU --add /Applications/Utilities/Activity\ Monitor.app --allhomes
$DU --add /Applications/Utilities/Console.app --allhomes
$DU --add /Applications/Utilities/Disk\ Utility.app --allhomes
$DU --add /Applications/Utilities/Terminal.app --allhomes

# Last of all, configure the desktop background!

echo "" >> $LOG
echo $( date )" - Setting up the desktop background" >> $LOG

sqlite3 /Users/ualserv/Library/Application\ Support/Dock/desktoppicture.db << EOF
UPDATE data SET value = "/Library/Desktop Pictures/default_black2560x1600.jpg";
.quit
EOF

killall Dock

# All done!

echo "" >> $LOG
echo $( date )" - Completed server build" >> $LOG

# Making sure the JAMF firstrun folder is empty as this occasionally doesn't clear itself up.
rm -rf /Library/Application\ Support/JAMF/FirstRun/*
shutdown -r now

exit 0
