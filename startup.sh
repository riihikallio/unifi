#! /bin/sh

# Version 1.3.4
# This is a startup script for UniFi Controller on Debian based Google Compute Engine instances.
# For instructions and how-to:  https://metis.fi/en/2018/02/unifi-on-gcp/
# For comments and code walkthrough:  https://metis.fi/en/2018/02/gcp-unifi-code/
#
# You may use this as you see fit as long as I am credited for my work.
# (c) 2018 Petri Riihikallio Metis Oy

###########################################################
#
# Set up logging for unattended scripts and UniFi's MongoDB log
# Variables $LOG and $MONGOLOG are used later on in the script.
#
LOG="/var/log/unifi/gcp-unifi.log"
if [ ! -f /etc/logrotate.d/gcp-unifi.conf ]; then
	cat > /etc/logrotate.d/gcp-unifi.conf <<_EOF
$LOG {
	monthly
	rotate 4
	compress
}
_EOF
	echo "Script logrotate set up"
fi

MONGOLOG="/usr/lib/unifi/logs/mongod.log"
if [ ! -f /etc/logrotate.d/unifi-mongod.conf ]; then
	cat > /etc/logrotate.d/unifi-mongod.conf <<_EOF
$MONGOLOG {
	weekly
	rotate 10
	copytruncate
	delaycompress
	compress
	notifempty
	missingok
}
_EOF
	echo "MongoDB logrotate set up"
fi

###########################################################
#
# Turn off IPv6 for now
#
if [ ! -f /etc/sysctl.d/20-disableIPv6.conf ]; then
	echo "net.ipv6.conf.all.disable_ipv6=1" > /etc/sysctl.d/20-disableIPv6.conf
	sysctl --system > /dev/null
	echo "IPv6 disabled"
fi

###########################################################
#
# Update DynDNS as early in the script as possible
#
ddns=$(curl -fs -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/ddns-url")
if [ ${ddns} ]; then
	curl -fs ${ddns}
	echo "Dynamic DNS accessed"
fi

###########################################################
#
# Create a swap file for small memory instances and increase /run
#
if [ ! -f /swapfile ]; then
	memory=$(free -m | grep "^Mem:" | tr -s " " | cut -d " " -f 2)
	echo "${memory} megabytes of memory detected"
	if [ -z ${memory} ] || [ "0${memory}" -lt "2048" ]; then
		fallocate -l 2G /swapfile
		chmod 600 /swapfile
		mkswap /swapfile >/dev/null
		swapon /swapfile
		echo '/swapfile none swap sw 0 0' >> /etc/fstab
		echo 'tmpfs /run tmpfs rw,nodev,nosuid,size=400M 0 0' >> /etc/fstab
		mount -o remount,rw,nodev,nosuid,size=400M tmpfs /run
		echo "Swap file created"
	fi
fi

###########################################################
#
# Add backports if it doesn't exist
#
release=$(lsb_release -a 2>/dev/null | grep "^Codename:" | cut -f 2)
if [ ${release} ] && [ ! -f /etc/apt/sources.list.d/backports.list ]; then
	cat > /etc/apt/sources.list.d/backports.list <<_EOF
deb http://deb.debian.org/debian/ ${release}-backports main
deb-src http://deb.debian.org/debian/ ${release}-backports main
_EOF
	echo "Backports (${release}) added to APT sources"
fi

###########################################################
#
# Install stuff
#

# Required preliminiaries
if [ ! -f /usr/share/misc/apt-upgraded-1 ]; then
	export APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE=DontWarn    # For CGP packages
	curl -Lfs https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add -    # For CGP packages
	apt-get -qq update -y >/dev/null
	DEBIAN_FRONTEND=noninteractive apt-get -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" upgrade -y >/dev/null    # GRUB upgrades require special flags
	rm /usr/share/misc/apt-upgraded    # Old flag file
	touch /usr/share/misc/apt-upgraded-1
	echo "System upgraded"
fi

# HAVEGEd is straightforward
haveged=$(dpkg-query -W --showformat='${Status}\n' haveged 2>/dev/null)
if [ "x${haveged}" != "xinstall ok installed" ]; then 
	if apt-get -qq install -y haveged >/dev/null; then
		echo "Haveged installed"
	fi
fi
certbot=$(dpkg-query -W --showformat='${Status}\n' certbot 2>/dev/null)
if [ "x${certbot}" != "xinstall ok installed" ]; then
if (apt-get -qq install -y -t ${release}-backports certbot >/dev/null) || (apt-get -qq install -y certbot >/dev/null); then
		echo "CertBot installed"
	fi
fi

# UniFi needs https support, custom repo and APT update first
apt-get -qq install -y apt-transport-https >/dev/null
unifi=$(dpkg-query -W --showformat='${Status}\n' unifi 2>/dev/null)
if [ "x${unifi}" != "xinstall ok installed" ]; then
	echo "deb http://www.ubnt.com/downloads/unifi/debian stable ubiquiti" > /etc/apt/sources.list.d/unifi.list
	curl -Lfs -o /etc/apt/trusted.gpg.d/unifi-repo.gpg https://dl.ubnt.com/unifi/unifi-repo.gpg
	apt-get -qq update -y >/dev/null
	
	if apt-get -qq install -y openjdk-8-jre-headless >/dev/null; then
		echo "Java 8 installed"
	fi
	if apt-get -qq install -y unifi >/dev/null; then
		echo "Unifi installed"
	fi
	systemctl stop mongodb
	systemctl disable mongodb
fi

# Lighttpd needs a config file and a reload
httpd=$(dpkg-query -W --showformat='${Status}\n' lighttpd 2>/dev/null)
if [ "x${httpd}" != "xinstall ok installed" ]; then
	if apt-get -qq install -y lighttpd >/dev/null; then
		cat > /etc/lighttpd/conf-enabled/10-unifi-redirect.conf <<_EOF
\$HTTP["scheme"] == "http" {
    \$HTTP["host"] =~ ".*" {
        url.redirect = (".*" => "https://%0:8443")
    }
}
_EOF
		systemctl reload-or-restart lighttpd
		echo "Lighttpd installed"
	fi
fi

# Fail2Ban needs three files and a reload
f2b=$(dpkg-query -W --showformat='${Status}\n' fail2ban 2>/dev/null)
if [ "x${f2b}" != "xinstall ok installed" ]; then 
	if apt-get -qq install -y fail2ban >/dev/null; then
			echo "Fail2Ban installed"
	fi
	if [ ! -f /etc/fail2ban/filter.d/unifi-controller.conf ]; then
		cat > /etc/fail2ban/filter.d/unifi-controller.conf <<_EOF
[Definition]
failregex = ^.* Failed .* login for .* from <HOST>\s*$
_EOF
		cat > /etc/fail2ban/jail.d/unifi-controller.conf <<_EOF
[unifi-controller]
filter   = unifi-controller
port     = 8443
logpath  = /var/log/unifi/server.log
_EOF
	fi
	# The .local file will be installed in any case
	cat > /etc/fail2ban/jail.d/unifi-controller.local <<_EOF
[unifi-controller]
enabled  = true
maxretry = 3
bantime  = 3600
findtime = 3600
_EOF
	systemctl reload-or-restart fail2ban
fi

###########################################################
#
# Set the time zone
#
tz=$(curl -fs -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/timezone")
if [ ${tz} ] && [ -f /usr/share/zoneinfo/${tz} ]; then
	apt-get -qq install -y dbus >/dev/null
	if ! systemctl start dbus; then
		echo "Trying to start dbus"
		sleep 15
		systemctl start dbus
	fi
	if timedatectl set-timezone $tz; then echo "Localtime set to ${tz}"; fi
	systemctl reload-or-restart rsyslog
fi

###########################################################
#
# Set up unattended upgrades after 04:00 with automatic reboots
#
if [ ! -f /etc/apt/apt.conf.d/51unattended-upgrades-unifi ]; then
	cat > /etc/apt/apt.conf.d/51unattended-upgrades-unifi <<_EOF
Acquire::AllowReleaseInfoChanges "true";
Unattended-Upgrade::Origins-Pattern {
	"o=Debian,a=stable";
	"c=ubiquiti";
};
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "true";
_EOF

	cat > /etc/systemd/system/timers.target.wants/apt-daily-upgrade.timer <<_EOF
[Unit]
Description=Daily apt upgrade and clean activities
After=apt-daily.timer
[Timer]
OnCalendar=4:00
RandomizedDelaySec=30m
Persistent=true
[Install]
WantedBy=timers.target
_EOF
	systemctl daemon-reload
	systemctl reload-or-restart unattended-upgrades
	echo "Unattended upgrades set up"
fi

###########################################################
#
# Set up automatic repair for broken MongoDB on boot
#
if [ ! -f /usr/local/sbin/unifidb-repair.sh ]; then
	cat > /usr/local/sbin/unifidb-repair.sh <<_EOF
#! /bin/sh
if ! pgrep mongod; then
	if [ -f /var/lib/unifi/db/mongod.lock ] \
	|| [ -f /var/lib/unifi/db/WiredTiger.lock ] \
	|| [ -f /var/run/unifi/db.needsRepair ] \
	|| [ -f /var/run/unifi/launcher.looping ]; then
		if [ -f /var/lib/unifi/db/mongod.lock ]; then rm -f /var/lib/unifi/db/mongod.lock; fi
		if [ -f /var/lib/unifi/db/WiredTiger.lock ]; then rm -f /var/lib/unifi/db/WiredTiger.lock; fi
		if [ -f /var/run/unifi/db.needsRepair ]; then rm -f /var/run/unifi/db.needsRepair; fi
		if [ -f /var/run/unifi/launcher.looping ]; then rm -f /var/run/unifi/launcher.looping; fi
		echo >> $LOG
		echo "Repairing Unifi DB on \$(date)" >> $LOG
		su -c "/usr/bin/mongod --repair --dbpath /var/lib/unifi/db --smallfiles --logappend --logpath ${MONGOLOG} 2>>$LOG" unifi
	fi
else
	echo "MongoDB is running. Exiting..."
	exit 1
fi
exit 0
_EOF
	chmod a+x /usr/local/sbin/unifidb-repair.sh

	cat > /etc/systemd/system/unifidb-repair.service <<_EOF
[Unit]
Description=Repair UniFi MongoDB database at boot
Before=unifi.service mongodb.service
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/unifidb-repair.sh
[Install]
WantedBy=multi-user.target
_EOF
	systemctl enable unifidb-repair.service
	echo "Unifi DB autorepair set up"
fi

###########################################################
#
# Set up daily backup to a bucket after 01:00
#
bucket=$(curl -fs -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/bucket")
if [ ${bucket} ]; then
	cat > /etc/systemd/system/unifi-backup.service <<_EOF
[Unit]
Description=Daily backup to ${bucket} service
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/bin/gsutil rsync -r -d /var/lib/unifi/backup gs://$bucket
_EOF

	cat > /etc/systemd/system/unifi-backup.timer <<_EOF
[Unit]
Description=Daily backup to ${bucket} timer
[Timer]
OnCalendar=1:00
RandomizedDelaySec=30m
[Install]
WantedBy=timers.target
_EOF
	systemctl daemon-reload
	systemctl start unifi-backup.timer
	echo "Backups to ${bucket} set up"
fi

###########################################################
#
# Adjust Java heap (advanced setup)
#
# xms=$(curl -fs -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/xms")
# xmx=$(curl -fs -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/xmx")
# if [ ${xms} ] || [ ${xmx} ]; then touch /usr/share/misc/java-heap-adjusted; fi
#
# if [ -e /usr/share/misc/java-heap-adjusted ]; then
#	 if [ "0${xms}" -lt 100 ]; then xms=1024; fi
#	 if grep -e "^\s*unifi.xms=[0-9]" /var/lib/unifi/system.properties >/dev/null; then
#	 	sed -i -e "s/^[[:space:]]*unifi.xms=[[:digit:]]\+/unifi.xms=${xms}/" /var/lib/unifi/system.properties
#	 else
#	 	echo "unifi.xms=${xms}" >>/var/lib/unifi/system.properties
#	 fi
#	 message=" xms=${xms}"
#	 
#	 if [ "0${xmx}" -lt "${xms}" ]; then xmx=${xms}; fi
#	 if grep -e "^\s*unifi.xmx=[0-9]" /var/lib/unifi/system.properties >/dev/null; then
#	 	sed -i -e "s/^[[:space:]]*unifi.xmx=[[:digit:]]\+/unifi.xmx=${xmx}/" /var/lib/unifi/system.properties
#	 else
#	 	echo "unifi.xmx=${xmx}" >>/var/lib/unifi/system.properties
#	 fi
#	 message="${message} xmx=${xmx}"
#	 
#	 if [ -n "${message}" ]; then
#	 	echo "Java heap set to:${message}"
#	 fi
#	 systemctl restart unifi
# fi


###########################################################
#
# Set up Let's Encrypt
#
dnsname=$(curl -fs -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/dns-name")
if [ -z ${dnsname} ]; then exit 0; fi
privkey=/etc/letsencrypt/live/${dnsname}/privkey.pem
pubcrt=/etc/letsencrypt/live/${dnsname}/cert.pem
chain=/etc/letsencrypt/live/${dnsname}/chain.pem
caroot=/usr/share/misc/ca_root.pem
# Conversion file, easier to debug. //JJ
p12=/etc/letsencrypt/live/${dnsname}/p12
# So we can import the chain, not only the individual certificate. //JJ
combo=/etc/letsencrypt/live/${dnsname}/combo.pem

# Write the cross signed root certificate to disk
# Upd: LetsEncrypt cert topology has changed. I added X1 root cert, self-signed, not cross-signed, valid untill 2035. Feedback welcome.//JJ
if [ ! -f $caroot ]; then
	cat > $caroot <<_EOF
-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----
_EOF
fi

# Write pre and post hooks to stop Lighttpd for the renewal
if [ ! -d /etc/letsencrypt/renewal-hooks/pre ]; then
	mkdir -p /etc/letsencrypt/renewal-hooks/pre
fi
cat > /etc/letsencrypt/renewal-hooks/pre/lighttpd <<_EOF
#! /bin/sh
systemctl stop lighttpd
_EOF
chmod a+x /etc/letsencrypt/renewal-hooks/pre/lighttpd

if [ ! -d /etc/letsencrypt/renewal-hooks/post ]; then
	mkdir -p /etc/letsencrypt/renewal-hooks/post
fi
cat > /etc/letsencrypt/renewal-hooks/post/lighttpd <<_EOF
#! /bin/sh
systemctl start lighttpd
_EOF
chmod a+x /etc/letsencrypt/renewal-hooks/post/lighttpd

# Write the deploy hook to import the cert into Java
# Upd: remove java interaction and use keytool to perform all import operations. //JJ
if [ ! -d /etc/letsencrypt/renewal-hooks/deploy ]; then
	mkdir -p /etc/letsencrypt/renewal-hooks/deploy
fi
cat > /etc/letsencrypt/renewal-hooks/deploy/unifi <<_EOF
#! /bin/sh

if [ -e $privkey ] && [ -e $pubcrt ] && [ -e $chain ]; then

	echo >> $LOG
	echo "Importing new certificate on \$(date)" >> $LOG
	# p12=\$(mktemp)
	
	# Preparing combo move of importing a cert chain. //JJ
	cat $pubcrt $chain $caroot > $combo

	if ! openssl pkcs12 -export \\
	-in $combo \\
	-inkey $privkey \\
	-CAfile $chain \\
	-out ${p12} -passout pass:aircontrolenterprise \\
	-caname root -name unifi >/dev/null ; then
		echo "OpenSSL export failed" >> $LOG
		exit 1
	fi
	
	if ! keytool -delete -alias unifi \\
	-keystore /var/lib/unifi/keystore \\
	-deststorepass aircontrolenterprise >/dev/null ; then
		echo "KeyTool delete failed" >> $LOG
	fi
	
	if ! keytool -importkeystore \\
	-srckeystore ${p12} \\
	-srcstoretype pkcs12 \\
	-srcstorepass aircontrolenterprise \\
	-destkeystore /var/lib/unifi/keystore \\
	-deststorepass aircontrolenterprise \\
	-destkeypass aircontrolenterprise \\
	-alias unifi -trustcacerts >/dev/null; then
		echo "KeyTool import failed" >> $LOG
		exit 2
	fi
	
	systemctl restart unifi
	
# Parking java import command //JJ
# 	systemctl stop unifi
#	if ! java -jar /usr/lib/unifi/lib/ace.jar import_cert \\
#	$pubcrt $chain $caroot >/dev/null; then
#		echo "Java import_cert failed" >> $LOG
#		systemctl start unifi
#		exit 3
#	fi
#   systemctl start unifi

	rm -f ${p12}
	echo "Success" >> $LOG
else
	echo "Certificate files missing" >> $LOG
	exit 4
fi
_EOF
chmod a+x /etc/letsencrypt/renewal-hooks/deploy/unifi

# Write a script to acquire the first certificate (for a systemd timer)
cat > /usr/local/sbin/certbotrun.sh <<_EOF
#! /bin/sh
extIP=\$(curl -fs -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip")
dnsIP=\$(getent hosts ${dnsname} | cut -d " " -f 1)

echo >> $LOG
echo "CertBot run on \$(date)" >> $LOG
if [ x\${extIP} = x\${dnsIP} ]; then
	if [ ! -d /etc/letsencrypt/live/${dnsname} ]; then
		systemctl stop lighttpd
		if certbot certonly -d $dnsname --standalone --agree-tos --register-unsafely-without-email >> $LOG; then
			echo "Received certificate for ${dnsname}" >> $LOG
		fi
		systemctl start lighttpd
	fi
	if /etc/letsencrypt/renewal-hooks/deploy/unifi; then
		systemctl stop certbotrun.timer
		echo "Certificate installed for ${dnsname}" >> $LOG
	fi
else
	echo "No action because ${dnsname} doesn't resolve to ${extIP}" >> $LOG
fi
_EOF
chmod a+x /usr/local/sbin/certbotrun.sh

# Write the systemd unit files
if [ ! -f /etc/systemd/system/certbotrun.timer ]; then
	cat > /etc/systemd/system/certbotrun.timer <<_EOF
[Unit]
Description=Run CertBot hourly until success
[Timer]
OnCalendar=hourly
RandomizedDelaySec=15m
[Install]
WantedBy=timers.target
_EOF
	systemctl daemon-reload

	cat > /etc/systemd/system/certbotrun.service <<_EOF
[Unit]
Description=Run CertBot hourly until success
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/certbotrun.sh
_EOF
fi

# Start the above
if [ ! -d /etc/letsencrypt/live/${dnsname} ]; then
	if ! /usr/local/sbin/certbotrun.sh; then
		echo "Installing hourly CertBot run"
		systemctl start certbotrun.timer
	fi
fi

