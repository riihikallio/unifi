#! /bin/sh

# This is a startup script for UniFi Controller on Debian based Google Compute Engine instances.
# For instructions and how-to:  https://metis.fi/en/2018/01/unifi-on-gcp/
# For comments and code walkthrough:  https://metis.fi/en/2018/01/gcp-unifi-code/
# You may use this as you see fit as long as I am credited for my work.
# (c) 2018 Petri Riihikallio Metis Oy

#
# Set up logging
#
LOG="/var/log/gcp-unifi.log"
echo >> $LOG
echo "Startup on $(date)" >> $LOG
if [ ! -f /etc/logrotate.d/gcp-unifi.conf ]; then
	cat > /etc/logrotate.d/gcp-unifi.conf <<_EOF
/var/log/gcp-unifi.log {
weekly
rotate 4
compress
}
_EOF
	echo "Logrotate set up" >> $LOG
fi

#
# Update DynDNS as early in the script as possible
#
ddns=$(curl -fs -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/ddns-url")
if [ $ddns ]; then
	curl -fs $ddns
	echo "Dynamic DNS accessed" >> $LOG
	fi

#
# Create a swap file for small memory instances
#
if [ ! -f /swapfile ]; then
	memory=$(free -m | grep "^Mem:" | tr -s " " | cut -d " " -f 2)
	echo "${memory} megabytes of memory" >> $LOG
	if [ -z "$memory" ] || [ "$memory" -lt "4096" ]; then
		fallocate -l 4G /swapfile
		chmod 600 /swapfile
		mkswap /swapfile
		swapon /swapfile
		cp /etc/fstab /etc/fstab.bak
		echo '/swapfile none swap sw 0 0' >> /etc/fstab
		echo "Swap file created" >> $LOG
	fi
fi

#
# Set time zone
#
tz=$(curl -fs -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/timezone")
if [ $tz ] && [ -f /usr/share/zoneinfo/${tz} ]; then
	rm -f /etc/localtime
	ln -s /usr/share/zoneinfo/${tz} /etc/localtime
	echo "Localtime set to ${tz}" >> $LOG
fi

#
# Add Unifi to APT sources
#
if [ ! -f /etc/apt/trusted.gpg.d/unifi-repo.gpg ]; then
	echo "deb http://www.ubnt.com/downloads/unifi/debian stable ubiquiti" > /etc/apt/sources.list.d/unifi.list
	curl -fs -o /etc/apt/trusted.gpg.d/unifi-repo.gpg https://dl.ubnt.com/unifi/unifi-repo.gpg
	if [ $? ]; then echo "Unifi added to APT sources" >> $LOG; fi
fi

#
# Add backports if it doesn't exist
#
release=$(lsb_release -a 2>/dev/null | grep "^Codename:" | cut -f 2)
if [ ! -f /etc/apt/sources.list.d/backports.list ]; then
	cat > /etc/apt/sources.list.d/backports.list <<_EOF
deb http://deb.debian.org/debian/ ${release}-backports main
deb-src http://deb.debian.org/debian/ ${release}-backports main
_EOF
	echo "Backports (${release}) added to APT sources" >> $LOG
fi

#
# Install stuff
#
apt-get -qq update
if [ ! -f /var/run/apt-upgraded ]; then
	apt-get -qq upgrade -y
	touch /var/run/apt-upgraded
fi

httpd=$(dpkg-query -W --showformat='${Status}\n' lighttpd)
if [ "x$httpd" != "xinstall ok installed" ]; then
	apt-get -qq install -y lighttpd
	cat > /etc/lighttpd/conf-enabled/10-unifi-redirect.conf <<_EOF
\$HTTP["scheme"] == "http" {
    \$HTTP["host"] =~ ".*" {
        url.redirect = (".*" => "https://%0:8443")
    }
}
_EOF
	systemctl reload-or-restart lighttpd
	echo "Lighttpd installed" >> $LOG
fi

haveged=$(dpkg-query -W --showformat='${Status}\n' haveged | grep "install ok installed")
if [ "x$haveged" != "xinstall ok installed" ]; then 
	apt-get -qq install -y haveged
	echo "Haveged installed" >> $LOG
	fi
certbot=$(dpkg-query -W --showformat='${Status}\n' certbot | grep "install ok installed")
if [ "x$certbot" != "xinstall ok installed" ]; then
	apt-get -qq install -y -t ${release}-backports certbot
	echo "CertBot installed from ${release}-backports" >> $LOG
	fi
unifi=$(dpkg-query -W --showformat='${Status}\n' unifi | grep "install ok installed")
if [ "x$unifi" != "xinstall ok installed" ]; then
	apt-get -qq install -y unifi
	echo "Unifi installed" >> $LOG
	systemctl disable mongodb
fi

#
# Set up unattended upgrades with automatic reboots
#
if [ ! -f /etc/apt/apt.conf.d/51unattended-upgrades-unifi ]; then
	cat > /etc/apt/apt.conf.d/51unattended-upgrades-unifi <<_EOF
Unattended-Upgrade::Origins-Pattern {
	"o=Debian,a=stable";
	"c=ubiquiti";
};
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "03:21";
_EOF
	systemctl reload-or-restart unattended-upgrades
	echo "Unattended upgrades set up" >> $LOG
fi

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
		su -c "/usr/bin/mongod --repair --dbpath /var/lib/unifi/db --logappend --logpath /usr/lib/unifi/logs/mongod.log 2>>$LOG" unifi
	fi
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
	echo "Unifi DB autorepair set up" >> $LOG
fi

#
# Set up daily backup to a bucket
#
bucket=$(curl -fs -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/bucket")
if [ $bucket ]; then
	cat > /etc/systemd/system/unifi-backup.timer <<_EOF
[Unit]
Description=Daily backup to ${bucket} timer
[Timer]
OnCalendar=daily
RandomizedDelaySec=6h
[Install]
WantedBy=timers.target
_EOF
	cat > /etc/systemd/system/unifi-backup.service <<_EOF
[Unit]
Description=Daily backup to ${bucket} service
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/bin/gsutil rsync -r -d /var/lib/unifi/backup gs://$bucket
_EOF
	systemctl start unifi-backup.timer
	systemctl enable unifi-backup.timer
	echo "Backups to ${bucket} set up" >> $LOG
fi

#
# Set up Let's Encrypt
#
dnsname=$(curl -fs -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/dns-name")
extIP=$(curl -fs -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip")
dnsIP=$(getent hosts $dnsname | cut -d " " -f 1)
if [ $dnsname ] && [ $extIP = $dnsIP ] && [ ! -d /etc/letsencrypt/live/${dnsname} ]; then
	systemctl stop lighttpd
    x=$(certbot certonly -d $dnsname --standalone --agree-tos --register-unsafely-without-email)
	systemctl start lighttpd
	if [ "$x" ]; then echo "Received certifacate for ${dnsname}" >> $LOG
		else echo "CertBot failed for ${dnsname}" >> $LOG; exit 1;
	fi
		
	# Write the cross signed certificate to disk
	cat > /var/lib/unifi/ca_chain.pem <<_EOF
-----BEGIN CERTIFICATE-----
MIIDSjCCAjKgAwIBAgIQRK+wgNajJ7qJMDmGLvhAazANBgkqhkiG9w0BAQUFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTAwMDkzMDIxMTIxOVoXDTIxMDkzMDE0MDExNVow
PzEkMCIGA1UEChMbRGlnaXRhbCBTaWduYXR1cmUgVHJ1c3QgQ28uMRcwFQYDVQQD
Ew5EU1QgUm9vdCBDQSBYMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AN+v6ZdQCINXtMxiZfaQguzH0yxrMMpb7NnDfcdAwRgUi+DoM3ZJKuM/IUmTrE4O
rz5Iy2Xu/NMhD2XSKtkyj4zl93ewEnu1lcCJo6m67XMuegwGMoOifooUMM0RoOEq
OLl5CjH9UL2AZd+3UWODyOKIYepLYYHsUmu5ouJLGiifSKOeDNoJjj4XLh7dIN9b
xiqKqy69cK3FCxolkHRyxXtqqzTWMIn/5WgTe1QLyNau7Fqckh49ZLOMxt+/yUFw
7BZy1SbsOFU5Q9D8/RhcQPGX69Wam40dutolucbY38EVAjqr2m7xPi71XAicPNaD
aeQQmxkqtilX4+U9m5/wAl0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNV
HQ8BAf8EBAMCAQYwHQYDVR0OBBYEFMSnsaR7LHH62+FLkHX/xBVghYkQMA0GCSqG
SIb3DQEBBQUAA4IBAQCjGiybFwBcqR7uKGY3Or+Dxz9LwwmglSBd49lZRNI+DT69
ikugdB/OEIKcdBodfpga3csTS7MgROSR6cz8faXbauX+5v3gTt23ADq1cEmv8uXr
AvHRAosZy5Q6XkjEGB5YGV8eAlrwDPGxrancWYaLbumR9YbK+rlmM6pZW87ipxZz
R8srzJmwN0jP41ZL9c8PDHIyh8bwRLtTcm1D9SZImlJnt1ir/md2cXjbDaJWFBM5
JDGFoqgCWjBH4d1QB7wCCZAA62RjYJsWvIjJEubSfZGL+T0yjWW06XyxV3bqxbYo
Ob8VZRzI9neWagqNdwvYkQsEjgfbKbYK7p2CNTUQ
-----END CERTIFICATE-----
_EOF

	# Write the deploy hook to import the cert into Java
	cat > /etc/letsencrypt/renewal-hooks/deploy/unifi <<_EOF
#! /bin/sh

if [ -f /etc/letsencrypt/live/${dnsname}/privkey.pem ] \\
	&& [ -f /etc/letsencrypt/live/${dnsname}/cert.pem ] \\
	&& [ -f /etc/letsencrypt/live/${dnsname}/cert.pem ]; then

	p12=\$(mktemp)
	echo >> $LOG
	echo "Importing new certificate on \$(date)" >> $LOG
	systemctl stop unifi
	
	openssl pkcs12 -export \\
	-in /etc/letsencrypt/live/${dnsname}/cert.pem \\
	-inkey /etc/letsencrypt/live/${dnsname}/privkey.pem \\
	-CAfile /etc/letsencrypt/live/${dnsname}/cert.pem \\
	-out \${p12} -passout pass:aircontrolenterprise \\
	-caname root -name unifi
	x=\$?
	if [ ! "\$x" ]; then
		echo "OpenSSL export failed" >> $LOG
		systemctl start unifi
		exit 1
	fi
	
	keytool -delete -alias unifi \\
	-keystore /var/lib/unifi/keystore \\
	-deststorepass aircontrolenterprise
	x=\$?
	if [ ! "\$x" ]; then
		echo "KeyTool delete failed" >> $LOG
		systemctl start unifi
		exit 2
	fi
	
	keytool -importkeystore \\
	-srckeystore \${p12} -srcstoretype PKCS12 \\
	-srcstorepass aircontrolenterprise \\
	-destkeystore /var/lib/unifi/keystore \\
	-deststorepass aircontrolenterprise \\
	-destkeypass aircontrolenterprise \\
	-alias unifi -trustcacerts
	x=\$?
	if [ ! "\$x" ]; then
		echo "KeyTool import failed" >> $LOG
		systemctl start unifi
		exit 3
	fi
	
	java -jar /usr/lib/unifi/lib/ace.jar import_cert \\
	/etc/letsencrypt/live/${dnsname}/cert.pem \\
	/etc/letsencrypt/live/${dnsname}/cert.pem \\
	/var/lib/unifi/ca_chain.pem
	x=\$?
	if [ ! "\$x" ]; then
		echo "Java import_cert failed" >> $LOG
		systemctl start unifi
		exit 4
	fi
	
	rm -f \${p12}
	systemctl start unifi
	echo "Success" >> $LOG
fi
_EOF
	chmod a+x /etc/letsencrypt/renewal-hooks/deploy/unifi
	# Run the deploy hook once to import the first cert
	/etc/letsencrypt/renewal-hooks/deploy/unifi
fi
