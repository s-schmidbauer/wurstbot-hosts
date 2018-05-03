have entries of both hosts in load balancing
/etc/resolv.conf

# nice to haves
- know all relevant config files and what vars they reference (like IPs, netmasks, MACs etc.)
- have a simple backup of all important config files (cvs and remote)
- assign qos minimums for all core services like ntpd, dns etc. through hfsc
- dnscrypt-proxy to encrypt outgoing dns querys from our ns
- dhcpd synchronization with partner using -y and -Y options (see man) - DONE, WORKING?
- secure dns zone transfers and secondary nameserver - DONE
- dnssec to also use with cert pinning, pubkey publishing (start: https://calomel.org/nsd_dns.html)
- repo server for tftp and as repository
- nsca-client to read out status of execution
- sms notifications through usb modem
- sensors from motherboard can be read and used for monitoring

# all servers
- pkg_add -uv
- syspatch
- set installpath to eu address or local repo
- run syspatch to install latest patches
- make sure one wheel user exist for non-ldap access (not root)
- doas is configured and preserves envs
- configure hostname.if and mygate and myname and resolv.conf
- sensorsd - https://calomel.org/sensorsd_config.html
- power management
- nrpe-client
- bacula client
- cvs - http://vasc.ri.cmu.edu/old_help/Archiving/Cvs/cvs_tutorial.texinfo.html
- install nrpe and nsca-client
- make local check commands for in nrpe.conf
- take pf.guide from openbsd official site for router
- rcctl enable pf
- pfctl -nf /etc/pf.conf
- pfctl -f /etc/pf.conf

# DOAS - /etc/doas.conf

following allows members of wheel to execute all commands while setting an unsetting some env vars

vi /etc/doas.conf
permit persist setenv { -ENV PS1=$DOAS_PS1 SSH_AUTH_SOCK } :wheel

logoff and back in. then: doas rcctl reload nsd

# BACKUPSCRIPT
---------------------------



# SYSTEM MAINTENANCE
----------------------------
doas crontab -e


@daily  syspatch
@daily  pkg_add -u
@daily  /usr/local/bin/renew-certs.sh
@daily  /usr/local/bin/renew-ocsp.sh
@daily  /home/admin/mysql-backup.sh

/usr/local/bin/renew-certs.sh
------------------------------------
#!/bin/sh

acme-client node5.wurstbot.com

if [ $? -eq 0 ]
 then
 rcctl reload httpd
fi

/usr/local/bin/renew-ocsp.sh
------------------------------------
#!/bin/sh

ocspcheck -vN -o /etc/ssl/node4.wurstbot.com.der /etc/ssl/node4.wurstbot.com.fullchain.pem

if [ $? == 0 ];
then
 rcctl reload httpd
fi





# pf - /etc/pf.conf

table <martians> { 0.0.0.0/8 10.0.0.0/8 127.0.0.0/8 169.254.0.0/16     \
                   172.16.0.0/12 192.0.0.0/24 192.0.2.0/24 224.0.0.0/3 \
                   192.168.0.0/16 198.18.0.0/15 198.51.100.0/24        \
                   203.0.113.0/24 }

set skip on lo

block return    # block stateless traffic
pass            # establish keep-state

## By default, do not permit remote connections to X11
block return in on ! lo0 proto tcp to port 6000:6010

set block-policy drop
set loginterface egress
set skip on lo0
match in all scrub (no-df random-id max-mss 1440)
block in quick on egress from <martians> to any
block return out quick on egress from any to <martians>
block all
pass out quick inet
pass in on egress inet proto icmp from any to (egress)
pass in on egress inet proto tcp from any to (egress) port { http, https, 3128, 3200, 465, 5666, 10050, 10051, smtp, submission, imap, imaps }

the last line allows the number of services

## pfsync

sync states of pf between hosts over internal interface (using multicast)
on both hosts, create a pfsync interface. use internal interface (em1) to sync

vi /etc/hostname.pfsync0
inet 172.16.0.1/2 255.255.255.0

ifconfig pfsync0 172.16.0.1 or 2 255.255.255.0 syncdev em1 up


## configure carp

allow carp and pfsync traffic on carp interface in pf. reload ruleset.
create carp interface and bind to VIP 172.16.0.10. master will use advskew 100, backup 110 or higher. lower wins.
vi /etc/pf.conf
carp_dev=em1
pass out on $carp_dev proto carp
pass out on $carp_dev proto pfsync
pfctl -nf /etc/pf.conf
pfctl -f /etc/pf.conf

use preempt to fail back to origial master and honor advskew even after failing over to backup
sysctl net.inet.carp.preempt=1
echo 'net.inet.carp.preempt=1' >> /etc/sysctl.conf

ifconfig carp0 create
sysctl net.inet.carp.allow=1
echo 'net.inet.carp.allow=1' >> /etc/sysctl.conf
ifconfig carp0 vhid 1 pass foobar carpdev em1 advskew 110 172.16.0.10 netmask 255.255.255.0
ifconfig carp0


### monitor multicast traffic
tcpdump -i em1 -vv net 224.0.0.0/4


# unbound, in /var/unbound/etc/unbound.conf
-------------------------------------------
--------------------------------------------
listen on local interfaces port 53. Stub zone to foward local queries to NSD.
-----------------------
-----------------------
server:
        interface: 127.0.0.1
        interface: 192.168.100.118
        interface: ::1
        do-ip6: yes

        access-control: 0.0.0.0/0 refuse
        access-control: 127.0.0.0/8 allow
        access-control: 192.168.100.0/24 allow
        access-control: ::0/0 refuse
        access-control: ::1 allow

        hide-identity: yes
        hide-version: yes

        do-not-query-localhost: no
        local-zone: "wurstbot.com" nodefault

        # root key file, automatically updated
        #auto-trust-anchor-file: "/var/unbound/etc/root.key"

remote-control:
        control-enable: yes
        control-use-cert: no
        control-interface: /var/run/unbound.sock

stub-zone:
       name: "wurstbot.com"
       stub-addr: 127.0.0.1@5353

then, in /etc/resolv.conf:
search wurstbot.com
domain wurstbot.com
nameserver 192.168.100.116
nameserver 192.168.100.115

unbound-control-setup #to generate keys for remote control
rcctl start unbound
rcctl reload unbound
unbound-control status

enabling dnssec. specify a file location to be written that unbound can read from.
this was NOT working. name resolution was broken after activating it.
the root anchor gets updated automatically according to documentation.
-------------------------------
unbound-anchor -a /var/unbound/db/root.key

in the unbound.conf
auto-trust-anchor-file: "/var/unbound/etc/root.key"


# NSD - /var/nsd/etc/nsd.conf
--------------------
--------------------
binds to the 5353 port of local interfaces
nsd only can do axfr zone transfers, so the fallback is needed
provide the port only on slave in request-xfr

rcctl enable nsd
vi /var/nsd/etc/nsd.conf

server:
        hide-version: yes
        verbosity: 2
        database: "" # disable database
        ip-address: 127.0.0.1
        ip-address: 192.168.100.118

        port: 5353

remote-control:
        control-enable: yes

## on master, provide to slave

key:
        name: "wurstbotkey"
        algorithm: hmac-sha256
        secret: "gsJQqhLnBfV/Qqdc/BqUC1p+yNg28ev2R2oxLbxg+wo="

pattern:
        name: "toslave"
        notify: 192.168.100.115 wurstbotkey
        provide-xfr: 192.168.100.115 wurstbotkey
        allow-axfr-fallback: yes

zone:
        name: "wurstbot.com"
        zonefile: "wurstbot.com.zone"
        include-pattern: "toslave"
zone:
        name: "100.168.192.in-addr.arpa"
        zonefile: "wurstbot.com.reverse"
        include-pattern: "toslave"



## on slave, pull from master on port 5353
-------------------------------------------
key:
        name: "wurstbotkey"
        algorithm: hmac-sha256
        secret: "gsJQqhLnBfV/Qqdc/BqUC1p+yNg28ev2R2oxLbxg+wo="
pattern:
        name: "frommaster"
        allow-notify: 192.168.100.116 wurstbotkey
        request-xfr: AXFR 192.168.100.116@5353 wurstbotkey
        allow-axfr-fallback: yes
zone:
        name: "wurstbot.com"
        zonefile: "wurstbot.com.zone"
        include-pattern: "frommaster"
zone:
        name: "100.168.192.in-addr.arpa"
        zonefile: "wurstbot.com.reverse"
        include-pattern: "frommaster"

### on master
nsd-control notify

### on slave, check logs after running this
nsd-control force_update wurstbot.com


### restart to activate changes for stub zone!
rcctl restart nsd
dig @127.0.0.1 -p 53 google.com
dig @127.0.0.1 -p 53 ns.wurstbot.com

### test zonetransfer
dig axfr @ns.wurstbot.com

### on dns master and notify slave
raise serial in master zone file when making an change, then on master:

nsd-control notify wurstbot.com

### on dns slave, start transfer and check for new serial
nsd-control transfer
nsd-control force_transfer wurstbot.com
nsd-control zonestatus wurstbot.com


## FORWARD ZONE
-----------------------------
-----------------------------
vi /var/nsd/zones/wurstbot.com.zone

$ORIGIN wurstbot.com.
$TTL 86400

@       3600    SOA     ns.wurstbot.com. hostmaster.wurstbot.com. (
                        2014110502      ; serial
                        1800            ; refresh
                        7200            ; retry
                        1209600         ; expire
                        3600 )          ; negative

                NS      ns.wurstbot.com.
                NS      ns2.wurstbot.com.

                MX      0 mail.wurstbot.com.

@       IN      A       192.168.100.116
ns              A       192.168.100.116
ns2              A       192.168.100.115
mail              A       192.168.100.116

## REVERSE ZONE
-------------------------------
-------------------------------
vi /var/nsd/zones/wurstbot.com.reverse
$ORIGIN 100.168.192.in-addr.arpa.
$TTL 86400

@ IN  SOA     ns.wurstbot.com. hostmaster.wurstbot.com. (
                        2014110502      ; serial
                        1800            ; refresh
                        7200            ; retry
                        1209600         ; expire
                        3600 )          ; negative

                        IN      NS      ns.wurstbot.com
                        IN      NS      ns2.wurstbot.com.

116                       IN      PTR     ns.wurstbot.com.
115                       IN      PTR     ns2.wurstbot.com.
116                       IN      PTR     www.wurstbot.com.



### resolv.conf

to allow lan connected unbound(:53) first. internal request will be passed by unbound to nsd

search wurstbot.com
domain wurstbot.com
nameserver 192.168.100.116
nameserver 192.168.100.115


# dhcpd - /etc/dhcpd.conf

rcctl enable dhcpd
rcctl set dhcpd flags em0   #set this to the LAN interface

master: rcctl set dhcpd flags -y em0
slave: rcctl set dhcpd flags -Y em0

vi /etc/dhcpd.conf

subnet 192.168.100.0 netmask 255.255.255.0 {
        default-lease-time 3600;
        max-lease-time 7200;
        option subnet-mask 255.255.255.0;
        option routers 192.168.100.254;
        option domain-name 'wurstbot.com';
        option domain-name-servers 192.168.100.118, 192.168.100.254;
        range 192.168.100.220 192.168.100.230;
}

rcctl start dhcpd
cat dhclient.leases.em0
cat dhcpd.leases


### dhcpd sync. must have multicast enabled on both hosts
---------------------------------
vi /etc/sysctl.conf
net.inet.ip.forwarding=1
net.inet.ip.mforwarding=1

vi /etc/rc.conf.local
multicast_host=YES

create dhcpd key to 2nd server
dd if=/dev/random of=/var/db/dhcpd.key bs=2048 count=1
scp /var/db/dhcpd.key admin@ns2:/var/db/dhcpd.key

on primary, listen on em0: dhcpd -y em0 -Y em0
on second, just receive on em0:  dhcpd -Y em0

### NFS

mkdir /data
vi /etc/exports
/data -alldirs -ro -mapall=remote -network=192.168.100 -mask=255.255.255.0

rcctl enable portmap mountd nfsd
rcctl start portmap mountd nfsd
rcctl reload mountd

nfsstat - display statistics
nfsstat -m - show health of mount
showmount - show files / folders mounted by clients

on client, install nfs client and mount it
sudo apt-get install nfs-common
sudo mount -t nfs -o noatime,intr 192.168.100.118:/data shared


# NTPD - /etc/ntpd.conf

listen on 192.168.100.118
servers pool.ntp.org
sensor *
constraints from "https://www.google.com"

rcctl enable ntpd
rcctl start ntpd


# MYSQL - /etc/my.cnf

pkg_add mariadb-server
rcctl enable mysqld

Make sure to listen on an address in /etc/my.cnf
listen on 0.0.0.0

mysql_install_db
rcctl start mysqld
mysql_secure_installation
rcctl restart mysqld

## mysql master configuration
mysql -u root -p
GRANT REPLICATION SLAVE ON *.* TO 'slave_user'@'%' IDENTIFIED BY 'password';
FLUSH PRIVILEGES;
USE mydatabase;
FLUSH TABLES WITH READ LOCK;
SHOW MASTER STATUS;

mysqldump -u root -p --opt mydatabase > mydatabase.sql
scp mydatabase.sql admin@ns2:

## mysql slave config
create database mydatabase;

CHANGE MASTER TO MASTER_HOST='172.16.0.1',MASTER_USER='slave_user', MASTER_PASSWORD='secret', MASTER_LOG_FILE='mysql-bin.000010', MASTER_LOG_POS=326;

in /etc/my.cnf on the master
binlog_do_db            = mydatabase

rcctl restart mysqld
start slave;
show slave status\G


# relayd - /etc/relayd.conf

config below has on tcp relay for dns bound on 8853 and a web frontend

rcctl relayd enable

vi /etc/relayd.conf

relayd_addr="192.168.100.116"
dns_port="8853"
http_port="8000"
table <web_hosts> { 127.0.0.1, 192.168.100.115 }
table <dns_hosts> { 127.0.0.1, 192.168.100.115 }

interval 2
timeout 200
prefork 2
log updates

http protocol "httpfilter" {
    tcp { nodelay, sack, socket buffer 65536, backlog 100 }
    return error
}

dns protocol "dnsfilter" {
   ### TCP performance options
    tcp { nodelay, sack, socket buffer 1024, backlog 1000 }
}

relay dnsproxy {
        listen on $relayd_addr port $dns_port
        protocol "dnsfilter"
        forward to <dns_hosts> port 53 mode loadbalance check tcp
}

relay httpproxy {
   listen on $relayd_addr port $http_port
   protocol "httpfilter"
   forward to <web_hosts> port 80 mode loadbalance check http "/" code 200
}


chmod 600 /etc/relayd.conf
rcctl start relayd
relayctl show hosts
relayctl monitor
relayctl log verbose

relayctl show sessions
session 0:7 192.168.100.114:48684 -> :0 RUNNING
        age 00:00:00, idle 00:00:00, relay 1, pid 3300


# httpd - /etc/httpd.conf
--------------------
--------------------

rcctl enable httpd

local="127.0.0.1"
int_if="192.168.100.118"

types { include "/usr/share/misc/mime.types" }

server "www.wurstbot.com" {
        listen on $local port 80
        listen on $int_if port 80
        #listen on $int_if tls port 443
}

server "ns.wurstbot.com" {
        listen on $int_if port 80
        listen on $ext_if port 80

        # Set max upload size to 513M (in bytes)
        connection max request body 537919488

        location "/db_structure.xml" { block }
        location "/.ht*"             { block }
        location "/README"           { block }
        location "/data*"            { block }
        location "/config*"          { block }

        directory {
                index "index.php"
        }

        location "*.php*" {
                root { "/owncloud", strip 1 }
                fastcgi socket "/run/php-fpm.sock"
        }

        location "/owncloud*" {
                root { "/owncloud", strip 1 }
        }
}

for cgi applications, add
       location "/cgi-bin/nagios/*.cgi" {
                root { "/" }
                fastcgi socket "/run/slowcgi.sock"
       }

enforce https for this domain
.. and remove the regular port binding from the vhost for 443:

server "www.wurstbot.com" {
        listen on lo port 80
        listen on egress port 80
        block return 301 "https://$SERVER_NAME$REQUEST_URI"
}


check the config:
httpd -n
httpd -nf /etc/httpd.conf


create a basic index page
echo '<h1>hello</h1>' >> /var/www/htdocs/index.html

example config:

server "*.wurstbot.com" {
        listen on lo port 80
        listen on egress port 80
        block return 301 "https://www.wurstbot.com/$REQUEST_URI"
}

server "node4.wurstbot.com" {
        listen on lo port 80
        listen on egress port 80
        block return 301 "https://$SERVER_NAME$REQUEST_URI"
}


server "node4.wurstbot.com" {
        alias "www.wurstbot.com"
        alias "mail4.wurstbot.com"
        root "/wurstbot.com"

        listen on lo tls port 443
        listen on egress tls port 443
        tls certificate "/etc/ssl/node4.wurstbot.com.crt"
        tls key "/etc/ssl/private/node4.wurstbot.com.key"
        tls ocsp "/etc/ssl/node4.wurstbot.com.der"
        connection { max requests 100, timeout 600 }

        location "/.well-known/acme-challenge/*" {
                root "/acme"
                root strip 2
        }
}


# ACME-CLIENT

doas vi /etc/acme-client.conf

domain node2.wurstbot.com {
        #alternative names { www.wurstbot.com }
        domain key "/etc/ssl/private/node2.wurstbot.com.key"
        domain certificate "/etc/ssl/node2.wurstbot.com.crt"
        domain full chain certificate "/etc/ssl/node2.wurstbot.com.fullchain.pem"
        sign with letsencrypt
}

make sure to have a section for acme in your httpd.conf for each(!) vhost required:
        location "/.well-known/acme-challenge/*" {
                root "/acme"
                root strip 2
        }

make the key and cert with all domain names configured
doas acme-client -vAD node2.wurstbot.com

delete the key if necessary to re-create a cert with new domains: (make a backup before!)

doas rm /etc/ssl/private/node2*
doas rm /etc/ssl/node2*

to generate a ocsp stapling file:
doas ocspcheck -No /etc/ssl/node1.wurstbot.com.der /etc/ssl/node1.wurstbot.com.fullchain.pem

in /etc/httpd.conf:
        #listen on lo tls port 443
        #listen on egress tls port 443
        #tls certificate "/etc/ssl/node1.wurstbot.com.crt"
        #tls key "/etc/ssl/private/node1.wurstbot.com.key"
        #tls ocsp "/etc/ssl/node1.wurstbot.com.der"


# PHP-FPM - /etc/php*
------------------------------------
install php. php-fpm is included.
symlink installed extensions from the example dir to the /etc/php-5.6 dir to use them

pkg_add php php-curl php-mysql php-zip php-gd php-mcrypt php-bz2 php-intl
rcctl enable php56_fpm

ln -s /etc/php-5.6.sample/curl.ini /etc/php-5.6/curl.ini
ln -s /etc/php-5.6.sample/mysql.ini /etc/php-5.6/mysql.ini
ln -s /etc/php-5.6.sample/zip.ini  /etc/php-5.6/zip.ini
ln -s /etc/php-5.6.sample/gd.ini  /etc/php-5.6/gd.ini
ln -s /etc/php-5.6.sample/mcrypt.ini  /etc/php-5.6/mcrypt.ini
ln -s /etc/php-5.6.sample/bz2.ini  /etc/php-5.6/bz2.ini
ln -s /etc/php-5.6.sample/intl.ini  /etc/php-5.6/intl.ini

rcctl restart php56_fpm

To use a IP address binding instead of a Unix socket, use this config.
----------------------------------------------------------------------
Using an IP is required when running multiple PHP applications on the same server.

;listen = /var/www/run/php-fpm.sock
listen = 127.0.0.1:6060

rcctl restart php56_fpm

In /etc/httpd.conf, use this undocumented option
#listen = /var/www/run/php-fpm.sock
listen = 127.0.0.1:6060

        location "*.php*" {
                #fastcgi socket "/run/php-fpm.sock"
                fastcgi socket ":6060"
        }



# NRPE - /etc/nrpe.cfg
------------------------------------------
------------------------------------------
install without ssl to avoid openssl
define some nrpe commands on the system to be monitored so the remote nagios server can call them

pkg_add nrpe (add the one without ssl)

rcctl start nrpe
rcctl enable nrpe

allow nrpe in the firewall of the systems to be monitored:
pass in on egress proto tcp from any to any port 5666

vi /etc/nrpe.cfg
server_address=192.168.100.116
log_facility=daemon
server_port=5666
allowed_hosts=127.0.0.1,192.168.100.0/24,172.16.1.0/24
debug=0
connection_timeout=300
allow_weak_random_seed=0


command[check_users]=/usr/local/libexec/nagios/check_users -w 5 -c 10
command[check_load]=/usr/local/libexec/nagios/check_load -w 15,10,5 -c 30,25,20
command[check_disk]=/usr/local/libexec/nagios/check_disk -w 20% -c 10%
command[check_zombie_procs]=/usr/local/libexec/nagios/check_procs -w 5 -c 10 -s Z
command[check_total_procs]=/usr/local/libexec/nagios/check_procs -w 150 -c 200

command[check_disk_root]=/usr/local/libexec/nagios/check_disk -w 20 -c 10 -p /

rcctl restart nrpe

on the nagios server, define a new command using the command and use it within a service
doas vi /etc/nagios/objects/commands.cfg

define command {
    command_name    check_nrpe
    command_line    $USER1$/check_nrpe -H $HOSTADDRESS$ -c $ARG1$
}


on the host to be monitored, setup nrpe to allow connections and define the required checks locally
doas vi /etc/nrpe.cfg

allowed_hosts=127.0.0.1,93.170.104.52,93.171.216.20

command[check_disk_var]=/usr/local/libexec/nagios/check_disk -w 20% -c 10% -p /var
command[check_disk_home=/usr/local/libexec/nagios/check_disk -w 20% -c 10% -p /home
command[check_disk_usr]=/usr/local/libexec/nagios/check_disk -w 20% -c 10% -p /usr
command[check_disk_usr_local]=/usr/local/libexec/nagios/check_disk -w 20% -c 10% -p /usr/local
command[check_disk_tmp]=/usr/local/libexec/nagios/check_disk -w 20% -c 10% -p /tmp


finally, on the server, add the check command in a new service
doas vi /etc/nagios/objects/localhost.cfg

define service{
        use                             local-service         ; Name of service template to use
        host_name                       node1
        service_description             Disk /home
        check_command                   check_nrpe!check_disk_home
        notifications_enabled           0
        }



# NSCA client - /etc/send_nsca.cfg
???


# LDAPD - /etc/ldapd.conf
------------------------------------
secure just marks this as a trusted network.
i could not figure out how to do the tls config

rcctl enable ldapd

cp /etc/examples/ldapd.conf /etc/ldapd.conf
int_if='em1'
listen $int_if secure

secure connection. symlink to default folder when using the 'tls' option. expects cert to be named like interface

openssl req -new -newkey rsa:2048 -nodes -keyout ns.wurstbot.com.key -out ns.wurstbot.com.csr
openssl req -new -x509 -days 3652 -key /etc/ssl/ns.wurstbot.com.key -out /etc/ssl/ns.wurstbot.com.crt
mv ns.wurstbot.com.* /etc/ssl
ln -s /etc/ssl/ns.wurstbot.com.crt /etc/ldap/certs/em1.crt

## configtest and show stats
ldapd -nf /etc/ldapd.conf
rcctl start ldapd


# SPAMD - /etc/mail/spamd.conf
------------------------------
rcctl enable spamd

doas vi /etc/rc.conf.local
spamd_black=NO
spamd_flags=-4 -G25:4:864 -h mail2.wurstbot.com -l127.0.0.1 -n \"Sendmail 8.11.4/8.11.1\" -S10 -s1 -v -w1
spamlogd_flags="-I -i lo0"

add our local network to nospamd table. all other will suffer from torture ;)
echo '192.168.100.0' >> /etc/mail/nospamd

in /etc/pf.conf
-------------------
remove regular smtp binding. port 25 will be forwarded to spamd on port 8025. from there, spamd-white will
be forwarded to port smtp

pass in on egress proto tcp to any port smtp
pass in on egress proto tcp to any port submission

firewall rules for spamd(8)

table <spamd-white> persist
table <nospamd> persist file "/etc/mail/nospamd"
pass in on egress proto tcp from any to any port smtp rdr-to 127.0.0.1 port spamd
pass in on egress proto tcp from <nospamd> to any port smtp
pass in log on egress proto tcp from <spamd-white> to any port smtp
pass out log on egress proto tcp to any port smtp

pfctl -nf /etc/pf.conf
pfctl -f /etc/pf.conf

spamlogd is required as its being used by pf do determine which hosts are trying to connect
doas rcctl enable spamlogd spamd

rcctl restart spamd




# SMTPD - /etc/mail/smtpd.conf

rcctl enable smtpd


make sure to uncomment tables not used like passwd or virtuals!
vi /etc/mail/smtpd.conf

table aliases file:/etc/mail/aliases
table domains file:/etc/mail/domains
table passwd file:/etc/mail/passwd
table virtuals file:/etc/mail/virtuals

To accept external mail, replace with: listen on all

listen on lo0
listen on egress port 25
listen on egress port 587

Uncomment the following to accept external mail for domain "wurstbot.com"

accept from any for domain "wurstbot.com" alias <aliases> deliver to mbox
accept for local alias <aliases> deliver to mbox
accept from local for any relay

#deliver to dovecot lmtp
#accept from local for local alias <aliases> deliver to lmtp "/var/dovecot/lmtp" rcpt-to
#accept from any for domain <domains> virtual <virtuals> deliver to lmtp /var/dovecot/lmtp" rcpt-to


#setup alias, domains, virtuals and credentials for smtp
vi /etc/mail/aliases
moo: admin

vi /etc/mail/domains
wurstbot.com

vi /etc/mail/virtuals
moo@wurstbot.com        admin@wurstbot.com
admin@wurstbot.com      vmail

#MAIL TLS setup
once this is done, you can also successfully relay mail to the outside

#create smtpd key and cert with common name like IP or hostname for testing
openssl req -new -x509 -nodes -newkey rsa:4096 -keyout /etc/ssl/private/smtpd.key -out /etc/ssl/smtpd.pem -days 1095

#fix the permissions or smtpd wont start
doas chmod 640 /etc/ssl/private/smtpd.key

#create a creds file. tool does not ** the password when being typed!
smtpctl encrypt
vi /etc/mail/creds
admin $2......

in /etc/mail/smtpd.conf:
mail1 is the name of the macro and can be anything
------------------------
pki mail1 certificate  "/etc/ssl/smtpd.pem"
pki mail1 key          "/etc/ssl/private/smtpd.key"

table creds file:/etc/mail/creds
listen on all port 25 tls pki mail1 auth <creds>
listen on all port 587 tls-require pki mail1 auth <creds>
listen on all port 465 smtps pki mail1 auth <creds>

#use auth-optional if you dont want to enforce auth


in pf.conf
--------------
pass in on egress proto tcp to any port 25
pass in on egress proto tcp to any port 587

#start and test

rcctl start smtpd
mail -s 'test message' s.schmidbauer@gmail.com
hello
.

mailq
smtpctl show queue
smtpctl show stats
smtpctl monitor
tail -f /var/log/maillog


full config file:

table aliases file:/etc/mail/aliases
table domains file:/etc/mail/domains

pki node5 certificate  "/etc/ssl/node5.wurstbot.com.crt"
pki node5 key          "/etc/ssl/private/node5.wurstbot.com.key"
table creds file:/etc/mail/creds

# To accept external mail, replace with: listen on all
#
listen on all port 25 tls pki node5 auth-optional <creds>
listen on all port 587 tls-require pki node5 auth-optional <creds>
listen on all port 465 smtps pki node5 auth-optional <creds>

# Uncomment the following to accept external mail for domain "wurstbot.com"
#
accept from any for domain <domains> alias <aliases> deliver to mbox
accept for local alias <aliases> deliver to mbox
accept from local for any relay

#deliver to dovecot lmtp
#accept from local for local alias <aliases> deliver to lmtp "/var/dovecot/lmtp" rcpt-to
#accept from any for domain <domains> virtual <virtuals> deliver to lmtp /var/dovecot/lmtp" rcpt-to


# DOVECOT - /etc/dovecot/dovecot.conf
------------------------------
------------------------------
To sync mail boxes: https://wiki2.dovecot.org/Tools/Doveadm/Sync

doas pkg_add dovecot

raise openfiles limit in /etc/login.conf for the dovecot user
dovecot:\
        :openfiles=2048:\
        :tc=daemon:

vi /etc/dovecot/dovecot.conf

protocols = imap lmtp pop3
listen = *, ::
!include conf.d/*.conf
!include_try local.conf

set the mail location you want (mandatory)

vi /etc/dovecot/conf.d/10-mail.conf
mail_location = mbox:~/mail:INBOX=/var/mail/%u

make a self signed cert
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/dovecot.pem -out /etc/ssl/dovecotcert.pem

make sure ssl paths are right
vi /etc/dovecot/conf.d/10-ssl.conf
ssl_cert = </etc/ssl/dovecotcert.pem
ssl_key = </etc/ssl/private/dovecot.pem
ssl_dh_parameters_length = 4096
ssl_protocols = !SSLv3 !SSLv2
ssl_cipher_list = AES128+EECDH:AES128+EDH
ssl_prefer_server_ciphers = yes


enable imaps on port 993 in 10-master.conf
  inet_listener imaps {
    port = 993
    ssl = yes
  }


dovecot sync between mailboxes using a ssh key on primary to connect to remote.
for one user or all. https://wiki2.dovecot.org/Tools/Doveadm/Sync
create an non-password protected ssh key. the command below usually needs to be run twice.
add a cronjob to do this hourly or so
-------------------------
touch ~/.ssh/id_ecdsa
chmod 400 ~/.ssh/id_ecdsa
doveadm sync -u admin ssh -i ~/.ssh/id_ecdsa -p 3200 admin@93.171.216.20 doveadm dsync-server -u admin

on the remote host, add the pub key to the authorized keys

running it for all users did not work
doveadm sync -A ssh -i .ssh/id_ecdsa -p 3200 admin@93.171.216.20 doveadm dsync-server -A

to make a backup, just copy the mbox file. use -C to remove the folder crap and just keep the files.
doas tar cfz ~/admin-mbox.tar.gz -C /var/mail/admin

#enabling settings for openbsd dovecot example config
#passdb {
#  driver = passwd-file
#  args = scheme=blf-crypt username_format=%n /etc/mail/passwd
#}
#
#userdb {
#  driver = static
#  args = uid=vmail gid=vmail home=/var/mail/%d/%n
#  default_fields = uid=vmail gid=vmail home=/home/vmail/%u
#}

#this needs to be tested more!!
#encryped passwd file to be used with dovecot / smtpd:
cat /etc/mail/passwd
admin:$2b$09$TrDCLLPGI7kO4.TRJV4anOm2Qg0eGk7LTUcCrJHf5q9ZN9IUcbXcS::::::

#make password hash with:
encrypt -p

on the mail client:
192.168.100.118 143 STARTTLS - username admin, system password
192.168.100.118 25 PASSWORD - username admin, system password

NAGIOS HTTPD - /etc/nagios/nagios.cfg
----------------------------------
----------------------------------
nagios config is symlinked to /var/www/etc/nagios from /etc/nagios

doas pkg_add nagios-chroot nagios-web
doas rcctl enable nagios
doas rcctl enable slowcgi
doas rcctl enable php56_fpm

#check config
nagios -v /var/www/etc/nagios/nagios.cfg

#make a htaccess file for user 'nagiosadmin' (default in nagios config) and make it readable by www
#the user must match whats defined in cgi.cfg to be allowed for the appropriate section, e. g. config or services
#defaults to nagiosadmin

doas htpasswd /var/www/.nagioshtaccess nagiosadmin
doas chown www:www /var/www/.nagioshtaccess
doas chmod 440 /var/www/.nagioshtaccess

in the /etc/httpd.conf:
authenticate with ".nagioshtaccess"
then, rcctl reload httpd


when receiving an error of 'no permissions to view objects', make sure the cgi auth works and the .nagioshtaccess file is correct. below only required
when htaccess is wrong (different user than nagiosadmin..)

vi /etc/nagios/cgi.cfg
use_authentication=0


working httpd config. the last section is to make
the css and images work.

server "nagios.wurstbot.com" {
        listen on $int_if port 80
        listen on $ext_if port 80
        root "/nagios"

        directory {
                index "index.php"
        }

        location "/cgi-bin/nagios/*.cgi" {
                root { "/" }
                fastcgi socket "/run/slowcgi.sock"
        }

        location "*.php*" {
                fastcgi socket ":6060"
        }

        location "/nagios*" {
                root { "/nagios", strip 1 }
        }
}

rcctl start php56_fpm
rcctl start slowcgi
rcctl start nagios


TOR - /etc/tor/torrc
-------------------------

doas pkg_add tor
doas vi /etc/tor/torrc
doas tor-gencert --create-identity-key -i /etc/tor/authority_identity_key
put the password hash in the tor config: HashedControlPassword 16:.....

echo 'doas sysctl kern.maxfiles=20000' >> /etc/sysctl.conf
doas sysctl kern.maxfiles=20000

doas rcctl enable tor
doas rcctl start tor

sample tor config:
######################

SOCKSPort 9050 # Default: Bind to localhost:9050 for local connections.
#SOCKSPort 192.168.0.1:9100 # Bind to this address:port too.

#SOCKSPolicy accept 192.168.0.0/16
#SOCKSPolicy accept6 FC00::/7
#SOCKSPolicy reject *

Log notice syslog
RunAsDaemon 1
DataDirectory /var/tor

#HashedControlPassword 16:...
#CookieAuthentication 1

#HiddenServiceDir /var/tor/hidden_service/
#HiddenServicePort 80 127.0.0.1:80
#HiddenServiceDir /var/tor/other_hidden_service/
#HiddenServicePort 1000 127.0.0.1:1000

## Required: what port to advertise for incoming Tor connections.
ORPort 8443
ORPort 127.0.0.1:8443 NoAdvertise
Address node1.wurstbot.com
RelayBandwidthRate 1024 KBytes  # Throttle traffic to 100KB/s (800Kbps)
RelayBandwidthBurst 2048 KBytes # But allow bursts up to 200KB (1600Kb)
#ContactInfo 0xFFFFFFFF Random Person <nobody AT example dot com>
# not for bridge relays
#DirPort 9001
#DirPortFrontPage /etc/tor/tor-exit-notice.html
#MyFamily $keyid,$keyid,...
User _tor
ExitPolicy reject *:* # no exits allowed



TOR OBFS PROXY
-------------------------
install go and obfs4proxy:

pkg_add go git
go get git.torproject.org/pluggable-transports/obfs4.git/obfs4proxy
cp ~/go/bin/obfs4proxy /usr/local/bin/

enable obfs4proxy in the tor config. set it to listen to static instead of dynamic ports.

ServerTransportPlugin obfs3,obfs4 exec /usr/local/bin/obfs4proxy
ExtORPort auto
ServerTransportListenAddr obfs3 0.0.0.0:8403
ServerTransportListenAddr obfs4 0.0.0.0:8404



ZABBIX SETUP
---------------------------------------------
---------------------------------------------

zabbix4 is active and running on node4
zabbix1 is stopped and disabled, but configured on node1

both zabbix point to the zabbix mysql database on node4
zabbix database is replicated to node5

both zabbix web are running.
only the primary zabbix is running.

zabbix4 web is pointing to primary db on node4 and the primary zabbix
zabbix5 web is pointing to primary db on node4 and the primary zabbix

failover tested:
---------------------------------
stop primary zabbix, start secondary zabbix (primary database active) - PASS
stop primary zabbix, start secondary zabbix (secondary database active) - PASS, make sure db sync is working!
both web interfaces working with secondary zabbix active - PASS

warning:
--------------------
more than one zabbix servers cannot run and point to the same db, this causes issues.


in case of issue with database:
---------------------------------------------
point zabbix server and web to node5 database
eventually promote the replica database to master

in case of issue with zabbix web:
---------------------------------------------
use secondary web interface
if required to make changes, point it to the primary database

in case of issue with zabbix server:
---------------------------------------------
start and enable the secondary zabbix server
make sure the primary zabbix server is stopped

the agents are configured to accept checks from node1 and node4




ZABBIX
---------------------------
doas pkg_add zabbix-server zabbix-web mariadb-server php-gd php-mysql php-mysqli
doas mysql_install_db
doas rcctl start mysqld
doas mysql_secure_installation
mysql -uroot -p



Enable the mysql extension in the /etc/php-5.6.ini
extension=mysql.so
extension=mysqli.so

.. and these zabbix specific options
max_execution_time 300
memory_limit 128M
post_max_size 16M
upload_max_filesize 2M
max_input_time 300
always_populate_raw_post_data -1

doas rcctl restart php56_fpm

shell> mysql -uroot -p
mysql> create database zabbix character set utf8 collate utf8_bin;
mysql> grant all privileges on zabbix.* to zabbix@127.0.0.1 identified by '<password>';
mysql> grant all privileges on zabbix.* to zabbix@localhost identified by '<password>';

also grant access from the backup host so the zabbix web interface can access the db:
mysql> grant all privileges on zabbix.* to zabbix@45.32.185.50 identified by 'secret';


mysql> quit;

https://sourceforge.net/projects/zabbix/files/ZABBIX%20Latest%20Stable/3.2.3/zabbix-3.2.3.tar.gz/download
scp -i .ssh/id_ecdsa -P 3200 Downloads/zabbix-3.2.3.tar.gz admin@node1.wurstbot.com:
tar xfz zabbix-3.2.3.tar.gz
cd zabbix-3.2.3                                                                                                                        find . -name '*.sql
./database/mysql/data.sql
./database/mysql/images.sql
./database/mysql/schema.sql
mysql -u zabbix -p zabbix < ./database/mysql/schema.sql
mysql -u zabbix -p zabbix < ./database/mysql/images.sql
mysql -u zabbix -p zabbix < ./database/mysql/data.sql

(optional / not required?)
make a _hard_link from the original mysql socket within the chroot
the hard link needs to be deleted and made newly every time the mysqld restarts!

doas rcctl restart mysqld
mkdir /var/www/var/run/mysql
doas rm /var/www/var/run/mysql/mysql.sock
doas ln /var/run/mysql/mysql.sock /var/www/var/run/mysql/mysql.sock

make sure its the right socket with the right timestamp!
(optional / not required?)

touch a log file and pid file and make the zabbix user own it.
doas touch /var/log/zabbix_server.log
doas chown _zabbix:_zabbix /var/log/zabbix_server.log
doas touch /var/run/zabbix_server.pid
doas chown _zabbix:_zabbix /var/run/zabbix_server.pid

lower the cache values to make sure the server has enough memory (in case a message in the log shows up!)
vi /etc/zabbix/zabbix_server.conf

PidFile=/var/run/zabbix_server.pid
LogType=file
LogFile=/var/log/zabbix_server.log
DBHost=localhost
DBName=zabbix
DBUser=zabbix
DBPassword=<password>
#DBSocket=/var/run/mysql/mysql.sock
DBPort=3306

lower the options of cache usage to a quarter of what the default is (small env)

raise the shmax
sysctl kern.shminfo.shmmax=134217728

i raised these
kern.shminfo.shmall: 32768 -> 524288
kern.shminfo.shmmni: 10 -> 240
kern.shminfo.shmmns: 60 -> 4096

doas sysctl kern.shminfo.shmall=524288
doas sysctl kern.shminfo.shmmni=240
doas sysctl kern.shminfo.shmmns=4096

doas touch /var/log/zabbix_server.log
doas chown _zabbix:_zabbix /var/log/zabbix_server.log
doas rcctl start zabbix_server
doas rcctl enable zabbix_server

Unlock an account:

update zabbix.users set attempt_failed=0 where alias='Admin';




ZABBIX WEB
---------------------
pkg_add zabbix-web

Copy php extension config to chrooted dir
doas mkdir -p /var/www/etc/php-5.6
doas cp /etc/php-5.6.sample/* /var/www/etc/php-5.6/

extension=gd.so
extension=mysql.so
extension=mysqli.so
extension=pspell.so
extension=mcrypt.so
extension=suhosin.so
extension=zip.so
extension=zabbix.so

Configure the web interface:
/var/www/zabbix/conf/zabbix.conf.php

If required, nagivate to the zabbix installer http://hostname/install.php

Login with Admin:password (default)

ZABBIX AGENT
------------------------------------

doas pkg_add zabbix-agent
doas vi /etc/zabbix/zabbix_agentd.conf

PidFile=/var/run/zabbix_agent.pid
LogType=file
LogFile=/var/log/zabbix_agent.log
LogFileSize=10
EnableRemoteCommands=1
LogRemoteCommands=1
Server=93.170.104.52
ServerActive=93.170.104.52
ListenPort=10050
Hostname=node1.wurstbot.com
ListenIP=0.0.0.0


Make a pid and log file

doas touch /var/run/zabbix_agent.pid
doas touch /var/log/zabbix_agent.log
doas chown _zabbix:_zabbix /var/run/zabbix_agent.pid
doas chown _zabbix:_zabbix /var/log/zabbix_agent.log
doas rcctl restart zabbix_agentd
doas tail -f /var/log/zabbix_agent.log
netstat -na | grep 10050

on issues, just start in foreground and check:
doas zabbix_agentd

open firewall (10050: agent, 10051: server..  and add the host on the zabbix server

ZABBIX CUSTOM CHECKS
--------------------------------
doas mkdir /etc/zabbix/externalscripts
doas chgrp _zabbix /etc/zabbix/externalscripts

In /etc/zabbix_server.conf:

ExternalScripts=/etc/zabbix/externalscripts


ZABBIX CUSTOM PARAMETERS
---------------------------------------
For example to use the MySQL template, include in the zabbix_agentd.conf a new file:

Include=/etc/zabbix/userparameter_mysql.conf


doas vi /etc/zabbix/userparameter_mysql.conf
doas chgrp _zabbix /etc/zabbix/userparameter_mysql.conf

UserParameter=mysql.status[*],echo "show global status where Variable_name='$1';" | HOME=/var/lib/mysql/DBNAME mysql -N | awk '{print $$2}'
UserParameter=mysql.version,mysql -V
UserParameter=mysql.ping,mysqladmin -u zabbix --password=secret ping | grep alive | wc -l | tr -d " "
UserParameter=mysql.uptime,mysqladmin -u zabbix --password=secret status | cut -f2 -d ":" | cut -f1 -d "T" | tr -d " "
UserParameter=mysql.threads,mysqladmin -u zabbix --password=secret status | cut -f3 -d ":" | cut -f1 -d "Q" | tr -d " "
UserParameter=mysql.questions,mysqladmin -u zabbix --password=secret status | cut -f4 -d ":"|cut -f1 -d "S" | tr -d " "
UserParameter=mysql.slowqueries,mysqladmin -u zabbix --password=secret status | cut -f5 -d ":" | cut -f1 -d "O" | tr -d " "
UserParameter=mysql.qps,mysqladmin -u zabbix --password=secret status | cut -f9 -d ":" | tr -d " "

doas rcctl restart zabbix_agentd

also, requires in /etc/my.cnf to specify username and password
(reason not clear)

[client]
user            = zabbix
password        = secret
port            = 3306

doas rcctl restart mysqld


Download and verify a file
--------------------------------------
ftp -C -S do https://file.zip
ftp -C -S do https://file.sha1sum
filesum='sha1sum file.zip'
validsum='cat file.sha1sum | tr -s ' ''
test $filesum -eq $validsum && echo 'valid' || echo 'invalid'
tar xfz filename -C /var/www/html


ROUNDCUBE
=======================================
vi /etc/php-5.6/suhosin.ini
suhosin.session.encrypt = off

mysql -u root -p
create database roundcubemail;
GRANT ALL PRIVILEGES ON roundcubemail.* TO roundcubemail@127.0.0.1 IDENTIFIED BY '***';
flush privileges;

cd /var/www/roundcubemail
doas vi config/config.inc.php
mysql -u roundcubemail -p roundcubemail < SQL/mysql.initial.sql

doas cp config/conf.inc.php.sample config/conf.inc.php
$config['enable_installer'] = true;


$config['db_dsnw'] = 'mysql://roundcubemail:***@127.0.0.1/roundcubemail';
$config['default_host'] = 'mail2.wurstbot.com';
$config['smtp_server'] = 'mail2.wurstbot.com';

webmail.wurstbot.com/installer

make a new httpd section:

server "webmail1.wurstbot.com" {
        root "/roundcubemail"

        listen on lo port 80
        listen on egress port 80

        #listen on lo tls port 443
        #listen on egress tls port 443
        #tls certificate "/etc/ssl/node1.wurstbot.com.crt"
        #tls key "/etc/ssl/private/node1.wurstbot.com.key"
        #tls ocsp "/etc/ssl/node4.wurstbot.com.der"

        directory {
                index "index.php"
        }

        location "*.php*" {
                fastcgi socket ":6060"
        }

        location "/roundcubemail*" {
                root { "/roundcubemail", strip 1 }
        }

        location "/.well-known/acme-challenge/*" {
                root "/acme"
                root strip 2
        }
}



SQUIRRELMAIL
=======================================

doas pkg_add php
doas rcctl enable php56_fpm
doas rcctl start php56_fpm

download squirrelmail-1.4.22.tar.gz
tar xfz squirrelmail-1.4.22.tar.gz
doas mv squirrelmail /var/www


cd /var/www/squirremail
doas mkdir data temp attach
chown -R root:wheel .
chown -R root:www data temp attach
doas chmod 0775 data/ temp/ attach/
doas chmod 0660 data/* temp/* attach/*

./configure

edit the config by hand to point the data and attach directory like this.
otherwise, the application tries to point to some weird place:

$data_dir                 = SM_PATH . 'data/';
$attachment_dir           = SM_PATH . 'attach/';

Setup the server settings to point to your IMAP and SMTP
I did not figure out how to use TLS, even when specifying the correct ports and enable TLS..

./configure

in the /etc/httpd.conf

server "webmail.wurstbot.com" {
        listen on lo port 80
        listen on egress port 80
        root "/webmail"

        directory {
                index "index.php"
        }

        location "*.php*" {
                fastcgi socket "/run/php-fpm.sock"
        }

        location "/webmail*" {
                root { "/webmail", strip 1 }
        }

}

doas rcctl reload httpd


see if all is good
http://webmail.wurstbot.com/src/configtest.php




ftp https://letsencrypt.org/certs/isrgrootx1.pem
ftp https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem

ssl_ca = </etc/ssl/ca.pem


INSECURE: when logging into remote server that does not allow SSL:
---------------------------------------------------------
vi /etc/dovecot/conf.d/10-ssl.conf
replace ssl = required to ssl = yes

and allow plaintext authentication explicitly.
a secure connection (even without ssl) is assumed when the imap server is belonging to the local server
vi /etc/dovecot/conf.d/10-ssl.conf
disable_plaintext_auth = yes




SQUID
---------------------------------


pkg_add squid

set the correct access file path
---------------------------------
access_log daemon:/var/log/access.log squid
cache_log daemon:/var/log/cache.log squid

acl localnet src 10.0.0.0/8     # RFC1918 possible internal network
acl localnet src 172.16.0.0/12  # RFC1918 possible internal network
acl localnet src 192.168.0.0/16 # RFC1918 possible internal network

acl home src 212.187.3.44
acl work src 84.207.225.37

acl SSL_ports port 443

http_access allow localnet
http_access allow localhost
http_access allow home
http_access allow work
http_access deny all

cache_mem 1024 MB
minimum_object_size 10 KB
maximum_object_size 10 MB



create log files:

doas mkdir /var/log/squid
doas touch /var/log/squid/access.log /var/log/squid/cache.log
doas chown _squid:_squid /var/log/squid/*.log


admin information:

doas squidclient mgr:info






SQUID LOG VIEWING
------------------------------------------

squidview
-------------------------------------
command line, but has good simple interface with options
http://www.rillion.net/squidview/
./configure ; make ; doas make install

config file located in ~/.squidview, not required
press m to toggle monitor mode and live log view (3 secs updated)
use h to to get to help.
the search can use negation and combine words: !doubleclick.net sex
create csv (text) reports of a user or multiple. very flexible with options.
create alias file to map IPs to user

screensquid
-----------------------------
promising, but requires mysql. did not try

calamaris
-----------------------------
does not run due to @hashTable bug. checking the web, this is due to legacy perl being used.
failed to continue.

squidanalyzer
-----------------------------
tar xfz squidanalyzer
doas mkdir /var/www/squidanalyzer
perl Makefile.PL INSTALLDIRS=site
make ; doas make install
failed to continue.

calamris
----------------------
pkg_add calamaris
cat /var/log/squid/access.log | calamaris -a -o daily.`date +"%w"` > /dev/null

lightsquid
----------------------
doas pkg_add lightsquid
doas perl -MCPAN -e shell
install CGI
install GD

cd /var/www/htdocs/lightsquid


cd /var/www/htdocs/lightsquid/lightsquid.conf
$logpath             ="/var/log/squid";

doas ./check-setup.pl
doas ./lightparser.pl

in /etc/httpd.conf

server "lightsquid.wurstbot.com" {
        listen on lo port 80
        listen on egress port 80
        root "/htdocs/lightsquid"

        directory {
                index "index.cgi"
        }

        location "*.cgi" {
                root { "/" }
                fastcgi socket "/run/slowcgi.sock"
        }

        location "/.well-known/acme-challenge/*" {
                root "/acme"
                root strip 2
        }

}




specific roles:
general: http://eradman.com/posts/run-your-own-server.html
pf - https://www.openbsd.org/faq/pf/
- have carp enabled for internal interface
- pf quality of service for certain service groups - https://calomel.org/pf_hfsc.html
openipsec / openiked - http://puffysecurity.com/wiki/openikedoffshore.html
nsd and unbound
- https://wiki.archlinux.org/index.php/Nsd
- https://www.vultr.com/docs/running-nsd-and-unbound-on-openbsd-5-6
- https://calomel.org/unbound_dns.html
- https://calomel.org/nsd_dns.html
dhcpd - https://www.pantz.org/software/dhcpd/dhcpdconfigfiles.html
tftp - http://eradman.com/posts/autoinstall-openbsd.html
sftp - https://calomel.org/ .. use with ssh_gatekeeper?
opendnssec
- https://calomel.org/nsd_dns.html
- https://www.opendnssec.org/wp-content/uploads/2009/06/opendnssec-start-guide.pdf
- https://www.grepular.com/Understanding_DNSSEC
ntpd - https://calomel.org/ntpd.html
ldapd - https://www.tumfatig.net/20150718/opensmtpd-dovecot-and-ldapd-on-openbsd-5-7/
- use for dovecot, owncloud, roundcube, dokuwiki logins
relayd - https://calomel.org/relayd.html
httpd - http://man.openbsd.org/httpd.conf
php-fpm - https://github.com/reyk/httpd/wiki/Running-ownCloud-with-httpd-on-OpenBSD


mail server:
- http://technoquarter.blogspot.nl/p/series.html
- https://frozen-geek.net/openbsd-email-server-1/
dovecot
smtpd
dkimproxy
spampd
SpamAssasisin


web server:
roundcube for webmail
owncloud for file exhange and connecting storage. also sharing and synching
dokuwiki markdown documentation and manuals. export files to html for public web server

--------------------------------------------------
networks
--------------------------------------------------
wan1 = external if
dmz1 = 172.16.0.0 .. dmz servers
lan1 = 10.1.1.0 .. internal servers
lan2 = 10.1.2.0 .. clients
lan3 = 10.1.3.0 .. management and monitoring
admins = 10.1.3.100, 10.1.3.101 ..

fw ext: allows traffic from dmz to wan
fw int: allows traffic from lan to dmz
lan: use ns and proxy for internet

--------------------------------------------------
firewall rules
--------------------------------------------------
#internet
from external allow to mail port smtps, imaps
#perform host-named based direction using relayd to reach webmail, cloud, wiki, www etc.
from external allow to lb port http, https

#dmz
from ns allow to anywhere port dns
from lb port http, https allow to web port backend-http, backend-https
from lb port varnish to web port http, https
from mail, web allow to db port mysql

#lan services
from lan1, lan2, lan3 allow to stor port ssh, nfs, bacula
from lan1, lan2, lan3 allow to ns port dns, ntp
from lan1, lan2, lan3 allow to mon port syslog
#only clients net uses dhcp and proxy
from lan2 allow to ns port dhcp
from lan2 allow to lb port squid

#admin and monitoring
from man allow to lan1, lan2, lan3 port ssh
from admins allow to man port ssh
from mon allow to lan1, lan2, lan3 port nagios-nrpe, cacti





DEPLOY
-------------------------
scp -r -i .ssh/id_ecdsa -P 3200 -v Desktop/www.wurstbot.com/ admin@node3.wurstbot.com:


fw-ext (wan1, dmz1 )
--------------------------------------------------
pf
nat
openiked (for tunnels from clients and site-to-site, e. g. secured transfers)


lb (dmz1)
--------------------------------------------------
ssl termination
relayd (reverse proxy -  for proxy and reverse proxy)
varnish (cache)
(squid (proxy) - for caching, if relayd not enough)
redis

mail (dmz1)
--------------------------------------------------
opensmtpd
clamsmtp
spamd
spamassasin
dkimproxy
dovecot
(mail storage)

web (dmz1)
--------------------------------------------------
httpd
php-fpm

owncloud (file access and sharing through nfs, sftp, s3. local filesync)
sabre / baikal (caldav, carddav)
roundcube (webmail)
dokuwiki (docu, markdown backed)
gitea  (version control, config files)
kanboard (projects)

wordpress with buddypress (2nd choice)
mediawiki (2nd choice)
gitlab (2nd choice)

fw-int (dmz1, lan1 )
--------------------------------------------------
nat
pf
carp


ns (dmz1, lan1)
--------------------------------------------------
nsd
unbound
opendnssec
dhcpd
ntpd
ldapd


stor (lan1)
--------------------------------------------------
nfs
opensshd (sftp)
bacula


repo (lan1)
--------------------------------------------------
gitea
ftpd
httpd


sql (lan1)
--------------------------------------------------
mariadb


man (lan3)
--------------------------------------------------
opensshd
ldapd
bacula-client


mon (lan3)
--------------------------------------------------
rsyslogd
cacti
nagios (db on sql)
sms sending with usb modem


clients (lan2)
