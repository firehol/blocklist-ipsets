### Contents

- [About this repo](#about-this-repo)

- [Using these ipsets](#using-these-ipsets)
 - [Which ones to use?](#which-ones-to-use)
   
 - [Using them in FireHOL](#using-them-in-firehol)
    * [Adding the ipsets in your firehol.conf](#adding-the-ipsets-in-your-fireholconf)
    * [Updating the ipsets while the firewall is running](#updating-the-ipsets-while-the-firewall-is-running)
    
 - [Using them using plain iptables commands](#using-them-using-plain-iptables-commands)
    * [Creating the ipsets](#creating-the-ipsets) 
    * [Updating the ipsets while the firewall is running](#updating-the-ipsets-while-the-firewall-is-running)
    
- [Dynamic List of ipsets included](#list-of-ipsets-included)

- [Comparison of ipsets](#comparison-of-ipsets)

---

# About this repo

This repository includes a list of ipsets dynamically updated with
firehol's (https://github.com/ktsaou/firehol) `update-ipsets.sh`
script found [here](https://github.com/ktsaou/firehol/blob/master/contrib/update-ipsets.sh).

This repo is self maintained. It it updated automatically from the script via a cron job.

## Why do we need blocklists?

As time passes and the internet matures in our life, cyber crime is becoming increasingly sophisticated.
Although there many tools (detection of malware, viruses, intrusion detection and prevension systems, etc)
to help us isolate the budguys, there are now a lot more than just such attacks.

What is more interesting is that the fraudsters or attackers in many cases are not going to do a
direct damage to you or your systems. They will use you and your systems to gain something else,
possibly not related or indirectly related to your business. Nowdays the attacks cannot be identified easily. They are
distributed and come to our systems from a vast amount of IPs around the world.

To get an idea, check for example the [XRumer](http://en.wikipedia.org/wiki/XRumer) software. This think mimics human
behaviour to post ads, it creates email accounts, responds to emails it receives, bypasses captchas, it goes gently
to stay unoticed, etc.

To increase our effectiveness we need to complement our security solutions with our 
shared knowledge, our shared experience in this fight.

Hopefully, there are many teams out there that do their best to identify the attacks and pinpoint
the attackers. These teams release blocklists. Blocklists of IPs (for use in firewalls), domains & URLs
(for use in proxies), etc.

What we are interested here is IPs.

Using IP blocklists at the internet side of your firewall is a key component of internet security.
These lists share key knowledge between us, allowing us to learn from each other and effectively
isolate fraudsters and attackers from our services.

I decided to upload these lists to a github repo because:

1. They are freely available on the internet. The intention of their creators is to help internet security.
 Keep in mind though that a few of these lists may have special licences attached. Before using them, please
 check their source site for any information regarding proper use.

2. Github provides (via `git pull`) a unified way of updating all the lists together.
 Pulling this repo regularly on your machines, you will update all the IP lists at once.

3. Github also provides a unified version control. Using it we can have a history of what each list has done,
 which IPs or subnets were added and which were removed.

## DNSBLs

Check also another tool included in FireHOL v3+, called `dnsbl-ipset.sh`.

This tool is capable of creating an ipset based on your traffic by looking up information on DNSBLs and scoring it according to your preferences.

More information [here](https://github.com/ktsaou/firehol/wiki/dnsbl-ipset.sh).


---

# Using these ipsets

Please be very careful what you choose to use and how you use it.
If you blacklist traffic using these lists you may end up blocking
your users, your customers, even yourself (!) from accessing your
services.

1. Goto to the site of each list and read how each list is maintained. You are going to trust these guys for doing their job right.

2. Most sites have either a donation system or commercial lists of higher quality. Try to support them. 

3. I have included the TOR network in these lists (`bm_tor`, `dm_tor`, `et_tor`). The TOR network is not necessarily bad and you should not block it if you want to allow your users be anonymous. I have included it because for certain cases, allowing an anonymity network might be a risky thing (such as eCommerce).

4. Apply any blacklist at the internet side of your firewall. Be very carefull. The `bogons` and `fullbogons` lists contain private, unroutable IPs that should not be routed on the internet. If you apply such a blocklist on your DMZ or LAN side, you will be blocked out of your firewall.

5. Always have a whitelist too, containing the IP addresses or subnets you trust. Try to build the rules in such a way that if an IP is in the whitelist, it should not be blocked by these blocklists.


## Which ones to use

These are the ones I install on all my firewalls:

1. **Abuse.ch** lists `feodo`, `palevo`, `sslbl`, `zeus`
   
   These folks are doing a great job tracking crimeware. Their blocklists are very focused.

2. **DShield.org** list `dshield`

   It contains the top 20 attacking class C (/24) subnets, over the last three days.

3. **Spamhaus.org** lists `spamhaus_drop`, `spamhaus_edrop`
   
   DROP (Don't Route Or Peer) and EDROP are advisory "drop all traffic" lists, consisting of netblocks that are "hijacked" or leased by professional spam or cyber-crime operations (used for dissemination of malware, trojan downloaders, botnet controllers).
   According to Spamhaus.org:

   > When implemented at a network or ISP's 'core routers', DROP and EDROP will help protect the network's users from spamming, scanning, harvesting, DNS-hijacking and DDoS attacks originating on rogue netblocks.
   > 
   > Spamhaus strongly encourages the use of DROP and EDROP by tier-1s and backbones.

4. **Team-Cymru.org** list `bogons` or `fullbogons`

   These are lists of IPs that should not be routed on the internet. None should be using them.
   Be very carefull to apply either of the two on the internet side of your network.

5. **OpenBL.org** lists `openbl*`
   
   The team of OpenBL tracks brute force attacks on their hosts. They suggest to use the default blacklist which has a retension policy of 90 days (`openbl`), but they also provide a list with retension of 1 day (`openbl_1d`).
   Their goal is to report abuse to the responsible provider so that the infection is disabled.

6. **Blocklist.de** list `blocklist_de`
   
   Is a network of users reporting abuse using `fail2ban`.
   Their goal is also to report abuse back, so that the infection is disabled.
   The list includes IPs that were participating in attacks in last 48 hours.

Of course there are more lists included. You can check them and decide if they fit for your needs.


---

## Using them in FireHOL

### Adding the ipsets in your firehol.conf

I use something like this:


```sh
	# our wan interface
	wan="dsl0"
	
	# our whitelist
	ipset4 create whitelist hash:net
	ipset4 add whitelist A.B.C.D/E # A.B.C.D/E is whitelisted
	
	# subnets
	for x in fullbogons dshield spamhaus_drop spamhaus_edrop voipbl
	do
		ipset4 create  ${x} hash:net
		ipset4 addfile ${x} ipsets/${x}.netset
		blacklist4 full inface "${wan}" log "BLACKLIST ${x^^}" ipset:${x} \
			except src ipset:whitelist
	done

	# individual IPs
	for x in zeus feodo palevo shunlist openbl blocklist_de malc0de ciarmy \
		malwaredomainlist snort_ipfilter stop_forum_spam_1h stop_forum_spam_7d \
		bruteforceblocker ri_connect_proxies ri_web_proxies
	do
		ipset4 create  ${x} hash:ip
		ipset4 addfile ${x} ipsets/${x}.ipset
		blacklist4 full inface "${wan}" log "BLACKLIST ${x^^}" ipset:${x} \
			except src ipset:whitelist
	done

	... rest of firehol.conf ...
```

### Updating the ipsets while the firewall is running

Just use the `update-ipsets.sh` script from the firehol distribution.
This script will update each ipset and call firehol to update the ipset while the firewall is running.

Keep in mind that you have to use the `update-ipsets.sh` script before activating the firewall, so that the ipsets exist on disk.

---

## Using them using plain iptables commands

### Creating the ipsets
TODO

### Updating the ipsets while the firewall is running
TODO

---

# List of ipsets included

The following list was automatically generated on Thu May 28 07:10:01 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|177044 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|22523 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|12665 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|3501 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|1348 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|266 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|724 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|14811 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|103 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|2287 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|224 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6406 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD)|ipv4 hash:ip|2403 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|387 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[clean_mx_viruses](#clean_mx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|104 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6405 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|975 subnets, 18056513 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botnet](#et_botnet)|[EmergingThreats.net](http://www.emergingthreats.net/) botnet IPs|ipv4 hash:ip|512 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net](http://www.emergingthreats.net/) compromised hosts (seems to be a derivate of other lists)|ipv4 hash:ip|2338 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6490 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[feodo](#feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|63 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
[fullbogons](#fullbogons)|[Team-Cymru.org](http://www.team-cymru.org) IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user - **excellent list - use it only your internet interface**|ipv4 hash:net|3666 subnets, 670786520 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt)
[geolite2_country](tree/master/geolite2_country)|[MaxMind GeoLite2](http://dev.maxmind.com/geoip/geoip2/geolite2/) databases are free IP geolocation databases comparable to, but less accurate than, MaxMind’s GeoIP2 databases. They include IPs per country, IPs per continent, IPs used by anonymous services (VPNs, Proxies, etc) and Satellite Providers.|ipv4 hash:net|All the world|updated every 7 days  from [this link](http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country-CSV.zip)
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) IPs that have been reported for bad deeds in p2p|ipv4 hash:ip|48134 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=cwworuawihqvocglcoss&fileformat=p2p&archiveformat=gz)
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) hijacked IP-Blocks Hijacked IP space are IP blocks that are being used without permission|ipv4 hash:net|535 subnets, 9177856 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=usrcshglbiilevmyfhse&fileformat=p2p&archiveformat=gz)
[ib_bluetack_level1](#ib_bluetack_level1)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Level 1 (for use in p2p): Companies or organizations who are clearly involved with trying to stop filesharing (e.g. Baytsp, MediaDefender, Mediasentry a.o.). Companies which anti-p2p activity has been seen from. Companies that produce or have a strong financial interest in copyrighted material (e.g. music, movie, software industries a.o.). Government ranges or companies that have a strong financial interest in doing work for governments. Legal industry ranges. IPs or ranges of ISPs from which anti-p2p activity has been observed. Basically this list will block all kinds of internet connections that most people would rather not have during their internet travels.|ipv4 hash:net|236319 subnets, 765065682 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz)
[ib_bluetack_level2](#ib_bluetack_level2)|[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 2 (for use in p2p). General corporate ranges. Ranges used by labs or researchers. Proxies.|ipv4 hash:net|78389 subnets, 348732007 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw&fileformat=p2p&archiveformat=gz)
[ib_bluetack_level3](#ib_bluetack_level3)|[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 3 (for use in p2p). Many portal-type websites. ISP ranges that may be dodgy for some reason. Ranges that belong to an individual, but which have not been determined to be used by a particular company. Ranges for things that are unusual in some way. The L3 list is aka the paranoid list.|ipv4 hash:net|18879 subnets, 139109195 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh&fileformat=p2p&archiveformat=gz)
[ib_bluetack_proxies](#ib_bluetack_proxies)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Open Proxies IPs list (without TOR)|ipv4 hash:ip|673 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=xoebmbyexwuiogmbyprb&fileformat=p2p&archiveformat=gz)
[ib_bluetack_spyware](#ib_bluetack_spyware)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) known malicious SPYWARE and ADWARE IP Address ranges|ipv4 hash:net|3339 subnets, 339461 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=llvtlsjyoyiczbkjsxpf&fileformat=p2p&archiveformat=gz)
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) web server hack and exploit attempts|ipv4 hash:ip|1460 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=ghlzqtqxnzctvvajwwag&fileformat=p2p&archiveformat=gz)
[malc0de](#malc0de)|[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days|ipv4 hash:ip|414 unique IPs|updated every 1 day  from [this link](http://malc0de.com/bl/IP_Blacklist.txt)
[malwaredomainlist](#malwaredomainlist)|[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses|ipv4 hash:ip|1283 unique IPs|updated every 12 hours  from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt)
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|23722 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
[openbl](#openbl)|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|9893 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt.gz)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|357 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_1days.txt.gz)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|4446 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt.gz)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7803 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt.gz)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|995 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt.gz)
[openbl_90d](#openbl_90d)|[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|9893 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt.gz)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
[php_bad](#php_bad)|[projecthoneypot.org](http://www.projecthoneypot.org/) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|281 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|281 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|398 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|257 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|417 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1668 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|4254 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|51 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|7236 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|641 subnets, 18117120 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|55 subnets, 421120 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|341 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
[stop_forum_spam_1h](#stop_forum_spam_1h)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|7646 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stop_forum_spam_30d](#stop_forum_spam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|92800 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
[stop_forum_spam_7d](#stop_forum_spam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|30710 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10286 subnets, 10757 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) default blocklist including hijacked sites and web hosting providers - **excellent list**|ipv4 hash:ip|266 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) includes IPv4 addresses that are used by the ZeuS trojan|ipv4 hash:ip|229 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Thu May 28 04:00:26 UTC 2015.

The ipset `alienvault_reputation` has **177044** entries, **177044** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|14946|0.0%|8.4%|
[openbl_90d](#openbl_90d)|9893|9893|9872|99.7%|5.5%|
[openbl](#openbl)|9893|9893|9872|99.7%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|8400|0.0%|4.7%|
[openbl_60d](#openbl_60d)|7803|7803|7785|99.7%|4.3%|
[et_block](#et_block)|975|18056513|5527|0.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|5207|0.0%|2.9%|
[openbl_30d](#openbl_30d)|4446|4446|4436|99.7%|2.5%|
[dshield](#dshield)|20|5120|3584|70.0%|2.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|1624|0.0%|0.9%|
[blocklist_de](#blocklist_de)|22523|22523|1593|7.0%|0.8%|
[bruteforceblocker](#bruteforceblocker)|2403|2403|1487|61.8%|0.8%|
[et_compromised](#et_compromised)|2338|2338|1463|62.5%|0.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|2287|2287|1355|59.2%|0.7%|
[openbl_7d](#openbl_7d)|995|995|990|99.4%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|519|0.0%|0.2%|
[ciarmy](#ciarmy)|387|387|375|96.8%|0.2%|
[openbl_1d](#openbl_1d)|357|357|355|99.4%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|293|0.0%|0.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|239|0.2%|0.1%|
[voipbl](#voipbl)|10286|10757|196|1.8%|0.1%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|123|1.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12665|12665|117|0.9%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|115|0.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|224|224|83|37.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14811|14811|77|0.5%|0.0%|
[zeus](#zeus)|266|266|67|25.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|724|724|64|8.8%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7646|7646|62|0.8%|0.0%|
[shunlist](#shunlist)|51|51|51|100.0%|0.0%|
[dm_tor](#dm_tor)|6405|6405|45|0.7%|0.0%|
[bm_tor](#bm_tor)|6406|6406|45|0.7%|0.0%|
[et_tor](#et_tor)|6490|6490|44|0.6%|0.0%|
[zeus_badips](#zeus_badips)|229|229|36|15.7%|0.0%|
[nixspam](#nixspam)|23722|23722|34|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3501|3501|27|0.7%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|103|103|18|17.4%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1348|1348|17|1.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|15|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|13|0.0%|0.0%|
[php_commenters](#php_commenters)|281|281|12|4.2%|0.0%|
[php_bad](#php_bad)|281|281|12|4.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|266|266|12|4.5%|0.0%|
[malc0de](#malc0de)|414|414|10|2.4%|0.0%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|8|0.5%|0.0%|
[sslbl](#sslbl)|341|341|7|2.0%|0.0%|
[php_dictionary](#php_dictionary)|398|398|7|1.7%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|6|0.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4254|4254|3|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|3|0.7%|0.0%|
[et_botnet](#et_botnet)|512|512|3|0.5%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|104|104|2|1.9%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1668|1668|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[feodo](#feodo)|63|63|1|1.5%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Thu May 28 06:56:04 UTC 2015.

The ipset `blocklist_de` has **22523** entries, **22523** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|14811|14811|14811|100.0%|65.7%|
[blocklist_de_apache](#blocklist_de_apache)|12665|12665|12665|100.0%|56.2%|
[blocklist_de_bots](#blocklist_de_bots)|3501|3501|3476|99.2%|15.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|2813|0.0%|12.4%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|2364|7.6%|10.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|2287|2287|2286|99.9%|10.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|2190|2.3%|9.7%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|1593|0.8%|7.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|1487|0.0%|6.6%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7646|7646|1484|19.4%|6.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|1442|0.0%|6.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1348|1348|1348|100.0%|5.9%|
[openbl_90d](#openbl_90d)|9893|9893|1342|13.5%|5.9%|
[openbl](#openbl)|9893|9893|1342|13.5%|5.9%|
[openbl_60d](#openbl_60d)|7803|7803|1284|16.4%|5.7%|
[openbl_30d](#openbl_30d)|4446|4446|1187|26.6%|5.2%|
[bruteforceblocker](#bruteforceblocker)|2403|2403|1138|47.3%|5.0%|
[et_compromised](#et_compromised)|2338|2338|1053|45.0%|4.6%|
[blocklist_de_imap](#blocklist_de_imap)|724|724|717|99.0%|3.1%|
[openbl_7d](#openbl_7d)|995|995|676|67.9%|3.0%|
[nixspam](#nixspam)|23722|23722|584|2.4%|2.5%|
[ri_web_proxies](#ri_web_proxies)|4254|4254|386|9.0%|1.7%|
[blocklist_de_ftp](#blocklist_de_ftp)|266|266|262|98.4%|1.1%|
[openbl_1d](#openbl_1d)|357|357|248|69.4%|1.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|224|224|224|100.0%|0.9%|
[et_block](#et_block)|975|18056513|191|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|184|0.0%|0.8%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|156|2.1%|0.6%|
[dshield](#dshield)|20|5120|142|2.7%|0.6%|
[blocklist_de_sip](#blocklist_de_sip)|103|103|84|81.5%|0.3%|
[php_commenters](#php_commenters)|281|281|82|29.1%|0.3%|
[ri_connect_proxies](#ri_connect_proxies)|1668|1668|81|4.8%|0.3%|
[php_bad](#php_bad)|281|281|81|28.8%|0.3%|
[php_dictionary](#php_dictionary)|398|398|71|17.8%|0.3%|
[php_spammers](#php_spammers)|417|417|64|15.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|60|0.0%|0.2%|
[voipbl](#voipbl)|10286|10757|37|0.3%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|37|0.0%|0.1%|
[ciarmy](#ciarmy)|387|387|33|8.5%|0.1%|
[php_harvesters](#php_harvesters)|257|257|30|11.6%|0.1%|
[et_tor](#et_tor)|6490|6490|27|0.4%|0.1%|
[dm_tor](#dm_tor)|6405|6405|25|0.3%|0.1%|
[bm_tor](#bm_tor)|6406|6406|25|0.3%|0.1%|
[shunlist](#shunlist)|51|51|10|19.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|7|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|3|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|104|104|1|0.9%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Thu May 28 06:56:07 UTC 2015.

The ipset `blocklist_de_apache` has **12665** entries, **12665** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22523|22523|12665|56.2%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|14811|14811|11059|74.6%|87.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|2220|0.0%|17.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1348|1348|1348|100.0%|10.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|1321|0.0%|10.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|1075|0.0%|8.4%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|199|0.2%|1.5%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|128|0.4%|1.0%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|117|0.0%|0.9%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7646|7646|86|1.1%|0.6%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|43|0.5%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|224|224|37|16.5%|0.2%|
[et_tor](#et_tor)|6490|6490|27|0.4%|0.2%|
[ciarmy](#ciarmy)|387|387|27|6.9%|0.2%|
[dm_tor](#dm_tor)|6405|6405|25|0.3%|0.1%|
[bm_tor](#bm_tor)|6406|6406|25|0.3%|0.1%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.1%|
[php_bad](#php_bad)|281|281|24|8.5%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3501|3501|20|0.5%|0.1%|
[openbl_90d](#openbl_90d)|9893|9893|15|0.1%|0.1%|
[openbl](#openbl)|9893|9893|15|0.1%|0.1%|
[openbl_60d](#openbl_60d)|7803|7803|10|0.1%|0.0%|
[et_block](#et_block)|975|18056513|8|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4446|4446|7|0.1%|0.0%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.0%|
[nixspam](#nixspam)|23722|23722|5|0.0%|0.0%|
[openbl_7d](#openbl_7d)|995|995|4|0.4%|0.0%|
[dshield](#dshield)|20|5120|4|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|3|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_compromised](#et_compromised)|2338|2338|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2403|2403|3|0.1%|0.0%|
[voipbl](#voipbl)|10286|10757|2|0.0%|0.0%|
[shunlist](#shunlist)|51|51|2|3.9%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|104|104|1|0.9%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Thu May 28 06:42:09 UTC 2015.

The ipset `blocklist_de_bots` has **3501** entries, **3501** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22523|22523|3476|15.4%|99.2%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|2212|7.2%|63.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|1938|2.0%|55.3%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7646|7646|1404|18.3%|40.1%|
[ri_web_proxies](#ri_web_proxies)|4254|4254|357|8.3%|10.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|150|0.0%|4.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|224|224|124|55.3%|3.5%|
[ri_connect_proxies](#ri_connect_proxies)|1668|1668|81|4.8%|2.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|80|0.0%|2.2%|
[php_commenters](#php_commenters)|281|281|67|23.8%|1.9%|
[php_bad](#php_bad)|281|281|67|23.8%|1.9%|
[nixspam](#nixspam)|23722|23722|47|0.1%|1.3%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|43|0.0%|1.2%|
[et_block](#et_block)|975|18056513|42|0.0%|1.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|40|0.0%|1.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|38|0.0%|1.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|30|0.0%|0.8%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|27|0.0%|0.7%|
[php_harvesters](#php_harvesters)|257|257|24|9.3%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|14811|14811|20|0.1%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|12665|12665|20|0.1%|0.5%|
[php_spammers](#php_spammers)|417|417|17|4.0%|0.4%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|15|0.2%|0.4%|
[php_dictionary](#php_dictionary)|398|398|10|2.5%|0.2%|
[openbl_90d](#openbl_90d)|9893|9893|3|0.0%|0.0%|
[openbl](#openbl)|9893|9893|3|0.0%|0.0%|
[voipbl](#voipbl)|10286|10757|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2338|2338|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2403|2403|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Thu May 28 06:56:11 UTC 2015.

The ipset `blocklist_de_bruteforce` has **1348** entries, **1348** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_apache](#blocklist_de_apache)|12665|12665|1348|10.6%|100.0%|
[blocklist_de](#blocklist_de)|22523|22523|1348|5.9%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|126|0.0%|9.3%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|68|0.2%|5.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|65|0.0%|4.8%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7646|7646|51|0.6%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|43|0.0%|3.1%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|40|0.5%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|28|0.0%|2.0%|
[et_tor](#et_tor)|6490|6490|24|0.3%|1.7%|
[dm_tor](#dm_tor)|6405|6405|23|0.3%|1.7%|
[bm_tor](#bm_tor)|6406|6406|23|0.3%|1.7%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|17|0.0%|1.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|224|224|12|5.3%|0.8%|
[openbl_90d](#openbl_90d)|9893|9893|6|0.0%|0.4%|
[openbl](#openbl)|9893|9893|6|0.0%|0.4%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.3%|
[nixspam](#nixspam)|23722|23722|5|0.0%|0.3%|
[php_commenters](#php_commenters)|281|281|4|1.4%|0.2%|
[php_bad](#php_bad)|281|281|4|1.4%|0.2%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|3|0.0%|0.2%|
[openbl_60d](#openbl_60d)|7803|7803|3|0.0%|0.2%|
[et_block](#et_block)|975|18056513|3|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.1%|
[voipbl](#voipbl)|10286|10757|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4446|4446|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2338|2338|1|0.0%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|104|104|1|0.9%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2403|2403|1|0.0%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Thu May 28 06:42:07 UTC 2015.

The ipset `blocklist_de_ftp` has **266** entries, **266** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22523|22523|262|1.1%|98.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|26|0.0%|9.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|17|0.0%|6.3%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|12|0.0%|4.5%|
[openbl_90d](#openbl_90d)|9893|9893|7|0.0%|2.6%|
[openbl](#openbl)|9893|9893|7|0.0%|2.6%|
[openbl_60d](#openbl_60d)|7803|7803|5|0.0%|1.8%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|4|0.0%|1.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|3|0.0%|1.1%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|2|0.0%|0.7%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.7%|
[openbl_30d](#openbl_30d)|4446|4446|2|0.0%|0.7%|
[nixspam](#nixspam)|23722|23722|2|0.0%|0.7%|
[ciarmy](#ciarmy)|387|387|2|0.5%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|224|224|2|0.8%|0.7%|
[openbl_7d](#openbl_7d)|995|995|1|0.1%|0.3%|
[openbl_1d](#openbl_1d)|357|357|1|0.2%|0.3%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Thu May 28 06:42:06 UTC 2015.

The ipset `blocklist_de_imap` has **724** entries, **724** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|14811|14811|717|4.8%|99.0%|
[blocklist_de](#blocklist_de)|22523|22523|717|3.1%|99.0%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|64|0.0%|8.8%|
[openbl_90d](#openbl_90d)|9893|9893|47|0.4%|6.4%|
[openbl](#openbl)|9893|9893|47|0.4%|6.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|44|0.0%|6.0%|
[openbl_60d](#openbl_60d)|7803|7803|43|0.5%|5.9%|
[openbl_30d](#openbl_30d)|4446|4446|39|0.8%|5.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|36|0.0%|4.9%|
[openbl_7d](#openbl_7d)|995|995|24|2.4%|3.3%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|14|0.0%|1.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|14|0.0%|1.9%|
[et_block](#et_block)|975|18056513|14|0.0%|1.9%|
[et_compromised](#et_compromised)|2338|2338|11|0.4%|1.5%|
[bruteforceblocker](#bruteforceblocker)|2403|2403|11|0.4%|1.5%|
[openbl_1d](#openbl_1d)|357|357|6|1.6%|0.8%|
[nixspam](#nixspam)|23722|23722|5|0.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.4%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|2|0.0%|0.2%|
[shunlist](#shunlist)|51|51|2|3.9%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|224|224|2|0.8%|0.2%|
[ciarmy](#ciarmy)|387|387|1|0.2%|0.1%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Thu May 28 06:56:06 UTC 2015.

The ipset `blocklist_de_mail` has **14811** entries, **14811** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22523|22523|14811|65.7%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|12665|12665|11059|87.3%|74.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|2245|0.0%|15.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|1352|0.0%|9.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|1161|0.0%|7.8%|
[blocklist_de_imap](#blocklist_de_imap)|724|724|717|99.0%|4.8%|
[nixspam](#nixspam)|23722|23722|529|2.2%|3.5%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|182|0.1%|1.2%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|98|1.3%|0.6%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|89|0.2%|0.6%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|77|0.0%|0.5%|
[php_dictionary](#php_dictionary)|398|398|62|15.5%|0.4%|
[openbl_90d](#openbl_90d)|9893|9893|55|0.5%|0.3%|
[openbl](#openbl)|9893|9893|55|0.5%|0.3%|
[openbl_60d](#openbl_60d)|7803|7803|51|0.6%|0.3%|
[openbl_30d](#openbl_30d)|4446|4446|45|1.0%|0.3%|
[php_spammers](#php_spammers)|417|417|42|10.0%|0.2%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7646|7646|33|0.4%|0.2%|
[ri_web_proxies](#ri_web_proxies)|4254|4254|27|0.6%|0.1%|
[openbl_7d](#openbl_7d)|995|995|25|2.5%|0.1%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|22|0.0%|0.1%|
[php_commenters](#php_commenters)|281|281|21|7.4%|0.1%|
[php_bad](#php_bad)|281|281|20|7.1%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3501|3501|20|0.5%|0.1%|
[et_block](#et_block)|975|18056513|19|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|224|224|19|8.4%|0.1%|
[et_compromised](#et_compromised)|2338|2338|17|0.7%|0.1%|
[bruteforceblocker](#bruteforceblocker)|2403|2403|17|0.7%|0.1%|
[openbl_1d](#openbl_1d)|357|357|7|1.9%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|5|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|4|1.5%|0.0%|
[et_tor](#et_tor)|6490|6490|3|0.0%|0.0%|
[shunlist](#shunlist)|51|51|2|3.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|2|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6405|6405|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6406|6406|2|0.0%|0.0%|
[voipbl](#voipbl)|10286|10757|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1668|1668|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|387|387|1|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2287|2287|1|0.0%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Thu May 28 06:56:08 UTC 2015.

The ipset `blocklist_de_sip` has **103** entries, **103** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22523|22523|84|0.3%|81.5%|
[voipbl](#voipbl)|10286|10757|29|0.2%|28.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|22|0.0%|21.3%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|18|0.0%|17.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|8|0.0%|7.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|4|0.0%|3.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|2|0.0%|1.9%|
[et_botnet](#et_botnet)|512|512|1|0.1%|0.9%|
[ciarmy](#ciarmy)|387|387|1|0.2%|0.9%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Thu May 28 06:42:03 UTC 2015.

The ipset `blocklist_de_ssh` has **2287** entries, **2287** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22523|22523|2286|10.1%|99.9%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|1355|0.7%|59.2%|
[openbl_90d](#openbl_90d)|9893|9893|1263|12.7%|55.2%|
[openbl](#openbl)|9893|9893|1263|12.7%|55.2%|
[openbl_60d](#openbl_60d)|7803|7803|1218|15.6%|53.2%|
[openbl_30d](#openbl_30d)|4446|4446|1133|25.4%|49.5%|
[bruteforceblocker](#bruteforceblocker)|2403|2403|1118|46.5%|48.8%|
[et_compromised](#et_compromised)|2338|2338|1033|44.1%|45.1%|
[openbl_7d](#openbl_7d)|995|995|646|64.9%|28.2%|
[openbl_1d](#openbl_1d)|357|357|239|66.9%|10.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|225|0.0%|9.8%|
[dshield](#dshield)|20|5120|137|2.6%|5.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|127|0.0%|5.5%|
[et_block](#et_block)|975|18056513|122|0.0%|5.3%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|116|0.0%|5.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|224|224|75|33.4%|3.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|51|0.0%|2.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|12|0.0%|0.5%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|7|0.0%|0.3%|
[shunlist](#shunlist)|51|51|6|11.7%|0.2%|
[voipbl](#voipbl)|10286|10757|3|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|3|0.0%|0.1%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|2|0.0%|0.0%|
[ciarmy](#ciarmy)|387|387|2|0.5%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7646|7646|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4254|4254|1|0.0%|0.0%|
[nixspam](#nixspam)|23722|23722|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14811|14811|1|0.0%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Thu May 28 06:42:11 UTC 2015.

The ipset `blocklist_de_strongips` has **224** entries, **224** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22523|22523|224|0.9%|100.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|125|0.1%|55.8%|
[blocklist_de_bots](#blocklist_de_bots)|3501|3501|124|3.5%|55.3%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|117|0.3%|52.2%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7646|7646|101|1.3%|45.0%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|83|0.0%|37.0%|
[openbl_90d](#openbl_90d)|9893|9893|76|0.7%|33.9%|
[openbl](#openbl)|9893|9893|76|0.7%|33.9%|
[openbl_60d](#openbl_60d)|7803|7803|75|0.9%|33.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|2287|2287|75|3.2%|33.4%|
[openbl_7d](#openbl_7d)|995|995|74|7.4%|33.0%|
[openbl_30d](#openbl_30d)|4446|4446|74|1.6%|33.0%|
[openbl_1d](#openbl_1d)|357|357|68|19.0%|30.3%|
[blocklist_de_apache](#blocklist_de_apache)|12665|12665|37|0.2%|16.5%|
[php_commenters](#php_commenters)|281|281|35|12.4%|15.6%|
[php_bad](#php_bad)|281|281|35|12.4%|15.6%|
[et_compromised](#et_compromised)|2338|2338|26|1.1%|11.6%|
[bruteforceblocker](#bruteforceblocker)|2403|2403|23|0.9%|10.2%|
[dshield](#dshield)|20|5120|19|0.3%|8.4%|
[blocklist_de_mail](#blocklist_de_mail)|14811|14811|19|0.1%|8.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|17|0.0%|7.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1348|1348|12|0.8%|5.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|8|0.0%|3.5%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|7|0.0%|3.1%|
[et_block](#et_block)|975|18056513|7|0.0%|3.1%|
[php_spammers](#php_spammers)|417|417|5|1.1%|2.2%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|4|0.0%|1.7%|
[ri_web_proxies](#ri_web_proxies)|4254|4254|3|0.0%|1.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.3%|
[blocklist_de_imap](#blocklist_de_imap)|724|724|2|0.2%|0.8%|
[blocklist_de_ftp](#blocklist_de_ftp)|266|266|2|0.7%|0.8%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|1|0.0%|0.4%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.4%|
[php_dictionary](#php_dictionary)|398|398|1|0.2%|0.4%|
[nixspam](#nixspam)|23722|23722|1|0.0%|0.4%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.4%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Thu May 28 07:00:11 UTC 2015.

The ipset `bm_tor` has **6406** entries, **6406** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[dm_tor](#dm_tor)|6405|6405|6405|100.0%|99.9%|
[et_tor](#et_tor)|6490|6490|5769|88.8%|90.0%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|1036|14.3%|16.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|610|0.0%|9.5%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|570|0.6%|8.8%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|435|1.4%|6.7%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7646|7646|272|3.5%|4.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|184|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|167|0.0%|2.6%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|45|0.0%|0.7%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[php_bad](#php_bad)|281|281|29|10.3%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|12665|12665|25|0.1%|0.3%|
[blocklist_de](#blocklist_de)|22523|22523|25|0.1%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1348|1348|23|1.7%|0.3%|
[openbl_90d](#openbl_90d)|9893|9893|21|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7803|7803|21|0.2%|0.3%|
[openbl](#openbl)|9893|9893|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|21|0.0%|0.3%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4254|4254|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|398|398|4|1.0%|0.0%|
[nixspam](#nixspam)|23722|23722|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|975|18056513|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1668|1668|2|0.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14811|14811|2|0.0%|0.0%|
[voipbl](#voipbl)|10286|10757|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## bogons

[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**

Source is downloaded from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt).

The last time downloaded was found to be dated: Thu Feb 19 00:18:26 UTC 2015.

The ipset `bogons` has **13** entries, **592708608** unique IPs.

The following table shows the overlaps of `bogons` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bogons`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bogons`.
- ` this % ` is the percentage **of this ipset (`bogons`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[fullbogons](#fullbogons)|3666|670786520|592708608|88.3%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|4194304|3.0%|0.7%|
[voipbl](#voipbl)|10286|10757|351|3.2%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|5|0.0%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2403|2403|1|0.0%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD)

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Thu May 28 04:00:29 UTC 2015.

The ipset `bruteforceblocker` has **2403** entries, **2403** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_compromised](#et_compromised)|2338|2338|2298|98.2%|95.6%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|1487|0.8%|61.8%|
[openbl_90d](#openbl_90d)|9893|9893|1412|14.2%|58.7%|
[openbl](#openbl)|9893|9893|1412|14.2%|58.7%|
[openbl_60d](#openbl_60d)|7803|7803|1396|17.8%|58.0%|
[openbl_30d](#openbl_30d)|4446|4446|1339|30.1%|55.7%|
[blocklist_de](#blocklist_de)|22523|22523|1138|5.0%|47.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|2287|2287|1118|48.8%|46.5%|
[openbl_7d](#openbl_7d)|995|995|511|51.3%|21.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|230|0.0%|9.5%|
[openbl_1d](#openbl_1d)|357|357|204|57.1%|8.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|148|0.0%|6.1%|
[et_block](#et_block)|975|18056513|98|0.0%|4.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|97|0.0%|4.0%|
[dshield](#dshield)|20|5120|95|1.8%|3.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|73|0.0%|3.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|224|224|23|10.2%|0.9%|
[blocklist_de_mail](#blocklist_de_mail)|14811|14811|17|0.1%|0.7%|
[blocklist_de_imap](#blocklist_de_imap)|724|724|11|1.5%|0.4%|
[shunlist](#shunlist)|51|51|8|15.6%|0.3%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|6|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12665|12665|3|0.0%|0.1%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[voipbl](#voipbl)|10286|10757|1|0.0%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7646|7646|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3666|670786520|1|0.0%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1348|1348|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3501|3501|1|0.0%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Thu May 28 06:15:06 UTC 2015.

The ipset `ciarmy` has **387** entries, **387** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|177044|177044|375|0.2%|96.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|70|0.0%|18.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|40|0.0%|10.3%|
[blocklist_de](#blocklist_de)|22523|22523|33|0.1%|8.5%|
[blocklist_de_apache](#blocklist_de_apache)|12665|12665|27|0.2%|6.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|21|0.0%|5.4%|
[voipbl](#voipbl)|10286|10757|3|0.0%|0.7%|
[shunlist](#shunlist)|51|51|2|3.9%|0.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|2287|2287|2|0.0%|0.5%|
[blocklist_de_ftp](#blocklist_de_ftp)|266|266|2|0.7%|0.5%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|1|0.0%|0.2%|
[openbl_90d](#openbl_90d)|9893|9893|1|0.0%|0.2%|
[openbl_7d](#openbl_7d)|995|995|1|0.1%|0.2%|
[openbl_60d](#openbl_60d)|7803|7803|1|0.0%|0.2%|
[openbl_30d](#openbl_30d)|4446|4446|1|0.0%|0.2%|
[openbl](#openbl)|9893|9893|1|0.0%|0.2%|
[et_block](#et_block)|975|18056513|1|0.0%|0.2%|
[dshield](#dshield)|20|5120|1|0.0%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|103|103|1|0.9%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|14811|14811|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|724|724|1|0.1%|0.2%|

## clean_mx_viruses

[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses

Source is downloaded from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive).

The last time downloaded was found to be dated: Thu May 28 04:21:25 UTC 2015.

The ipset `clean_mx_viruses` has **104** entries, **104** unique IPs.

The following table shows the overlaps of `clean_mx_viruses` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `clean_mx_viruses`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `clean_mx_viruses`.
- ` this % ` is the percentage **of this ipset (`clean_mx_viruses`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|13|0.0%|12.5%|
[malc0de](#malc0de)|414|414|11|2.6%|10.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|6|0.0%|5.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|4|0.0%|3.8%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|2|0.0%|1.9%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.9%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1348|1348|1|0.0%|0.9%|
[blocklist_de_apache](#blocklist_de_apache)|12665|12665|1|0.0%|0.9%|
[blocklist_de](#blocklist_de)|22523|22523|1|0.0%|0.9%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Thu May 28 07:00:08 UTC 2015.

The ipset `dm_tor` has **6405** entries, **6405** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6406|6406|6405|99.9%|100.0%|
[et_tor](#et_tor)|6490|6490|5768|88.8%|90.0%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|1036|14.3%|16.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|610|0.0%|9.5%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|570|0.6%|8.8%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|435|1.4%|6.7%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7646|7646|272|3.5%|4.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|184|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|167|0.0%|2.6%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|45|0.0%|0.7%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[php_bad](#php_bad)|281|281|29|10.3%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|12665|12665|25|0.1%|0.3%|
[blocklist_de](#blocklist_de)|22523|22523|25|0.1%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1348|1348|23|1.7%|0.3%|
[openbl_90d](#openbl_90d)|9893|9893|21|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7803|7803|21|0.2%|0.3%|
[openbl](#openbl)|9893|9893|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|21|0.0%|0.3%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4254|4254|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|398|398|4|1.0%|0.0%|
[nixspam](#nixspam)|23722|23722|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|975|18056513|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1668|1668|2|0.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14811|14811|2|0.0%|0.0%|
[voipbl](#voipbl)|10286|10757|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Thu May 28 06:55:56 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|177044|177044|3584|2.0%|70.0%|
[et_block](#et_block)|975|18056513|1024|0.0%|20.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|512|0.0%|10.0%|
[openbl_90d](#openbl_90d)|9893|9893|165|1.6%|3.2%|
[openbl](#openbl)|9893|9893|165|1.6%|3.2%|
[openbl_60d](#openbl_60d)|7803|7803|152|1.9%|2.9%|
[blocklist_de](#blocklist_de)|22523|22523|142|0.6%|2.7%|
[openbl_30d](#openbl_30d)|4446|4446|141|3.1%|2.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|2287|2287|137|5.9%|2.6%|
[openbl_7d](#openbl_7d)|995|995|115|11.5%|2.2%|
[bruteforceblocker](#bruteforceblocker)|2403|2403|95|3.9%|1.8%|
[et_compromised](#et_compromised)|2338|2338|90|3.8%|1.7%|
[openbl_1d](#openbl_1d)|357|357|45|12.6%|0.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|224|224|19|8.4%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|4|0.0%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12665|12665|4|0.0%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|1|0.0%|0.0%|
[nixspam](#nixspam)|23722|23722|1|0.0%|0.0%|
[ciarmy](#ciarmy)|387|387|1|0.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14811|14811|1|0.0%|0.0%|

## et_block

[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)

Source is downloaded from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt).

The last time downloaded was found to be dated: Wed May 27 04:30:01 UTC 2015.

The ipset `et_block` has **975** entries, **18056513** unique IPs.

The following table shows the overlaps of `et_block` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_block`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_block`.
- ` this % ` is the percentage **of this ipset (`et_block`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[spamhaus_drop](#spamhaus_drop)|641|18117120|18051584|99.6%|99.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|8401703|2.4%|46.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7211008|78.5%|39.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|2133031|0.2%|11.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|196440|0.1%|1.0%|
[fullbogons](#fullbogons)|3666|670786520|20480|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|5527|3.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1044|0.3%|0.0%|
[dshield](#dshield)|20|5120|1024|20.0%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|769|0.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|517|0.1%|0.0%|
[openbl_90d](#openbl_90d)|9893|9893|455|4.5%|0.0%|
[openbl](#openbl)|9893|9893|455|4.5%|0.0%|
[openbl_60d](#openbl_60d)|7803|7803|306|3.9%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|286|3.9%|0.0%|
[zeus](#zeus)|266|266|262|98.4%|0.0%|
[zeus_badips](#zeus_badips)|229|229|228|99.5%|0.0%|
[openbl_30d](#openbl_30d)|4446|4446|215|4.8%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|214|0.6%|0.0%|
[nixspam](#nixspam)|23722|23722|195|0.8%|0.0%|
[blocklist_de](#blocklist_de)|22523|22523|191|0.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2287|2287|122|5.3%|0.0%|
[openbl_7d](#openbl_7d)|995|995|99|9.9%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2403|2403|98|4.0%|0.0%|
[et_compromised](#et_compromised)|2338|2338|94|4.0%|0.0%|
[feodo](#feodo)|63|63|61|96.8%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7646|7646|50|0.6%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3501|3501|42|1.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|28|2.1%|0.0%|
[openbl_1d](#openbl_1d)|357|357|27|7.5%|0.0%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.0%|
[php_bad](#php_bad)|281|281|24|8.5%|0.0%|
[sslbl](#sslbl)|341|341|23|6.7%|0.0%|
[voipbl](#voipbl)|10286|10757|20|0.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14811|14811|19|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|724|724|14|1.9%|0.0%|
[palevo](#palevo)|13|13|12|92.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|10|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12665|12665|8|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|224|224|7|3.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[php_dictionary](#php_dictionary)|398|398|3|0.7%|0.0%|
[malc0de](#malc0de)|414|414|3|0.7%|0.0%|
[et_tor](#et_tor)|6490|6490|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6405|6405|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6406|6406|3|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1348|1348|3|0.2%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[et_botnet](#et_botnet)|512|512|1|0.1%|0.0%|
[ciarmy](#ciarmy)|387|387|1|0.2%|0.0%|

## et_botnet

[EmergingThreats.net](http://www.emergingthreats.net/) botnet IPs

Source is downloaded from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules).

The last time downloaded was found to be dated: Wed May 27 04:30:01 UTC 2015.

The ipset `et_botnet` has **512** entries, **512** unique IPs.

The following table shows the overlaps of `et_botnet` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_botnet`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_botnet`.
- ` this % ` is the percentage **of this ipset (`et_botnet`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|75|0.0%|14.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|43|0.0%|8.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|21|0.0%|4.1%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|3|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[et_block](#et_block)|975|18056513|1|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|103|103|1|0.9%|0.1%|

## et_compromised

[EmergingThreats.net](http://www.emergingthreats.net/) compromised hosts (seems to be a derivate of other lists)

Source is downloaded from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt).

The last time downloaded was found to be dated: Wed May 27 04:30:08 UTC 2015.

The ipset `et_compromised` has **2338** entries, **2338** unique IPs.

The following table shows the overlaps of `et_compromised` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_compromised`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_compromised`.
- ` this % ` is the percentage **of this ipset (`et_compromised`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bruteforceblocker](#bruteforceblocker)|2403|2403|2298|95.6%|98.2%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|1463|0.8%|62.5%|
[openbl_90d](#openbl_90d)|9893|9893|1388|14.0%|59.3%|
[openbl](#openbl)|9893|9893|1388|14.0%|59.3%|
[openbl_60d](#openbl_60d)|7803|7803|1377|17.6%|58.8%|
[openbl_30d](#openbl_30d)|4446|4446|1321|29.7%|56.5%|
[blocklist_de](#blocklist_de)|22523|22523|1053|4.6%|45.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2287|2287|1033|45.1%|44.1%|
[openbl_7d](#openbl_7d)|995|995|499|50.1%|21.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|225|0.0%|9.6%|
[openbl_1d](#openbl_1d)|357|357|207|57.9%|8.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|143|0.0%|6.1%|
[et_block](#et_block)|975|18056513|94|0.0%|4.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|92|0.0%|3.9%|
[dshield](#dshield)|20|5120|90|1.7%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|75|0.0%|3.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|224|224|26|11.6%|1.1%|
[blocklist_de_mail](#blocklist_de_mail)|14811|14811|17|0.1%|0.7%|
[blocklist_de_imap](#blocklist_de_imap)|724|724|11|1.5%|0.4%|
[shunlist](#shunlist)|51|51|8|15.6%|0.3%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|5|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|12665|12665|3|0.0%|0.1%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[voipbl](#voipbl)|10286|10757|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1348|1348|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3501|3501|1|0.0%|0.0%|

## et_tor

[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs

Source is downloaded from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules).

The last time downloaded was found to be dated: Wed May 27 04:30:09 UTC 2015.

The ipset `et_tor` has **6490** entries, **6490** unique IPs.

The following table shows the overlaps of `et_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_tor`.
- ` this % ` is the percentage **of this ipset (`et_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6406|6406|5769|90.0%|88.8%|
[dm_tor](#dm_tor)|6405|6405|5768|90.0%|88.8%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|1090|15.0%|16.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|608|0.0%|9.3%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|573|0.6%|8.8%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|442|1.4%|6.8%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7646|7646|270|3.5%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|184|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|165|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|44|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[php_bad](#php_bad)|281|281|29|10.3%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|12665|12665|27|0.2%|0.4%|
[blocklist_de](#blocklist_de)|22523|22523|27|0.1%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1348|1348|24|1.7%|0.3%|
[openbl_90d](#openbl_90d)|9893|9893|21|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7803|7803|21|0.2%|0.3%|
[openbl](#openbl)|9893|9893|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|21|0.0%|0.3%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4254|4254|5|0.1%|0.0%|
[php_dictionary](#php_dictionary)|398|398|3|0.7%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|975|18056513|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14811|14811|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1668|1668|2|0.1%|0.0%|
[nixspam](#nixspam)|23722|23722|2|0.0%|0.0%|
[voipbl](#voipbl)|10286|10757|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Thu May 28 07:00:37 UTC 2015.

The ipset `feodo` has **63** entries, **63** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|975|18056513|61|0.0%|96.8%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|48|0.6%|76.1%|
[sslbl](#sslbl)|341|341|20|5.8%|31.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|3|0.0%|4.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|3|0.0%|4.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|3|0.0%|4.7%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|1.5%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|1|0.0%|1.5%|

## fullbogons

[Team-Cymru.org](http://www.team-cymru.org) IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user - **excellent list - use it only your internet interface**

Source is downloaded from [this link](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt).

The last time downloaded was found to be dated: Wed May 27 09:35:07 UTC 2015.

The ipset `fullbogons` has **3666** entries, **670786520** unique IPs.

The following table shows the overlaps of `fullbogons` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `fullbogons`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `fullbogons`.
- ` this % ` is the percentage **of this ipset (`fullbogons`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bogons](#bogons)|13|592708608|592708608|100.0%|88.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|4233779|3.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|565248|6.1%|0.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|248327|0.0%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|235407|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|20480|0.1%|0.0%|
[et_block](#et_block)|975|18056513|20480|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|894|0.2%|0.0%|
[voipbl](#voipbl)|10286|10757|351|3.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|33|2.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|9|0.7%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2403|2403|1|0.0%|0.0%|

## ib_bluetack_badpeers

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) IPs that have been reported for bad deeds in p2p

Source is downloaded from [this link](http://list.iblocklist.com/?list=cwworuawihqvocglcoss&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Thu May 28 03:20:53 UTC 2015.

The ipset `ib_bluetack_badpeers` has **48134** entries, **48134** unique IPs.

The following table shows the overlaps of `ib_bluetack_badpeers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_badpeers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_badpeers`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_badpeers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|1172|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|432|0.0%|0.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|233|0.0%|0.4%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|14|0.0%|0.0%|
[fullbogons](#fullbogons)|3666|670786520|14|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|13|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.0%|
[et_block](#et_block)|975|18056513|10|0.0%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|6|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|6|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|6|0.0%|0.0%|
[nixspam](#nixspam)|23722|23722|4|0.0%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7646|7646|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|22523|22523|3|0.0%|0.0%|
[voipbl](#voipbl)|10286|10757|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[php_dictionary](#php_dictionary)|398|398|2|0.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14811|14811|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4254|4254|1|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3501|3501|1|0.0%|0.0%|

## ib_bluetack_hijacked

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) hijacked IP-Blocks Hijacked IP space are IP blocks that are being used without permission

Source is downloaded from [this link](http://list.iblocklist.com/?list=usrcshglbiilevmyfhse&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Thu May 28 03:50:50 UTC 2015.

The ipset `ib_bluetack_hijacked` has **535** entries, **9177856** unique IPs.

The following table shows the overlaps of `ib_bluetack_hijacked` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_hijacked`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_hijacked`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_hijacked`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[spamhaus_drop](#spamhaus_drop)|641|18117120|7211008|39.8%|78.5%|
[et_block](#et_block)|975|18056513|7211008|39.9%|78.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|2526625|0.7%|27.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|904796|0.1%|9.8%|
[fullbogons](#fullbogons)|3666|670786520|565248|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|145472|0.1%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1036|0.3%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|737|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|519|0.2%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|195|0.6%|0.0%|
[nixspam](#nixspam)|23722|23722|194|0.8%|0.0%|
[blocklist_de](#blocklist_de)|22523|22523|60|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3501|3501|40|1.1%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7646|7646|37|0.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|27|2.1%|0.0%|
[openbl_90d](#openbl_90d)|9893|9893|19|0.1%|0.0%|
[openbl](#openbl)|9893|9893|19|0.1%|0.0%|
[openbl_60d](#openbl_60d)|7803|7803|18|0.2%|0.0%|
[openbl_30d](#openbl_30d)|4446|4446|13|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2287|2287|12|0.5%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|11|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|10|4.3%|0.0%|
[zeus](#zeus)|266|266|10|3.7%|0.0%|
[openbl_7d](#openbl_7d)|995|995|9|0.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[openbl_1d](#openbl_1d)|357|357|5|1.4%|0.0%|
[et_compromised](#et_compromised)|2338|2338|5|0.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14811|14811|5|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2403|2403|4|0.1%|0.0%|
[et_tor](#et_tor)|6490|6490|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6405|6405|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6406|6406|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|224|224|3|1.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|724|724|3|0.4%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12665|12665|3|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1348|1348|2|0.1%|0.0%|
[voipbl](#voipbl)|10286|10757|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_dictionary](#php_dictionary)|398|398|1|0.2%|0.0%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.0%|
[php_bad](#php_bad)|281|281|1|0.3%|0.0%|
[et_botnet](#et_botnet)|512|512|1|0.1%|0.0%|

## ib_bluetack_level1

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Level 1 (for use in p2p): Companies or organizations who are clearly involved with trying to stop filesharing (e.g. Baytsp, MediaDefender, Mediasentry a.o.). Companies which anti-p2p activity has been seen from. Companies that produce or have a strong financial interest in copyrighted material (e.g. music, movie, software industries a.o.). Government ranges or companies that have a strong financial interest in doing work for governments. Legal industry ranges. IPs or ranges of ISPs from which anti-p2p activity has been observed. Basically this list will block all kinds of internet connections that most people would rather not have during their internet travels.

Source is downloaded from [this link](http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Wed May 27 09:29:59 UTC 2015.

The ipset `ib_bluetack_level1` has **236319** entries, **765065682** unique IPs.

The following table shows the overlaps of `ib_bluetack_level1` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level1`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level1`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level1`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|16317427|4.6%|2.1%|
[et_block](#et_block)|975|18056513|2133031|11.8%|0.2%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2133002|11.7%|0.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|1360049|0.9%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904796|9.8%|0.1%|
[fullbogons](#fullbogons)|3666|670786520|235407|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|33155|7.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|13328|3.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|5207|2.9%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|1498|1.6%|0.0%|
[blocklist_de](#blocklist_de)|22523|22523|1487|6.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14811|14811|1352|9.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12665|12665|1321|10.4%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|581|1.8%|0.0%|
[nixspam](#nixspam)|23722|23722|476|2.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|432|0.8%|0.0%|
[voipbl](#voipbl)|10286|10757|301|2.7%|0.0%|
[openbl_90d](#openbl_90d)|9893|9893|221|2.2%|0.0%|
[openbl](#openbl)|9893|9893|221|2.2%|0.0%|
[openbl_60d](#openbl_60d)|7803|7803|182|2.3%|0.0%|
[dm_tor](#dm_tor)|6405|6405|167|2.6%|0.0%|
[bm_tor](#bm_tor)|6406|6406|167|2.6%|0.0%|
[et_tor](#et_tor)|6490|6490|165|2.5%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7646|7646|156|2.0%|0.0%|
[openbl_30d](#openbl_30d)|4446|4446|101|2.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|98|6.7%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4254|4254|97|2.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|92|1.2%|0.0%|
[et_compromised](#et_compromised)|2338|2338|75|3.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2403|2403|73|3.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|66|5.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1668|1668|59|3.5%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|58|8.6%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2287|2287|51|2.2%|0.0%|
[et_botnet](#et_botnet)|512|512|43|8.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3501|3501|38|1.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1348|1348|28|2.0%|0.0%|
[ciarmy](#ciarmy)|387|387|21|5.4%|0.0%|
[openbl_7d](#openbl_7d)|995|995|19|1.9%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|724|724|14|1.9%|0.0%|
[malc0de](#malc0de)|414|414|12|2.8%|0.0%|
[php_dictionary](#php_dictionary)|398|398|9|2.2%|0.0%|
[zeus](#zeus)|266|266|7|2.6%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[openbl_1d](#openbl_1d)|357|357|7|1.9%|0.0%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.0%|
[php_commenters](#php_commenters)|281|281|5|1.7%|0.0%|
[php_bad](#php_bad)|281|281|5|1.7%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[zeus_badips](#zeus_badips)|229|229|4|1.7%|0.0%|
[dshield](#dshield)|20|5120|4|0.0%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|104|104|4|3.8%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|103|103|4|3.8%|0.0%|
[sslbl](#sslbl)|341|341|3|0.8%|0.0%|
[feodo](#feodo)|63|63|3|4.7%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|266|266|3|1.1%|0.0%|

## ib_bluetack_level2

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 2 (for use in p2p). General corporate ranges. Ranges used by labs or researchers. Proxies.

Source is downloaded from [this link](http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Thu May 28 03:50:51 UTC 2015.

The ipset `ib_bluetack_level2` has **78389** entries, **348732007** unique IPs.

The following table shows the overlaps of `ib_bluetack_level2` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level2`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level2`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level2`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|16317427|2.1%|4.6%|
[et_block](#et_block)|975|18056513|8401703|46.5%|2.4%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|8401434|46.3%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|2832265|2.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2526625|27.5%|0.7%|
[fullbogons](#fullbogons)|3666|670786520|248327|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|33368|7.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|8400|4.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|7752|2.2%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|2453|2.6%|0.0%|
[blocklist_de](#blocklist_de)|22523|22523|1442|6.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14811|14811|1161|7.8%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12665|12665|1075|8.4%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|927|3.0%|0.0%|
[nixspam](#nixspam)|23722|23722|553|2.3%|0.0%|
[openbl_90d](#openbl_90d)|9893|9893|516|5.2%|0.0%|
[openbl](#openbl)|9893|9893|516|5.2%|0.0%|
[voipbl](#voipbl)|10286|10757|428|3.9%|0.0%|
[openbl_60d](#openbl_60d)|7803|7803|365|4.6%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7646|7646|263|3.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|233|0.4%|0.0%|
[openbl_30d](#openbl_30d)|4446|4446|228|5.1%|0.0%|
[et_tor](#et_tor)|6490|6490|184|2.8%|0.0%|
[dm_tor](#dm_tor)|6405|6405|184|2.8%|0.0%|
[bm_tor](#bm_tor)|6406|6406|184|2.8%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4254|4254|150|3.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2403|2403|148|6.1%|0.0%|
[et_compromised](#et_compromised)|2338|2338|143|6.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2287|2287|127|5.5%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|100|1.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3501|3501|80|2.2%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1668|1668|75|4.4%|0.0%|
[openbl_7d](#openbl_7d)|995|995|50|5.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|45|3.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1348|1348|43|3.1%|0.0%|
[ciarmy](#ciarmy)|387|387|40|10.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|724|724|36|4.9%|0.0%|
[php_spammers](#php_spammers)|417|417|31|7.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|28|4.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|26|2.0%|0.0%|
[malc0de](#malc0de)|414|414|26|6.2%|0.0%|
[et_botnet](#et_botnet)|512|512|21|4.1%|0.0%|
[openbl_1d](#openbl_1d)|357|357|17|4.7%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|266|266|17|6.3%|0.0%|
[zeus](#zeus)|266|266|9|3.3%|0.0%|
[php_dictionary](#php_dictionary)|398|398|9|2.2%|0.0%|
[php_commenters](#php_commenters)|281|281|9|3.2%|0.0%|
[php_bad](#php_bad)|281|281|9|3.2%|0.0%|
[zeus_badips](#zeus_badips)|229|229|8|3.4%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|224|224|8|3.5%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|103|103|8|7.7%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[sslbl](#sslbl)|341|341|6|1.7%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|104|104|6|5.7%|0.0%|
[palevo](#palevo)|13|13|3|23.0%|0.0%|
[feodo](#feodo)|63|63|3|4.7%|0.0%|
[shunlist](#shunlist)|51|51|2|3.9%|0.0%|

## ib_bluetack_level3

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 3 (for use in p2p). Many portal-type websites. ISP ranges that may be dodgy for some reason. Ranges that belong to an individual, but which have not been determined to be used by a particular company. Ranges for things that are unusual in some way. The L3 list is aka the paranoid list.

Source is downloaded from [this link](http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Thu May 28 03:50:11 UTC 2015.

The ipset `ib_bluetack_level3` has **18879** entries, **139109195** unique IPs.

The following table shows the overlaps of `ib_bluetack_level3` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level3`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level3`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level3`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[fullbogons](#fullbogons)|3666|670786520|4233779|0.6%|3.0%|
[bogons](#bogons)|13|592708608|4194304|0.7%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|2832265|0.8%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|1360049|0.1%|0.9%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|270785|64.3%|0.1%|
[et_block](#et_block)|975|18056513|196440|1.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|195904|1.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|14946|8.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|9278|2.7%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|6226|6.7%|0.0%|
[blocklist_de](#blocklist_de)|22523|22523|2813|12.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14811|14811|2245|15.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12665|12665|2220|17.5%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|2079|6.7%|0.0%|
[voipbl](#voipbl)|10286|10757|1587|14.7%|0.0%|
[nixspam](#nixspam)|23722|23722|1449|6.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1172|2.4%|0.0%|
[openbl_90d](#openbl_90d)|9893|9893|959|9.6%|0.0%|
[openbl](#openbl)|9893|9893|959|9.6%|0.0%|
[openbl_60d](#openbl_60d)|7803|7803|716|9.1%|0.0%|
[dm_tor](#dm_tor)|6405|6405|610|9.5%|0.0%|
[bm_tor](#bm_tor)|6406|6406|610|9.5%|0.0%|
[et_tor](#et_tor)|6490|6490|608|9.3%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7646|7646|515|6.7%|0.0%|
[openbl_30d](#openbl_30d)|4446|4446|445|10.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2403|2403|230|9.5%|0.0%|
[et_compromised](#et_compromised)|2338|2338|225|9.6%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2287|2287|225|9.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|214|2.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3501|3501|150|4.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|146|11.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4254|4254|134|3.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1348|1348|126|9.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|110|7.5%|0.0%|
[openbl_7d](#openbl_7d)|995|995|96|9.6%|0.0%|
[malc0de](#malc0de)|414|414|76|18.3%|0.0%|
[et_botnet](#et_botnet)|512|512|75|14.6%|0.0%|
[ciarmy](#ciarmy)|387|387|70|18.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|51|7.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|724|724|44|6.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1668|1668|41|2.4%|0.0%|
[php_spammers](#php_spammers)|417|417|26|6.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|266|266|26|9.7%|0.0%|
[php_dictionary](#php_dictionary)|398|398|23|5.7%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|103|103|22|21.3%|0.0%|
[sslbl](#sslbl)|341|341|21|6.1%|0.0%|
[zeus](#zeus)|266|266|20|7.5%|0.0%|
[openbl_1d](#openbl_1d)|357|357|20|5.6%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|224|224|17|7.5%|0.0%|
[php_bad](#php_bad)|281|281|16|5.6%|0.0%|
[php_harvesters](#php_harvesters)|257|257|15|5.8%|0.0%|
[php_commenters](#php_commenters)|281|281|15|5.3%|0.0%|
[zeus_badips](#zeus_badips)|229|229|14|6.1%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|104|104|13|12.5%|0.0%|
[shunlist](#shunlist)|51|51|6|11.7%|0.0%|
[feodo](#feodo)|63|63|3|4.7%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|

## ib_bluetack_proxies

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Open Proxies IPs list (without TOR)

Source is downloaded from [this link](http://list.iblocklist.com/?list=xoebmbyexwuiogmbyprb&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Thu May 28 03:50:04 UTC 2015.

The ipset `ib_bluetack_proxies` has **673** entries, **673** unique IPs.

The following table shows the overlaps of `ib_bluetack_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_proxies`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|58|0.0%|8.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|51|0.0%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|28|0.0%|4.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|24|0.0%|3.5%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|12|0.0%|1.7%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|11|0.0%|1.6%|
[ri_web_proxies](#ri_web_proxies)|4254|4254|10|0.2%|1.4%|
[ri_connect_proxies](#ri_connect_proxies)|1668|1668|6|0.3%|0.8%|
[blocklist_de](#blocklist_de)|22523|22523|3|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.2%|
[nixspam](#nixspam)|23722|23722|2|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.2%|
[et_block](#et_block)|975|18056513|2|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|14811|14811|2|0.0%|0.2%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7646|7646|1|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|1|0.0%|0.1%|
[php_dictionary](#php_dictionary)|398|398|1|0.2%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3501|3501|1|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|1|0.0%|0.1%|

## ib_bluetack_spyware

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) known malicious SPYWARE and ADWARE IP Address ranges

Source is downloaded from [this link](http://list.iblocklist.com/?list=llvtlsjyoyiczbkjsxpf&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Thu May 28 03:20:02 UTC 2015.

The ipset `ib_bluetack_spyware` has **3339** entries, **339461** unique IPs.

The following table shows the overlaps of `ib_bluetack_spyware` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_spyware`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_spyware`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_spyware`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|13328|0.0%|3.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|9278|0.0%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|7752|0.0%|2.2%|
[et_block](#et_block)|975|18056513|1044|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|1037|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1036|0.0%|0.3%|
[fullbogons](#fullbogons)|3666|670786520|894|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|293|0.1%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|46|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|25|1.9%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|22|0.0%|0.0%|
[et_tor](#et_tor)|6490|6490|21|0.3%|0.0%|
[dm_tor](#dm_tor)|6405|6405|21|0.3%|0.0%|
[bm_tor](#bm_tor)|6406|6406|21|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|19|1.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|15|0.2%|0.0%|
[nixspam](#nixspam)|23722|23722|13|0.0%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7646|7646|9|0.1%|0.0%|
[blocklist_de](#blocklist_de)|22523|22523|7|0.0%|0.0%|
[openbl_90d](#openbl_90d)|9893|9893|6|0.0%|0.0%|
[openbl](#openbl)|9893|9893|6|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7803|7803|5|0.0%|0.0%|
[voipbl](#voipbl)|10286|10757|4|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4254|4254|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4446|4446|4|0.0%|0.0%|
[dshield](#dshield)|20|5120|4|0.0%|0.0%|
[malc0de](#malc0de)|414|414|3|0.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12665|12665|3|0.0%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2287|2287|2|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|103|103|2|1.9%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14811|14811|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[sslbl](#sslbl)|341|341|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_dictionary](#php_dictionary)|398|398|1|0.2%|0.0%|
[openbl_7d](#openbl_7d)|995|995|1|0.1%|0.0%|
[feodo](#feodo)|63|63|1|1.5%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1348|1348|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3501|3501|1|0.0%|0.0%|

## ib_bluetack_webexploit

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) web server hack and exploit attempts

Source is downloaded from [this link](http://list.iblocklist.com/?list=ghlzqtqxnzctvvajwwag&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Thu May 28 03:20:17 UTC 2015.

The ipset `ib_bluetack_webexploit` has **1460** entries, **1460** unique IPs.

The following table shows the overlaps of `ib_bluetack_webexploit` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_webexploit`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_webexploit`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_webexploit`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|110|0.0%|7.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|98|0.0%|6.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|45|0.0%|3.0%|
[fullbogons](#fullbogons)|3666|670786520|33|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|19|0.0%|1.3%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|8|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|6|0.0%|0.4%|
[et_block](#et_block)|975|18056513|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|3|0.2%|0.2%|
[blocklist_de](#blocklist_de)|22523|22523|3|0.0%|0.2%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|2|0.0%|0.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|2|0.0%|0.1%|
[openbl_90d](#openbl_90d)|9893|9893|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7803|7803|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|4446|4446|2|0.0%|0.1%|
[openbl](#openbl)|9893|9893|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.1%|
[bruteforceblocker](#bruteforceblocker)|2403|2403|2|0.0%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|2287|2287|2|0.0%|0.1%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7646|7646|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4254|4254|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|995|995|1|0.1%|0.0%|
[openbl_1d](#openbl_1d)|357|357|1|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_tor](#et_tor)|6490|6490|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2338|2338|1|0.0%|0.0%|
[et_botnet](#et_botnet)|512|512|1|0.1%|0.0%|
[dm_tor](#dm_tor)|6405|6405|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6406|6406|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|224|224|1|0.4%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3501|3501|1|0.0%|0.0%|

## malc0de

[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days

Source is downloaded from [this link](http://malc0de.com/bl/IP_Blacklist.txt).

The last time downloaded was found to be dated: Wed May 27 13:17:02 UTC 2015.

The ipset `malc0de` has **414** entries, **414** unique IPs.

The following table shows the overlaps of `malc0de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `malc0de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `malc0de`.
- ` this % ` is the percentage **of this ipset (`malc0de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|76|0.0%|18.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|26|0.0%|6.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|12|0.0%|2.8%|
[clean_mx_viruses](#clean_mx_viruses)|104|104|11|10.5%|2.6%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|10|0.0%|2.4%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|4|0.3%|0.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|3|0.0%|0.7%|
[et_block](#et_block)|975|18056513|3|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.4%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.2%|

## malwaredomainlist

[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses

Source is downloaded from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt).

The last time downloaded was found to be dated: Thu May 14 20:46:41 UTC 2015.

The ipset `malwaredomainlist` has **1283** entries, **1283** unique IPs.

The following table shows the overlaps of `malwaredomainlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `malwaredomainlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `malwaredomainlist`.
- ` this % ` is the percentage **of this ipset (`malwaredomainlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|146|0.0%|11.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|66|0.0%|5.1%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|28|0.0%|2.1%|
[et_block](#et_block)|975|18056513|28|0.0%|2.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|26|0.0%|2.0%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|25|0.3%|1.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|25|0.0%|1.9%|
[fullbogons](#fullbogons)|3666|670786520|9|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|6|0.0%|0.4%|
[malc0de](#malc0de)|414|414|4|0.9%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.2%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|2|0.0%|0.1%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|1|0.0%|0.0%|
[et_botnet](#et_botnet)|512|512|1|0.1%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|104|104|1|0.9%|0.0%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Thu May 28 07:00:02 UTC 2015.

The ipset `nixspam` has **23722** entries, **23722** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|1449|0.0%|6.1%|
[blocklist_de](#blocklist_de)|22523|22523|584|2.5%|2.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|553|0.0%|2.3%|
[blocklist_de_mail](#blocklist_de_mail)|14811|14811|529|3.5%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|476|0.0%|2.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|229|0.2%|0.9%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|201|0.0%|0.8%|
[et_block](#et_block)|975|18056513|195|0.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|194|0.0%|0.8%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|160|2.2%|0.6%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|134|0.4%|0.5%|
[php_dictionary](#php_dictionary)|398|398|93|23.3%|0.3%|
[php_spammers](#php_spammers)|417|417|81|19.4%|0.3%|
[ri_web_proxies](#ri_web_proxies)|4254|4254|75|1.7%|0.3%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7646|7646|55|0.7%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3501|3501|47|1.3%|0.1%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|34|0.0%|0.1%|
[php_commenters](#php_commenters)|281|281|16|5.6%|0.0%|
[php_bad](#php_bad)|281|281|15|5.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|13|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1668|1668|12|0.7%|0.0%|
[openbl_90d](#openbl_90d)|9893|9893|8|0.0%|0.0%|
[openbl](#openbl)|9893|9893|8|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7803|7803|7|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|6|2.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|724|724|5|0.6%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1348|1348|5|0.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12665|12665|5|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4446|4446|4|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6405|6405|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6406|6406|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6490|6490|2|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|266|266|2|0.7%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|995|995|1|0.1%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|224|224|1|0.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2287|2287|1|0.0%|0.0%|

## openbl

[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**

Source is downloaded from [this link](http://www.openbl.org/lists/base.txt.gz).

The last time downloaded was found to be dated: Thu May 28 03:17:13 UTC 2015.

The ipset `openbl` has **9893** entries, **9893** unique IPs.

The following table shows the overlaps of `openbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl`.
- ` this % ` is the percentage **of this ipset (`openbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9893|9893|9893|100.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|9872|5.5%|99.7%|
[openbl_60d](#openbl_60d)|7803|7803|7803|100.0%|78.8%|
[openbl_30d](#openbl_30d)|4446|4446|4446|100.0%|44.9%|
[bruteforceblocker](#bruteforceblocker)|2403|2403|1412|58.7%|14.2%|
[et_compromised](#et_compromised)|2338|2338|1388|59.3%|14.0%|
[blocklist_de](#blocklist_de)|22523|22523|1342|5.9%|13.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|2287|2287|1263|55.2%|12.7%|
[openbl_7d](#openbl_7d)|995|995|995|100.0%|10.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|959|0.0%|9.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|516|0.0%|5.2%|
[et_block](#et_block)|975|18056513|455|0.0%|4.5%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|447|0.0%|4.5%|
[openbl_1d](#openbl_1d)|357|357|357|100.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|221|0.0%|2.2%|
[dshield](#dshield)|20|5120|165|3.2%|1.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|224|224|76|33.9%|0.7%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|70|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|14811|14811|55|0.3%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|724|724|47|6.4%|0.4%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|36|0.1%|0.3%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|25|0.3%|0.2%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7646|7646|23|0.3%|0.2%|
[et_tor](#et_tor)|6490|6490|21|0.3%|0.2%|
[dm_tor](#dm_tor)|6405|6405|21|0.3%|0.2%|
[bm_tor](#bm_tor)|6406|6406|21|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|19|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12665|12665|15|0.1%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|14|0.0%|0.1%|
[voipbl](#voipbl)|10286|10757|11|0.1%|0.1%|
[shunlist](#shunlist)|51|51|10|19.6%|0.1%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.0%|
[php_bad](#php_bad)|281|281|8|2.8%|0.0%|
[nixspam](#nixspam)|23722|23722|8|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|266|266|7|2.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|6|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1348|1348|6|0.4%|0.0%|
[php_harvesters](#php_harvesters)|257|257|5|1.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3501|3501|3|0.0%|0.0%|
[zeus](#zeus)|266|266|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[sslbl](#sslbl)|341|341|1|0.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4254|4254|1|0.0%|0.0%|
[ciarmy](#ciarmy)|387|387|1|0.2%|0.0%|

## openbl_1d

[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_1days.txt.gz).

The last time downloaded was found to be dated: Wed May 20 19:07:00 UTC 2015.

The ipset `openbl_1d` has **357** entries, **357** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9893|9893|357|3.6%|100.0%|
[openbl_60d](#openbl_60d)|7803|7803|357|4.5%|100.0%|
[openbl_30d](#openbl_30d)|4446|4446|357|8.0%|100.0%|
[openbl](#openbl)|9893|9893|357|3.6%|100.0%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|355|0.2%|99.4%|
[blocklist_de](#blocklist_de)|22523|22523|248|1.1%|69.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|2287|2287|239|10.4%|66.9%|
[et_compromised](#et_compromised)|2338|2338|207|8.8%|57.9%|
[openbl_7d](#openbl_7d)|995|995|206|20.7%|57.7%|
[bruteforceblocker](#bruteforceblocker)|2403|2403|204|8.4%|57.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|224|224|68|30.3%|19.0%|
[dshield](#dshield)|20|5120|45|0.8%|12.6%|
[et_block](#et_block)|975|18056513|27|0.0%|7.5%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|26|0.0%|7.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|20|0.0%|5.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|17|0.0%|4.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|7|0.0%|1.9%|
[blocklist_de_mail](#blocklist_de_mail)|14811|14811|7|0.0%|1.9%|
[blocklist_de_imap](#blocklist_de_imap)|724|724|6|0.8%|1.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|1.4%|
[shunlist](#shunlist)|51|51|2|3.9%|0.5%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|1|0.0%|0.2%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|266|266|1|0.3%|0.2%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt.gz).

The last time downloaded was found to be dated: Thu May 28 03:17:01 UTC 2015.

The ipset `openbl_30d` has **4446** entries, **4446** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9893|9893|4446|44.9%|100.0%|
[openbl_60d](#openbl_60d)|7803|7803|4446|56.9%|100.0%|
[openbl](#openbl)|9893|9893|4446|44.9%|100.0%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|4436|2.5%|99.7%|
[bruteforceblocker](#bruteforceblocker)|2403|2403|1339|55.7%|30.1%|
[et_compromised](#et_compromised)|2338|2338|1321|56.5%|29.7%|
[blocklist_de](#blocklist_de)|22523|22523|1187|5.2%|26.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|2287|2287|1133|49.5%|25.4%|
[openbl_7d](#openbl_7d)|995|995|995|100.0%|22.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|445|0.0%|10.0%|
[openbl_1d](#openbl_1d)|357|357|357|100.0%|8.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|228|0.0%|5.1%|
[et_block](#et_block)|975|18056513|215|0.0%|4.8%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|210|0.0%|4.7%|
[dshield](#dshield)|20|5120|141|2.7%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|101|0.0%|2.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|224|224|74|33.0%|1.6%|
[blocklist_de_mail](#blocklist_de_mail)|14811|14811|45|0.3%|1.0%|
[blocklist_de_imap](#blocklist_de_imap)|724|724|39|5.3%|0.8%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|21|0.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|13|0.0%|0.2%|
[shunlist](#shunlist)|51|51|9|17.6%|0.2%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|7|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12665|12665|7|0.0%|0.1%|
[nixspam](#nixspam)|23722|23722|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|4|0.0%|0.0%|
[voipbl](#voipbl)|10286|10757|3|0.0%|0.0%|
[zeus](#zeus)|266|266|2|0.7%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7646|7646|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|266|266|2|0.7%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|387|387|1|0.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1348|1348|1|0.0%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt.gz).

The last time downloaded was found to be dated: Thu May 28 03:17:01 UTC 2015.

The ipset `openbl_60d` has **7803** entries, **7803** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9893|9893|7803|78.8%|100.0%|
[openbl](#openbl)|9893|9893|7803|78.8%|100.0%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|7785|4.3%|99.7%|
[openbl_30d](#openbl_30d)|4446|4446|4446|100.0%|56.9%|
[bruteforceblocker](#bruteforceblocker)|2403|2403|1396|58.0%|17.8%|
[et_compromised](#et_compromised)|2338|2338|1377|58.8%|17.6%|
[blocklist_de](#blocklist_de)|22523|22523|1284|5.7%|16.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|2287|2287|1218|53.2%|15.6%|
[openbl_7d](#openbl_7d)|995|995|995|100.0%|12.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|716|0.0%|9.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|365|0.0%|4.6%|
[openbl_1d](#openbl_1d)|357|357|357|100.0%|4.5%|
[et_block](#et_block)|975|18056513|306|0.0%|3.9%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|300|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|182|0.0%|2.3%|
[dshield](#dshield)|20|5120|152|2.9%|1.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|224|224|75|33.4%|0.9%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|63|0.0%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|14811|14811|51|0.3%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|724|724|43|5.9%|0.5%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|34|0.1%|0.4%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|25|0.3%|0.3%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7646|7646|22|0.2%|0.2%|
[et_tor](#et_tor)|6490|6490|21|0.3%|0.2%|
[dm_tor](#dm_tor)|6405|6405|21|0.3%|0.2%|
[bm_tor](#bm_tor)|6406|6406|21|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|18|0.0%|0.2%|
[shunlist](#shunlist)|51|51|10|19.6%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12665|12665|10|0.0%|0.1%|
[voipbl](#voipbl)|10286|10757|9|0.0%|0.1%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.1%|
[php_bad](#php_bad)|281|281|8|2.8%|0.1%|
[nixspam](#nixspam)|23722|23722|7|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|5|1.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|5|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|266|266|5|1.8%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1348|1348|3|0.2%|0.0%|
[zeus](#zeus)|266|266|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|387|387|1|0.2%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt.gz).

The last time downloaded was found to be dated: Thu May 28 03:17:00 UTC 2015.

The ipset `openbl_7d` has **995** entries, **995** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9893|9893|995|10.0%|100.0%|
[openbl_60d](#openbl_60d)|7803|7803|995|12.7%|100.0%|
[openbl_30d](#openbl_30d)|4446|4446|995|22.3%|100.0%|
[openbl](#openbl)|9893|9893|995|10.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|990|0.5%|99.4%|
[blocklist_de](#blocklist_de)|22523|22523|676|3.0%|67.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|2287|2287|646|28.2%|64.9%|
[bruteforceblocker](#bruteforceblocker)|2403|2403|511|21.2%|51.3%|
[et_compromised](#et_compromised)|2338|2338|499|21.3%|50.1%|
[openbl_1d](#openbl_1d)|357|357|206|57.7%|20.7%|
[dshield](#dshield)|20|5120|115|2.2%|11.5%|
[et_block](#et_block)|975|18056513|99|0.0%|9.9%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|96|0.0%|9.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|96|0.0%|9.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|224|224|74|33.0%|7.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|50|0.0%|5.0%|
[blocklist_de_mail](#blocklist_de_mail)|14811|14811|25|0.1%|2.5%|
[blocklist_de_imap](#blocklist_de_imap)|724|724|24|3.3%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|19|0.0%|1.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|9|0.0%|0.9%|
[shunlist](#shunlist)|51|51|5|9.8%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|12665|12665|4|0.0%|0.4%|
[voipbl](#voipbl)|10286|10757|2|0.0%|0.2%|
[zeus](#zeus)|266|266|1|0.3%|0.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|1|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|1|0.0%|0.1%|
[nixspam](#nixspam)|23722|23722|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.1%|
[ciarmy](#ciarmy)|387|387|1|0.2%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|266|266|1|0.3%|0.1%|

## openbl_90d

[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_90days.txt.gz).

The last time downloaded was found to be dated: Thu May 28 03:17:13 UTC 2015.

The ipset `openbl_90d` has **9893** entries, **9893** unique IPs.

The following table shows the overlaps of `openbl_90d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_90d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_90d`.
- ` this % ` is the percentage **of this ipset (`openbl_90d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl](#openbl)|9893|9893|9893|100.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|9872|5.5%|99.7%|
[openbl_60d](#openbl_60d)|7803|7803|7803|100.0%|78.8%|
[openbl_30d](#openbl_30d)|4446|4446|4446|100.0%|44.9%|
[bruteforceblocker](#bruteforceblocker)|2403|2403|1412|58.7%|14.2%|
[et_compromised](#et_compromised)|2338|2338|1388|59.3%|14.0%|
[blocklist_de](#blocklist_de)|22523|22523|1342|5.9%|13.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|2287|2287|1263|55.2%|12.7%|
[openbl_7d](#openbl_7d)|995|995|995|100.0%|10.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|959|0.0%|9.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|516|0.0%|5.2%|
[et_block](#et_block)|975|18056513|455|0.0%|4.5%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|447|0.0%|4.5%|
[openbl_1d](#openbl_1d)|357|357|357|100.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|221|0.0%|2.2%|
[dshield](#dshield)|20|5120|165|3.2%|1.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|224|224|76|33.9%|0.7%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|70|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|14811|14811|55|0.3%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|724|724|47|6.4%|0.4%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|36|0.1%|0.3%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|25|0.3%|0.2%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7646|7646|23|0.3%|0.2%|
[et_tor](#et_tor)|6490|6490|21|0.3%|0.2%|
[dm_tor](#dm_tor)|6405|6405|21|0.3%|0.2%|
[bm_tor](#bm_tor)|6406|6406|21|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|19|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12665|12665|15|0.1%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|14|0.0%|0.1%|
[voipbl](#voipbl)|10286|10757|11|0.1%|0.1%|
[shunlist](#shunlist)|51|51|10|19.6%|0.1%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.0%|
[php_bad](#php_bad)|281|281|8|2.8%|0.0%|
[nixspam](#nixspam)|23722|23722|8|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|266|266|7|2.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|6|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1348|1348|6|0.4%|0.0%|
[php_harvesters](#php_harvesters)|257|257|5|1.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3501|3501|3|0.0%|0.0%|
[zeus](#zeus)|266|266|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[sslbl](#sslbl)|341|341|1|0.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4254|4254|1|0.0%|0.0%|
[ciarmy](#ciarmy)|387|387|1|0.2%|0.0%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Thu May 28 07:00:35 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|975|18056513|12|0.0%|92.3%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|11|0.1%|84.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|3|0.0%|23.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|2|0.0%|15.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|1|0.0%|7.6%|

## php_bad

[projecthoneypot.org](http://www.projecthoneypot.org/) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1).

The last time downloaded was found to be dated: Thu May 28 06:40:10 UTC 2015.

The ipset `php_bad` has **281** entries, **281** unique IPs.

The following table shows the overlaps of `php_bad` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_bad`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_bad`.
- ` this % ` is the percentage **of this ipset (`php_bad`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[php_commenters](#php_commenters)|281|281|279|99.2%|99.2%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|193|0.2%|68.6%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|190|0.6%|67.6%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7646|7646|113|1.4%|40.2%|
[blocklist_de](#blocklist_de)|22523|22523|81|0.3%|28.8%|
[blocklist_de_bots](#blocklist_de_bots)|3501|3501|67|1.9%|23.8%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|42|0.5%|14.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|224|224|35|15.6%|12.4%|
[php_spammers](#php_spammers)|417|417|32|7.6%|11.3%|
[et_tor](#et_tor)|6490|6490|29|0.4%|10.3%|
[dm_tor](#dm_tor)|6405|6405|29|0.4%|10.3%|
[bm_tor](#bm_tor)|6406|6406|29|0.4%|10.3%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|25|0.0%|8.8%|
[et_block](#et_block)|975|18056513|24|0.0%|8.5%|
[blocklist_de_apache](#blocklist_de_apache)|12665|12665|24|0.1%|8.5%|
[php_dictionary](#php_dictionary)|398|398|21|5.2%|7.4%|
[blocklist_de_mail](#blocklist_de_mail)|14811|14811|20|0.1%|7.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|16|0.0%|5.6%|
[nixspam](#nixspam)|23722|23722|15|0.0%|5.3%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|12|0.0%|4.2%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|9|0.0%|3.2%|
[openbl_90d](#openbl_90d)|9893|9893|8|0.0%|2.8%|
[openbl_60d](#openbl_60d)|7803|7803|8|0.1%|2.8%|
[openbl](#openbl)|9893|9893|8|0.0%|2.8%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|7|0.0%|2.4%|
[ri_web_proxies](#ri_web_proxies)|4254|4254|7|0.1%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|5|0.0%|1.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1348|1348|4|0.2%|1.4%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.3%|
[zeus](#zeus)|266|266|1|0.3%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|

## php_commenters

[projecthoneypot.org](http://www.projecthoneypot.org/) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1).

The last time downloaded was found to be dated: Thu May 28 06:40:12 UTC 2015.

The ipset `php_commenters` has **281** entries, **281** unique IPs.

The following table shows the overlaps of `php_commenters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_commenters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_commenters`.
- ` this % ` is the percentage **of this ipset (`php_commenters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[php_bad](#php_bad)|281|281|279|99.2%|99.2%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|194|0.2%|69.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|191|0.6%|67.9%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7646|7646|113|1.4%|40.2%|
[blocklist_de](#blocklist_de)|22523|22523|82|0.3%|29.1%|
[blocklist_de_bots](#blocklist_de_bots)|3501|3501|67|1.9%|23.8%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|41|0.5%|14.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|224|224|35|15.6%|12.4%|
[php_spammers](#php_spammers)|417|417|32|7.6%|11.3%|
[et_tor](#et_tor)|6490|6490|29|0.4%|10.3%|
[dm_tor](#dm_tor)|6405|6405|29|0.4%|10.3%|
[bm_tor](#bm_tor)|6406|6406|29|0.4%|10.3%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|25|0.0%|8.8%|
[et_block](#et_block)|975|18056513|24|0.0%|8.5%|
[blocklist_de_apache](#blocklist_de_apache)|12665|12665|24|0.1%|8.5%|
[php_dictionary](#php_dictionary)|398|398|21|5.2%|7.4%|
[blocklist_de_mail](#blocklist_de_mail)|14811|14811|21|0.1%|7.4%|
[nixspam](#nixspam)|23722|23722|16|0.0%|5.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|15|0.0%|5.3%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|12|0.0%|4.2%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|9|0.0%|3.2%|
[openbl_90d](#openbl_90d)|9893|9893|8|0.0%|2.8%|
[openbl_60d](#openbl_60d)|7803|7803|8|0.1%|2.8%|
[openbl](#openbl)|9893|9893|8|0.0%|2.8%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|7|0.0%|2.4%|
[ri_web_proxies](#ri_web_proxies)|4254|4254|7|0.1%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|5|0.0%|1.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1348|1348|4|0.2%|1.4%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.3%|
[zeus](#zeus)|266|266|1|0.3%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|

## php_dictionary

[projecthoneypot.org](http://www.projecthoneypot.org/) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1).

The last time downloaded was found to be dated: Thu May 28 06:40:13 UTC 2015.

The ipset `php_dictionary` has **398** entries, **398** unique IPs.

The following table shows the overlaps of `php_dictionary` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_dictionary`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_dictionary`.
- ` this % ` is the percentage **of this ipset (`php_dictionary`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[nixspam](#nixspam)|23722|23722|93|0.3%|23.3%|
[php_spammers](#php_spammers)|417|417|81|19.4%|20.3%|
[blocklist_de](#blocklist_de)|22523|22523|71|0.3%|17.8%|
[blocklist_de_mail](#blocklist_de_mail)|14811|14811|62|0.4%|15.5%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|61|0.0%|15.3%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|61|0.8%|15.3%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|53|0.1%|13.3%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7646|7646|24|0.3%|6.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|23|0.0%|5.7%|
[php_commenters](#php_commenters)|281|281|21|7.4%|5.2%|
[php_bad](#php_bad)|281|281|21|7.4%|5.2%|
[ri_web_proxies](#ri_web_proxies)|4254|4254|20|0.4%|5.0%|
[blocklist_de_bots](#blocklist_de_bots)|3501|3501|10|0.2%|2.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|9|0.0%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|9|0.0%|2.2%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|7|0.0%|1.7%|
[dm_tor](#dm_tor)|6405|6405|4|0.0%|1.0%|
[bm_tor](#bm_tor)|6406|6406|4|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|3|0.0%|0.7%|
[et_tor](#et_tor)|6490|6490|3|0.0%|0.7%|
[et_block](#et_block)|975|18056513|3|0.0%|0.7%|
[ri_connect_proxies](#ri_connect_proxies)|1668|1668|2|0.1%|0.5%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.5%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|224|224|1|0.4%|0.2%|

## php_harvesters

[projecthoneypot.org](http://www.projecthoneypot.org/) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1).

The last time downloaded was found to be dated: Thu May 28 06:40:08 UTC 2015.

The ipset `php_harvesters` has **257** entries, **257** unique IPs.

The following table shows the overlaps of `php_harvesters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_harvesters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_harvesters`.
- ` this % ` is the percentage **of this ipset (`php_harvesters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|60|0.0%|23.3%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|50|0.1%|19.4%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7646|7646|35|0.4%|13.6%|
[blocklist_de](#blocklist_de)|22523|22523|30|0.1%|11.6%|
[blocklist_de_bots](#blocklist_de_bots)|3501|3501|24|0.6%|9.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|15|0.0%|5.8%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|10|0.1%|3.8%|
[php_commenters](#php_commenters)|281|281|9|3.2%|3.5%|
[php_bad](#php_bad)|281|281|9|3.2%|3.5%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|9|0.0%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|7|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|7|0.0%|2.7%|
[et_tor](#et_tor)|6490|6490|7|0.1%|2.7%|
[dm_tor](#dm_tor)|6405|6405|7|0.1%|2.7%|
[bm_tor](#bm_tor)|6406|6406|7|0.1%|2.7%|
[nixspam](#nixspam)|23722|23722|6|0.0%|2.3%|
[openbl_90d](#openbl_90d)|9893|9893|5|0.0%|1.9%|
[openbl_60d](#openbl_60d)|7803|7803|5|0.0%|1.9%|
[openbl](#openbl)|9893|9893|5|0.0%|1.9%|
[blocklist_de_mail](#blocklist_de_mail)|14811|14811|4|0.0%|1.5%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.7%|
[blocklist_de_ftp](#blocklist_de_ftp)|266|266|2|0.7%|0.7%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|1|0.0%|0.3%|
[ri_web_proxies](#ri_web_proxies)|4254|4254|1|0.0%|0.3%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.3%|
[php_dictionary](#php_dictionary)|398|398|1|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|
[fullbogons](#fullbogons)|3666|670786520|1|0.0%|0.3%|
[et_block](#et_block)|975|18056513|1|0.0%|0.3%|
[bogons](#bogons)|13|592708608|1|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|224|224|1|0.4%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|12665|12665|1|0.0%|0.3%|

## php_spammers

[projecthoneypot.org](http://www.projecthoneypot.org/) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1).

The last time downloaded was found to be dated: Thu May 28 06:40:10 UTC 2015.

The ipset `php_spammers` has **417** entries, **417** unique IPs.

The following table shows the overlaps of `php_spammers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_spammers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_spammers`.
- ` this % ` is the percentage **of this ipset (`php_spammers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|88|0.0%|21.1%|
[php_dictionary](#php_dictionary)|398|398|81|20.3%|19.4%|
[nixspam](#nixspam)|23722|23722|81|0.3%|19.4%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|64|0.2%|15.3%|
[blocklist_de](#blocklist_de)|22523|22523|64|0.2%|15.3%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|63|0.8%|15.1%|
[blocklist_de_mail](#blocklist_de_mail)|14811|14811|42|0.2%|10.0%|
[php_commenters](#php_commenters)|281|281|32|11.3%|7.6%|
[php_bad](#php_bad)|281|281|32|11.3%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|31|0.0%|7.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|26|0.0%|6.2%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7646|7646|25|0.3%|5.9%|
[ri_web_proxies](#ri_web_proxies)|4254|4254|17|0.3%|4.0%|
[blocklist_de_bots](#blocklist_de_bots)|3501|3501|17|0.4%|4.0%|
[et_tor](#et_tor)|6490|6490|6|0.0%|1.4%|
[dm_tor](#dm_tor)|6405|6405|6|0.0%|1.4%|
[bm_tor](#bm_tor)|6406|6406|6|0.0%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|5|0.0%|1.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|224|224|5|2.2%|1.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1348|1348|5|0.3%|1.1%|
[blocklist_de_apache](#blocklist_de_apache)|12665|12665|5|0.0%|1.1%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|3|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.4%|
[ri_connect_proxies](#ri_connect_proxies)|1668|1668|2|0.1%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[et_block](#et_block)|975|18056513|2|0.0%|0.4%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.2%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Thu May 28 02:59:35 UTC 2015.

The ipset `ri_connect_proxies` has **1668** entries, **1668** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|949|1.0%|56.8%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|687|2.2%|41.1%|
[ri_web_proxies](#ri_web_proxies)|4254|4254|677|15.9%|40.5%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7646|7646|171|2.2%|10.2%|
[blocklist_de_bots](#blocklist_de_bots)|3501|3501|81|2.3%|4.8%|
[blocklist_de](#blocklist_de)|22523|22523|81|0.3%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|75|0.0%|4.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|59|0.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|41|0.0%|2.4%|
[nixspam](#nixspam)|23722|23722|12|0.0%|0.7%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.3%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|3|0.0%|0.1%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.1%|
[php_dictionary](#php_dictionary)|398|398|2|0.5%|0.1%|
[et_tor](#et_tor)|6490|6490|2|0.0%|0.1%|
[dm_tor](#dm_tor)|6405|6405|2|0.0%|0.1%|
[bm_tor](#bm_tor)|6406|6406|2|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|14811|14811|1|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Thu May 28 03:24:35 UTC 2015.

The ipset `ri_web_proxies` has **4254** entries, **4254** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|2028|2.1%|47.6%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|1585|5.1%|37.2%|
[ri_connect_proxies](#ri_connect_proxies)|1668|1668|677|40.5%|15.9%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7646|7646|545|7.1%|12.8%|
[blocklist_de](#blocklist_de)|22523|22523|386|1.7%|9.0%|
[blocklist_de_bots](#blocklist_de_bots)|3501|3501|357|10.1%|8.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|150|0.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|134|0.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|97|0.0%|2.2%|
[nixspam](#nixspam)|23722|23722|75|0.3%|1.7%|
[blocklist_de_mail](#blocklist_de_mail)|14811|14811|27|0.1%|0.6%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|25|0.3%|0.5%|
[php_dictionary](#php_dictionary)|398|398|20|5.0%|0.4%|
[php_spammers](#php_spammers)|417|417|17|4.0%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|10|1.4%|0.2%|
[php_commenters](#php_commenters)|281|281|7|2.4%|0.1%|
[php_bad](#php_bad)|281|281|7|2.4%|0.1%|
[et_tor](#et_tor)|6490|6490|5|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6405|6405|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6406|6406|4|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|224|224|3|1.3%|0.0%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[openbl_90d](#openbl_90d)|9893|9893|1|0.0%|0.0%|
[openbl](#openbl)|9893|9893|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2287|2287|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Thu May 28 06:30:03 UTC 2015.

The ipset `shunlist` has **51** entries, **51** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|177044|177044|51|0.0%|100.0%|
[openbl_90d](#openbl_90d)|9893|9893|10|0.1%|19.6%|
[openbl_60d](#openbl_60d)|7803|7803|10|0.1%|19.6%|
[openbl](#openbl)|9893|9893|10|0.1%|19.6%|
[blocklist_de](#blocklist_de)|22523|22523|10|0.0%|19.6%|
[openbl_30d](#openbl_30d)|4446|4446|9|0.2%|17.6%|
[et_compromised](#et_compromised)|2338|2338|8|0.3%|15.6%|
[bruteforceblocker](#bruteforceblocker)|2403|2403|8|0.3%|15.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|6|0.0%|11.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|2287|2287|6|0.2%|11.7%|
[openbl_7d](#openbl_7d)|995|995|5|0.5%|9.8%|
[voipbl](#voipbl)|10286|10757|3|0.0%|5.8%|
[openbl_1d](#openbl_1d)|357|357|2|0.5%|3.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|2|0.0%|3.9%|
[ciarmy](#ciarmy)|387|387|2|0.5%|3.9%|
[blocklist_de_mail](#blocklist_de_mail)|14811|14811|2|0.0%|3.9%|
[blocklist_de_imap](#blocklist_de_imap)|724|724|2|0.2%|3.9%|
[blocklist_de_apache](#blocklist_de_apache)|12665|12665|2|0.0%|3.9%|

## snort_ipfilter

[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)

Source is downloaded from [this link](http://labs.snort.org/feeds/ip-filter.blf).

The last time downloaded was found to be dated: Thu May 28 00:30:00 UTC 2015.

The ipset `snort_ipfilter` has **7236** entries, **7236** unique IPs.

The following table shows the overlaps of `snort_ipfilter` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `snort_ipfilter`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `snort_ipfilter`.
- ` this % ` is the percentage **of this ipset (`snort_ipfilter`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_tor](#et_tor)|6490|6490|1090|16.7%|15.0%|
[dm_tor](#dm_tor)|6405|6405|1036|16.1%|14.3%|
[bm_tor](#bm_tor)|6406|6406|1036|16.1%|14.3%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|679|0.7%|9.3%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|522|1.6%|7.2%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7646|7646|295|3.8%|4.0%|
[et_block](#et_block)|975|18056513|286|0.0%|3.9%|
[zeus](#zeus)|266|266|227|85.3%|3.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|214|0.0%|2.9%|
[zeus_badips](#zeus_badips)|229|229|201|87.7%|2.7%|
[nixspam](#nixspam)|23722|23722|160|0.6%|2.2%|
[blocklist_de](#blocklist_de)|22523|22523|156|0.6%|2.1%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|123|0.0%|1.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|100|0.0%|1.3%|
[blocklist_de_mail](#blocklist_de_mail)|14811|14811|98|0.6%|1.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|92|0.0%|1.2%|
[php_spammers](#php_spammers)|417|417|63|15.1%|0.8%|
[php_dictionary](#php_dictionary)|398|398|61|15.3%|0.8%|
[feodo](#feodo)|63|63|48|76.1%|0.6%|
[blocklist_de_apache](#blocklist_de_apache)|12665|12665|43|0.3%|0.5%|
[php_bad](#php_bad)|281|281|42|14.9%|0.5%|
[php_commenters](#php_commenters)|281|281|41|14.5%|0.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1348|1348|40|2.9%|0.5%|
[ri_web_proxies](#ri_web_proxies)|4254|4254|25|0.5%|0.3%|
[openbl_90d](#openbl_90d)|9893|9893|25|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7803|7803|25|0.3%|0.3%|
[openbl](#openbl)|9893|9893|25|0.2%|0.3%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|25|1.9%|0.3%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|20|0.0%|0.2%|
[sslbl](#sslbl)|341|341|17|4.9%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|15|0.0%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3501|3501|15|0.4%|0.2%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|10|3.8%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|6|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1668|1668|3|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2287|2287|3|0.1%|0.0%|
[openbl_30d](#openbl_30d)|4446|4446|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[openbl_7d](#openbl_7d)|995|995|1|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2338|2338|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2403|2403|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|224|224|1|0.4%|0.0%|

## spamhaus_drop

[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**

Source is downloaded from [this link](http://www.spamhaus.org/drop/drop.txt).

The last time downloaded was found to be dated: Mon May 25 12:30:10 UTC 2015.

The ipset `spamhaus_drop` has **641** entries, **18117120** unique IPs.

The following table shows the overlaps of `spamhaus_drop` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `spamhaus_drop`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `spamhaus_drop`.
- ` this % ` is the percentage **of this ipset (`spamhaus_drop`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|975|18056513|18051584|99.9%|99.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|8401434|2.4%|46.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7211008|78.5%|39.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|2133002|0.2%|11.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|195904|0.1%|1.0%|
[fullbogons](#fullbogons)|3666|670786520|20480|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|1624|0.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1037|0.3%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|788|0.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|512|0.1%|0.0%|
[dshield](#dshield)|20|5120|512|10.0%|0.0%|
[openbl_90d](#openbl_90d)|9893|9893|447|4.5%|0.0%|
[openbl](#openbl)|9893|9893|447|4.5%|0.0%|
[openbl_60d](#openbl_60d)|7803|7803|300|3.8%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|235|0.7%|0.0%|
[openbl_30d](#openbl_30d)|4446|4446|210|4.7%|0.0%|
[nixspam](#nixspam)|23722|23722|201|0.8%|0.0%|
[blocklist_de](#blocklist_de)|22523|22523|184|0.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2287|2287|116|5.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2403|2403|97|4.0%|0.0%|
[openbl_7d](#openbl_7d)|995|995|96|9.6%|0.0%|
[et_compromised](#et_compromised)|2338|2338|92|3.9%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7646|7646|53|0.6%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3501|3501|43|1.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|28|2.1%|0.0%|
[openbl_1d](#openbl_1d)|357|357|26|7.2%|0.0%|
[php_commenters](#php_commenters)|281|281|25|8.8%|0.0%|
[php_bad](#php_bad)|281|281|25|8.8%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14811|14811|22|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|20|0.2%|0.0%|
[zeus_badips](#zeus_badips)|229|229|16|6.9%|0.0%|
[zeus](#zeus)|266|266|16|6.0%|0.0%|
[voipbl](#voipbl)|10286|10757|14|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|724|724|14|1.9%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|224|224|7|3.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[sslbl](#sslbl)|341|341|3|0.8%|0.0%|
[php_dictionary](#php_dictionary)|398|398|3|0.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1348|1348|3|0.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12665|12665|3|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[malc0de](#malc0de)|414|414|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6490|6490|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6405|6405|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6406|6406|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[et_botnet](#et_botnet)|512|512|1|0.1%|0.0%|

## spamhaus_edrop

[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**

Source is downloaded from [this link](http://www.spamhaus.org/drop/edrop.txt).

The last time downloaded was found to be dated: Fri May 22 19:52:08 UTC 2015.

The ipset `spamhaus_edrop` has **55** entries, **421120** unique IPs.

The following table shows the overlaps of `spamhaus_edrop` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `spamhaus_edrop`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `spamhaus_edrop`.
- ` this % ` is the percentage **of this ipset (`spamhaus_edrop`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|270785|0.1%|64.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|33368|0.0%|7.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|33155|0.0%|7.8%|
[et_block](#et_block)|975|18056513|517|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|512|0.0%|0.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|109|0.1%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|40|0.1%|0.0%|
[blocklist_de](#blocklist_de)|22523|22523|37|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3501|3501|30|0.8%|0.0%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|15|0.0%|0.0%|
[openbl_90d](#openbl_90d)|9893|9893|14|0.1%|0.0%|
[openbl](#openbl)|9893|9893|14|0.1%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7646|7646|10|0.1%|0.0%|
[php_commenters](#php_commenters)|281|281|7|2.4%|0.0%|
[php_bad](#php_bad)|281|281|7|2.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|6|0.0%|0.0%|
[zeus_badips](#zeus_badips)|229|229|5|2.1%|0.0%|
[zeus](#zeus)|266|266|5|1.8%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14811|14811|5|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|224|224|4|1.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12665|12665|3|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|724|724|2|0.2%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[openbl_60d](#openbl_60d)|7803|7803|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4446|4446|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|357|357|1|0.2%|0.0%|
[nixspam](#nixspam)|23722|23722|1|0.0%|0.0%|
[malc0de](#malc0de)|414|414|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Thu May 28 07:00:07 UTC 2015.

The ipset `sslbl` has **341** entries, **341** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|975|18056513|23|0.0%|6.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|21|0.0%|6.1%|
[feodo](#feodo)|63|63|20|31.7%|5.8%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|17|0.2%|4.9%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|7|0.0%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|6|0.0%|1.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|3|0.0%|0.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|3|0.0%|0.8%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|1|0.0%|0.2%|
[openbl_90d](#openbl_90d)|9893|9893|1|0.0%|0.2%|
[openbl](#openbl)|9893|9893|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.2%|

## stop_forum_spam_1h

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Thu May 28 06:00:02 UTC 2015.

The ipset `stop_forum_spam_1h` has **7646** entries, **7646** unique IPs.

The following table shows the overlaps of `stop_forum_spam_1h` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stop_forum_spam_1h`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stop_forum_spam_1h`.
- ` this % ` is the percentage **of this ipset (`stop_forum_spam_1h`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|7203|23.4%|94.2%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|4333|4.6%|56.6%|
[blocklist_de](#blocklist_de)|22523|22523|1484|6.5%|19.4%|
[blocklist_de_bots](#blocklist_de_bots)|3501|3501|1404|40.1%|18.3%|
[ri_web_proxies](#ri_web_proxies)|4254|4254|545|12.8%|7.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|515|0.0%|6.7%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|295|4.0%|3.8%|
[dm_tor](#dm_tor)|6405|6405|272|4.2%|3.5%|
[bm_tor](#bm_tor)|6406|6406|272|4.2%|3.5%|
[et_tor](#et_tor)|6490|6490|270|4.1%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|263|0.0%|3.4%|
[ri_connect_proxies](#ri_connect_proxies)|1668|1668|171|10.2%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|156|0.0%|2.0%|
[php_commenters](#php_commenters)|281|281|113|40.2%|1.4%|
[php_bad](#php_bad)|281|281|113|40.2%|1.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|224|224|101|45.0%|1.3%|
[blocklist_de_apache](#blocklist_de_apache)|12665|12665|86|0.6%|1.1%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|62|0.0%|0.8%|
[nixspam](#nixspam)|23722|23722|55|0.2%|0.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|53|0.0%|0.6%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1348|1348|51|3.7%|0.6%|
[et_block](#et_block)|975|18056513|50|0.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|37|0.0%|0.4%|
[php_harvesters](#php_harvesters)|257|257|35|13.6%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|14811|14811|33|0.2%|0.4%|
[php_spammers](#php_spammers)|417|417|25|5.9%|0.3%|
[php_dictionary](#php_dictionary)|398|398|24|6.0%|0.3%|
[openbl_90d](#openbl_90d)|9893|9893|23|0.2%|0.3%|
[openbl](#openbl)|9893|9893|23|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7803|7803|22|0.2%|0.2%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|10|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|9|0.0%|0.1%|
[voipbl](#voipbl)|10286|10757|4|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4446|4446|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2403|2403|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2287|2287|1|0.0%|0.0%|

## stop_forum_spam_30d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip).

The last time downloaded was found to be dated: Wed May 27 12:20:20 UTC 2015.

The ipset `stop_forum_spam_30d` has **92800** entries, **92800** unique IPs.

The following table shows the overlaps of `stop_forum_spam_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stop_forum_spam_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stop_forum_spam_30d`.
- ` this % ` is the percentage **of this ipset (`stop_forum_spam_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|25780|83.9%|27.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|6226|0.0%|6.7%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7646|7646|4333|56.6%|4.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|2453|0.0%|2.6%|
[blocklist_de](#blocklist_de)|22523|22523|2190|9.7%|2.3%|
[ri_web_proxies](#ri_web_proxies)|4254|4254|2028|47.6%|2.1%|
[blocklist_de_bots](#blocklist_de_bots)|3501|3501|1938|55.3%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|1498|0.0%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|1668|1668|949|56.8%|1.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|788|0.0%|0.8%|
[et_block](#et_block)|975|18056513|769|0.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|737|0.0%|0.7%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|679|9.3%|0.7%|
[et_tor](#et_tor)|6490|6490|573|8.8%|0.6%|
[dm_tor](#dm_tor)|6405|6405|570|8.8%|0.6%|
[bm_tor](#bm_tor)|6406|6406|570|8.8%|0.6%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|239|0.1%|0.2%|
[nixspam](#nixspam)|23722|23722|229|0.9%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|12665|12665|199|1.5%|0.2%|
[php_commenters](#php_commenters)|281|281|194|69.0%|0.2%|
[php_bad](#php_bad)|281|281|193|68.6%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|14811|14811|182|1.2%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|224|224|125|55.8%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|109|0.0%|0.1%|
[php_spammers](#php_spammers)|417|417|88|21.1%|0.0%|
[openbl_90d](#openbl_90d)|9893|9893|70|0.7%|0.0%|
[openbl](#openbl)|9893|9893|70|0.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1348|1348|65|4.8%|0.0%|
[openbl_60d](#openbl_60d)|7803|7803|63|0.8%|0.0%|
[php_dictionary](#php_dictionary)|398|398|61|15.3%|0.0%|
[php_harvesters](#php_harvesters)|257|257|60|23.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|46|0.0%|0.0%|
[voipbl](#voipbl)|10286|10757|39|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|24|3.5%|0.0%|
[openbl_30d](#openbl_30d)|4446|4446|21|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2287|2287|7|0.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2403|2403|6|0.2%|0.0%|
[et_compromised](#et_compromised)|2338|2338|5|0.2%|0.0%|
[zeus](#zeus)|266|266|4|1.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|266|266|4|1.5%|0.0%|
[zeus_badips](#zeus_badips)|229|229|3|1.3%|0.0%|
[fullbogons](#fullbogons)|3666|670786520|3|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|2|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[sslbl](#sslbl)|341|341|1|0.2%|0.0%|
[openbl_7d](#openbl_7d)|995|995|1|0.1%|0.0%|
[openbl_1d](#openbl_1d)|357|357|1|0.2%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|387|387|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|

## stop_forum_spam_7d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip).

The last time downloaded was found to be dated: Thu May 28 02:00:08 UTC 2015.

The ipset `stop_forum_spam_7d` has **30710** entries, **30710** unique IPs.

The following table shows the overlaps of `stop_forum_spam_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stop_forum_spam_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stop_forum_spam_7d`.
- ` this % ` is the percentage **of this ipset (`stop_forum_spam_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|25780|27.7%|83.9%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7646|7646|7203|94.2%|23.4%|
[blocklist_de](#blocklist_de)|22523|22523|2364|10.4%|7.6%|
[blocklist_de_bots](#blocklist_de_bots)|3501|3501|2212|63.1%|7.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|2079|0.0%|6.7%|
[ri_web_proxies](#ri_web_proxies)|4254|4254|1585|37.2%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|927|0.0%|3.0%|
[ri_connect_proxies](#ri_connect_proxies)|1668|1668|687|41.1%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|581|0.0%|1.8%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|522|7.2%|1.6%|
[et_tor](#et_tor)|6490|6490|442|6.8%|1.4%|
[dm_tor](#dm_tor)|6405|6405|435|6.7%|1.4%|
[bm_tor](#bm_tor)|6406|6406|435|6.7%|1.4%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|235|0.0%|0.7%|
[et_block](#et_block)|975|18056513|214|0.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|195|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|191|67.9%|0.6%|
[php_bad](#php_bad)|281|281|190|67.6%|0.6%|
[nixspam](#nixspam)|23722|23722|134|0.5%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|12665|12665|128|1.0%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|224|224|117|52.2%|0.3%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|115|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|14811|14811|89|0.6%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1348|1348|68|5.0%|0.2%|
[php_spammers](#php_spammers)|417|417|64|15.3%|0.2%|
[php_dictionary](#php_dictionary)|398|398|53|13.3%|0.1%|
[php_harvesters](#php_harvesters)|257|257|50|19.4%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|40|0.0%|0.1%|
[openbl_90d](#openbl_90d)|9893|9893|36|0.3%|0.1%|
[openbl](#openbl)|9893|9893|36|0.3%|0.1%|
[openbl_60d](#openbl_60d)|7803|7803|34|0.4%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|22|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|12|1.7%|0.0%|
[voipbl](#voipbl)|10286|10757|11|0.1%|0.0%|
[openbl_30d](#openbl_30d)|4446|4446|7|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[et_compromised](#et_compromised)|2338|2338|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2403|2403|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2287|2287|2|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|266|266|2|0.7%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Thu May 28 05:20:26 UTC 2015.

The ipset `voipbl` has **10286** entries, **10757** unique IPs.

The following table shows the overlaps of `voipbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `voipbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `voipbl`.
- ` this % ` is the percentage **of this ipset (`voipbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|1587|0.0%|14.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|428|0.0%|3.9%|
[fullbogons](#fullbogons)|3666|670786520|351|0.0%|3.2%|
[bogons](#bogons)|13|592708608|351|0.0%|3.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|301|0.0%|2.7%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|196|0.1%|1.8%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|39|0.0%|0.3%|
[blocklist_de](#blocklist_de)|22523|22523|37|0.1%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|103|103|29|28.1%|0.2%|
[et_block](#et_block)|975|18056513|20|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|14|0.0%|0.1%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|11|0.0%|0.1%|
[openbl_90d](#openbl_90d)|9893|9893|11|0.1%|0.1%|
[openbl](#openbl)|9893|9893|11|0.1%|0.1%|
[openbl_60d](#openbl_60d)|7803|7803|9|0.1%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7646|7646|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|4|0.0%|0.0%|
[shunlist](#shunlist)|51|51|3|5.8%|0.0%|
[openbl_30d](#openbl_30d)|4446|4446|3|0.0%|0.0%|
[ciarmy](#ciarmy)|387|387|3|0.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2287|2287|3|0.1%|0.0%|
[openbl_7d](#openbl_7d)|995|995|2|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3501|3501|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12665|12665|2|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[et_tor](#et_tor)|6490|6490|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2338|2338|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6405|6405|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2403|2403|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6406|6406|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14811|14811|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1348|1348|1|0.0%|0.0%|

## zeus

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) default blocklist including hijacked sites and web hosting providers - **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist).

The last time downloaded was found to be dated: Thu May 28 04:30:42 UTC 2015.

The ipset `zeus` has **266** entries, **266** unique IPs.

The following table shows the overlaps of `zeus` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus`.
- ` this % ` is the percentage **of this ipset (`zeus`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|975|18056513|262|0.0%|98.4%|
[zeus_badips](#zeus_badips)|229|229|229|100.0%|86.0%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|227|3.1%|85.3%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|67|0.0%|25.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|20|0.0%|7.5%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|16|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|9|0.0%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|7|0.0%|2.6%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|5|0.0%|1.8%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|4|0.0%|1.5%|
[openbl_90d](#openbl_90d)|9893|9893|2|0.0%|0.7%|
[openbl_60d](#openbl_60d)|7803|7803|2|0.0%|0.7%|
[openbl_30d](#openbl_30d)|4446|4446|2|0.0%|0.7%|
[openbl](#openbl)|9893|9893|2|0.0%|0.7%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|1|0.0%|0.3%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.3%|
[php_bad](#php_bad)|281|281|1|0.3%|0.3%|
[openbl_7d](#openbl_7d)|995|995|1|0.1%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.3%|
[et_compromised](#et_compromised)|2338|2338|1|0.0%|0.3%|
[bruteforceblocker](#bruteforceblocker)|2403|2403|1|0.0%|0.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|2287|2287|1|0.0%|0.3%|
[blocklist_de](#blocklist_de)|22523|22523|1|0.0%|0.3%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) includes IPv4 addresses that are used by the ZeuS trojan

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Thu May 28 06:20:24 UTC 2015.

The ipset `zeus_badips` has **229** entries, **229** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|266|266|229|86.0%|100.0%|
[et_block](#et_block)|975|18056513|228|0.0%|99.5%|
[snort_ipfilter](#snort_ipfilter)|7236|7236|201|2.7%|87.7%|
[alienvault_reputation](#alienvault_reputation)|177044|177044|36|0.0%|15.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|16|0.0%|6.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|14|0.0%|6.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|8|0.0%|3.4%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|5|0.0%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|4|0.0%|1.7%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|3|0.0%|1.3%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|1|0.0%|0.4%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.4%|
[php_bad](#php_bad)|281|281|1|0.3%|0.4%|
[openbl_90d](#openbl_90d)|9893|9893|1|0.0%|0.4%|
[openbl_60d](#openbl_60d)|7803|7803|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|4446|4446|1|0.0%|0.4%|
[openbl](#openbl)|9893|9893|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.4%|
[et_compromised](#et_compromised)|2338|2338|1|0.0%|0.4%|
[bruteforceblocker](#bruteforceblocker)|2403|2403|1|0.0%|0.4%|
