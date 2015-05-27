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

The following list was automatically generated on Wed May 27 20:57:14 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|179777 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|23450 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|12942 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|3496 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|1627 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|559 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|944 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|15139 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|106 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|2302 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|225 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6537 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD)|ipv4 hash:ip|2391 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|414 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[clean_mx_viruses](#clean_mx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|299 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6535 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|974 subnets, 18056767 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botnet](#et_botnet)|[EmergingThreats.net](http://www.emergingthreats.net/) botnet IPs|ipv4 hash:ip|505 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net](http://www.emergingthreats.net/) compromised hosts (seems to be a derivate of other lists)|ipv4 hash:ip|2292 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6400 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[feodo](#feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|62 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
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
[infiltrated](#infiltrated)|[infiltrated.net](http://www.infiltrated.net) (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|0 unique IPs|updated every 12 hours  from [this link](http://www.infiltrated.net/blacklisted)
[malc0de](#malc0de)|[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days|ipv4 hash:ip|414 unique IPs|updated every 1 day  from [this link](http://malc0de.com/bl/IP_Blacklist.txt)
[malwaredomainlist](#malwaredomainlist)|[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses|ipv4 hash:ip|1283 unique IPs|updated every 12 hours  from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt)
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|27666 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
[openbl](#openbl)|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|9899 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt.gz)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|357 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_1days.txt.gz)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|4451 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt.gz)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7818 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt.gz)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|1004 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt.gz)
[openbl_90d](#openbl_90d)|[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|9899 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt.gz)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
[php_bad](#php_bad)|[projecthoneypot.org](http://www.projecthoneypot.org/) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|246 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|246 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|398 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|235 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|378 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1622 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|4122 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|51 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|7341 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|641 subnets, 18117120 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|55 subnets, 421120 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|336 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
[stop_forum_spam_1h](#stop_forum_spam_1h)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|7897 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stop_forum_spam_30d](#stop_forum_spam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|92800 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
[stop_forum_spam_7d](#stop_forum_spam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|30172 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10286 subnets, 10757 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) default blocklist including hijacked sites and web hosting providers - **excellent list**|ipv4 hash:ip|267 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) includes IPv4 addresses that are used by the ZeuS trojan|ipv4 hash:ip|229 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Wed May 27 16:31:08 UTC 2015.

The ipset `alienvault_reputation` has **179777** entries, **179777** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|14961|0.0%|8.3%|
[openbl_90d](#openbl_90d)|9899|9899|9872|99.7%|5.4%|
[openbl](#openbl)|9899|9899|9872|99.7%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|8413|0.0%|4.6%|
[openbl_60d](#openbl_60d)|7818|7818|7794|99.6%|4.3%|
[et_block](#et_block)|974|18056767|5529|0.0%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|5212|0.0%|2.8%|
[openbl_30d](#openbl_30d)|4451|4451|4435|99.6%|2.4%|
[dshield](#dshield)|20|5120|2840|55.4%|1.5%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|1624|0.0%|0.9%|
[blocklist_de](#blocklist_de)|23450|23450|1601|6.8%|0.8%|
[bruteforceblocker](#bruteforceblocker)|2391|2391|1477|61.7%|0.8%|
[et_compromised](#et_compromised)|2292|2292|1454|63.4%|0.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|2302|2302|1351|58.6%|0.7%|
[openbl_7d](#openbl_7d)|1004|1004|993|98.9%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|519|0.0%|0.2%|
[ciarmy](#ciarmy)|414|414|402|97.1%|0.2%|
[openbl_1d](#openbl_1d)|357|357|355|99.4%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|293|0.0%|0.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|240|0.2%|0.1%|
[voipbl](#voipbl)|10286|10757|202|1.8%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12942|12942|123|0.9%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|122|1.6%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|117|0.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|83|36.8%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15139|15139|82|0.5%|0.0%|
[zeus](#zeus)|267|267|68|25.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|944|944|61|6.4%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|57|0.7%|0.0%|
[shunlist](#shunlist)|51|51|50|98.0%|0.0%|
[dm_tor](#dm_tor)|6535|6535|45|0.6%|0.0%|
[bm_tor](#bm_tor)|6537|6537|45|0.6%|0.0%|
[et_tor](#et_tor)|6400|6400|44|0.6%|0.0%|
[nixspam](#nixspam)|27666|27666|42|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|36|15.7%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3496|3496|26|0.7%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|106|106|19|17.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1627|1627|17|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|15|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|13|0.0%|0.0%|
[php_commenters](#php_commenters)|246|246|12|4.8%|0.0%|
[php_bad](#php_bad)|246|246|12|4.8%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|559|559|12|2.1%|0.0%|
[malc0de](#malc0de)|414|414|11|2.6%|0.0%|
[php_harvesters](#php_harvesters)|235|235|9|3.8%|0.0%|
[sslbl](#sslbl)|336|336|7|2.0%|0.0%|
[php_dictionary](#php_dictionary)|398|398|7|1.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|6|0.4%|0.0%|
[php_spammers](#php_spammers)|378|378|4|1.0%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|299|299|4|1.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4122|4122|3|0.0%|0.0%|
[et_botnet](#et_botnet)|505|505|3|0.5%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1622|1622|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[feodo](#feodo)|62|62|1|1.6%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Wed May 27 20:28:03 UTC 2015.

The ipset `blocklist_de` has **23450** entries, **23450** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|15139|15139|15139|100.0%|64.5%|
[blocklist_de_apache](#blocklist_de_apache)|12942|12942|12942|100.0%|55.1%|
[blocklist_de_bots](#blocklist_de_bots)|3496|3496|3496|100.0%|14.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|2878|0.0%|12.2%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|2398|2.5%|10.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2302|2302|2302|100.0%|9.8%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|2178|7.2%|9.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1627|1627|1626|99.9%|6.9%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|1601|0.8%|6.8%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|1487|18.8%|6.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|1485|0.0%|6.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|1440|0.0%|6.1%|
[openbl_90d](#openbl_90d)|9899|9899|1349|13.6%|5.7%|
[openbl](#openbl)|9899|9899|1349|13.6%|5.7%|
[openbl_60d](#openbl_60d)|7818|7818|1295|16.5%|5.5%|
[openbl_30d](#openbl_30d)|4451|4451|1189|26.7%|5.0%|
[bruteforceblocker](#bruteforceblocker)|2391|2391|1129|47.2%|4.8%|
[et_compromised](#et_compromised)|2292|2292|1013|44.1%|4.3%|
[nixspam](#nixspam)|27666|27666|952|3.4%|4.0%|
[blocklist_de_imap](#blocklist_de_imap)|944|944|944|100.0%|4.0%|
[openbl_7d](#openbl_7d)|1004|1004|676|67.3%|2.8%|
[blocklist_de_ftp](#blocklist_de_ftp)|559|559|558|99.8%|2.3%|
[ri_web_proxies](#ri_web_proxies)|4122|4122|378|9.1%|1.6%|
[openbl_1d](#openbl_1d)|357|357|251|70.3%|1.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|225|100.0%|0.9%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|193|2.6%|0.8%|
[et_block](#et_block)|974|18056767|192|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|189|0.0%|0.8%|
[dshield](#dshield)|20|5120|100|1.9%|0.4%|
[blocklist_de_sip](#blocklist_de_sip)|106|106|87|82.0%|0.3%|
[php_dictionary](#php_dictionary)|398|398|79|19.8%|0.3%|
[ri_connect_proxies](#ri_connect_proxies)|1622|1622|78|4.8%|0.3%|
[php_commenters](#php_commenters)|246|246|75|30.4%|0.3%|
[php_bad](#php_bad)|246|246|75|30.4%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|66|0.0%|0.2%|
[php_spammers](#php_spammers)|378|378|63|16.6%|0.2%|
[voipbl](#voipbl)|10286|10757|42|0.3%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|40|0.0%|0.1%|
[ciarmy](#ciarmy)|414|414|39|9.4%|0.1%|
[et_tor](#et_tor)|6400|6400|32|0.5%|0.1%|
[dm_tor](#dm_tor)|6535|6535|29|0.4%|0.1%|
[bm_tor](#bm_tor)|6537|6537|28|0.4%|0.1%|
[php_harvesters](#php_harvesters)|235|235|26|11.0%|0.1%|
[shunlist](#shunlist)|51|51|11|21.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|6|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|3|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.0%|
[zeus](#zeus)|267|267|1|0.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Wed May 27 20:28:07 UTC 2015.

The ipset `blocklist_de_apache` has **12942** entries, **12942** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|23450|23450|12942|55.1%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|15139|15139|11059|73.0%|85.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|2225|0.0%|17.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1627|1627|1626|99.9%|12.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|1316|0.0%|10.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|1073|0.0%|8.2%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|207|0.2%|1.5%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|123|0.4%|0.9%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|123|0.0%|0.9%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|81|1.0%|0.6%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|50|0.6%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|35|15.5%|0.2%|
[ciarmy](#ciarmy)|414|414|32|7.7%|0.2%|
[et_tor](#et_tor)|6400|6400|30|0.4%|0.2%|
[dm_tor](#dm_tor)|6535|6535|29|0.4%|0.2%|
[bm_tor](#bm_tor)|6537|6537|28|0.4%|0.2%|
[php_commenters](#php_commenters)|246|246|21|8.5%|0.1%|
[php_bad](#php_bad)|246|246|21|8.5%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3496|3496|19|0.5%|0.1%|
[openbl_90d](#openbl_90d)|9899|9899|15|0.1%|0.1%|
[openbl](#openbl)|9899|9899|15|0.1%|0.1%|
[nixspam](#nixspam)|27666|27666|12|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7818|7818|10|0.1%|0.0%|
[et_block](#et_block)|974|18056767|9|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4451|4451|7|0.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|5|0.0%|0.0%|
[openbl_7d](#openbl_7d)|1004|1004|5|0.4%|0.0%|
[voipbl](#voipbl)|10286|10757|4|0.0%|0.0%|
[php_spammers](#php_spammers)|378|378|4|1.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_compromised](#et_compromised)|2292|2292|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2391|2391|3|0.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|2|0.0%|0.0%|
[shunlist](#shunlist)|51|51|2|3.9%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|235|235|1|0.4%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Wed May 27 20:28:09 UTC 2015.

The ipset `blocklist_de_bots` has **3496** entries, **3496** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|23450|23450|3496|14.9%|100.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|2111|2.2%|60.3%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|2010|6.6%|57.4%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|1398|17.7%|39.9%|
[ri_web_proxies](#ri_web_proxies)|4122|4122|346|8.3%|9.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|145|0.0%|4.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|126|56.0%|3.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|85|0.0%|2.4%|
[ri_connect_proxies](#ri_connect_proxies)|1622|1622|76|4.6%|2.1%|
[php_commenters](#php_commenters)|246|246|63|25.6%|1.8%|
[php_bad](#php_bad)|246|246|63|25.6%|1.8%|
[nixspam](#nixspam)|27666|27666|49|0.1%|1.4%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|46|0.0%|1.3%|
[et_block](#et_block)|974|18056767|46|0.0%|1.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|44|0.0%|1.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|37|0.0%|1.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|34|0.0%|0.9%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|26|0.0%|0.7%|
[php_harvesters](#php_harvesters)|235|235|20|8.5%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|15139|15139|19|0.1%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|12942|12942|19|0.1%|0.5%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|18|0.2%|0.5%|
[php_spammers](#php_spammers)|378|378|14|3.7%|0.4%|
[php_dictionary](#php_dictionary)|398|398|14|3.5%|0.4%|
[voipbl](#voipbl)|10286|10757|2|0.0%|0.0%|
[openbl_90d](#openbl_90d)|9899|9899|2|0.0%|0.0%|
[openbl](#openbl)|9899|9899|2|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2292|2292|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2391|2391|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Wed May 27 20:28:11 UTC 2015.

The ipset `blocklist_de_bruteforce` has **1627** entries, **1627** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_apache](#blocklist_de_apache)|12942|12942|1626|12.5%|99.9%|
[blocklist_de](#blocklist_de)|23450|23450|1626|6.9%|99.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|130|0.0%|7.9%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|72|0.0%|4.4%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|61|0.2%|3.7%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|47|0.6%|2.8%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|42|0.5%|2.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|41|0.0%|2.5%|
[et_tor](#et_tor)|6400|6400|27|0.4%|1.6%|
[dm_tor](#dm_tor)|6535|6535|27|0.4%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|26|0.0%|1.5%|
[bm_tor](#bm_tor)|6537|6537|26|0.3%|1.5%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|17|0.0%|1.0%|
[nixspam](#nixspam)|27666|27666|12|0.0%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|12|5.3%|0.7%|
[openbl_90d](#openbl_90d)|9899|9899|6|0.0%|0.3%|
[openbl](#openbl)|9899|9899|6|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|5|0.0%|0.3%|
[et_block](#et_block)|974|18056767|5|0.0%|0.3%|
[php_spammers](#php_spammers)|378|378|4|1.0%|0.2%|
[php_commenters](#php_commenters)|246|246|4|1.6%|0.2%|
[php_bad](#php_bad)|246|246|4|1.6%|0.2%|
[openbl_60d](#openbl_60d)|7818|7818|3|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.1%|
[voipbl](#voipbl)|10286|10757|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4451|4451|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2292|2292|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2391|2391|1|0.0%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Wed May 27 20:42:09 UTC 2015.

The ipset `blocklist_de_ftp` has **559** entries, **559** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|23450|23450|558|2.3%|99.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|54|0.0%|9.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|18|0.0%|3.2%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|12|0.0%|2.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|9|0.0%|1.6%|
[openbl_90d](#openbl_90d)|9899|9899|8|0.0%|1.4%|
[openbl](#openbl)|9899|9899|8|0.0%|1.4%|
[openbl_60d](#openbl_60d)|7818|7818|7|0.0%|1.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|5|0.0%|0.8%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|4|0.0%|0.7%|
[php_harvesters](#php_harvesters)|235|235|4|1.7%|0.7%|
[nixspam](#nixspam)|27666|27666|3|0.0%|0.5%|
[ciarmy](#ciarmy)|414|414|3|0.7%|0.5%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|2|0.0%|0.3%|
[openbl_30d](#openbl_30d)|4451|4451|2|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|1|0.0%|0.1%|
[openbl_7d](#openbl_7d)|1004|1004|1|0.0%|0.1%|
[openbl_1d](#openbl_1d)|357|357|1|0.2%|0.1%|
[et_compromised](#et_compromised)|2292|2292|1|0.0%|0.1%|
[et_block](#et_block)|974|18056767|1|0.0%|0.1%|
[dshield](#dshield)|20|5120|1|0.0%|0.1%|
[bruteforceblocker](#bruteforceblocker)|2391|2391|1|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|1|0.4%|0.1%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Wed May 27 20:28:08 UTC 2015.

The ipset `blocklist_de_imap` has **944** entries, **944** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|15139|15139|944|6.2%|100.0%|
[blocklist_de](#blocklist_de)|23450|23450|944|4.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|64|0.0%|6.7%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|61|0.0%|6.4%|
[openbl_90d](#openbl_90d)|9899|9899|46|0.4%|4.8%|
[openbl](#openbl)|9899|9899|46|0.4%|4.8%|
[openbl_60d](#openbl_60d)|7818|7818|42|0.5%|4.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|40|0.0%|4.2%|
[openbl_30d](#openbl_30d)|4451|4451|37|0.8%|3.9%|
[openbl_7d](#openbl_7d)|1004|1004|23|2.2%|2.4%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|12|0.0%|1.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|12|0.0%|1.2%|
[et_compromised](#et_compromised)|2292|2292|12|0.5%|1.2%|
[et_block](#et_block)|974|18056767|12|0.0%|1.2%|
[bruteforceblocker](#bruteforceblocker)|2391|2391|12|0.5%|1.2%|
[openbl_1d](#openbl_1d)|357|357|6|1.6%|0.6%|
[nixspam](#nixspam)|27666|27666|4|0.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|2|0.8%|0.2%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|1|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.1%|
[shunlist](#shunlist)|51|51|1|1.9%|0.1%|
[ciarmy](#ciarmy)|414|414|1|0.2%|0.1%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Wed May 27 20:28:06 UTC 2015.

The ipset `blocklist_de_mail` has **15139** entries, **15139** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|23450|23450|15139|64.5%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|12942|12942|11059|85.4%|73.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|2284|0.0%|15.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|1354|0.0%|8.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|1159|0.0%|7.6%|
[blocklist_de_imap](#blocklist_de_imap)|944|944|944|100.0%|6.2%|
[nixspam](#nixspam)|27666|27666|885|3.1%|5.8%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|191|0.2%|1.2%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|125|1.7%|0.8%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|94|0.3%|0.6%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|82|0.0%|0.5%|
[php_dictionary](#php_dictionary)|398|398|65|16.3%|0.4%|
[openbl_90d](#openbl_90d)|9899|9899|60|0.6%|0.3%|
[openbl](#openbl)|9899|9899|60|0.6%|0.3%|
[openbl_60d](#openbl_60d)|7818|7818|56|0.7%|0.3%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|49|0.6%|0.3%|
[openbl_30d](#openbl_30d)|4451|4451|48|1.0%|0.3%|
[php_spammers](#php_spammers)|378|378|44|11.6%|0.2%|
[ri_web_proxies](#ri_web_proxies)|4122|4122|31|0.7%|0.2%|
[openbl_7d](#openbl_7d)|1004|1004|26|2.5%|0.1%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|22|0.0%|0.1%|
[et_compromised](#et_compromised)|2292|2292|20|0.8%|0.1%|
[bruteforceblocker](#bruteforceblocker)|2391|2391|20|0.8%|0.1%|
[php_commenters](#php_commenters)|246|246|19|7.7%|0.1%|
[php_bad](#php_bad)|246|246|19|7.7%|0.1%|
[et_block](#et_block)|974|18056767|19|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|19|8.4%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3496|3496|19|0.5%|0.1%|
[openbl_1d](#openbl_1d)|357|357|8|2.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|4|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1622|1622|2|0.1%|0.0%|
[php_harvesters](#php_harvesters)|235|235|2|0.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|2|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6535|6535|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6537|6537|2|0.0%|0.0%|
[voipbl](#voipbl)|10286|10757|1|0.0%|0.0%|
[shunlist](#shunlist)|51|51|1|1.9%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|414|414|1|0.2%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Wed May 27 20:28:08 UTC 2015.

The ipset `blocklist_de_sip` has **106** entries, **106** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|23450|23450|87|0.3%|82.0%|
[voipbl](#voipbl)|10286|10757|31|0.2%|29.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|21|0.0%|19.8%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|19|0.0%|17.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|10|0.0%|9.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|4|0.0%|3.7%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|2|0.0%|1.8%|
[et_botnet](#et_botnet)|505|505|1|0.1%|0.9%|
[ciarmy](#ciarmy)|414|414|1|0.2%|0.9%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Wed May 27 20:28:03 UTC 2015.

The ipset `blocklist_de_ssh` has **2302** entries, **2302** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|23450|23450|2302|9.8%|100.0%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|1351|0.7%|58.6%|
[openbl_90d](#openbl_90d)|9899|9899|1264|12.7%|54.9%|
[openbl](#openbl)|9899|9899|1264|12.7%|54.9%|
[openbl_60d](#openbl_60d)|7818|7818|1222|15.6%|53.0%|
[openbl_30d](#openbl_30d)|4451|4451|1132|25.4%|49.1%|
[bruteforceblocker](#bruteforceblocker)|2391|2391|1104|46.1%|47.9%|
[et_compromised](#et_compromised)|2292|2292|988|43.1%|42.9%|
[openbl_7d](#openbl_7d)|1004|1004|644|64.1%|27.9%|
[openbl_1d](#openbl_1d)|357|357|242|67.7%|10.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|225|0.0%|9.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|122|0.0%|5.2%|
[et_block](#et_block)|974|18056767|117|0.0%|5.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|115|0.0%|4.9%|
[dshield](#dshield)|20|5120|96|1.8%|4.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|76|33.7%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|51|0.0%|2.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|12|0.0%|0.5%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|9|0.0%|0.3%|
[shunlist](#shunlist)|51|51|8|15.6%|0.3%|
[voipbl](#voipbl)|10286|10757|4|0.0%|0.1%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|4|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|3|0.0%|0.1%|
[nixspam](#nixspam)|27666|27666|3|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[ciarmy](#ciarmy)|414|414|2|0.4%|0.0%|
[zeus](#zeus)|267|267|1|0.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4122|4122|1|0.0%|0.0%|
[php_spammers](#php_spammers)|378|378|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1|0.0%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Wed May 27 20:28:11 UTC 2015.

The ipset `blocklist_de_strongips` has **225** entries, **225** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|23450|23450|225|0.9%|100.0%|
[blocklist_de_bots](#blocklist_de_bots)|3496|3496|126|3.6%|56.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|125|0.1%|55.5%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|116|0.3%|51.5%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|102|1.2%|45.3%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|83|0.0%|36.8%|
[openbl_90d](#openbl_90d)|9899|9899|76|0.7%|33.7%|
[openbl_60d](#openbl_60d)|7818|7818|76|0.9%|33.7%|
[openbl](#openbl)|9899|9899|76|0.7%|33.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|2302|2302|76|3.3%|33.7%|
[openbl_30d](#openbl_30d)|4451|4451|74|1.6%|32.8%|
[openbl_7d](#openbl_7d)|1004|1004|73|7.2%|32.4%|
[openbl_1d](#openbl_1d)|357|357|68|19.0%|30.2%|
[dshield](#dshield)|20|5120|35|0.6%|15.5%|
[blocklist_de_apache](#blocklist_de_apache)|12942|12942|35|0.2%|15.5%|
[php_commenters](#php_commenters)|246|246|32|13.0%|14.2%|
[php_bad](#php_bad)|246|246|32|13.0%|14.2%|
[et_compromised](#et_compromised)|2292|2292|26|1.1%|11.5%|
[bruteforceblocker](#bruteforceblocker)|2391|2391|25|1.0%|11.1%|
[blocklist_de_mail](#blocklist_de_mail)|15139|15139|19|0.1%|8.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|17|0.0%|7.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1627|1627|12|0.7%|5.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|7|0.0%|3.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|6|0.0%|2.6%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|6|0.0%|2.6%|
[et_block](#et_block)|974|18056767|6|0.0%|2.6%|
[php_spammers](#php_spammers)|378|378|5|1.3%|2.2%|
[ri_web_proxies](#ri_web_proxies)|4122|4122|3|0.0%|1.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.3%|
[nixspam](#nixspam)|27666|27666|2|0.0%|0.8%|
[blocklist_de_imap](#blocklist_de_imap)|944|944|2|0.2%|0.8%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|1|0.0%|0.4%|
[php_harvesters](#php_harvesters)|235|235|1|0.4%|0.4%|
[php_dictionary](#php_dictionary)|398|398|1|0.2%|0.4%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.4%|
[blocklist_de_ftp](#blocklist_de_ftp)|559|559|1|0.1%|0.4%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Wed May 27 20:50:59 UTC 2015.

The ipset `bm_tor` has **6537** entries, **6537** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[dm_tor](#dm_tor)|6535|6535|6385|97.7%|97.6%|
[et_tor](#et_tor)|6400|6400|5680|88.7%|86.8%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|1045|14.2%|15.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|607|0.0%|9.2%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|566|0.6%|8.6%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|424|1.4%|6.4%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|229|2.8%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|182|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|166|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|45|0.0%|0.6%|
[php_commenters](#php_commenters)|246|246|28|11.3%|0.4%|
[php_bad](#php_bad)|246|246|28|11.3%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|12942|12942|28|0.2%|0.4%|
[blocklist_de](#blocklist_de)|23450|23450|28|0.1%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1627|1627|26|1.5%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|21|0.0%|0.3%|
[openbl_90d](#openbl_90d)|9899|9899|20|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7818|7818|20|0.2%|0.3%|
[openbl](#openbl)|9899|9899|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|235|235|7|2.9%|0.1%|
[ri_web_proxies](#ri_web_proxies)|4122|4122|5|0.1%|0.0%|
[php_spammers](#php_spammers)|378|378|5|1.3%|0.0%|
[php_dictionary](#php_dictionary)|398|398|3|0.7%|0.0%|
[nixspam](#nixspam)|27666|27666|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|974|18056767|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1622|1622|2|0.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15139|15139|2|0.0%|0.0%|
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
[php_harvesters](#php_harvesters)|235|235|1|0.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2391|2391|1|0.0%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD)

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Wed May 27 18:20:15 UTC 2015.

The ipset `bruteforceblocker` has **2391** entries, **2391** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_compromised](#et_compromised)|2292|2292|2248|98.0%|94.0%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|1477|0.8%|61.7%|
[openbl_90d](#openbl_90d)|9899|9899|1403|14.1%|58.6%|
[openbl](#openbl)|9899|9899|1403|14.1%|58.6%|
[openbl_60d](#openbl_60d)|7818|7818|1391|17.7%|58.1%|
[openbl_30d](#openbl_30d)|4451|4451|1331|29.9%|55.6%|
[blocklist_de](#blocklist_de)|23450|23450|1129|4.8%|47.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2302|2302|1104|47.9%|46.1%|
[openbl_7d](#openbl_7d)|1004|1004|507|50.4%|21.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|231|0.0%|9.6%|
[openbl_1d](#openbl_1d)|357|357|207|57.9%|8.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|148|0.0%|6.1%|
[et_block](#et_block)|974|18056767|97|0.0%|4.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|96|0.0%|4.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|74|0.0%|3.0%|
[dshield](#dshield)|20|5120|64|1.2%|2.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|25|11.1%|1.0%|
[blocklist_de_mail](#blocklist_de_mail)|15139|15139|20|0.1%|0.8%|
[blocklist_de_imap](#blocklist_de_imap)|944|944|12|1.2%|0.5%|
[shunlist](#shunlist)|51|51|9|17.6%|0.3%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|6|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|3|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12942|12942|3|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|267|267|1|0.3%|0.0%|
[voipbl](#voipbl)|10286|10757|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|1|0.0%|0.0%|
[nixspam](#nixspam)|27666|27666|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3666|670786520|1|0.0%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|559|559|1|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1627|1627|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3496|3496|1|0.0%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Wed May 27 18:15:07 UTC 2015.

The ipset `ciarmy` has **414** entries, **414** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|179777|179777|402|0.2%|97.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|68|0.0%|16.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|47|0.0%|11.3%|
[blocklist_de](#blocklist_de)|23450|23450|39|0.1%|9.4%|
[blocklist_de_apache](#blocklist_de_apache)|12942|12942|32|0.2%|7.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|26|0.0%|6.2%|
[dshield](#dshield)|20|5120|7|0.1%|1.6%|
[voipbl](#voipbl)|10286|10757|3|0.0%|0.7%|
[blocklist_de_ftp](#blocklist_de_ftp)|559|559|3|0.5%|0.7%|
[nixspam](#nixspam)|27666|27666|2|0.0%|0.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|2302|2302|2|0.0%|0.4%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|1|0.0%|0.2%|
[shunlist](#shunlist)|51|51|1|1.9%|0.2%|
[openbl_90d](#openbl_90d)|9899|9899|1|0.0%|0.2%|
[openbl_7d](#openbl_7d)|1004|1004|1|0.0%|0.2%|
[openbl_60d](#openbl_60d)|7818|7818|1|0.0%|0.2%|
[openbl_30d](#openbl_30d)|4451|4451|1|0.0%|0.2%|
[openbl](#openbl)|9899|9899|1|0.0%|0.2%|
[et_block](#et_block)|974|18056767|1|0.0%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|106|106|1|0.9%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|15139|15139|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|944|944|1|0.1%|0.2%|

## clean_mx_viruses

[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses

Source is downloaded from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive).

The last time downloaded was found to be dated: Wed May 27 16:01:01 UTC 2015.

The ipset `clean_mx_viruses` has **299** entries, **299** unique IPs.

The following table shows the overlaps of `clean_mx_viruses` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `clean_mx_viruses`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `clean_mx_viruses`.
- ` this % ` is the percentage **of this ipset (`clean_mx_viruses`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|40|0.0%|13.3%|
[malc0de](#malc0de)|414|414|21|5.0%|7.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|10|0.0%|3.3%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|9|0.1%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|9|0.0%|3.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|4|0.3%|1.3%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|4|0.0%|1.3%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|3|0.0%|1.0%|
[zeus](#zeus)|267|267|1|0.3%|0.3%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|1|0.0%|0.3%|
[ri_web_proxies](#ri_web_proxies)|4122|4122|1|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.3%|
[et_block](#et_block)|974|18056767|1|0.0%|0.3%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Wed May 27 20:50:56 UTC 2015.

The ipset `dm_tor` has **6535** entries, **6535** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6537|6537|6385|97.6%|97.7%|
[et_tor](#et_tor)|6400|6400|5670|88.5%|86.7%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|1051|14.3%|16.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|608|0.0%|9.3%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|570|0.6%|8.7%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|428|1.4%|6.5%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|229|2.8%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|184|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|169|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|45|0.0%|0.6%|
[blocklist_de_apache](#blocklist_de_apache)|12942|12942|29|0.2%|0.4%|
[blocklist_de](#blocklist_de)|23450|23450|29|0.1%|0.4%|
[php_commenters](#php_commenters)|246|246|28|11.3%|0.4%|
[php_bad](#php_bad)|246|246|28|11.3%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1627|1627|27|1.6%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|21|0.0%|0.3%|
[openbl_90d](#openbl_90d)|9899|9899|20|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7818|7818|20|0.2%|0.3%|
[openbl](#openbl)|9899|9899|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|235|235|7|2.9%|0.1%|
[php_spammers](#php_spammers)|378|378|6|1.5%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4122|4122|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|398|398|4|1.0%|0.0%|
[nixspam](#nixspam)|27666|27666|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|974|18056767|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1622|1622|2|0.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15139|15139|2|0.0%|0.0%|
[voipbl](#voipbl)|10286|10757|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Wed May 27 18:56:07 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|179777|179777|2840|1.5%|55.4%|
[et_block](#et_block)|974|18056767|768|0.0%|15.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|256|0.0%|5.0%|
[openbl_90d](#openbl_90d)|9899|9899|133|1.3%|2.5%|
[openbl](#openbl)|9899|9899|133|1.3%|2.5%|
[openbl_60d](#openbl_60d)|7818|7818|126|1.6%|2.4%|
[openbl_30d](#openbl_30d)|4451|4451|102|2.2%|1.9%|
[blocklist_de](#blocklist_de)|23450|23450|100|0.4%|1.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|2302|2302|96|4.1%|1.8%|
[openbl_7d](#openbl_7d)|1004|1004|88|8.7%|1.7%|
[openbl_1d](#openbl_1d)|357|357|65|18.2%|1.2%|
[bruteforceblocker](#bruteforceblocker)|2391|2391|64|2.6%|1.2%|
[et_compromised](#et_compromised)|2292|2292|61|2.6%|1.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|35|15.5%|0.6%|
[ciarmy](#ciarmy)|414|414|7|1.6%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|5|0.0%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|4|0.0%|0.0%|
[malc0de](#malc0de)|414|414|2|0.4%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12942|12942|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15139|15139|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|559|559|1|0.1%|0.0%|

## et_block

[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)

Source is downloaded from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt).

The last time downloaded was found to be dated: Tue May 26 04:30:01 UTC 2015.

The ipset `et_block` has **974** entries, **18056767** unique IPs.

The following table shows the overlaps of `et_block` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_block`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_block`.
- ` this % ` is the percentage **of this ipset (`et_block`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[spamhaus_drop](#spamhaus_drop)|641|18117120|18051584|99.6%|99.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|8401959|2.4%|46.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7211008|78.5%|39.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|2133017|0.2%|11.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|196439|0.1%|1.0%|
[fullbogons](#fullbogons)|3666|670786520|20480|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|5529|3.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1301|0.3%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|771|0.8%|0.0%|
[dshield](#dshield)|20|5120|768|15.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|517|0.1%|0.0%|
[openbl_90d](#openbl_90d)|9899|9899|453|4.5%|0.0%|
[openbl](#openbl)|9899|9899|453|4.5%|0.0%|
[openbl_60d](#openbl_60d)|7818|7818|304|3.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|286|3.8%|0.0%|
[zeus](#zeus)|267|267|262|98.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|227|99.1%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|225|0.7%|0.0%|
[openbl_30d](#openbl_30d)|4451|4451|214|4.8%|0.0%|
[blocklist_de](#blocklist_de)|23450|23450|192|0.8%|0.0%|
[nixspam](#nixspam)|27666|27666|178|0.6%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2302|2302|117|5.0%|0.0%|
[openbl_7d](#openbl_7d)|1004|1004|98|9.7%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2391|2391|97|4.0%|0.0%|
[et_compromised](#et_compromised)|2292|2292|91|3.9%|0.0%|
[feodo](#feodo)|62|62|59|95.1%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|54|0.6%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3496|3496|46|1.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|28|2.1%|0.0%|
[openbl_1d](#openbl_1d)|357|357|26|7.2%|0.0%|
[php_commenters](#php_commenters)|246|246|24|9.7%|0.0%|
[php_bad](#php_bad)|246|246|24|9.7%|0.0%|
[sslbl](#sslbl)|336|336|23|6.8%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15139|15139|19|0.1%|0.0%|
[voipbl](#voipbl)|10286|10757|18|0.1%|0.0%|
[palevo](#palevo)|13|13|13|100.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|944|944|12|1.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12942|12942|9|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|6|2.6%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1627|1627|5|0.3%|0.0%|
[php_dictionary](#php_dictionary)|398|398|3|0.7%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6535|6535|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6537|6537|3|0.0%|0.0%|
[php_spammers](#php_spammers)|378|378|2|0.5%|0.0%|
[malc0de](#malc0de)|414|414|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[php_harvesters](#php_harvesters)|235|235|1|0.4%|0.0%|
[et_botnet](#et_botnet)|505|505|1|0.1%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|299|299|1|0.3%|0.0%|
[ciarmy](#ciarmy)|414|414|1|0.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|559|559|1|0.1%|0.0%|

## et_botnet

[EmergingThreats.net](http://www.emergingthreats.net/) botnet IPs

Source is downloaded from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules).

The last time downloaded was found to be dated: Tue May 26 04:30:01 UTC 2015.

The ipset `et_botnet` has **505** entries, **505** unique IPs.

The following table shows the overlaps of `et_botnet` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_botnet`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_botnet`.
- ` this % ` is the percentage **of this ipset (`et_botnet`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|73|0.0%|14.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|42|0.0%|8.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|21|0.0%|4.1%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|3|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|1|0.0%|0.1%|
[nixspam](#nixspam)|27666|27666|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[et_block](#et_block)|974|18056767|1|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|106|106|1|0.9%|0.1%|

## et_compromised

[EmergingThreats.net](http://www.emergingthreats.net/) compromised hosts (seems to be a derivate of other lists)

Source is downloaded from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt).

The last time downloaded was found to be dated: Tue May 26 04:30:08 UTC 2015.

The ipset `et_compromised` has **2292** entries, **2292** unique IPs.

The following table shows the overlaps of `et_compromised` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_compromised`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_compromised`.
- ` this % ` is the percentage **of this ipset (`et_compromised`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bruteforceblocker](#bruteforceblocker)|2391|2391|2248|94.0%|98.0%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|1454|0.8%|63.4%|
[openbl_90d](#openbl_90d)|9899|9899|1376|13.9%|60.0%|
[openbl](#openbl)|9899|9899|1376|13.9%|60.0%|
[openbl_60d](#openbl_60d)|7818|7818|1366|17.4%|59.5%|
[openbl_30d](#openbl_30d)|4451|4451|1307|29.3%|57.0%|
[blocklist_de](#blocklist_de)|23450|23450|1013|4.3%|44.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|2302|2302|988|42.9%|43.1%|
[openbl_7d](#openbl_7d)|1004|1004|494|49.2%|21.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|222|0.0%|9.6%|
[openbl_1d](#openbl_1d)|357|357|204|57.1%|8.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|144|0.0%|6.2%|
[et_block](#et_block)|974|18056767|91|0.0%|3.9%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|90|0.0%|3.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|70|0.0%|3.0%|
[dshield](#dshield)|20|5120|61|1.1%|2.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|26|11.5%|1.1%|
[blocklist_de_mail](#blocklist_de_mail)|15139|15139|20|0.1%|0.8%|
[blocklist_de_imap](#blocklist_de_imap)|944|944|12|1.2%|0.5%|
[shunlist](#shunlist)|51|51|9|17.6%|0.3%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|5|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12942|12942|3|0.0%|0.1%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|267|267|1|0.3%|0.0%|
[voipbl](#voipbl)|10286|10757|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|1|0.0%|0.0%|
[nixspam](#nixspam)|27666|27666|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|559|559|1|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1627|1627|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3496|3496|1|0.0%|0.0%|

## et_tor

[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs

Source is downloaded from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules).

The last time downloaded was found to be dated: Tue May 26 04:30:08 UTC 2015.

The ipset `et_tor` has **6400** entries, **6400** unique IPs.

The following table shows the overlaps of `et_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_tor`.
- ` this % ` is the percentage **of this ipset (`et_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6537|6537|5680|86.8%|88.7%|
[dm_tor](#dm_tor)|6535|6535|5670|86.7%|88.5%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|1085|14.7%|16.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|609|0.0%|9.5%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|580|0.6%|9.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|440|1.4%|6.8%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|231|2.9%|3.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|185|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|164|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|44|0.0%|0.6%|
[blocklist_de](#blocklist_de)|23450|23450|32|0.1%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|12942|12942|30|0.2%|0.4%|
[php_commenters](#php_commenters)|246|246|28|11.3%|0.4%|
[php_bad](#php_bad)|246|246|28|11.3%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1627|1627|27|1.6%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|21|0.0%|0.3%|
[openbl_90d](#openbl_90d)|9899|9899|20|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7818|7818|20|0.2%|0.3%|
[openbl](#openbl)|9899|9899|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|235|235|7|2.9%|0.1%|
[php_spammers](#php_spammers)|378|378|6|1.5%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4122|4122|5|0.1%|0.0%|
[nixspam](#nixspam)|27666|27666|4|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15139|15139|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|398|398|3|0.7%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|974|18056767|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1622|1622|2|0.1%|0.0%|
[voipbl](#voipbl)|10286|10757|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2302|2302|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Wed May 27 20:51:04 UTC 2015.

The ipset `feodo` has **62** entries, **62** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|974|18056767|59|0.0%|95.1%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|48|0.6%|77.4%|
[sslbl](#sslbl)|336|336|20|5.9%|32.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|3|0.0%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|3|0.0%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|3|0.0%|4.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|1.6%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|1|0.0%|1.6%|

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
[et_block](#et_block)|974|18056767|20480|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|894|0.2%|0.0%|
[voipbl](#voipbl)|10286|10757|351|3.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|33|2.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|9|0.7%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|235|235|1|0.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2391|2391|1|0.0%|0.0%|

## ib_bluetack_badpeers

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) IPs that have been reported for bad deeds in p2p

Source is downloaded from [this link](http://list.iblocklist.com/?list=cwworuawihqvocglcoss&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Wed May 27 03:10:44 UTC 2015.

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
[alienvault_reputation](#alienvault_reputation)|179777|179777|13|0.0%|0.0%|
[nixspam](#nixspam)|27666|27666|11|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|6|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|6|0.0%|0.0%|
[et_block](#et_block)|974|18056767|6|0.0%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|23450|23450|3|0.0%|0.0%|
[voipbl](#voipbl)|10286|10757|2|0.0%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|235|235|2|0.8%|0.0%|
[php_dictionary](#php_dictionary)|398|398|2|0.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15139|15139|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4122|4122|1|0.0%|0.0%|
[php_spammers](#php_spammers)|378|378|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3496|3496|1|0.0%|0.0%|

## ib_bluetack_hijacked

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) hijacked IP-Blocks Hijacked IP space are IP blocks that are being used without permission

Source is downloaded from [this link](http://list.iblocklist.com/?list=usrcshglbiilevmyfhse&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Wed May 27 03:40:02 UTC 2015.

The ipset `ib_bluetack_hijacked` has **535** entries, **9177856** unique IPs.

The following table shows the overlaps of `ib_bluetack_hijacked` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_hijacked`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_hijacked`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_hijacked`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[spamhaus_drop](#spamhaus_drop)|641|18117120|7211008|39.8%|78.5%|
[et_block](#et_block)|974|18056767|7211008|39.9%|78.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|2526625|0.7%|27.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|904796|0.1%|9.8%|
[fullbogons](#fullbogons)|3666|670786520|565248|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|145472|0.1%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1036|0.3%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|737|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|519|0.2%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|209|0.6%|0.0%|
[nixspam](#nixspam)|27666|27666|178|0.6%|0.0%|
[blocklist_de](#blocklist_de)|23450|23450|66|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3496|3496|44|1.2%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|35|0.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|27|2.1%|0.0%|
[openbl_90d](#openbl_90d)|9899|9899|19|0.1%|0.0%|
[openbl](#openbl)|9899|9899|19|0.1%|0.0%|
[openbl_60d](#openbl_60d)|7818|7818|18|0.2%|0.0%|
[openbl_30d](#openbl_30d)|4451|4451|13|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2302|2302|12|0.5%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|11|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|10|4.3%|0.0%|
[zeus](#zeus)|267|267|10|3.7%|0.0%|
[openbl_7d](#openbl_7d)|1004|1004|9|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[openbl_1d](#openbl_1d)|357|357|5|1.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2391|2391|5|0.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15139|15139|5|0.0%|0.0%|
[et_compromised](#et_compromised)|2292|2292|4|0.1%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6535|6535|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6537|6537|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|3|1.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|944|944|3|0.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1627|1627|3|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12942|12942|3|0.0%|0.0%|
[php_spammers](#php_spammers)|378|378|2|0.5%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|559|559|2|0.3%|0.0%|
[voipbl](#voipbl)|10286|10757|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|235|235|1|0.4%|0.0%|
[php_dictionary](#php_dictionary)|398|398|1|0.2%|0.0%|
[php_commenters](#php_commenters)|246|246|1|0.4%|0.0%|
[php_bad](#php_bad)|246|246|1|0.4%|0.0%|
[et_botnet](#et_botnet)|505|505|1|0.1%|0.0%|

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
[et_block](#et_block)|974|18056767|2133017|11.8%|0.2%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2133002|11.7%|0.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|1360049|0.9%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904796|9.8%|0.1%|
[fullbogons](#fullbogons)|3666|670786520|235407|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|33155|7.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|13328|3.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|5212|2.8%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|1498|1.6%|0.0%|
[blocklist_de](#blocklist_de)|23450|23450|1485|6.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15139|15139|1354|8.9%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12942|12942|1316|10.1%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|578|1.9%|0.0%|
[nixspam](#nixspam)|27666|27666|549|1.9%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|432|0.8%|0.0%|
[voipbl](#voipbl)|10286|10757|301|2.7%|0.0%|
[openbl_90d](#openbl_90d)|9899|9899|222|2.2%|0.0%|
[openbl](#openbl)|9899|9899|222|2.2%|0.0%|
[openbl_60d](#openbl_60d)|7818|7818|183|2.3%|0.0%|
[dm_tor](#dm_tor)|6535|6535|169|2.5%|0.0%|
[bm_tor](#bm_tor)|6537|6537|166|2.5%|0.0%|
[et_tor](#et_tor)|6400|6400|164|2.5%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|155|1.9%|0.0%|
[openbl_30d](#openbl_30d)|4451|4451|102|2.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|98|6.7%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4122|4122|95|2.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|91|1.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2391|2391|74|3.0%|0.0%|
[et_compromised](#et_compromised)|2292|2292|70|3.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|66|5.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1622|1622|59|3.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|58|8.6%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2302|2302|51|2.2%|0.0%|
[et_botnet](#et_botnet)|505|505|42|8.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3496|3496|37|1.0%|0.0%|
[ciarmy](#ciarmy)|414|414|26|6.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1627|1627|26|1.5%|0.0%|
[openbl_7d](#openbl_7d)|1004|1004|20|1.9%|0.0%|
[malc0de](#malc0de)|414|414|12|2.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|944|944|12|1.2%|0.0%|
[php_dictionary](#php_dictionary)|398|398|9|2.2%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|299|299|9|3.0%|0.0%|
[zeus](#zeus)|267|267|7|2.6%|0.0%|
[php_harvesters](#php_harvesters)|235|235|7|2.9%|0.0%|
[openbl_1d](#openbl_1d)|357|357|7|1.9%|0.0%|
[php_spammers](#php_spammers)|378|378|5|1.3%|0.0%|
[php_commenters](#php_commenters)|246|246|5|2.0%|0.0%|
[php_bad](#php_bad)|246|246|5|2.0%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|559|559|5|0.8%|0.0%|
[zeus_badips](#zeus_badips)|229|229|4|1.7%|0.0%|
[dshield](#dshield)|20|5120|4|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|106|106|4|3.7%|0.0%|
[sslbl](#sslbl)|336|336|3|0.8%|0.0%|
[feodo](#feodo)|62|62|3|4.8%|0.0%|

## ib_bluetack_level2

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 2 (for use in p2p). General corporate ranges. Ranges used by labs or researchers. Proxies.

Source is downloaded from [this link](http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Wed May 27 03:41:02 UTC 2015.

The ipset `ib_bluetack_level2` has **78389** entries, **348732007** unique IPs.

The following table shows the overlaps of `ib_bluetack_level2` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level2`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level2`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level2`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|16317427|2.1%|4.6%|
[et_block](#et_block)|974|18056767|8401959|46.5%|2.4%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|8401434|46.3%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|2832265|2.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2526625|27.5%|0.7%|
[fullbogons](#fullbogons)|3666|670786520|248327|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|33368|7.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|8413|4.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|7752|2.2%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|2453|2.6%|0.0%|
[blocklist_de](#blocklist_de)|23450|23450|1440|6.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15139|15139|1159|7.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12942|12942|1073|8.2%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|894|2.9%|0.0%|
[nixspam](#nixspam)|27666|27666|757|2.7%|0.0%|
[openbl_90d](#openbl_90d)|9899|9899|516|5.2%|0.0%|
[openbl](#openbl)|9899|9899|516|5.2%|0.0%|
[voipbl](#voipbl)|10286|10757|428|3.9%|0.0%|
[openbl_60d](#openbl_60d)|7818|7818|366|4.6%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|270|3.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|233|0.4%|0.0%|
[openbl_30d](#openbl_30d)|4451|4451|230|5.1%|0.0%|
[et_tor](#et_tor)|6400|6400|185|2.8%|0.0%|
[dm_tor](#dm_tor)|6535|6535|184|2.8%|0.0%|
[bm_tor](#bm_tor)|6537|6537|182|2.7%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4122|4122|148|3.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2391|2391|148|6.1%|0.0%|
[et_compromised](#et_compromised)|2292|2292|144|6.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2302|2302|122|5.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|105|1.4%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3496|3496|85|2.4%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1622|1622|73|4.5%|0.0%|
[openbl_7d](#openbl_7d)|1004|1004|51|5.0%|0.0%|
[ciarmy](#ciarmy)|414|414|47|11.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|45|3.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1627|1627|41|2.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|944|944|40|4.2%|0.0%|
[php_spammers](#php_spammers)|378|378|29|7.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|28|4.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|26|2.0%|0.0%|
[malc0de](#malc0de)|414|414|26|6.2%|0.0%|
[et_botnet](#et_botnet)|505|505|21|4.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|559|559|18|3.2%|0.0%|
[openbl_1d](#openbl_1d)|357|357|17|4.7%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|299|299|10|3.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|106|106|10|9.4%|0.0%|
[zeus](#zeus)|267|267|9|3.3%|0.0%|
[php_dictionary](#php_dictionary)|398|398|9|2.2%|0.0%|
[zeus_badips](#zeus_badips)|229|229|8|3.4%|0.0%|
[php_commenters](#php_commenters)|246|246|8|3.2%|0.0%|
[php_bad](#php_bad)|246|246|8|3.2%|0.0%|
[php_harvesters](#php_harvesters)|235|235|7|2.9%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|7|3.1%|0.0%|
[sslbl](#sslbl)|336|336|5|1.4%|0.0%|
[shunlist](#shunlist)|51|51|3|5.8%|0.0%|
[palevo](#palevo)|13|13|3|23.0%|0.0%|
[feodo](#feodo)|62|62|3|4.8%|0.0%|

## ib_bluetack_level3

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 3 (for use in p2p). Many portal-type websites. ISP ranges that may be dodgy for some reason. Ranges that belong to an individual, but which have not been determined to be used by a particular company. Ranges for things that are unusual in some way. The L3 list is aka the paranoid list.

Source is downloaded from [this link](http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Wed May 27 03:40:30 UTC 2015.

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
[et_block](#et_block)|974|18056767|196439|1.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|195904|1.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|14961|8.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|9278|2.7%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|6226|6.7%|0.0%|
[blocklist_de](#blocklist_de)|23450|23450|2878|12.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15139|15139|2284|15.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12942|12942|2225|17.1%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|2067|6.8%|0.0%|
[nixspam](#nixspam)|27666|27666|1720|6.2%|0.0%|
[voipbl](#voipbl)|10286|10757|1587|14.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1172|2.4%|0.0%|
[openbl_90d](#openbl_90d)|9899|9899|959|9.6%|0.0%|
[openbl](#openbl)|9899|9899|959|9.6%|0.0%|
[openbl_60d](#openbl_60d)|7818|7818|717|9.1%|0.0%|
[et_tor](#et_tor)|6400|6400|609|9.5%|0.0%|
[dm_tor](#dm_tor)|6535|6535|608|9.3%|0.0%|
[bm_tor](#bm_tor)|6537|6537|607|9.2%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|564|7.1%|0.0%|
[openbl_30d](#openbl_30d)|4451|4451|444|9.9%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2391|2391|231|9.6%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2302|2302|225|9.7%|0.0%|
[et_compromised](#et_compromised)|2292|2292|222|9.6%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|219|2.9%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|146|11.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3496|3496|145|4.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4122|4122|133|3.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1627|1627|130|7.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|110|7.5%|0.0%|
[openbl_7d](#openbl_7d)|1004|1004|93|9.2%|0.0%|
[malc0de](#malc0de)|414|414|76|18.3%|0.0%|
[et_botnet](#et_botnet)|505|505|73|14.4%|0.0%|
[ciarmy](#ciarmy)|414|414|68|16.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|944|944|64|6.7%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|559|559|54|9.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|51|7.5%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|299|299|40|13.3%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1622|1622|39|2.4%|0.0%|
[php_spammers](#php_spammers)|378|378|24|6.3%|0.0%|
[php_dictionary](#php_dictionary)|398|398|23|5.7%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|106|106|21|19.8%|0.0%|
[zeus](#zeus)|267|267|20|7.4%|0.0%|
[openbl_1d](#openbl_1d)|357|357|20|5.6%|0.0%|
[sslbl](#sslbl)|336|336|19|5.6%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|17|7.5%|0.0%|
[zeus_badips](#zeus_badips)|229|229|14|6.1%|0.0%|
[php_harvesters](#php_harvesters)|235|235|14|5.9%|0.0%|
[php_commenters](#php_commenters)|246|246|12|4.8%|0.0%|
[php_bad](#php_bad)|246|246|12|4.8%|0.0%|
[shunlist](#shunlist)|51|51|6|11.7%|0.0%|
[feodo](#feodo)|62|62|3|4.8%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|

## ib_bluetack_proxies

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Open Proxies IPs list (without TOR)

Source is downloaded from [this link](http://list.iblocklist.com/?list=xoebmbyexwuiogmbyprb&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Wed May 27 03:40:03 UTC 2015.

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
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|12|0.0%|1.7%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|11|0.0%|1.6%|
[ri_web_proxies](#ri_web_proxies)|4122|4122|10|0.2%|1.4%|
[ri_connect_proxies](#ri_connect_proxies)|1622|1622|6|0.3%|0.8%|
[blocklist_de](#blocklist_de)|23450|23450|3|0.0%|0.4%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|2|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.2%|
[nixspam](#nixspam)|27666|27666|2|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.2%|
[et_block](#et_block)|974|18056767|2|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|15139|15139|2|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|1|0.0%|0.1%|
[php_dictionary](#php_dictionary)|398|398|1|0.2%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3496|3496|1|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|1|0.0%|0.1%|

## ib_bluetack_spyware

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) known malicious SPYWARE and ADWARE IP Address ranges

Source is downloaded from [this link](http://list.iblocklist.com/?list=llvtlsjyoyiczbkjsxpf&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Wed May 27 03:10:11 UTC 2015.

The ipset `ib_bluetack_spyware` has **3339** entries, **339461** unique IPs.

The following table shows the overlaps of `ib_bluetack_spyware` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_spyware`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_spyware`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_spyware`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|13328|0.0%|3.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|9278|0.0%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|7752|0.0%|2.2%|
[et_block](#et_block)|974|18056767|1301|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|1037|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1036|0.0%|0.3%|
[fullbogons](#fullbogons)|3666|670786520|894|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|293|0.1%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|46|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|25|1.9%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|21|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|21|0.3%|0.0%|
[dm_tor](#dm_tor)|6535|6535|21|0.3%|0.0%|
[bm_tor](#bm_tor)|6537|6537|21|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|19|1.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|15|0.2%|0.0%|
[nixspam](#nixspam)|27666|27666|14|0.0%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|8|0.1%|0.0%|
[openbl_90d](#openbl_90d)|9899|9899|6|0.0%|0.0%|
[openbl](#openbl)|9899|9899|6|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[blocklist_de](#blocklist_de)|23450|23450|6|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7818|7818|5|0.0%|0.0%|
[dshield](#dshield)|20|5120|5|0.0%|0.0%|
[voipbl](#voipbl)|10286|10757|4|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4122|4122|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4451|4451|4|0.0%|0.0%|
[malc0de](#malc0de)|414|414|3|0.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12942|12942|3|0.0%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|106|106|2|1.8%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15139|15139|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|267|267|1|0.3%|0.0%|
[sslbl](#sslbl)|336|336|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|235|235|1|0.4%|0.0%|
[php_dictionary](#php_dictionary)|398|398|1|0.2%|0.0%|
[openbl_7d](#openbl_7d)|1004|1004|1|0.0%|0.0%|
[feodo](#feodo)|62|62|1|1.6%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|299|299|1|0.3%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2302|2302|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1627|1627|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3496|3496|1|0.0%|0.0%|

## ib_bluetack_webexploit

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) web server hack and exploit attempts

Source is downloaded from [this link](http://list.iblocklist.com/?list=ghlzqtqxnzctvvajwwag&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Wed May 27 03:10:31 UTC 2015.

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
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[et_block](#et_block)|974|18056767|7|0.0%|0.4%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|3|0.2%|0.2%|
[blocklist_de](#blocklist_de)|23450|23450|3|0.0%|0.2%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|2|0.0%|0.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|2|0.0%|0.1%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.1%|
[bruteforceblocker](#bruteforceblocker)|2391|2391|2|0.0%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|2302|2302|2|0.0%|0.1%|
[ri_web_proxies](#ri_web_proxies)|4122|4122|1|0.0%|0.0%|
[openbl_90d](#openbl_90d)|9899|9899|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|1004|1004|1|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7818|7818|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4451|4451|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|357|357|1|0.2%|0.0%|
[openbl](#openbl)|9899|9899|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2292|2292|1|0.0%|0.0%|
[et_botnet](#et_botnet)|505|505|1|0.1%|0.0%|
[dm_tor](#dm_tor)|6535|6535|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6537|6537|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|1|0.4%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3496|3496|1|0.0%|0.0%|

## infiltrated

[infiltrated.net](http://www.infiltrated.net) (this list seems to be updated frequently, but we found no information about it)

Source is downloaded from [this link](http://www.infiltrated.net/blacklisted).

The last time downloaded was found to be dated: Wed May 27 17:40:20 UTC 2015.

The ipset `infiltrated` has **0** entries, **0** unique IPs.

The following table shows the overlaps of `infiltrated` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `infiltrated`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `infiltrated`.
- ` this % ` is the percentage **of this ipset (`infiltrated`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|

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
[clean_mx_viruses](#clean_mx_viruses)|299|299|21|7.0%|5.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|12|0.0%|2.8%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|11|0.0%|2.6%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|4|0.3%|0.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|3|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.4%|
[et_block](#et_block)|974|18056767|2|0.0%|0.4%|
[dshield](#dshield)|20|5120|2|0.0%|0.4%|
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
[et_block](#et_block)|974|18056767|28|0.0%|2.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|26|0.0%|2.0%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|25|0.3%|1.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|25|0.0%|1.9%|
[fullbogons](#fullbogons)|3666|670786520|9|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|6|0.0%|0.4%|
[malc0de](#malc0de)|414|414|4|0.9%|0.3%|
[clean_mx_viruses](#clean_mx_viruses)|299|299|4|1.3%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.2%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|2|0.0%|0.1%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|1|0.0%|0.0%|
[nixspam](#nixspam)|27666|27666|1|0.0%|0.0%|
[et_botnet](#et_botnet)|505|505|1|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3496|3496|1|0.0%|0.0%|
[blocklist_de](#blocklist_de)|23450|23450|1|0.0%|0.0%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Wed May 27 20:45:02 UTC 2015.

The ipset `nixspam` has **27666** entries, **27666** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|1720|0.0%|6.2%|
[blocklist_de](#blocklist_de)|23450|23450|952|4.0%|3.4%|
[blocklist_de_mail](#blocklist_de_mail)|15139|15139|885|5.8%|3.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|757|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|549|0.0%|1.9%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|234|0.2%|0.8%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|199|2.7%|0.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|180|0.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|178|0.0%|0.6%|
[et_block](#et_block)|974|18056767|178|0.0%|0.6%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|137|0.4%|0.4%|
[php_dictionary](#php_dictionary)|398|398|102|25.6%|0.3%|
[ri_web_proxies](#ri_web_proxies)|4122|4122|79|1.9%|0.2%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|74|0.9%|0.2%|
[php_spammers](#php_spammers)|378|378|72|19.0%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3496|3496|49|1.4%|0.1%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|42|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|14|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1622|1622|13|0.8%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1627|1627|12|0.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12942|12942|12|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|11|0.0%|0.0%|
[php_commenters](#php_commenters)|246|246|9|3.6%|0.0%|
[php_bad](#php_bad)|246|246|9|3.6%|0.0%|
[openbl_90d](#openbl_90d)|9899|9899|9|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7818|7818|9|0.1%|0.0%|
[openbl](#openbl)|9899|9899|9|0.0%|0.0%|
[php_harvesters](#php_harvesters)|235|235|6|2.5%|0.0%|
[voipbl](#voipbl)|10286|10757|5|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4451|4451|4|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|944|944|4|0.4%|0.0%|
[dm_tor](#dm_tor)|6535|6535|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6537|6537|3|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2302|2302|3|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|559|559|3|0.5%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[ciarmy](#ciarmy)|414|414|2|0.4%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|2|0.8%|0.0%|
[openbl_7d](#openbl_7d)|1004|1004|1|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2292|2292|1|0.0%|0.0%|
[et_botnet](#et_botnet)|505|505|1|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2391|2391|1|0.0%|0.0%|

## openbl

[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**

Source is downloaded from [this link](http://www.openbl.org/lists/base.txt.gz).

The last time downloaded was found to be dated: Wed May 27 19:17:01 UTC 2015.

The ipset `openbl` has **9899** entries, **9899** unique IPs.

The following table shows the overlaps of `openbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl`.
- ` this % ` is the percentage **of this ipset (`openbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9899|9899|9899|100.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|9872|5.4%|99.7%|
[openbl_60d](#openbl_60d)|7818|7818|7818|100.0%|78.9%|
[openbl_30d](#openbl_30d)|4451|4451|4451|100.0%|44.9%|
[bruteforceblocker](#bruteforceblocker)|2391|2391|1403|58.6%|14.1%|
[et_compromised](#et_compromised)|2292|2292|1376|60.0%|13.9%|
[blocklist_de](#blocklist_de)|23450|23450|1349|5.7%|13.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|2302|2302|1264|54.9%|12.7%|
[openbl_7d](#openbl_7d)|1004|1004|1004|100.0%|10.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|959|0.0%|9.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|516|0.0%|5.2%|
[et_block](#et_block)|974|18056767|453|0.0%|4.5%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|447|0.0%|4.5%|
[openbl_1d](#openbl_1d)|357|357|357|100.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|222|0.0%|2.2%|
[dshield](#dshield)|20|5120|133|2.5%|1.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|76|33.7%|0.7%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|70|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|15139|15139|60|0.3%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|944|944|46|4.8%|0.4%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|38|0.1%|0.3%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|25|0.3%|0.2%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|22|0.2%|0.2%|
[et_tor](#et_tor)|6400|6400|20|0.3%|0.2%|
[dm_tor](#dm_tor)|6535|6535|20|0.3%|0.2%|
[bm_tor](#bm_tor)|6537|6537|20|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|19|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12942|12942|15|0.1%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|14|0.0%|0.1%|
[voipbl](#voipbl)|10286|10757|11|0.1%|0.1%|
[shunlist](#shunlist)|51|51|11|21.5%|0.1%|
[nixspam](#nixspam)|27666|27666|9|0.0%|0.0%|
[php_commenters](#php_commenters)|246|246|8|3.2%|0.0%|
[php_bad](#php_bad)|246|246|8|3.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|559|559|8|1.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|6|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1627|1627|6|0.3%|0.0%|
[php_harvesters](#php_harvesters)|235|235|4|1.7%|0.0%|
[zeus](#zeus)|267|267|2|0.7%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3496|3496|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[sslbl](#sslbl)|336|336|1|0.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4122|4122|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ciarmy](#ciarmy)|414|414|1|0.2%|0.0%|

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
[openbl_90d](#openbl_90d)|9899|9899|357|3.6%|100.0%|
[openbl_60d](#openbl_60d)|7818|7818|357|4.5%|100.0%|
[openbl_30d](#openbl_30d)|4451|4451|357|8.0%|100.0%|
[openbl](#openbl)|9899|9899|357|3.6%|100.0%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|355|0.1%|99.4%|
[blocklist_de](#blocklist_de)|23450|23450|251|1.0%|70.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|2302|2302|242|10.5%|67.7%|
[openbl_7d](#openbl_7d)|1004|1004|208|20.7%|58.2%|
[bruteforceblocker](#bruteforceblocker)|2391|2391|207|8.6%|57.9%|
[et_compromised](#et_compromised)|2292|2292|204|8.9%|57.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|68|30.2%|19.0%|
[dshield](#dshield)|20|5120|65|1.2%|18.2%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|26|0.0%|7.2%|
[et_block](#et_block)|974|18056767|26|0.0%|7.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|20|0.0%|5.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|17|0.0%|4.7%|
[blocklist_de_mail](#blocklist_de_mail)|15139|15139|8|0.0%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|7|0.0%|1.9%|
[blocklist_de_imap](#blocklist_de_imap)|944|944|6|0.6%|1.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|1.4%|
[shunlist](#shunlist)|51|51|2|3.9%|0.5%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|1|0.0%|0.2%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|559|559|1|0.1%|0.2%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt.gz).

The last time downloaded was found to be dated: Wed May 27 19:17:00 UTC 2015.

The ipset `openbl_30d` has **4451** entries, **4451** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9899|9899|4451|44.9%|100.0%|
[openbl_60d](#openbl_60d)|7818|7818|4451|56.9%|100.0%|
[openbl](#openbl)|9899|9899|4451|44.9%|100.0%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|4435|2.4%|99.6%|
[bruteforceblocker](#bruteforceblocker)|2391|2391|1331|55.6%|29.9%|
[et_compromised](#et_compromised)|2292|2292|1307|57.0%|29.3%|
[blocklist_de](#blocklist_de)|23450|23450|1189|5.0%|26.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|2302|2302|1132|49.1%|25.4%|
[openbl_7d](#openbl_7d)|1004|1004|1004|100.0%|22.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|444|0.0%|9.9%|
[openbl_1d](#openbl_1d)|357|357|357|100.0%|8.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|230|0.0%|5.1%|
[et_block](#et_block)|974|18056767|214|0.0%|4.8%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|211|0.0%|4.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|102|0.0%|2.2%|
[dshield](#dshield)|20|5120|102|1.9%|2.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|74|32.8%|1.6%|
[blocklist_de_mail](#blocklist_de_mail)|15139|15139|48|0.3%|1.0%|
[blocklist_de_imap](#blocklist_de_imap)|944|944|37|3.9%|0.8%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|21|0.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|13|0.0%|0.2%|
[shunlist](#shunlist)|51|51|10|19.6%|0.2%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|7|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12942|12942|7|0.0%|0.1%|
[nixspam](#nixspam)|27666|27666|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|4|0.0%|0.0%|
[voipbl](#voipbl)|10286|10757|3|0.0%|0.0%|
[zeus](#zeus)|267|267|2|0.7%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|2|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|559|559|2|0.3%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ciarmy](#ciarmy)|414|414|1|0.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1627|1627|1|0.0%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt.gz).

The last time downloaded was found to be dated: Wed May 27 19:17:00 UTC 2015.

The ipset `openbl_60d` has **7818** entries, **7818** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9899|9899|7818|78.9%|100.0%|
[openbl](#openbl)|9899|9899|7818|78.9%|100.0%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|7794|4.3%|99.6%|
[openbl_30d](#openbl_30d)|4451|4451|4451|100.0%|56.9%|
[bruteforceblocker](#bruteforceblocker)|2391|2391|1391|58.1%|17.7%|
[et_compromised](#et_compromised)|2292|2292|1366|59.5%|17.4%|
[blocklist_de](#blocklist_de)|23450|23450|1295|5.5%|16.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|2302|2302|1222|53.0%|15.6%|
[openbl_7d](#openbl_7d)|1004|1004|1004|100.0%|12.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|717|0.0%|9.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|366|0.0%|4.6%|
[openbl_1d](#openbl_1d)|357|357|357|100.0%|4.5%|
[et_block](#et_block)|974|18056767|304|0.0%|3.8%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|301|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|183|0.0%|2.3%|
[dshield](#dshield)|20|5120|126|2.4%|1.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|76|33.7%|0.9%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|63|0.0%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|15139|15139|56|0.3%|0.7%|
[blocklist_de_imap](#blocklist_de_imap)|944|944|42|4.4%|0.5%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|35|0.1%|0.4%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|25|0.3%|0.3%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|20|0.2%|0.2%|
[et_tor](#et_tor)|6400|6400|20|0.3%|0.2%|
[dm_tor](#dm_tor)|6535|6535|20|0.3%|0.2%|
[bm_tor](#bm_tor)|6537|6537|20|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|18|0.0%|0.2%|
[shunlist](#shunlist)|51|51|11|21.5%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12942|12942|10|0.0%|0.1%|
[voipbl](#voipbl)|10286|10757|9|0.0%|0.1%|
[nixspam](#nixspam)|27666|27666|9|0.0%|0.1%|
[php_commenters](#php_commenters)|246|246|8|3.2%|0.1%|
[php_bad](#php_bad)|246|246|8|3.2%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|559|559|7|1.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|5|0.0%|0.0%|
[php_harvesters](#php_harvesters)|235|235|4|1.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1627|1627|3|0.1%|0.0%|
[zeus](#zeus)|267|267|2|0.7%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ciarmy](#ciarmy)|414|414|1|0.2%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt.gz).

The last time downloaded was found to be dated: Wed May 27 19:17:00 UTC 2015.

The ipset `openbl_7d` has **1004** entries, **1004** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9899|9899|1004|10.1%|100.0%|
[openbl_60d](#openbl_60d)|7818|7818|1004|12.8%|100.0%|
[openbl_30d](#openbl_30d)|4451|4451|1004|22.5%|100.0%|
[openbl](#openbl)|9899|9899|1004|10.1%|100.0%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|993|0.5%|98.9%|
[blocklist_de](#blocklist_de)|23450|23450|676|2.8%|67.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|2302|2302|644|27.9%|64.1%|
[bruteforceblocker](#bruteforceblocker)|2391|2391|507|21.2%|50.4%|
[et_compromised](#et_compromised)|2292|2292|494|21.5%|49.2%|
[openbl_1d](#openbl_1d)|357|357|208|58.2%|20.7%|
[et_block](#et_block)|974|18056767|98|0.0%|9.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|97|0.0%|9.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|93|0.0%|9.2%|
[dshield](#dshield)|20|5120|88|1.7%|8.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|73|32.4%|7.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|51|0.0%|5.0%|
[blocklist_de_mail](#blocklist_de_mail)|15139|15139|26|0.1%|2.5%|
[blocklist_de_imap](#blocklist_de_imap)|944|944|23|2.4%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|20|0.0%|1.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|9|0.0%|0.8%|
[shunlist](#shunlist)|51|51|6|11.7%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|12942|12942|5|0.0%|0.4%|
[voipbl](#voipbl)|10286|10757|2|0.0%|0.1%|
[zeus](#zeus)|267|267|1|0.3%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|1|0.0%|0.0%|
[nixspam](#nixspam)|27666|27666|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.0%|
[ciarmy](#ciarmy)|414|414|1|0.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|559|559|1|0.1%|0.0%|

## openbl_90d

[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_90days.txt.gz).

The last time downloaded was found to be dated: Wed May 27 19:17:01 UTC 2015.

The ipset `openbl_90d` has **9899** entries, **9899** unique IPs.

The following table shows the overlaps of `openbl_90d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_90d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_90d`.
- ` this % ` is the percentage **of this ipset (`openbl_90d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl](#openbl)|9899|9899|9899|100.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|9872|5.4%|99.7%|
[openbl_60d](#openbl_60d)|7818|7818|7818|100.0%|78.9%|
[openbl_30d](#openbl_30d)|4451|4451|4451|100.0%|44.9%|
[bruteforceblocker](#bruteforceblocker)|2391|2391|1403|58.6%|14.1%|
[et_compromised](#et_compromised)|2292|2292|1376|60.0%|13.9%|
[blocklist_de](#blocklist_de)|23450|23450|1349|5.7%|13.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|2302|2302|1264|54.9%|12.7%|
[openbl_7d](#openbl_7d)|1004|1004|1004|100.0%|10.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|959|0.0%|9.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|516|0.0%|5.2%|
[et_block](#et_block)|974|18056767|453|0.0%|4.5%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|447|0.0%|4.5%|
[openbl_1d](#openbl_1d)|357|357|357|100.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|222|0.0%|2.2%|
[dshield](#dshield)|20|5120|133|2.5%|1.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|76|33.7%|0.7%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|70|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|15139|15139|60|0.3%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|944|944|46|4.8%|0.4%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|38|0.1%|0.3%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|25|0.3%|0.2%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|22|0.2%|0.2%|
[et_tor](#et_tor)|6400|6400|20|0.3%|0.2%|
[dm_tor](#dm_tor)|6535|6535|20|0.3%|0.2%|
[bm_tor](#bm_tor)|6537|6537|20|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|19|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12942|12942|15|0.1%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|14|0.0%|0.1%|
[voipbl](#voipbl)|10286|10757|11|0.1%|0.1%|
[shunlist](#shunlist)|51|51|11|21.5%|0.1%|
[nixspam](#nixspam)|27666|27666|9|0.0%|0.0%|
[php_commenters](#php_commenters)|246|246|8|3.2%|0.0%|
[php_bad](#php_bad)|246|246|8|3.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|559|559|8|1.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|6|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1627|1627|6|0.3%|0.0%|
[php_harvesters](#php_harvesters)|235|235|4|1.7%|0.0%|
[zeus](#zeus)|267|267|2|0.7%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3496|3496|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[sslbl](#sslbl)|336|336|1|0.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4122|4122|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ciarmy](#ciarmy)|414|414|1|0.2%|0.0%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Wed May 27 20:51:02 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|974|18056767|13|0.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|11|0.1%|84.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|3|0.0%|23.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|2|0.0%|15.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|1|0.0%|7.6%|

## php_bad

[projecthoneypot.org](http://www.projecthoneypot.org/) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1).

The last time downloaded was found to be dated: Wed May 27 20:20:24 UTC 2015.

The ipset `php_bad` has **246** entries, **246** unique IPs.

The following table shows the overlaps of `php_bad` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_bad`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_bad`.
- ` this % ` is the percentage **of this ipset (`php_bad`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[php_commenters](#php_commenters)|246|246|245|99.5%|99.5%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|180|0.1%|73.1%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|175|0.5%|71.1%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|111|1.4%|45.1%|
[blocklist_de](#blocklist_de)|23450|23450|75|0.3%|30.4%|
[blocklist_de_bots](#blocklist_de_bots)|3496|3496|63|1.8%|25.6%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|37|0.5%|15.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|32|14.2%|13.0%|
[et_tor](#et_tor)|6400|6400|28|0.4%|11.3%|
[dm_tor](#dm_tor)|6535|6535|28|0.4%|11.3%|
[bm_tor](#bm_tor)|6537|6537|28|0.4%|11.3%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|25|0.0%|10.1%|
[php_spammers](#php_spammers)|378|378|25|6.6%|10.1%|
[et_block](#et_block)|974|18056767|24|0.0%|9.7%|
[blocklist_de_apache](#blocklist_de_apache)|12942|12942|21|0.1%|8.5%|
[blocklist_de_mail](#blocklist_de_mail)|15139|15139|19|0.1%|7.7%|
[php_dictionary](#php_dictionary)|398|398|15|3.7%|6.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|12|0.0%|4.8%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|12|0.0%|4.8%|
[php_harvesters](#php_harvesters)|235|235|9|3.8%|3.6%|
[nixspam](#nixspam)|27666|27666|9|0.0%|3.6%|
[openbl_90d](#openbl_90d)|9899|9899|8|0.0%|3.2%|
[openbl_60d](#openbl_60d)|7818|7818|8|0.1%|3.2%|
[openbl](#openbl)|9899|9899|8|0.0%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|8|0.0%|3.2%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|7|0.0%|2.8%|
[ri_web_proxies](#ri_web_proxies)|4122|4122|7|0.1%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|5|0.0%|2.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1627|1627|4|0.2%|1.6%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.4%|
[zeus](#zeus)|267|267|1|0.3%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.4%|

## php_commenters

[projecthoneypot.org](http://www.projecthoneypot.org/) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1).

The last time downloaded was found to be dated: Wed May 27 20:20:25 UTC 2015.

The ipset `php_commenters` has **246** entries, **246** unique IPs.

The following table shows the overlaps of `php_commenters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_commenters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_commenters`.
- ` this % ` is the percentage **of this ipset (`php_commenters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[php_bad](#php_bad)|246|246|245|99.5%|99.5%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|181|0.1%|73.5%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|176|0.5%|71.5%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|112|1.4%|45.5%|
[blocklist_de](#blocklist_de)|23450|23450|75|0.3%|30.4%|
[blocklist_de_bots](#blocklist_de_bots)|3496|3496|63|1.8%|25.6%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|36|0.4%|14.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|32|14.2%|13.0%|
[et_tor](#et_tor)|6400|6400|28|0.4%|11.3%|
[dm_tor](#dm_tor)|6535|6535|28|0.4%|11.3%|
[bm_tor](#bm_tor)|6537|6537|28|0.4%|11.3%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|25|0.0%|10.1%|
[php_spammers](#php_spammers)|378|378|24|6.3%|9.7%|
[et_block](#et_block)|974|18056767|24|0.0%|9.7%|
[blocklist_de_apache](#blocklist_de_apache)|12942|12942|21|0.1%|8.5%|
[blocklist_de_mail](#blocklist_de_mail)|15139|15139|19|0.1%|7.7%|
[php_dictionary](#php_dictionary)|398|398|14|3.5%|5.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|12|0.0%|4.8%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|12|0.0%|4.8%|
[php_harvesters](#php_harvesters)|235|235|9|3.8%|3.6%|
[nixspam](#nixspam)|27666|27666|9|0.0%|3.6%|
[openbl_90d](#openbl_90d)|9899|9899|8|0.0%|3.2%|
[openbl_60d](#openbl_60d)|7818|7818|8|0.1%|3.2%|
[openbl](#openbl)|9899|9899|8|0.0%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|8|0.0%|3.2%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|7|0.0%|2.8%|
[ri_web_proxies](#ri_web_proxies)|4122|4122|7|0.1%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|5|0.0%|2.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1627|1627|4|0.2%|1.6%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.4%|
[zeus](#zeus)|267|267|1|0.3%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.4%|

## php_dictionary

[projecthoneypot.org](http://www.projecthoneypot.org/) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1).

The last time downloaded was found to be dated: Wed May 27 20:20:26 UTC 2015.

The ipset `php_dictionary` has **398** entries, **398** unique IPs.

The following table shows the overlaps of `php_dictionary` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_dictionary`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_dictionary`.
- ` this % ` is the percentage **of this ipset (`php_dictionary`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[nixspam](#nixspam)|27666|27666|102|0.3%|25.6%|
[blocklist_de](#blocklist_de)|23450|23450|79|0.3%|19.8%|
[php_spammers](#php_spammers)|378|378|74|19.5%|18.5%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|70|0.9%|17.5%|
[blocklist_de_mail](#blocklist_de_mail)|15139|15139|65|0.4%|16.3%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|61|0.0%|15.3%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|48|0.1%|12.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|34|0.4%|8.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|23|0.0%|5.7%|
[ri_web_proxies](#ri_web_proxies)|4122|4122|19|0.4%|4.7%|
[php_bad](#php_bad)|246|246|15|6.0%|3.7%|
[php_commenters](#php_commenters)|246|246|14|5.6%|3.5%|
[blocklist_de_bots](#blocklist_de_bots)|3496|3496|14|0.4%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|9|0.0%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|9|0.0%|2.2%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|7|0.0%|1.7%|
[dm_tor](#dm_tor)|6535|6535|4|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|3|0.0%|0.7%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.7%|
[et_block](#et_block)|974|18056767|3|0.0%|0.7%|
[bm_tor](#bm_tor)|6537|6537|3|0.0%|0.7%|
[ri_connect_proxies](#ri_connect_proxies)|1622|1622|2|0.1%|0.5%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.5%|
[php_harvesters](#php_harvesters)|235|235|1|0.4%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|1|0.4%|0.2%|

## php_harvesters

[projecthoneypot.org](http://www.projecthoneypot.org/) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1).

The last time downloaded was found to be dated: Wed May 27 20:20:22 UTC 2015.

The ipset `php_harvesters` has **235** entries, **235** unique IPs.

The following table shows the overlaps of `php_harvesters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_harvesters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_harvesters`.
- ` this % ` is the percentage **of this ipset (`php_harvesters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|59|0.0%|25.1%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|48|0.1%|20.4%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|30|0.3%|12.7%|
[blocklist_de](#blocklist_de)|23450|23450|26|0.1%|11.0%|
[blocklist_de_bots](#blocklist_de_bots)|3496|3496|20|0.5%|8.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|14|0.0%|5.9%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|9|0.1%|3.8%|
[php_commenters](#php_commenters)|246|246|9|3.6%|3.8%|
[php_bad](#php_bad)|246|246|9|3.6%|3.8%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|9|0.0%|3.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|7|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|7|0.0%|2.9%|
[et_tor](#et_tor)|6400|6400|7|0.1%|2.9%|
[dm_tor](#dm_tor)|6535|6535|7|0.1%|2.9%|
[bm_tor](#bm_tor)|6537|6537|7|0.1%|2.9%|
[nixspam](#nixspam)|27666|27666|6|0.0%|2.5%|
[openbl_90d](#openbl_90d)|9899|9899|4|0.0%|1.7%|
[openbl_60d](#openbl_60d)|7818|7818|4|0.0%|1.7%|
[openbl](#openbl)|9899|9899|4|0.0%|1.7%|
[blocklist_de_ftp](#blocklist_de_ftp)|559|559|4|0.7%|1.7%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|15139|15139|2|0.0%|0.8%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|1|0.0%|0.4%|
[ri_web_proxies](#ri_web_proxies)|4122|4122|1|0.0%|0.4%|
[php_spammers](#php_spammers)|378|378|1|0.2%|0.4%|
[php_dictionary](#php_dictionary)|398|398|1|0.2%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.4%|
[fullbogons](#fullbogons)|3666|670786520|1|0.0%|0.4%|
[et_block](#et_block)|974|18056767|1|0.0%|0.4%|
[bogons](#bogons)|13|592708608|1|0.0%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|1|0.4%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|12942|12942|1|0.0%|0.4%|

## php_spammers

[projecthoneypot.org](http://www.projecthoneypot.org/) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1).

The last time downloaded was found to be dated: Wed May 27 20:20:23 UTC 2015.

The ipset `php_spammers` has **378** entries, **378** unique IPs.

The following table shows the overlaps of `php_spammers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_spammers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_spammers`.
- ` this % ` is the percentage **of this ipset (`php_spammers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|81|0.0%|21.4%|
[php_dictionary](#php_dictionary)|398|398|74|18.5%|19.5%|
[nixspam](#nixspam)|27666|27666|72|0.2%|19.0%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|63|0.8%|16.6%|
[blocklist_de](#blocklist_de)|23450|23450|63|0.2%|16.6%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|57|0.1%|15.0%|
[blocklist_de_mail](#blocklist_de_mail)|15139|15139|44|0.2%|11.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|29|0.0%|7.6%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|28|0.3%|7.4%|
[php_bad](#php_bad)|246|246|25|10.1%|6.6%|
[php_commenters](#php_commenters)|246|246|24|9.7%|6.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|24|0.0%|6.3%|
[ri_web_proxies](#ri_web_proxies)|4122|4122|16|0.3%|4.2%|
[blocklist_de_bots](#blocklist_de_bots)|3496|3496|14|0.4%|3.7%|
[et_tor](#et_tor)|6400|6400|6|0.0%|1.5%|
[dm_tor](#dm_tor)|6535|6535|6|0.0%|1.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|5|0.0%|1.3%|
[bm_tor](#bm_tor)|6537|6537|5|0.0%|1.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|5|2.2%|1.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1627|1627|4|0.2%|1.0%|
[blocklist_de_apache](#blocklist_de_apache)|12942|12942|4|0.0%|1.0%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|4|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.5%|
[ri_connect_proxies](#ri_connect_proxies)|1622|1622|2|0.1%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.5%|
[et_block](#et_block)|974|18056767|2|0.0%|0.5%|
[php_harvesters](#php_harvesters)|235|235|1|0.4%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2302|2302|1|0.0%|0.2%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Wed May 27 14:08:47 UTC 2015.

The ipset `ri_connect_proxies` has **1622** entries, **1622** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|938|1.0%|57.8%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|699|2.3%|43.0%|
[ri_web_proxies](#ri_web_proxies)|4122|4122|657|15.9%|40.5%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|186|2.3%|11.4%|
[blocklist_de](#blocklist_de)|23450|23450|78|0.3%|4.8%|
[blocklist_de_bots](#blocklist_de_bots)|3496|3496|76|2.1%|4.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|73|0.0%|4.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|59|0.0%|3.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|39|0.0%|2.4%|
[nixspam](#nixspam)|27666|27666|13|0.0%|0.8%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.3%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|4|0.0%|0.2%|
[php_spammers](#php_spammers)|378|378|2|0.5%|0.1%|
[php_dictionary](#php_dictionary)|398|398|2|0.5%|0.1%|
[et_tor](#et_tor)|6400|6400|2|0.0%|0.1%|
[dm_tor](#dm_tor)|6535|6535|2|0.0%|0.1%|
[bm_tor](#bm_tor)|6537|6537|2|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|15139|15139|2|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Wed May 27 17:38:27 UTC 2015.

The ipset `ri_web_proxies` has **4122** entries, **4122** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|1990|2.1%|48.2%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|1577|5.2%|38.2%|
[ri_connect_proxies](#ri_connect_proxies)|1622|1622|657|40.5%|15.9%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|554|7.0%|13.4%|
[blocklist_de](#blocklist_de)|23450|23450|378|1.6%|9.1%|
[blocklist_de_bots](#blocklist_de_bots)|3496|3496|346|9.8%|8.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|148|0.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|133|0.0%|3.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|95|0.0%|2.3%|
[nixspam](#nixspam)|27666|27666|79|0.2%|1.9%|
[blocklist_de_mail](#blocklist_de_mail)|15139|15139|31|0.2%|0.7%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|30|0.4%|0.7%|
[php_dictionary](#php_dictionary)|398|398|19|4.7%|0.4%|
[php_spammers](#php_spammers)|378|378|16|4.2%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|10|1.4%|0.2%|
[php_commenters](#php_commenters)|246|246|7|2.8%|0.1%|
[php_bad](#php_bad)|246|246|7|2.8%|0.1%|
[et_tor](#et_tor)|6400|6400|5|0.0%|0.1%|
[bm_tor](#bm_tor)|6537|6537|5|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6535|6535|4|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|3|1.3%|0.0%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|235|235|1|0.4%|0.0%|
[openbl_90d](#openbl_90d)|9899|9899|1|0.0%|0.0%|
[openbl](#openbl)|9899|9899|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|299|299|1|0.3%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2302|2302|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Wed May 27 18:30:03 UTC 2015.

The ipset `shunlist` has **51** entries, **51** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|179777|179777|50|0.0%|98.0%|
[openbl_90d](#openbl_90d)|9899|9899|11|0.1%|21.5%|
[openbl_60d](#openbl_60d)|7818|7818|11|0.1%|21.5%|
[openbl](#openbl)|9899|9899|11|0.1%|21.5%|
[blocklist_de](#blocklist_de)|23450|23450|11|0.0%|21.5%|
[openbl_30d](#openbl_30d)|4451|4451|10|0.2%|19.6%|
[et_compromised](#et_compromised)|2292|2292|9|0.3%|17.6%|
[bruteforceblocker](#bruteforceblocker)|2391|2391|9|0.3%|17.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|2302|2302|8|0.3%|15.6%|
[openbl_7d](#openbl_7d)|1004|1004|6|0.5%|11.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|6|0.0%|11.7%|
[voipbl](#voipbl)|10286|10757|3|0.0%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|3|0.0%|5.8%|
[openbl_1d](#openbl_1d)|357|357|2|0.5%|3.9%|
[blocklist_de_apache](#blocklist_de_apache)|12942|12942|2|0.0%|3.9%|
[ciarmy](#ciarmy)|414|414|1|0.2%|1.9%|
[blocklist_de_mail](#blocklist_de_mail)|15139|15139|1|0.0%|1.9%|
[blocklist_de_imap](#blocklist_de_imap)|944|944|1|0.1%|1.9%|

## snort_ipfilter

[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)

Source is downloaded from [this link](http://labs.snort.org/feeds/ip-filter.blf).

The last time downloaded was found to be dated: Wed May 27 12:30:00 UTC 2015.

The ipset `snort_ipfilter` has **7341** entries, **7341** unique IPs.

The following table shows the overlaps of `snort_ipfilter` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `snort_ipfilter`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `snort_ipfilter`.
- ` this % ` is the percentage **of this ipset (`snort_ipfilter`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_tor](#et_tor)|6400|6400|1085|16.9%|14.7%|
[dm_tor](#dm_tor)|6535|6535|1051|16.0%|14.3%|
[bm_tor](#bm_tor)|6537|6537|1045|15.9%|14.2%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|695|0.7%|9.4%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|526|1.7%|7.1%|
[et_block](#et_block)|974|18056767|286|0.0%|3.8%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|275|3.4%|3.7%|
[zeus](#zeus)|267|267|226|84.6%|3.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|219|0.0%|2.9%|
[zeus_badips](#zeus_badips)|229|229|200|87.3%|2.7%|
[nixspam](#nixspam)|27666|27666|199|0.7%|2.7%|
[blocklist_de](#blocklist_de)|23450|23450|193|0.8%|2.6%|
[blocklist_de_mail](#blocklist_de_mail)|15139|15139|125|0.8%|1.7%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|122|0.0%|1.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|105|0.0%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|91|0.0%|1.2%|
[php_dictionary](#php_dictionary)|398|398|70|17.5%|0.9%|
[php_spammers](#php_spammers)|378|378|63|16.6%|0.8%|
[blocklist_de_apache](#blocklist_de_apache)|12942|12942|50|0.3%|0.6%|
[feodo](#feodo)|62|62|48|77.4%|0.6%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1627|1627|47|2.8%|0.6%|
[php_bad](#php_bad)|246|246|37|15.0%|0.5%|
[php_commenters](#php_commenters)|246|246|36|14.6%|0.4%|
[ri_web_proxies](#ri_web_proxies)|4122|4122|30|0.7%|0.4%|
[openbl_90d](#openbl_90d)|9899|9899|25|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7818|7818|25|0.3%|0.3%|
[openbl](#openbl)|9899|9899|25|0.2%|0.3%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|25|1.9%|0.3%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|20|0.0%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3496|3496|18|0.5%|0.2%|
[sslbl](#sslbl)|336|336|17|5.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|15|0.0%|0.2%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.1%|
[php_harvesters](#php_harvesters)|235|235|9|3.8%|0.1%|
[clean_mx_viruses](#clean_mx_viruses)|299|299|9|3.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|6|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1622|1622|4|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2302|2302|3|0.1%|0.0%|
[openbl_30d](#openbl_30d)|4451|4451|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[voipbl](#voipbl)|10286|10757|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|1004|1004|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2292|2292|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2391|2391|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|1|0.4%|0.0%|

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
[et_block](#et_block)|974|18056767|18051584|99.9%|99.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|8401434|2.4%|46.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7211008|78.5%|39.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|2133002|0.2%|11.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|195904|0.1%|1.0%|
[fullbogons](#fullbogons)|3666|670786520|20480|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|1624|0.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1037|0.3%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|788|0.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|512|0.1%|0.0%|
[openbl_90d](#openbl_90d)|9899|9899|447|4.5%|0.0%|
[openbl](#openbl)|9899|9899|447|4.5%|0.0%|
[openbl_60d](#openbl_60d)|7818|7818|301|3.8%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|246|0.8%|0.0%|
[openbl_30d](#openbl_30d)|4451|4451|211|4.7%|0.0%|
[blocklist_de](#blocklist_de)|23450|23450|189|0.8%|0.0%|
[nixspam](#nixspam)|27666|27666|180|0.6%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2302|2302|115|4.9%|0.0%|
[openbl_7d](#openbl_7d)|1004|1004|97|9.6%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2391|2391|96|4.0%|0.0%|
[et_compromised](#et_compromised)|2292|2292|90|3.9%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|56|0.7%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3496|3496|46|1.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|28|2.1%|0.0%|
[openbl_1d](#openbl_1d)|357|357|26|7.2%|0.0%|
[php_commenters](#php_commenters)|246|246|25|10.1%|0.0%|
[php_bad](#php_bad)|246|246|25|10.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15139|15139|22|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|20|0.2%|0.0%|
[zeus_badips](#zeus_badips)|229|229|16|6.9%|0.0%|
[zeus](#zeus)|267|267|16|5.9%|0.0%|
[voipbl](#voipbl)|10286|10757|14|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|944|944|12|1.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|6|2.6%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1627|1627|5|0.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12942|12942|5|0.0%|0.0%|
[sslbl](#sslbl)|336|336|3|0.8%|0.0%|
[php_dictionary](#php_dictionary)|398|398|3|0.7%|0.0%|
[php_spammers](#php_spammers)|378|378|2|0.5%|0.0%|
[malc0de](#malc0de)|414|414|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6400|6400|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6535|6535|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6537|6537|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|235|235|1|0.4%|0.0%|
[et_botnet](#et_botnet)|505|505|1|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|559|559|1|0.1%|0.0%|

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
[et_block](#et_block)|974|18056767|517|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|512|0.0%|0.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|109|0.1%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|41|0.1%|0.0%|
[blocklist_de](#blocklist_de)|23450|23450|40|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3496|3496|34|0.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|15|0.0%|0.0%|
[openbl_90d](#openbl_90d)|9899|9899|14|0.1%|0.0%|
[openbl](#openbl)|9899|9899|14|0.1%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|10|0.1%|0.0%|
[php_commenters](#php_commenters)|246|246|7|2.8%|0.0%|
[php_bad](#php_bad)|246|246|7|2.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|6|2.6%|0.0%|
[zeus_badips](#zeus_badips)|229|229|5|2.1%|0.0%|
[zeus](#zeus)|267|267|5|1.8%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15139|15139|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12942|12942|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|235|235|1|0.4%|0.0%|
[openbl_60d](#openbl_60d)|7818|7818|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4451|4451|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|357|357|1|0.2%|0.0%|
[malc0de](#malc0de)|414|414|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|944|944|1|0.1%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Wed May 27 20:30:06 UTC 2015.

The ipset `sslbl` has **336** entries, **336** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|974|18056767|23|0.0%|6.8%|
[feodo](#feodo)|62|62|20|32.2%|5.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|19|0.0%|5.6%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|17|0.2%|5.0%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|7|0.0%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|5|0.0%|1.4%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|3|0.0%|0.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|3|0.0%|0.8%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|1|0.0%|0.2%|
[openbl_90d](#openbl_90d)|9899|9899|1|0.0%|0.2%|
[openbl](#openbl)|9899|9899|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.2%|

## stop_forum_spam_1h

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Wed May 27 20:40:29 UTC 2015.

The ipset `stop_forum_spam_1h` has **7897** entries, **7897** unique IPs.

The following table shows the overlaps of `stop_forum_spam_1h` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stop_forum_spam_1h`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stop_forum_spam_1h`.
- ` this % ` is the percentage **of this ipset (`stop_forum_spam_1h`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|5334|17.6%|67.5%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|4498|4.8%|56.9%|
[blocklist_de](#blocklist_de)|23450|23450|1487|6.3%|18.8%|
[blocklist_de_bots](#blocklist_de_bots)|3496|3496|1398|39.9%|17.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|564|0.0%|7.1%|
[ri_web_proxies](#ri_web_proxies)|4122|4122|554|13.4%|7.0%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|275|3.7%|3.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|270|0.0%|3.4%|
[et_tor](#et_tor)|6400|6400|231|3.6%|2.9%|
[dm_tor](#dm_tor)|6535|6535|229|3.5%|2.8%|
[bm_tor](#bm_tor)|6537|6537|229|3.5%|2.8%|
[ri_connect_proxies](#ri_connect_proxies)|1622|1622|186|11.4%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|155|0.0%|1.9%|
[php_commenters](#php_commenters)|246|246|112|45.5%|1.4%|
[php_bad](#php_bad)|246|246|111|45.1%|1.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|102|45.3%|1.2%|
[blocklist_de_apache](#blocklist_de_apache)|12942|12942|81|0.6%|1.0%|
[nixspam](#nixspam)|27666|27666|74|0.2%|0.9%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|57|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|56|0.0%|0.7%|
[et_block](#et_block)|974|18056767|54|0.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|15139|15139|49|0.3%|0.6%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1627|1627|42|2.5%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|35|0.0%|0.4%|
[php_dictionary](#php_dictionary)|398|398|34|8.5%|0.4%|
[php_harvesters](#php_harvesters)|235|235|30|12.7%|0.3%|
[php_spammers](#php_spammers)|378|378|28|7.4%|0.3%|
[openbl_90d](#openbl_90d)|9899|9899|22|0.2%|0.2%|
[openbl](#openbl)|9899|9899|22|0.2%|0.2%|
[openbl_60d](#openbl_60d)|7818|7818|20|0.2%|0.2%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|10|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|8|0.0%|0.1%|
[voipbl](#voipbl)|10286|10757|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4451|4451|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|559|559|2|0.3%|0.0%|

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
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|28354|93.9%|30.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|6226|0.0%|6.7%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|4498|56.9%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|2453|0.0%|2.6%|
[blocklist_de](#blocklist_de)|23450|23450|2398|10.2%|2.5%|
[blocklist_de_bots](#blocklist_de_bots)|3496|3496|2111|60.3%|2.2%|
[ri_web_proxies](#ri_web_proxies)|4122|4122|1990|48.2%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|1498|0.0%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|1622|1622|938|57.8%|1.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|788|0.0%|0.8%|
[et_block](#et_block)|974|18056767|771|0.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|737|0.0%|0.7%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|695|9.4%|0.7%|
[et_tor](#et_tor)|6400|6400|580|9.0%|0.6%|
[dm_tor](#dm_tor)|6535|6535|570|8.7%|0.6%|
[bm_tor](#bm_tor)|6537|6537|566|8.6%|0.6%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|240|0.1%|0.2%|
[nixspam](#nixspam)|27666|27666|234|0.8%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|12942|12942|207|1.5%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|15139|15139|191|1.2%|0.2%|
[php_commenters](#php_commenters)|246|246|181|73.5%|0.1%|
[php_bad](#php_bad)|246|246|180|73.1%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|125|55.5%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|109|0.0%|0.1%|
[php_spammers](#php_spammers)|378|378|81|21.4%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1627|1627|72|4.4%|0.0%|
[openbl_90d](#openbl_90d)|9899|9899|70|0.7%|0.0%|
[openbl](#openbl)|9899|9899|70|0.7%|0.0%|
[openbl_60d](#openbl_60d)|7818|7818|63|0.8%|0.0%|
[php_dictionary](#php_dictionary)|398|398|61|15.3%|0.0%|
[php_harvesters](#php_harvesters)|235|235|59|25.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|46|0.0%|0.0%|
[voipbl](#voipbl)|10286|10757|39|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|24|3.5%|0.0%|
[openbl_30d](#openbl_30d)|4451|4451|21|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2302|2302|9|0.3%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|559|559|9|1.6%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2391|2391|6|0.2%|0.0%|
[et_compromised](#et_compromised)|2292|2292|5|0.2%|0.0%|
[zeus](#zeus)|267|267|4|1.4%|0.0%|
[zeus_badips](#zeus_badips)|229|229|3|1.3%|0.0%|
[fullbogons](#fullbogons)|3666|670786520|3|0.0%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|299|299|3|1.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|2|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[sslbl](#sslbl)|336|336|1|0.2%|0.0%|
[openbl_7d](#openbl_7d)|1004|1004|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|357|357|1|0.2%|0.0%|
[ciarmy](#ciarmy)|414|414|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|944|944|1|0.1%|0.0%|

## stop_forum_spam_7d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip).

The last time downloaded was found to be dated: Wed May 27 02:00:07 UTC 2015.

The ipset `stop_forum_spam_7d` has **30172** entries, **30172** unique IPs.

The following table shows the overlaps of `stop_forum_spam_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stop_forum_spam_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stop_forum_spam_7d`.
- ` this % ` is the percentage **of this ipset (`stop_forum_spam_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|28354|30.5%|93.9%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|5334|67.5%|17.6%|
[blocklist_de](#blocklist_de)|23450|23450|2178|9.2%|7.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|2067|0.0%|6.8%|
[blocklist_de_bots](#blocklist_de_bots)|3496|3496|2010|57.4%|6.6%|
[ri_web_proxies](#ri_web_proxies)|4122|4122|1577|38.2%|5.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|894|0.0%|2.9%|
[ri_connect_proxies](#ri_connect_proxies)|1622|1622|699|43.0%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|578|0.0%|1.9%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|526|7.1%|1.7%|
[et_tor](#et_tor)|6400|6400|440|6.8%|1.4%|
[dm_tor](#dm_tor)|6535|6535|428|6.5%|1.4%|
[bm_tor](#bm_tor)|6537|6537|424|6.4%|1.4%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|246|0.0%|0.8%|
[et_block](#et_block)|974|18056767|225|0.0%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|209|0.0%|0.6%|
[php_commenters](#php_commenters)|246|246|176|71.5%|0.5%|
[php_bad](#php_bad)|246|246|175|71.1%|0.5%|
[nixspam](#nixspam)|27666|27666|137|0.4%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|12942|12942|123|0.9%|0.4%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|117|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|225|225|116|51.5%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|15139|15139|94|0.6%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1627|1627|61|3.7%|0.2%|
[php_spammers](#php_spammers)|378|378|57|15.0%|0.1%|
[php_harvesters](#php_harvesters)|235|235|48|20.4%|0.1%|
[php_dictionary](#php_dictionary)|398|398|48|12.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|41|0.0%|0.1%|
[openbl_90d](#openbl_90d)|9899|9899|38|0.3%|0.1%|
[openbl](#openbl)|9899|9899|38|0.3%|0.1%|
[openbl_60d](#openbl_60d)|7818|7818|35|0.4%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|21|0.0%|0.0%|
[voipbl](#voipbl)|10286|10757|12|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|12|1.7%|0.0%|
[openbl_30d](#openbl_30d)|4451|4451|7|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2302|2302|4|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|559|559|4|0.7%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2391|2391|3|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[et_compromised](#et_compromised)|2292|2292|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|267|267|1|0.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|299|299|1|0.3%|0.0%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Wed May 27 20:48:55 UTC 2015.

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
[alienvault_reputation](#alienvault_reputation)|179777|179777|202|0.1%|1.8%|
[blocklist_de](#blocklist_de)|23450|23450|42|0.1%|0.3%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|39|0.0%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|106|106|31|29.2%|0.2%|
[et_block](#et_block)|974|18056767|18|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|14|0.0%|0.1%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|12|0.0%|0.1%|
[openbl_90d](#openbl_90d)|9899|9899|11|0.1%|0.1%|
[openbl](#openbl)|9899|9899|11|0.1%|0.1%|
[openbl_60d](#openbl_60d)|7818|7818|9|0.1%|0.0%|
[nixspam](#nixspam)|27666|27666|5|0.0%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|4|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2302|2302|4|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12942|12942|4|0.0%|0.0%|
[shunlist](#shunlist)|51|51|3|5.8%|0.0%|
[openbl_30d](#openbl_30d)|4451|4451|3|0.0%|0.0%|
[ciarmy](#ciarmy)|414|414|3|0.7%|0.0%|
[openbl_7d](#openbl_7d)|1004|1004|2|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3496|3496|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|1|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2292|2292|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6535|6535|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2391|2391|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6537|6537|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15139|15139|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1627|1627|1|0.0%|0.0%|

## zeus

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) default blocklist including hijacked sites and web hosting providers - **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist).

The last time downloaded was found to be dated: Wed May 27 20:27:36 UTC 2015.

The ipset `zeus` has **267** entries, **267** unique IPs.

The following table shows the overlaps of `zeus` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus`.
- ` this % ` is the percentage **of this ipset (`zeus`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|974|18056767|262|0.0%|98.1%|
[zeus_badips](#zeus_badips)|229|229|229|100.0%|85.7%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|226|3.0%|84.6%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|68|0.0%|25.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|20|0.0%|7.4%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|16|0.0%|5.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|9|0.0%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|7|0.0%|2.6%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|5|0.0%|1.8%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|4|0.0%|1.4%|
[openbl_90d](#openbl_90d)|9899|9899|2|0.0%|0.7%|
[openbl_60d](#openbl_60d)|7818|7818|2|0.0%|0.7%|
[openbl_30d](#openbl_30d)|4451|4451|2|0.0%|0.7%|
[openbl](#openbl)|9899|9899|2|0.0%|0.7%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|1|0.0%|0.3%|
[php_commenters](#php_commenters)|246|246|1|0.4%|0.3%|
[php_bad](#php_bad)|246|246|1|0.4%|0.3%|
[openbl_7d](#openbl_7d)|1004|1004|1|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.3%|
[et_compromised](#et_compromised)|2292|2292|1|0.0%|0.3%|
[clean_mx_viruses](#clean_mx_viruses)|299|299|1|0.3%|0.3%|
[bruteforceblocker](#bruteforceblocker)|2391|2391|1|0.0%|0.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|2302|2302|1|0.0%|0.3%|
[blocklist_de](#blocklist_de)|23450|23450|1|0.0%|0.3%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) includes IPv4 addresses that are used by the ZeuS trojan

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Wed May 27 20:51:00 UTC 2015.

The ipset `zeus_badips` has **229** entries, **229** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|267|267|229|85.7%|100.0%|
[et_block](#et_block)|974|18056767|227|0.0%|99.1%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|200|2.7%|87.3%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|36|0.0%|15.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|16|0.0%|6.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|14|0.0%|6.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|8|0.0%|3.4%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|5|0.0%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|4|0.0%|1.7%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|3|0.0%|1.3%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|1|0.0%|0.4%|
[php_commenters](#php_commenters)|246|246|1|0.4%|0.4%|
[php_bad](#php_bad)|246|246|1|0.4%|0.4%|
[openbl_90d](#openbl_90d)|9899|9899|1|0.0%|0.4%|
[openbl_60d](#openbl_60d)|7818|7818|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|4451|4451|1|0.0%|0.4%|
[openbl](#openbl)|9899|9899|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.4%|
[et_compromised](#et_compromised)|2292|2292|1|0.0%|0.4%|
[bruteforceblocker](#bruteforceblocker)|2391|2391|1|0.0%|0.4%|
