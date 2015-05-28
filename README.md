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

1. **Abuse.ch** lists `feodo`, `palevo`, `sslbl`, `zeus`, `zeus_badips`
   
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

   These are lists of IPs that should not be routed on the internet. No one should be using them.
   Be very carefull to apply either of the two on the internet side of your network.

5. **OpenBL.org** lists `openbl*`
   
   The team of OpenBL tracks brute force attacks on their hosts. They suggest to use the default blacklist which has a retension policy of 90 days (`openbl`), but they also provide lists with different retension policies (from 1 day to 1 year).
   Their goal is to report abuse to the responsible provider so that the infection is disabled.

6. **Blocklist.de** lists `blocklist_de*`
   
   Is a network of users reporting abuse mainly using `fail2ban`.
   They only include IPs that has attacked them in the last 48 hours.
   Their goal is also to report abuse back, so that the infection is disabled.


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
	
	# subnets - netsets
	for x in fullbogons dshield spamhaus_drop spamhaus_edrop
	do
		ipset4 create  ${x} hash:net
		ipset4 addfile ${x} ipsets/${x}.netset
		blacklist4 full inface "${wan}" log "BLACKLIST ${x^^}" ipset:${x} \
			except src ipset:whitelist
	done

	# individual IPs - ipsets
	for x in feodo palevo sslbl zeus openbl blocklist_de
	do
		ipset4 create  ${x} hash:ip
		ipset4 addfile ${x} ipsets/${x}.ipset
		blacklist4 full inface "${wan}" log "BLACKLIST ${x^^}" ipset:${x} \
			except src ipset:whitelist
	done

	... rest of firehol.conf ...
```

If you are concerned about iptables performance, change the `blacklist4` keyword `full` to `input`.
This will block only inbound NEW connections, i.e. only the first packet for every NEW inbound connection will be checked.
All other traffic passes through unchecked.

> Before adding these rules to your `firehol.conf` you should run `update-ipsets.sh` to enable them.

### Updating the ipsets while the firewall is running

Just use the `update-ipsets.sh` script from the firehol distribution.
This script will update each ipset and call firehol to update the ipset while the firewall is running.

> You can add `update-ipsets.sh` to cron, to run every 30 mins. `update-ipsets.sh` is smart enough to download
> a list only when it needs to.

---

## Using them using plain iptables commands

### Creating the ipsets
TODO

### Updating the ipsets while the firewall is running
TODO

---

# List of ipsets included

The following list was automatically generated on Thu May 28 22:23:05 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|172159 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|22289 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|12789 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|3468 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|1483 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|270 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|687 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|14576 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|93 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|2201 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|228 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6492 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD)|ipv4 hash:ip|2428 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|415 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|509 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6490 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|975 subnets, 18056513 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botnet](#et_botnet)|[EmergingThreats.net](http://www.emergingthreats.net/) botnet IPs|ipv4 hash:ip|512 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net](http://www.emergingthreats.net/) compromised hosts (seems to be a derivate of other lists)|ipv4 hash:ip|2338 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6490 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[feodo](#feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|67 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
[fullbogons](#fullbogons)|[Team-Cymru.org](http://www.team-cymru.org) IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user - **excellent list - use it only your internet interface**|ipv4 hash:net|3656 subnets, 670735064 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt)
[geolite2_country](https://github.com/ktsaou/blocklist-ipsets/tree/master/geolite2_country)|[MaxMind GeoLite2](http://dev.maxmind.com/geoip/geoip2/geolite2/) databases are free IP geolocation databases comparable to, but less accurate than, MaxMind’s GeoIP2 databases. They include IPs per country, IPs per continent, IPs used by anonymous services (VPNs, Proxies, etc) and Satellite Providers.|ipv4 hash:net|All the world|updated every 7 days  from [this link](http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country-CSV.zip)
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) IPs that have been reported for bad deeds in p2p|ipv4 hash:ip|48134 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=cwworuawihqvocglcoss&fileformat=p2p&archiveformat=gz)
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) hijacked IP-Blocks Hijacked IP space are IP blocks that are being used without permission|ipv4 hash:net|535 subnets, 9177856 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=usrcshglbiilevmyfhse&fileformat=p2p&archiveformat=gz)
[ib_bluetack_level1](#ib_bluetack_level1)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Level 1 (for use in p2p): Companies or organizations who are clearly involved with trying to stop filesharing (e.g. Baytsp, MediaDefender, Mediasentry a.o.). Companies which anti-p2p activity has been seen from. Companies that produce or have a strong financial interest in copyrighted material (e.g. music, movie, software industries a.o.). Government ranges or companies that have a strong financial interest in doing work for governments. Legal industry ranges. IPs or ranges of ISPs from which anti-p2p activity has been observed. Basically this list will block all kinds of internet connections that most people would rather not have during their internet travels.|ipv4 hash:net|236319 subnets, 765065682 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz)
[ib_bluetack_level2](#ib_bluetack_level2)|[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 2 (for use in p2p). General corporate ranges. Ranges used by labs or researchers. Proxies.|ipv4 hash:net|78389 subnets, 348732007 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw&fileformat=p2p&archiveformat=gz)
[ib_bluetack_level3](#ib_bluetack_level3)|[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 3 (for use in p2p). Many portal-type websites. ISP ranges that may be dodgy for some reason. Ranges that belong to an individual, but which have not been determined to be used by a particular company. Ranges for things that are unusual in some way. The L3 list is aka the paranoid list.|ipv4 hash:net|18879 subnets, 139109195 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh&fileformat=p2p&archiveformat=gz)
[ib_bluetack_proxies](#ib_bluetack_proxies)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Open Proxies IPs list (without TOR)|ipv4 hash:ip|673 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=xoebmbyexwuiogmbyprb&fileformat=p2p&archiveformat=gz)
[ib_bluetack_spyware](#ib_bluetack_spyware)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) known malicious SPYWARE and ADWARE IP Address ranges|ipv4 hash:net|3339 subnets, 339461 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=llvtlsjyoyiczbkjsxpf&fileformat=p2p&archiveformat=gz)
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) web server hack and exploit attempts|ipv4 hash:ip|1460 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=ghlzqtqxnzctvvajwwag&fileformat=p2p&archiveformat=gz)
[malc0de](#malc0de)|[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days|ipv4 hash:ip|411 unique IPs|updated every 1 day  from [this link](http://malc0de.com/bl/IP_Blacklist.txt)
[malwaredomainlist](#malwaredomainlist)|[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses|ipv4 hash:ip|1283 unique IPs|updated every 12 hours  from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt)
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|25659 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
[openbl](#openbl)|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|9854 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt.gz)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|357 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_1days.txt.gz)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|4446 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt.gz)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7777 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt.gz)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|995 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt.gz)
[openbl_90d](#openbl_90d)|[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|9854 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt.gz)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
[php_bad](#php_bad)|[projecthoneypot.org](http://www.projecthoneypot.org/) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|281 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|281 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|433 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|257 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|417 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1722 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|65 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1714 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|4417 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|51 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|7240 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|641 subnets, 18117120 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|55 subnets, 421120 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|345 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|7697 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|92103 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|30710 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10303 subnets, 10775 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1893 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|266 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|229 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Thu May 28 22:00:49 UTC 2015.

The ipset `alienvault_reputation` has **172159** entries, **172159** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|14655|0.0%|8.5%|
[openbl_90d](#openbl_90d)|9854|9854|9833|99.7%|5.7%|
[openbl](#openbl)|9854|9854|9833|99.7%|5.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|7877|0.0%|4.5%|
[openbl_60d](#openbl_60d)|7777|7777|7759|99.7%|4.5%|
[et_block](#et_block)|975|18056513|5273|0.0%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|4678|0.0%|2.7%|
[openbl_30d](#openbl_30d)|4446|4446|4436|99.7%|2.5%|
[dshield](#dshield)|20|5120|2820|55.0%|1.6%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|1622|0.0%|0.9%|
[blocklist_de](#blocklist_de)|22289|22289|1534|6.8%|0.8%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|1507|62.0%|0.8%|
[et_compromised](#et_compromised)|2338|2338|1471|62.9%|0.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|2201|2201|1309|59.4%|0.7%|
[openbl_7d](#openbl_7d)|995|995|990|99.4%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|518|0.0%|0.3%|
[ciarmy](#ciarmy)|415|415|407|98.0%|0.2%|
[openbl_1d](#openbl_1d)|357|357|355|99.4%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|293|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|227|0.2%|0.1%|
[voipbl](#voipbl)|10303|10775|197|1.8%|0.1%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|121|1.6%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30710|30710|116|0.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12789|12789|100|0.7%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|228|228|86|37.7%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14576|14576|80|0.5%|0.0%|
[zeus](#zeus)|266|266|67|25.1%|0.0%|
[nixspam](#nixspam)|25659|25659|65|0.2%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7697|7697|61|0.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|687|687|61|8.8%|0.0%|
[shunlist](#shunlist)|51|51|51|100.0%|0.0%|
[et_tor](#et_tor)|6490|6490|44|0.6%|0.0%|
[dm_tor](#dm_tor)|6490|6490|44|0.6%|0.0%|
[bm_tor](#bm_tor)|6492|6492|44|0.6%|0.0%|
[zeus_badips](#zeus_badips)|229|229|36|15.7%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3468|3468|24|0.6%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|93|93|19|20.4%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1483|1483|18|1.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|15|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|270|270|14|5.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|13|0.0%|0.0%|
[php_commenters](#php_commenters)|281|281|12|4.2%|0.0%|
[php_bad](#php_bad)|281|281|12|4.2%|0.0%|
[malc0de](#malc0de)|411|411|10|2.4%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|509|509|10|1.9%|0.0%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|8|0.5%|0.0%|
[sslbl](#sslbl)|345|345|7|2.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|7|1.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|7|0.5%|0.0%|
[xroxy](#xroxy)|1893|1893|3|0.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4417|4417|3|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|3|0.7%|0.0%|
[et_botnet](#et_botnet)|512|512|3|0.5%|0.0%|
[proxyrss](#proxyrss)|1722|1722|2|0.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1714|1714|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[feodo](#feodo)|67|67|1|1.4%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Thu May 28 21:56:05 UTC 2015.

The ipset `blocklist_de` has **22289** entries, **22289** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|14576|14576|14564|99.9%|65.3%|
[blocklist_de_apache](#blocklist_de_apache)|12789|12789|12778|99.9%|57.3%|
[blocklist_de_bots](#blocklist_de_bots)|3468|3468|3460|99.7%|15.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|2838|0.0%|12.7%|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|2588|2.8%|11.6%|
[stopforumspam_7d](#stopforumspam_7d)|30710|30710|2208|7.1%|9.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|2201|2201|2201|100.0%|9.8%|
[stopforumspam_1d](#stopforumspam_1d)|7697|7697|1641|21.3%|7.3%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|1534|0.8%|6.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|1485|0.0%|6.6%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1483|1483|1483|100.0%|6.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|1453|0.0%|6.5%|
[openbl_90d](#openbl_90d)|9854|9854|1305|13.2%|5.8%|
[openbl](#openbl)|9854|9854|1305|13.2%|5.8%|
[openbl_60d](#openbl_60d)|7777|7777|1247|16.0%|5.5%|
[openbl_30d](#openbl_30d)|4446|4446|1155|25.9%|5.1%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|1109|45.6%|4.9%|
[et_compromised](#et_compromised)|2338|2338|990|42.3%|4.4%|
[blocklist_de_imap](#blocklist_de_imap)|687|687|687|100.0%|3.0%|
[openbl_7d](#openbl_7d)|995|995|661|66.4%|2.9%|
[nixspam](#nixspam)|25659|25659|656|2.5%|2.9%|
[ri_web_proxies](#ri_web_proxies)|4417|4417|388|8.7%|1.7%|
[xroxy](#xroxy)|1893|1893|296|15.6%|1.3%|
[blocklist_de_ftp](#blocklist_de_ftp)|270|270|270|100.0%|1.2%|
[openbl_1d](#openbl_1d)|357|357|242|67.7%|1.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|228|228|228|100.0%|1.0%|
[proxyrss](#proxyrss)|1722|1722|226|13.1%|1.0%|
[et_block](#et_block)|975|18056513|199|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|194|0.0%|0.8%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|186|2.5%|0.8%|
[dshield](#dshield)|20|5120|135|2.6%|0.6%|
[ri_connect_proxies](#ri_connect_proxies)|1714|1714|79|4.6%|0.3%|
[php_commenters](#php_commenters)|281|281|76|27.0%|0.3%|
[php_bad](#php_bad)|281|281|75|26.6%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|74|0.0%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|93|93|74|79.5%|0.3%|
[php_dictionary](#php_dictionary)|433|433|73|16.8%|0.3%|
[php_spammers](#php_spammers)|417|417|66|15.8%|0.2%|
[voipbl](#voipbl)|10303|10775|35|0.3%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|34|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|33|12.8%|0.1%|
[ciarmy](#ciarmy)|415|415|30|7.2%|0.1%|
[dm_tor](#dm_tor)|6490|6490|24|0.3%|0.1%|
[bm_tor](#bm_tor)|6492|6492|24|0.3%|0.1%|
[et_tor](#et_tor)|6490|6490|23|0.3%|0.1%|
[proxz](#proxz)|65|65|18|27.6%|0.0%|
[shunlist](#shunlist)|51|51|12|23.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|7|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|509|509|2|0.3%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Thu May 28 22:14:06 UTC 2015.

The ipset `blocklist_de_apache` has **12789** entries, **12789** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22289|22289|12778|57.3%|99.9%|
[blocklist_de_mail](#blocklist_de_mail)|14576|14576|11059|75.8%|86.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|2226|0.0%|17.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1483|1483|1482|99.9%|11.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|1322|0.0%|10.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|1079|0.0%|8.4%|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|221|0.2%|1.7%|
[stopforumspam_7d](#stopforumspam_7d)|30710|30710|133|0.4%|1.0%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|100|0.0%|0.7%|
[stopforumspam_1d](#stopforumspam_1d)|7697|7697|92|1.1%|0.7%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|40|0.5%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|228|228|35|15.3%|0.2%|
[ciarmy](#ciarmy)|415|415|26|6.2%|0.2%|
[dm_tor](#dm_tor)|6490|6490|24|0.3%|0.1%|
[bm_tor](#bm_tor)|6492|6492|24|0.3%|0.1%|
[php_commenters](#php_commenters)|281|281|23|8.1%|0.1%|
[php_bad](#php_bad)|281|281|23|8.1%|0.1%|
[et_tor](#et_tor)|6490|6490|23|0.3%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3468|3468|17|0.4%|0.1%|
[nixspam](#nixspam)|25659|25659|15|0.0%|0.1%|
[openbl_90d](#openbl_90d)|9854|9854|11|0.1%|0.0%|
[openbl](#openbl)|9854|9854|11|0.1%|0.0%|
[openbl_60d](#openbl_60d)|7777|7777|8|0.1%|0.0%|
[et_block](#et_block)|975|18056513|8|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.0%|
[openbl_30d](#openbl_30d)|4446|4446|5|0.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_compromised](#et_compromised)|2338|2338|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|3|0.1%|0.0%|
[voipbl](#voipbl)|10303|10775|2|0.0%|0.0%|
[shunlist](#shunlist)|51|51|2|3.9%|0.0%|
[openbl_7d](#openbl_7d)|995|995|2|0.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|509|509|2|0.3%|0.0%|
[xroxy](#xroxy)|1893|1893|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4417|4417|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1722|1722|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Thu May 28 22:14:09 UTC 2015.

The ipset `blocklist_de_bots` has **3468** entries, **3468** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22289|22289|3460|15.5%|99.7%|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|2283|2.4%|65.8%|
[stopforumspam_7d](#stopforumspam_7d)|30710|30710|2032|6.6%|58.5%|
[stopforumspam_1d](#stopforumspam_1d)|7697|7697|1546|20.0%|44.5%|
[ri_web_proxies](#ri_web_proxies)|4417|4417|357|8.0%|10.2%|
[xroxy](#xroxy)|1893|1893|249|13.1%|7.1%|
[proxyrss](#proxyrss)|1722|1722|223|12.9%|6.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|154|0.0%|4.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|228|228|128|56.1%|3.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|78|0.0%|2.2%|
[ri_connect_proxies](#ri_connect_proxies)|1714|1714|77|4.4%|2.2%|
[php_commenters](#php_commenters)|281|281|61|21.7%|1.7%|
[php_bad](#php_bad)|281|281|61|21.7%|1.7%|
[nixspam](#nixspam)|25659|25659|55|0.2%|1.5%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|52|0.0%|1.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|52|0.0%|1.4%|
[et_block](#et_block)|975|18056513|51|0.0%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|41|0.0%|1.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|29|0.0%|0.8%|
[php_harvesters](#php_harvesters)|257|257|27|10.5%|0.7%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|24|0.3%|0.6%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|24|0.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|14576|14576|17|0.1%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|12789|12789|17|0.1%|0.4%|
[proxz](#proxz)|65|65|16|24.6%|0.4%|
[php_spammers](#php_spammers)|417|417|16|3.8%|0.4%|
[php_dictionary](#php_dictionary)|433|433|12|2.7%|0.3%|
[openbl_90d](#openbl_90d)|9854|9854|3|0.0%|0.0%|
[openbl](#openbl)|9854|9854|3|0.0%|0.0%|
[voipbl](#voipbl)|10303|10775|2|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2338|2338|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1483|1483|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Thu May 28 21:56:11 UTC 2015.

The ipset `blocklist_de_bruteforce` has **1483** entries, **1483** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22289|22289|1483|6.6%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|12789|12789|1482|11.5%|99.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|137|0.0%|9.2%|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|84|0.0%|5.6%|
[stopforumspam_7d](#stopforumspam_7d)|30710|30710|73|0.2%|4.9%|
[stopforumspam_1d](#stopforumspam_1d)|7697|7697|55|0.7%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|45|0.0%|3.0%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|37|0.5%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|28|0.0%|1.8%|
[dm_tor](#dm_tor)|6490|6490|21|0.3%|1.4%|
[bm_tor](#bm_tor)|6492|6492|21|0.3%|1.4%|
[et_tor](#et_tor)|6490|6490|20|0.3%|1.3%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|18|0.0%|1.2%|
[nixspam](#nixspam)|25659|25659|13|0.0%|0.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|228|228|10|4.3%|0.6%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.3%|
[openbl_90d](#openbl_90d)|9854|9854|5|0.0%|0.3%|
[openbl](#openbl)|9854|9854|5|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|4|0.0%|0.2%|
[php_commenters](#php_commenters)|281|281|4|1.4%|0.2%|
[php_bad](#php_bad)|281|281|4|1.4%|0.2%|
[et_block](#et_block)|975|18056513|4|0.0%|0.2%|
[openbl_60d](#openbl_60d)|7777|7777|3|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.1%|
[cleanmx_viruses](#cleanmx_viruses)|509|509|2|0.3%|0.1%|
[xroxy](#xroxy)|1893|1893|1|0.0%|0.0%|
[voipbl](#voipbl)|10303|10775|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4417|4417|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1722|1722|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4446|4446|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2338|2338|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3468|3468|1|0.0%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Thu May 28 21:56:08 UTC 2015.

The ipset `blocklist_de_ftp` has **270** entries, **270** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22289|22289|270|1.2%|100.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|23|0.0%|8.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|17|0.0%|6.2%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|14|0.0%|5.1%|
[openbl_90d](#openbl_90d)|9854|9854|8|0.0%|2.9%|
[openbl](#openbl)|9854|9854|8|0.0%|2.9%|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|7|0.0%|2.5%|
[openbl_60d](#openbl_60d)|7777|7777|6|0.0%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|6|0.0%|2.2%|
[nixspam](#nixspam)|25659|25659|3|0.0%|1.1%|
[stopforumspam_7d](#stopforumspam_7d)|30710|30710|2|0.0%|0.7%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.7%|
[openbl_30d](#openbl_30d)|4446|4446|2|0.0%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|228|228|2|0.8%|0.7%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|1|0.0%|0.3%|
[openbl_7d](#openbl_7d)|995|995|1|0.1%|0.3%|
[openbl_1d](#openbl_1d)|357|357|1|0.2%|0.3%|
[ciarmy](#ciarmy)|415|415|1|0.2%|0.3%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Thu May 28 22:14:07 UTC 2015.

The ipset `blocklist_de_imap` has **687** entries, **687** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|14576|14576|687|4.7%|100.0%|
[blocklist_de](#blocklist_de)|22289|22289|687|3.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|61|0.0%|8.8%|
[openbl_90d](#openbl_90d)|9854|9854|50|0.5%|7.2%|
[openbl](#openbl)|9854|9854|50|0.5%|7.2%|
[openbl_60d](#openbl_60d)|7777|7777|46|0.5%|6.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|46|0.0%|6.6%|
[openbl_30d](#openbl_30d)|4446|4446|42|0.9%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|42|0.0%|6.1%|
[openbl_7d](#openbl_7d)|995|995|24|2.4%|3.4%|
[et_compromised](#et_compromised)|2338|2338|16|0.6%|2.3%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|16|0.6%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|14|0.0%|2.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|13|0.0%|1.8%|
[et_block](#et_block)|975|18056513|13|0.0%|1.8%|
[openbl_1d](#openbl_1d)|357|357|7|1.9%|1.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|30710|30710|2|0.0%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|2|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|2|0.0%|0.2%|
[shunlist](#shunlist)|51|51|2|3.9%|0.2%|
[nixspam](#nixspam)|25659|25659|2|0.0%|0.2%|
[voipbl](#voipbl)|10303|10775|1|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.1%|
[ciarmy](#ciarmy)|415|415|1|0.2%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|228|228|1|0.4%|0.1%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Thu May 28 22:14:05 UTC 2015.

The ipset `blocklist_de_mail` has **14576** entries, **14576** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22289|22289|14564|65.3%|99.9%|
[blocklist_de_apache](#blocklist_de_apache)|12789|12789|11059|86.4%|75.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|2279|0.0%|15.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|1346|0.0%|9.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|1172|0.0%|8.0%|
[blocklist_de_imap](#blocklist_de_imap)|687|687|687|100.0%|4.7%|
[nixspam](#nixspam)|25659|25659|584|2.2%|4.0%|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|203|0.2%|1.3%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|122|1.6%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|30710|30710|98|0.3%|0.6%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|80|0.0%|0.5%|
[openbl_90d](#openbl_90d)|9854|9854|64|0.6%|0.4%|
[openbl](#openbl)|9854|9854|64|0.6%|0.4%|
[php_dictionary](#php_dictionary)|433|433|62|14.3%|0.4%|
[openbl_60d](#openbl_60d)|7777|7777|59|0.7%|0.4%|
[openbl_30d](#openbl_30d)|4446|4446|52|1.1%|0.3%|
[php_spammers](#php_spammers)|417|417|46|11.0%|0.3%|
[xroxy](#xroxy)|1893|1893|45|2.3%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7697|7697|42|0.5%|0.2%|
[ri_web_proxies](#ri_web_proxies)|4417|4417|30|0.6%|0.2%|
[openbl_7d](#openbl_7d)|995|995|26|2.6%|0.1%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|24|0.0%|0.1%|
[php_commenters](#php_commenters)|281|281|23|8.1%|0.1%|
[php_bad](#php_bad)|281|281|22|7.8%|0.1%|
[et_compromised](#et_compromised)|2338|2338|22|0.9%|0.1%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|22|0.9%|0.1%|
[et_block](#et_block)|975|18056513|20|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|228|228|18|7.8%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3468|3468|17|0.4%|0.1%|
[openbl_1d](#openbl_1d)|357|357|9|2.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|4|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|4|1.5%|0.0%|
[et_tor](#et_tor)|6490|6490|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6490|6490|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6492|6492|3|0.0%|0.0%|
[shunlist](#shunlist)|51|51|2|3.9%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1714|1714|2|0.1%|0.0%|
[proxz](#proxz)|65|65|2|3.0%|0.0%|
[voipbl](#voipbl)|10303|10775|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1722|1722|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[ciarmy](#ciarmy)|415|415|1|0.2%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Thu May 28 21:56:08 UTC 2015.

The ipset `blocklist_de_sip` has **93** entries, **93** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22289|22289|74|0.3%|79.5%|
[voipbl](#voipbl)|10303|10775|27|0.2%|29.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|20|0.0%|21.5%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|19|0.0%|20.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|6|0.0%|6.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|4|0.0%|4.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|2|0.0%|2.1%|
[nixspam](#nixspam)|25659|25659|1|0.0%|1.0%|
[et_botnet](#et_botnet)|512|512|1|0.1%|1.0%|
[ciarmy](#ciarmy)|415|415|1|0.2%|1.0%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Thu May 28 21:56:04 UTC 2015.

The ipset `blocklist_de_ssh` has **2201** entries, **2201** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22289|22289|2201|9.8%|100.0%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|1309|0.7%|59.4%|
[openbl_90d](#openbl_90d)|9854|9854|1219|12.3%|55.3%|
[openbl](#openbl)|9854|9854|1219|12.3%|55.3%|
[openbl_60d](#openbl_60d)|7777|7777|1174|15.0%|53.3%|
[openbl_30d](#openbl_30d)|4446|4446|1096|24.6%|49.7%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|1083|44.6%|49.2%|
[et_compromised](#et_compromised)|2338|2338|964|41.2%|43.7%|
[openbl_7d](#openbl_7d)|995|995|632|63.5%|28.7%|
[openbl_1d](#openbl_1d)|357|357|232|64.9%|10.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|218|0.0%|9.9%|
[dshield](#dshield)|20|5120|135|2.6%|6.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|125|0.0%|5.6%|
[et_block](#et_block)|975|18056513|120|0.0%|5.4%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|114|0.0%|5.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|228|228|77|33.7%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|48|0.0%|2.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|13|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|8|0.0%|0.3%|
[shunlist](#shunlist)|51|51|8|15.6%|0.3%|
[voipbl](#voipbl)|10303|10775|3|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|3|0.0%|0.1%|
[nixspam](#nixspam)|25659|25659|3|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|3|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30710|30710|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[xroxy](#xroxy)|1893|1893|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7697|7697|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4417|4417|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1722|1722|1|0.0%|0.0%|
[ciarmy](#ciarmy)|415|415|1|0.2%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Thu May 28 22:14:10 UTC 2015.

The ipset `blocklist_de_strongips` has **228** entries, **228** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22289|22289|228|1.0%|100.0%|
[blocklist_de_bots](#blocklist_de_bots)|3468|3468|128|3.6%|56.1%|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|127|0.1%|55.7%|
[stopforumspam_7d](#stopforumspam_7d)|30710|30710|116|0.3%|50.8%|
[stopforumspam_1d](#stopforumspam_1d)|7697|7697|110|1.4%|48.2%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|86|0.0%|37.7%|
[openbl_90d](#openbl_90d)|9854|9854|78|0.7%|34.2%|
[openbl](#openbl)|9854|9854|78|0.7%|34.2%|
[openbl_60d](#openbl_60d)|7777|7777|77|0.9%|33.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|2201|2201|77|3.4%|33.7%|
[openbl_30d](#openbl_30d)|4446|4446|76|1.7%|33.3%|
[openbl_7d](#openbl_7d)|995|995|75|7.5%|32.8%|
[openbl_1d](#openbl_1d)|357|357|69|19.3%|30.2%|
[blocklist_de_apache](#blocklist_de_apache)|12789|12789|35|0.2%|15.3%|
[php_commenters](#php_commenters)|281|281|32|11.3%|14.0%|
[php_bad](#php_bad)|281|281|32|11.3%|14.0%|
[et_compromised](#et_compromised)|2338|2338|26|1.1%|11.4%|
[dshield](#dshield)|20|5120|24|0.4%|10.5%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|20|0.8%|8.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|19|0.0%|8.3%|
[blocklist_de_mail](#blocklist_de_mail)|14576|14576|18|0.1%|7.8%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1483|1483|10|0.6%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|8|0.0%|3.5%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|7|0.0%|3.0%|
[et_block](#et_block)|975|18056513|7|0.0%|3.0%|
[xroxy](#xroxy)|1893|1893|6|0.3%|2.6%|
[php_spammers](#php_spammers)|417|417|5|1.1%|2.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|4|0.0%|1.7%|
[ri_web_proxies](#ri_web_proxies)|4417|4417|3|0.0%|1.3%|
[proxyrss](#proxyrss)|1722|1722|3|0.1%|1.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.3%|
[nixspam](#nixspam)|25659|25659|2|0.0%|0.8%|
[blocklist_de_ftp](#blocklist_de_ftp)|270|270|2|0.7%|0.8%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|1|0.0%|0.4%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.4%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|687|687|1|0.1%|0.4%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Thu May 28 21:54:06 UTC 2015.

The ipset `bm_tor` has **6492** entries, **6492** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[dm_tor](#dm_tor)|6490|6490|6490|100.0%|99.9%|
[et_tor](#et_tor)|6490|6490|5664|87.2%|87.2%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|1047|14.4%|16.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|614|0.0%|9.4%|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|582|0.6%|8.9%|
[stopforumspam_7d](#stopforumspam_7d)|30710|30710|434|1.4%|6.6%|
[stopforumspam_1d](#stopforumspam_1d)|7697|7697|343|4.4%|5.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|182|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|163|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|44|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[php_bad](#php_bad)|281|281|29|10.3%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|12789|12789|24|0.1%|0.3%|
[blocklist_de](#blocklist_de)|22289|22289|24|0.1%|0.3%|
[openbl_90d](#openbl_90d)|9854|9854|21|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7777|7777|21|0.2%|0.3%|
[openbl](#openbl)|9854|9854|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|21|0.0%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1483|1483|21|1.4%|0.3%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4417|4417|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14576|14576|3|0.0%|0.0%|
[xroxy](#xroxy)|1893|1893|2|0.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1714|1714|2|0.1%|0.0%|
[et_block](#et_block)|975|18056513|2|0.0%|0.0%|
[voipbl](#voipbl)|10303|10775|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1722|1722|1|0.0%|0.0%|
[nixspam](#nixspam)|25659|25659|1|0.0%|0.0%|
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
[fullbogons](#fullbogons)|3656|670735064|592708608|88.3%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|4194304|3.0%|0.7%|
[voipbl](#voipbl)|10303|10775|351|3.2%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|5|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|1|0.0%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD)

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Thu May 28 20:10:06 UTC 2015.

The ipset `bruteforceblocker` has **2428** entries, **2428** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_compromised](#et_compromised)|2338|2338|2278|97.4%|93.8%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|1507|0.8%|62.0%|
[openbl_90d](#openbl_90d)|9854|9854|1432|14.5%|58.9%|
[openbl](#openbl)|9854|9854|1432|14.5%|58.9%|
[openbl_60d](#openbl_60d)|7777|7777|1415|18.1%|58.2%|
[openbl_30d](#openbl_30d)|4446|4446|1357|30.5%|55.8%|
[blocklist_de](#blocklist_de)|22289|22289|1109|4.9%|45.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|2201|2201|1083|49.2%|44.6%|
[openbl_7d](#openbl_7d)|995|995|515|51.7%|21.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|233|0.0%|9.5%|
[openbl_1d](#openbl_1d)|357|357|201|56.3%|8.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|146|0.0%|6.0%|
[et_block](#et_block)|975|18056513|103|0.0%|4.2%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|102|0.0%|4.2%|
[dshield](#dshield)|20|5120|98|1.9%|4.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|73|0.0%|3.0%|
[blocklist_de_mail](#blocklist_de_mail)|14576|14576|22|0.1%|0.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|228|228|20|8.7%|0.8%|
[blocklist_de_imap](#blocklist_de_imap)|687|687|16|2.3%|0.6%|
[shunlist](#shunlist)|51|51|9|17.6%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|6|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|12789|12789|3|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30710|30710|2|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7697|7697|2|0.0%|0.0%|
[proxyrss](#proxyrss)|1722|1722|2|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[xroxy](#xroxy)|1893|1893|1|0.0%|0.0%|
[voipbl](#voipbl)|10303|10775|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|1|0.0%|0.0%|
[proxz](#proxz)|65|65|1|1.5%|0.0%|
[fullbogons](#fullbogons)|3656|670735064|1|0.0%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1483|1483|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3468|3468|1|0.0%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Thu May 28 22:15:05 UTC 2015.

The ipset `ciarmy` has **415** entries, **415** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|172159|172159|407|0.2%|98.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|76|0.0%|18.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|40|0.0%|9.6%|
[blocklist_de](#blocklist_de)|22289|22289|30|0.1%|7.2%|
[blocklist_de_apache](#blocklist_de_apache)|12789|12789|26|0.2%|6.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|24|0.0%|5.7%|
[voipbl](#voipbl)|10303|10775|3|0.0%|0.7%|
[shunlist](#shunlist)|51|51|2|3.9%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|1|0.0%|0.2%|
[openbl_90d](#openbl_90d)|9854|9854|1|0.0%|0.2%|
[openbl_7d](#openbl_7d)|995|995|1|0.1%|0.2%|
[openbl_60d](#openbl_60d)|7777|7777|1|0.0%|0.2%|
[openbl_30d](#openbl_30d)|4446|4446|1|0.0%|0.2%|
[openbl](#openbl)|9854|9854|1|0.0%|0.2%|
[et_block](#et_block)|975|18056513|1|0.0%|0.2%|
[dshield](#dshield)|20|5120|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2201|2201|1|0.0%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|93|93|1|1.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|14576|14576|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|687|687|1|0.1%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|270|270|1|0.3%|0.2%|

## cleanmx_viruses

[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses

Source is downloaded from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive).

The last time downloaded was found to be dated: Thu May 28 16:40:36 UTC 2015.

The ipset `cleanmx_viruses` has **509** entries, **509** unique IPs.

The following table shows the overlaps of `cleanmx_viruses` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `cleanmx_viruses`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `cleanmx_viruses`.
- ` this % ` is the percentage **of this ipset (`cleanmx_viruses`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|73|0.0%|14.3%|
[malc0de](#malc0de)|411|411|32|7.7%|6.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|22|0.0%|4.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|14|0.0%|2.7%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|10|0.0%|1.9%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|4|0.0%|0.7%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|3|0.2%|0.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|3|0.0%|0.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1483|1483|2|0.1%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|12789|12789|2|0.0%|0.3%|
[blocklist_de](#blocklist_de)|22289|22289|2|0.0%|0.3%|
[zeus](#zeus)|266|266|1|0.3%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|1|0.0%|0.1%|
[et_block](#et_block)|975|18056513|1|0.0%|0.1%|
[dshield](#dshield)|20|5120|1|0.0%|0.1%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Thu May 28 21:54:04 UTC 2015.

The ipset `dm_tor` has **6490** entries, **6490** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6492|6492|6490|99.9%|100.0%|
[et_tor](#et_tor)|6490|6490|5663|87.2%|87.2%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|1047|14.4%|16.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|614|0.0%|9.4%|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|582|0.6%|8.9%|
[stopforumspam_7d](#stopforumspam_7d)|30710|30710|434|1.4%|6.6%|
[stopforumspam_1d](#stopforumspam_1d)|7697|7697|343|4.4%|5.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|182|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|163|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|44|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[php_bad](#php_bad)|281|281|29|10.3%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|12789|12789|24|0.1%|0.3%|
[blocklist_de](#blocklist_de)|22289|22289|24|0.1%|0.3%|
[openbl_90d](#openbl_90d)|9854|9854|21|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7777|7777|21|0.2%|0.3%|
[openbl](#openbl)|9854|9854|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|21|0.0%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1483|1483|21|1.4%|0.3%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4417|4417|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14576|14576|3|0.0%|0.0%|
[xroxy](#xroxy)|1893|1893|2|0.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1714|1714|2|0.1%|0.0%|
[et_block](#et_block)|975|18056513|2|0.0%|0.0%|
[voipbl](#voipbl)|10303|10775|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1722|1722|1|0.0%|0.0%|
[nixspam](#nixspam)|25659|25659|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Thu May 28 18:55:57 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|172159|172159|2820|1.6%|55.0%|
[et_block](#et_block)|975|18056513|1024|0.0%|20.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|512|0.0%|10.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|256|0.0%|5.0%|
[openbl_90d](#openbl_90d)|9854|9854|147|1.4%|2.8%|
[openbl](#openbl)|9854|9854|147|1.4%|2.8%|
[openbl_60d](#openbl_60d)|7777|7777|144|1.8%|2.8%|
[openbl_30d](#openbl_30d)|4446|4446|139|3.1%|2.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|2201|2201|135|6.1%|2.6%|
[blocklist_de](#blocklist_de)|22289|22289|135|0.6%|2.6%|
[openbl_7d](#openbl_7d)|995|995|119|11.9%|2.3%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|98|4.0%|1.9%|
[et_compromised](#et_compromised)|2338|2338|89|3.8%|1.7%|
[openbl_1d](#openbl_1d)|357|357|51|14.2%|0.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|228|228|24|10.5%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|4|0.0%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|4|0.0%|0.0%|
[nixspam](#nixspam)|25659|25659|1|0.0%|0.0%|
[malc0de](#malc0de)|411|411|1|0.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|509|509|1|0.1%|0.0%|
[ciarmy](#ciarmy)|415|415|1|0.2%|0.0%|

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
[fullbogons](#fullbogons)|3656|670735064|20480|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|5273|3.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1044|0.3%|0.0%|
[dshield](#dshield)|20|5120|1024|20.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|762|0.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|517|0.1%|0.0%|
[openbl_90d](#openbl_90d)|9854|9854|455|4.6%|0.0%|
[openbl](#openbl)|9854|9854|455|4.6%|0.0%|
[openbl_60d](#openbl_60d)|7777|7777|287|3.6%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|286|3.9%|0.0%|
[zeus](#zeus)|266|266|262|98.4%|0.0%|
[zeus_badips](#zeus_badips)|229|229|228|99.5%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30710|30710|214|0.6%|0.0%|
[openbl_30d](#openbl_30d)|4446|4446|212|4.7%|0.0%|
[blocklist_de](#blocklist_de)|22289|22289|199|0.8%|0.0%|
[nixspam](#nixspam)|25659|25659|148|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2201|2201|120|5.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|103|4.2%|0.0%|
[openbl_7d](#openbl_7d)|995|995|97|9.7%|0.0%|
[et_compromised](#et_compromised)|2338|2338|94|4.0%|0.0%|
[feodo](#feodo)|67|67|61|91.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3468|3468|51|1.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7697|7697|37|0.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|28|2.1%|0.0%|
[openbl_1d](#openbl_1d)|357|357|27|7.5%|0.0%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.0%|
[php_bad](#php_bad)|281|281|24|8.5%|0.0%|
[sslbl](#sslbl)|345|345|23|6.6%|0.0%|
[voipbl](#voipbl)|10303|10775|20|0.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14576|14576|20|0.1%|0.0%|
[palevo](#palevo)|13|13|13|100.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|687|687|13|1.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|10|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12789|12789|8|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|228|228|7|3.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1483|1483|4|0.2%|0.0%|
[malc0de](#malc0de)|411|411|3|0.7%|0.0%|
[et_tor](#et_tor)|6490|6490|3|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[dm_tor](#dm_tor)|6490|6490|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6492|6492|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[et_botnet](#et_botnet)|512|512|1|0.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|509|509|1|0.1%|0.0%|
[ciarmy](#ciarmy)|415|415|1|0.2%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|172159|172159|3|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[et_block](#et_block)|975|18056513|1|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|93|93|1|1.0%|0.1%|

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
[bruteforceblocker](#bruteforceblocker)|2428|2428|2278|93.8%|97.4%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|1471|0.8%|62.9%|
[openbl_90d](#openbl_90d)|9854|9854|1396|14.1%|59.7%|
[openbl](#openbl)|9854|9854|1396|14.1%|59.7%|
[openbl_60d](#openbl_60d)|7777|7777|1386|17.8%|59.2%|
[openbl_30d](#openbl_30d)|4446|4446|1328|29.8%|56.8%|
[blocklist_de](#blocklist_de)|22289|22289|990|4.4%|42.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|2201|2201|964|43.7%|41.2%|
[openbl_7d](#openbl_7d)|995|995|495|49.7%|21.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|225|0.0%|9.6%|
[openbl_1d](#openbl_1d)|357|357|207|57.9%|8.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|143|0.0%|6.1%|
[et_block](#et_block)|975|18056513|94|0.0%|4.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|92|0.0%|3.9%|
[dshield](#dshield)|20|5120|89|1.7%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|75|0.0%|3.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|228|228|26|11.4%|1.1%|
[blocklist_de_mail](#blocklist_de_mail)|14576|14576|22|0.1%|0.9%|
[blocklist_de_imap](#blocklist_de_imap)|687|687|16|2.3%|0.6%|
[shunlist](#shunlist)|51|51|9|17.6%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|5|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|12789|12789|3|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30710|30710|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[voipbl](#voipbl)|10303|10775|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7697|7697|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|1|0.0%|0.0%|
[proxz](#proxz)|65|65|1|1.5%|0.0%|
[proxyrss](#proxyrss)|1722|1722|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1483|1483|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3468|3468|1|0.0%|0.0%|

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
[bm_tor](#bm_tor)|6492|6492|5664|87.2%|87.2%|
[dm_tor](#dm_tor)|6490|6490|5663|87.2%|87.2%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|1090|15.0%|16.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|608|0.0%|9.3%|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|591|0.6%|9.1%|
[stopforumspam_7d](#stopforumspam_7d)|30710|30710|442|1.4%|6.8%|
[stopforumspam_1d](#stopforumspam_1d)|7697|7697|333|4.3%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|184|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|165|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|44|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[php_bad](#php_bad)|281|281|29|10.3%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|12789|12789|23|0.1%|0.3%|
[blocklist_de](#blocklist_de)|22289|22289|23|0.1%|0.3%|
[openbl_90d](#openbl_90d)|9854|9854|21|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7777|7777|21|0.2%|0.3%|
[openbl](#openbl)|9854|9854|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|21|0.0%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1483|1483|20|1.3%|0.3%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4417|4417|5|0.1%|0.0%|
[php_dictionary](#php_dictionary)|433|433|3|0.6%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|975|18056513|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14576|14576|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1714|1714|2|0.1%|0.0%|
[xroxy](#xroxy)|1893|1893|1|0.0%|0.0%|
[voipbl](#voipbl)|10303|10775|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1722|1722|1|0.0%|0.0%|
[nixspam](#nixspam)|25659|25659|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Thu May 28 21:54:16 UTC 2015.

The ipset `feodo` has **67** entries, **67** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|975|18056513|61|0.0%|91.0%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|48|0.6%|71.6%|
[sslbl](#sslbl)|345|345|24|6.9%|35.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|4|0.0%|5.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|3|0.0%|4.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|3|0.0%|4.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|1.4%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|1|0.0%|1.4%|

## fullbogons

[Team-Cymru.org](http://www.team-cymru.org) IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user - **excellent list - use it only your internet interface**

Source is downloaded from [this link](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt).

The last time downloaded was found to be dated: Thu May 28 09:35:12 UTC 2015.

The ipset `fullbogons` has **3656** entries, **670735064** unique IPs.

The following table shows the overlaps of `fullbogons` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `fullbogons`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `fullbogons`.
- ` this % ` is the percentage **of this ipset (`fullbogons`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bogons](#bogons)|13|592708608|592708608|100.0%|88.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|4233779|3.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|565248|6.1%|0.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|248327|0.0%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|235151|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|20480|0.1%|0.0%|
[et_block](#et_block)|975|18056513|20480|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|894|0.2%|0.0%|
[voipbl](#voipbl)|10303|10775|351|3.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|33|2.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|9|0.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|1|0.0%|0.0%|

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
[nixspam](#nixspam)|25659|25659|20|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|16|0.0%|0.0%|
[fullbogons](#fullbogons)|3656|670735064|14|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|13|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.0%|
[et_block](#et_block)|975|18056513|10|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30710|30710|6|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|6|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|6|0.0%|0.0%|
[xroxy](#xroxy)|1893|1893|3|0.1%|0.0%|
[voipbl](#voipbl)|10303|10775|2|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7697|7697|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4417|4417|1|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14576|14576|1|0.0%|0.0%|
[blocklist_de](#blocklist_de)|22289|22289|1|0.0%|0.0%|

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
[fullbogons](#fullbogons)|3656|670735064|565248|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|145472|0.1%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1036|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|741|0.8%|0.0%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|518|0.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30710|30710|195|0.6%|0.0%|
[nixspam](#nixspam)|25659|25659|148|0.5%|0.0%|
[blocklist_de](#blocklist_de)|22289|22289|74|0.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3468|3468|52|1.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7697|7697|33|0.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|27|2.1%|0.0%|
[openbl_90d](#openbl_90d)|9854|9854|19|0.1%|0.0%|
[openbl](#openbl)|9854|9854|19|0.1%|0.0%|
[openbl_60d](#openbl_60d)|7777|7777|18|0.2%|0.0%|
[openbl_30d](#openbl_30d)|4446|4446|13|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2201|2201|13|0.5%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|11|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|10|4.3%|0.0%|
[zeus](#zeus)|266|266|10|3.7%|0.0%|
[openbl_7d](#openbl_7d)|995|995|9|0.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14576|14576|6|0.0%|0.0%|
[openbl_1d](#openbl_1d)|357|357|5|1.4%|0.0%|
[et_compromised](#et_compromised)|2338|2338|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|5|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|687|687|4|0.5%|0.0%|
[et_tor](#et_tor)|6490|6490|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6490|6490|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6492|6492|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|228|228|3|1.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12789|12789|3|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1483|1483|2|0.1%|0.0%|
[voipbl](#voipbl)|10303|10775|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.0%|
[php_bad](#php_bad)|281|281|1|0.3%|0.0%|
[et_botnet](#et_botnet)|512|512|1|0.1%|0.0%|

## ib_bluetack_level1

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Level 1 (for use in p2p): Companies or organizations who are clearly involved with trying to stop filesharing (e.g. Baytsp, MediaDefender, Mediasentry a.o.). Companies which anti-p2p activity has been seen from. Companies that produce or have a strong financial interest in copyrighted material (e.g. music, movie, software industries a.o.). Government ranges or companies that have a strong financial interest in doing work for governments. Legal industry ranges. IPs or ranges of ISPs from which anti-p2p activity has been observed. Basically this list will block all kinds of internet connections that most people would rather not have during their internet travels.

Source is downloaded from [this link](http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Thu May 28 09:22:00 UTC 2015.

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
[fullbogons](#fullbogons)|3656|670735064|235151|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|33155|7.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|13328|3.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|4678|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|1511|1.6%|0.0%|
[blocklist_de](#blocklist_de)|22289|22289|1485|6.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14576|14576|1346|9.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12789|12789|1322|10.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30710|30710|581|1.8%|0.0%|
[nixspam](#nixspam)|25659|25659|457|1.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|432|0.8%|0.0%|
[voipbl](#voipbl)|10303|10775|301|2.7%|0.0%|
[openbl_90d](#openbl_90d)|9854|9854|220|2.2%|0.0%|
[openbl](#openbl)|9854|9854|220|2.2%|0.0%|
[openbl_60d](#openbl_60d)|7777|7777|181|2.3%|0.0%|
[et_tor](#et_tor)|6490|6490|165|2.5%|0.0%|
[dm_tor](#dm_tor)|6490|6490|163|2.5%|0.0%|
[bm_tor](#bm_tor)|6492|6492|163|2.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7697|7697|143|1.8%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4417|4417|103|2.3%|0.0%|
[openbl_30d](#openbl_30d)|4446|4446|100|2.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|98|6.7%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|85|1.1%|0.0%|
[et_compromised](#et_compromised)|2338|2338|75|3.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|73|3.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|66|5.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1714|1714|61|3.5%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|58|8.6%|0.0%|
[xroxy](#xroxy)|1893|1893|51|2.6%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2201|2201|48|2.1%|0.0%|
[et_botnet](#et_botnet)|512|512|43|8.3%|0.0%|
[proxyrss](#proxyrss)|1722|1722|41|2.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3468|3468|41|1.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1483|1483|28|1.8%|0.0%|
[ciarmy](#ciarmy)|415|415|24|5.7%|0.0%|
[openbl_7d](#openbl_7d)|995|995|16|1.6%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|509|509|14|2.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|687|687|14|2.0%|0.0%|
[malc0de](#malc0de)|411|411|12|2.9%|0.0%|
[php_dictionary](#php_dictionary)|433|433|9|2.0%|0.0%|
[zeus](#zeus)|266|266|8|3.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[openbl_1d](#openbl_1d)|357|357|7|1.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|270|270|6|2.2%|0.0%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.0%|
[php_commenters](#php_commenters)|281|281|5|1.7%|0.0%|
[php_bad](#php_bad)|281|281|5|1.7%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[zeus_badips](#zeus_badips)|229|229|4|1.7%|0.0%|
[dshield](#dshield)|20|5120|4|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|93|93|4|4.3%|0.0%|
[sslbl](#sslbl)|345|345|3|0.8%|0.0%|
[feodo](#feodo)|67|67|3|4.4%|0.0%|
[proxz](#proxz)|65|65|1|1.5%|0.0%|

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
[fullbogons](#fullbogons)|3656|670735064|248327|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|33368|7.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|7877|4.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|7752|2.2%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|2467|2.6%|0.0%|
[blocklist_de](#blocklist_de)|22289|22289|1453|6.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14576|14576|1172|8.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12789|12789|1079|8.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30710|30710|927|3.0%|0.0%|
[nixspam](#nixspam)|25659|25659|650|2.5%|0.0%|
[openbl_90d](#openbl_90d)|9854|9854|511|5.1%|0.0%|
[openbl](#openbl)|9854|9854|511|5.1%|0.0%|
[voipbl](#voipbl)|10303|10775|428|3.9%|0.0%|
[openbl_60d](#openbl_60d)|7777|7777|361|4.6%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|233|0.4%|0.0%|
[openbl_30d](#openbl_30d)|4446|4446|229|5.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7697|7697|223|2.8%|0.0%|
[et_tor](#et_tor)|6490|6490|184|2.8%|0.0%|
[dm_tor](#dm_tor)|6490|6490|182|2.8%|0.0%|
[bm_tor](#bm_tor)|6492|6492|182|2.8%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4417|4417|153|3.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|146|6.0%|0.0%|
[et_compromised](#et_compromised)|2338|2338|143|6.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2201|2201|125|5.6%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|101|1.3%|0.0%|
[xroxy](#xroxy)|1893|1893|85|4.4%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3468|3468|78|2.2%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1714|1714|76|4.4%|0.0%|
[proxyrss](#proxyrss)|1722|1722|63|3.6%|0.0%|
[openbl_7d](#openbl_7d)|995|995|53|5.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|687|687|46|6.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|45|3.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1483|1483|45|3.0%|0.0%|
[ciarmy](#ciarmy)|415|415|40|9.6%|0.0%|
[php_spammers](#php_spammers)|417|417|31|7.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|28|4.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|26|2.0%|0.0%|
[malc0de](#malc0de)|411|411|26|6.3%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|270|270|23|8.5%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|509|509|22|4.3%|0.0%|
[et_botnet](#et_botnet)|512|512|21|4.1%|0.0%|
[openbl_1d](#openbl_1d)|357|357|17|4.7%|0.0%|
[php_dictionary](#php_dictionary)|433|433|10|2.3%|0.0%|
[zeus](#zeus)|266|266|9|3.3%|0.0%|
[php_commenters](#php_commenters)|281|281|9|3.2%|0.0%|
[php_bad](#php_bad)|281|281|9|3.2%|0.0%|
[zeus_badips](#zeus_badips)|229|229|8|3.4%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|228|228|8|3.5%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[sslbl](#sslbl)|345|345|6|1.7%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|93|93|6|6.4%|0.0%|
[proxz](#proxz)|65|65|4|6.1%|0.0%|
[shunlist](#shunlist)|51|51|3|5.8%|0.0%|
[feodo](#feodo)|67|67|3|4.4%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|

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
[fullbogons](#fullbogons)|3656|670735064|4233779|0.6%|3.0%|
[bogons](#bogons)|13|592708608|4194304|0.7%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|2832265|0.8%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|1360049|0.1%|0.9%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|270785|64.3%|0.1%|
[et_block](#et_block)|975|18056513|196440|1.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|195904|1.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|14655|8.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|9278|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|6117|6.6%|0.0%|
[blocklist_de](#blocklist_de)|22289|22289|2838|12.7%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14576|14576|2279|15.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12789|12789|2226|17.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30710|30710|2079|6.7%|0.0%|
[nixspam](#nixspam)|25659|25659|1666|6.4%|0.0%|
[voipbl](#voipbl)|10303|10775|1588|14.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1172|2.4%|0.0%|
[openbl_90d](#openbl_90d)|9854|9854|951|9.6%|0.0%|
[openbl](#openbl)|9854|9854|951|9.6%|0.0%|
[openbl_60d](#openbl_60d)|7777|7777|719|9.2%|0.0%|
[dm_tor](#dm_tor)|6490|6490|614|9.4%|0.0%|
[bm_tor](#bm_tor)|6492|6492|614|9.4%|0.0%|
[et_tor](#et_tor)|6490|6490|608|9.3%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7697|7697|550|7.1%|0.0%|
[openbl_30d](#openbl_30d)|4446|4446|445|10.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|233|9.5%|0.0%|
[et_compromised](#et_compromised)|2338|2338|225|9.6%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|222|3.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2201|2201|218|9.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3468|3468|154|4.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|146|11.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4417|4417|138|3.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1483|1483|137|9.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|110|7.5%|0.0%|
[openbl_7d](#openbl_7d)|995|995|90|9.0%|0.0%|
[malc0de](#malc0de)|411|411|76|18.4%|0.0%|
[ciarmy](#ciarmy)|415|415|76|18.3%|0.0%|
[et_botnet](#et_botnet)|512|512|75|14.6%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|509|509|73|14.3%|0.0%|
[xroxy](#xroxy)|1893|1893|72|3.8%|0.0%|
[proxyrss](#proxyrss)|1722|1722|61|3.5%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|51|7.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|687|687|42|6.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1714|1714|41|2.3%|0.0%|
[php_spammers](#php_spammers)|417|417|26|6.2%|0.0%|
[php_dictionary](#php_dictionary)|433|433|24|5.5%|0.0%|
[sslbl](#sslbl)|345|345|22|6.3%|0.0%|
[openbl_1d](#openbl_1d)|357|357|20|5.6%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|93|93|20|21.5%|0.0%|
[zeus](#zeus)|266|266|19|7.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|228|228|19|8.3%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|270|270|17|6.2%|0.0%|
[php_bad](#php_bad)|281|281|16|5.6%|0.0%|
[php_harvesters](#php_harvesters)|257|257|15|5.8%|0.0%|
[php_commenters](#php_commenters)|281|281|15|5.3%|0.0%|
[zeus_badips](#zeus_badips)|229|229|14|6.1%|0.0%|
[proxz](#proxz)|65|65|8|12.3%|0.0%|
[shunlist](#shunlist)|51|51|4|7.8%|0.0%|
[feodo](#feodo)|67|67|4|5.9%|0.0%|
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
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|22|0.0%|3.2%|
[xroxy](#xroxy)|1893|1893|12|0.6%|1.7%|
[stopforumspam_7d](#stopforumspam_7d)|30710|30710|12|0.0%|1.7%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|11|0.0%|1.6%|
[ri_web_proxies](#ri_web_proxies)|4417|4417|10|0.2%|1.4%|
[proxyrss](#proxyrss)|1722|1722|9|0.5%|1.3%|
[stopforumspam_1d](#stopforumspam_1d)|7697|7697|7|0.0%|1.0%|
[ri_connect_proxies](#ri_connect_proxies)|1714|1714|6|0.3%|0.8%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.2%|
[et_block](#et_block)|975|18056513|2|0.0%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3468|3468|2|0.0%|0.2%|
[blocklist_de](#blocklist_de)|22289|22289|2|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|1|0.0%|0.1%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.1%|
[nixspam](#nixspam)|25659|25659|1|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|1|0.0%|0.1%|

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
[fullbogons](#fullbogons)|3656|670735064|894|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|293|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|44|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|25|1.9%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30710|30710|22|0.0%|0.0%|
[et_tor](#et_tor)|6490|6490|21|0.3%|0.0%|
[dm_tor](#dm_tor)|6490|6490|21|0.3%|0.0%|
[bm_tor](#bm_tor)|6492|6492|21|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|19|1.3%|0.0%|
[nixspam](#nixspam)|25659|25659|17|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|15|0.2%|0.0%|
[blocklist_de](#blocklist_de)|22289|22289|7|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7697|7697|6|0.0%|0.0%|
[openbl_90d](#openbl_90d)|9854|9854|6|0.0%|0.0%|
[openbl](#openbl)|9854|9854|6|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7777|7777|5|0.0%|0.0%|
[voipbl](#voipbl)|10303|10775|4|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4417|4417|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4446|4446|4|0.0%|0.0%|
[dshield](#dshield)|20|5120|4|0.0%|0.0%|
[malc0de](#malc0de)|411|411|3|0.7%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|509|509|3|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2201|2201|3|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12789|12789|3|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|93|93|2|2.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[xroxy](#xroxy)|1893|1893|1|0.0%|0.0%|
[sslbl](#sslbl)|345|345|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|
[openbl_7d](#openbl_7d)|995|995|1|0.1%|0.0%|
[feodo](#feodo)|67|67|1|1.4%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14576|14576|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1483|1483|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3468|3468|1|0.0%|0.0%|

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
[fullbogons](#fullbogons)|3656|670735064|33|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|19|0.0%|1.3%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|8|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|6|0.0%|0.4%|
[et_block](#et_block)|975|18056513|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|3|0.2%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|30710|30710|2|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|2|0.0%|0.1%|
[openbl_90d](#openbl_90d)|9854|9854|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7777|7777|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|4446|4446|2|0.0%|0.1%|
[openbl](#openbl)|9854|9854|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.1%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|2|0.0%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|2201|2201|2|0.0%|0.1%|
[blocklist_de](#blocklist_de)|22289|22289|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7697|7697|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4417|4417|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|995|995|1|0.1%|0.0%|
[openbl_1d](#openbl_1d)|357|357|1|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_tor](#et_tor)|6490|6490|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2338|2338|1|0.0%|0.0%|
[et_botnet](#et_botnet)|512|512|1|0.1%|0.0%|
[dm_tor](#dm_tor)|6490|6490|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6492|6492|1|0.0%|0.0%|

## malc0de

[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days

Source is downloaded from [this link](http://malc0de.com/bl/IP_Blacklist.txt).

The last time downloaded was found to be dated: Thu May 28 13:17:02 UTC 2015.

The ipset `malc0de` has **411** entries, **411** unique IPs.

The following table shows the overlaps of `malc0de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `malc0de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `malc0de`.
- ` this % ` is the percentage **of this ipset (`malc0de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|76|0.0%|18.4%|
[cleanmx_viruses](#cleanmx_viruses)|509|509|32|6.2%|7.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|26|0.0%|6.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|12|0.0%|2.9%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|10|0.0%|2.4%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|4|0.3%|0.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|3|0.0%|0.7%|
[et_block](#et_block)|975|18056513|3|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.4%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|1|0.0%|0.2%|
[dshield](#dshield)|20|5120|1|0.0%|0.2%|

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
[snort_ipfilter](#snort_ipfilter)|7240|7240|25|0.3%|1.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|25|0.0%|1.9%|
[fullbogons](#fullbogons)|3656|670735064|9|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|7|0.0%|0.5%|
[malc0de](#malc0de)|411|411|4|0.9%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.2%|
[cleanmx_viruses](#cleanmx_viruses)|509|509|3|0.5%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|2|0.0%|0.1%|
[nixspam](#nixspam)|25659|25659|2|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30710|30710|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7697|7697|1|0.0%|0.0%|
[et_botnet](#et_botnet)|512|512|1|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3468|3468|1|0.0%|0.0%|
[blocklist_de](#blocklist_de)|22289|22289|1|0.0%|0.0%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Thu May 28 22:15:03 UTC 2015.

The ipset `nixspam` has **25659** entries, **25659** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|1666|0.0%|6.4%|
[blocklist_de](#blocklist_de)|22289|22289|656|2.9%|2.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|650|0.0%|2.5%|
[blocklist_de_mail](#blocklist_de_mail)|14576|14576|584|4.0%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|457|0.0%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|236|0.2%|0.9%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|175|2.4%|0.6%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|151|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|148|0.0%|0.5%|
[et_block](#et_block)|975|18056513|148|0.0%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|30710|30710|138|0.4%|0.5%|
[php_dictionary](#php_dictionary)|433|433|94|21.7%|0.3%|
[xroxy](#xroxy)|1893|1893|92|4.8%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7697|7697|78|1.0%|0.3%|
[php_spammers](#php_spammers)|417|417|77|18.4%|0.3%|
[ri_web_proxies](#ri_web_proxies)|4417|4417|73|1.6%|0.2%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|65|0.0%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3468|3468|55|1.5%|0.2%|
[openbl_90d](#openbl_90d)|9854|9854|25|0.2%|0.0%|
[openbl](#openbl)|9854|9854|25|0.2%|0.0%|
[proxyrss](#proxyrss)|1722|1722|24|1.3%|0.0%|
[openbl_60d](#openbl_60d)|7777|7777|23|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|20|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|17|0.0%|0.0%|
[php_commenters](#php_commenters)|281|281|16|5.6%|0.0%|
[php_bad](#php_bad)|281|281|15|5.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12789|12789|15|0.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1714|1714|14|0.8%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1483|1483|13|0.8%|0.0%|
[openbl_30d](#openbl_30d)|4446|4446|12|0.2%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[proxz](#proxz)|65|65|5|7.6%|0.0%|
[voipbl](#voipbl)|10303|10775|4|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2201|2201|3|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|270|270|3|1.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|2|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|228|228|2|0.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|687|687|2|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[shunlist](#shunlist)|51|51|1|1.9%|0.0%|
[openbl_7d](#openbl_7d)|995|995|1|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[et_tor](#et_tor)|6490|6490|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6490|6490|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6492|6492|1|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|93|93|1|1.0%|0.0%|

## openbl

[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**

Source is downloaded from [this link](http://www.openbl.org/lists/base.txt.gz).

The last time downloaded was found to be dated: Thu May 28 19:27:00 UTC 2015.

The ipset `openbl` has **9854** entries, **9854** unique IPs.

The following table shows the overlaps of `openbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl`.
- ` this % ` is the percentage **of this ipset (`openbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9854|9854|9854|100.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|9833|5.7%|99.7%|
[openbl_60d](#openbl_60d)|7777|7777|7777|100.0%|78.9%|
[openbl_30d](#openbl_30d)|4446|4446|4446|100.0%|45.1%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|1432|58.9%|14.5%|
[et_compromised](#et_compromised)|2338|2338|1396|59.7%|14.1%|
[blocklist_de](#blocklist_de)|22289|22289|1305|5.8%|13.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2201|2201|1219|55.3%|12.3%|
[openbl_7d](#openbl_7d)|995|995|995|100.0%|10.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|951|0.0%|9.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|511|0.0%|5.1%|
[et_block](#et_block)|975|18056513|455|0.0%|4.6%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|447|0.0%|4.5%|
[openbl_1d](#openbl_1d)|357|357|357|100.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|220|0.0%|2.2%|
[dshield](#dshield)|20|5120|147|2.8%|1.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|228|228|78|34.2%|0.7%|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|66|0.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|14576|14576|64|0.4%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|687|687|50|7.2%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|30710|30710|36|0.1%|0.3%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|26|0.3%|0.2%|
[nixspam](#nixspam)|25659|25659|25|0.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7697|7697|23|0.2%|0.2%|
[et_tor](#et_tor)|6490|6490|21|0.3%|0.2%|
[dm_tor](#dm_tor)|6490|6490|21|0.3%|0.2%|
[bm_tor](#bm_tor)|6492|6492|21|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|19|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|14|0.0%|0.1%|
[voipbl](#voipbl)|10303|10775|12|0.1%|0.1%|
[shunlist](#shunlist)|51|51|11|21.5%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12789|12789|11|0.0%|0.1%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.0%|
[php_bad](#php_bad)|281|281|8|2.8%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|270|270|8|2.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|6|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|5|1.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1483|1483|5|0.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3468|3468|3|0.0%|0.0%|
[zeus](#zeus)|266|266|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[sslbl](#sslbl)|345|345|1|0.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4417|4417|1|0.0%|0.0%|
[ciarmy](#ciarmy)|415|415|1|0.2%|0.0%|

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
[openbl_90d](#openbl_90d)|9854|9854|357|3.6%|100.0%|
[openbl_60d](#openbl_60d)|7777|7777|357|4.5%|100.0%|
[openbl_30d](#openbl_30d)|4446|4446|357|8.0%|100.0%|
[openbl](#openbl)|9854|9854|357|3.6%|100.0%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|355|0.2%|99.4%|
[blocklist_de](#blocklist_de)|22289|22289|242|1.0%|67.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|2201|2201|232|10.5%|64.9%|
[et_compromised](#et_compromised)|2338|2338|207|8.8%|57.9%|
[openbl_7d](#openbl_7d)|995|995|206|20.7%|57.7%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|201|8.2%|56.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|228|228|69|30.2%|19.3%|
[dshield](#dshield)|20|5120|51|0.9%|14.2%|
[et_block](#et_block)|975|18056513|27|0.0%|7.5%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|26|0.0%|7.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|20|0.0%|5.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|17|0.0%|4.7%|
[blocklist_de_mail](#blocklist_de_mail)|14576|14576|9|0.0%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|7|0.0%|1.9%|
[blocklist_de_imap](#blocklist_de_imap)|687|687|7|1.0%|1.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|1.4%|
[shunlist](#shunlist)|51|51|2|3.9%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|1|0.0%|0.2%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|270|270|1|0.3%|0.2%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt.gz).

The last time downloaded was found to be dated: Thu May 28 19:27:00 UTC 2015.

The ipset `openbl_30d` has **4446** entries, **4446** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9854|9854|4446|45.1%|100.0%|
[openbl_60d](#openbl_60d)|7777|7777|4446|57.1%|100.0%|
[openbl](#openbl)|9854|9854|4446|45.1%|100.0%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|4436|2.5%|99.7%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|1357|55.8%|30.5%|
[et_compromised](#et_compromised)|2338|2338|1328|56.8%|29.8%|
[blocklist_de](#blocklist_de)|22289|22289|1155|5.1%|25.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|2201|2201|1096|49.7%|24.6%|
[openbl_7d](#openbl_7d)|995|995|995|100.0%|22.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|445|0.0%|10.0%|
[openbl_1d](#openbl_1d)|357|357|357|100.0%|8.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|229|0.0%|5.1%|
[et_block](#et_block)|975|18056513|212|0.0%|4.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|207|0.0%|4.6%|
[dshield](#dshield)|20|5120|139|2.7%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|100|0.0%|2.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|228|228|76|33.3%|1.7%|
[blocklist_de_mail](#blocklist_de_mail)|14576|14576|52|0.3%|1.1%|
[blocklist_de_imap](#blocklist_de_imap)|687|687|42|6.1%|0.9%|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|18|0.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|13|0.0%|0.2%|
[nixspam](#nixspam)|25659|25659|12|0.0%|0.2%|
[shunlist](#shunlist)|51|51|10|19.6%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|30710|30710|7|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12789|12789|5|0.0%|0.1%|
[voipbl](#voipbl)|10303|10775|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|4|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|3|0.0%|0.0%|
[zeus](#zeus)|266|266|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|270|270|2|0.7%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7697|7697|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|415|415|1|0.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1483|1483|1|0.0%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt.gz).

The last time downloaded was found to be dated: Thu May 28 19:27:00 UTC 2015.

The ipset `openbl_60d` has **7777** entries, **7777** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9854|9854|7777|78.9%|100.0%|
[openbl](#openbl)|9854|9854|7777|78.9%|100.0%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|7759|4.5%|99.7%|
[openbl_30d](#openbl_30d)|4446|4446|4446|100.0%|57.1%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|1415|58.2%|18.1%|
[et_compromised](#et_compromised)|2338|2338|1386|59.2%|17.8%|
[blocklist_de](#blocklist_de)|22289|22289|1247|5.5%|16.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2201|2201|1174|53.3%|15.0%|
[openbl_7d](#openbl_7d)|995|995|995|100.0%|12.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|719|0.0%|9.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|361|0.0%|4.6%|
[openbl_1d](#openbl_1d)|357|357|357|100.0%|4.5%|
[et_block](#et_block)|975|18056513|287|0.0%|3.6%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|281|0.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|181|0.0%|2.3%|
[dshield](#dshield)|20|5120|144|2.8%|1.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|228|228|77|33.7%|0.9%|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|59|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|14576|14576|59|0.4%|0.7%|
[blocklist_de_imap](#blocklist_de_imap)|687|687|46|6.6%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|30710|30710|34|0.1%|0.4%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|26|0.3%|0.3%|
[nixspam](#nixspam)|25659|25659|23|0.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7697|7697|21|0.2%|0.2%|
[et_tor](#et_tor)|6490|6490|21|0.3%|0.2%|
[dm_tor](#dm_tor)|6490|6490|21|0.3%|0.2%|
[bm_tor](#bm_tor)|6492|6492|21|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|18|0.0%|0.2%|
[shunlist](#shunlist)|51|51|11|21.5%|0.1%|
[voipbl](#voipbl)|10303|10775|9|0.0%|0.1%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.1%|
[php_bad](#php_bad)|281|281|8|2.8%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12789|12789|8|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|270|270|6|2.2%|0.0%|
[php_harvesters](#php_harvesters)|257|257|5|1.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|5|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1483|1483|3|0.2%|0.0%|
[zeus](#zeus)|266|266|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|415|415|1|0.2%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt.gz).

The last time downloaded was found to be dated: Thu May 28 19:27:00 UTC 2015.

The ipset `openbl_7d` has **995** entries, **995** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9854|9854|995|10.0%|100.0%|
[openbl_60d](#openbl_60d)|7777|7777|995|12.7%|100.0%|
[openbl_30d](#openbl_30d)|4446|4446|995|22.3%|100.0%|
[openbl](#openbl)|9854|9854|995|10.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|990|0.5%|99.4%|
[blocklist_de](#blocklist_de)|22289|22289|661|2.9%|66.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|2201|2201|632|28.7%|63.5%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|515|21.2%|51.7%|
[et_compromised](#et_compromised)|2338|2338|495|21.1%|49.7%|
[openbl_1d](#openbl_1d)|357|357|206|57.7%|20.7%|
[dshield](#dshield)|20|5120|119|2.3%|11.9%|
[et_block](#et_block)|975|18056513|97|0.0%|9.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|94|0.0%|9.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|90|0.0%|9.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|228|228|75|32.8%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|53|0.0%|5.3%|
[blocklist_de_mail](#blocklist_de_mail)|14576|14576|26|0.1%|2.6%|
[blocklist_de_imap](#blocklist_de_imap)|687|687|24|3.4%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|16|0.0%|1.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|9|0.0%|0.9%|
[shunlist](#shunlist)|51|51|5|9.8%|0.5%|
[voipbl](#voipbl)|10303|10775|3|0.0%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|2|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|2|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|12789|12789|2|0.0%|0.2%|
[zeus](#zeus)|266|266|1|0.3%|0.1%|
[nixspam](#nixspam)|25659|25659|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.1%|
[ciarmy](#ciarmy)|415|415|1|0.2%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|270|270|1|0.3%|0.1%|

## openbl_90d

[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_90days.txt.gz).

The last time downloaded was found to be dated: Thu May 28 19:27:00 UTC 2015.

The ipset `openbl_90d` has **9854** entries, **9854** unique IPs.

The following table shows the overlaps of `openbl_90d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_90d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_90d`.
- ` this % ` is the percentage **of this ipset (`openbl_90d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl](#openbl)|9854|9854|9854|100.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|9833|5.7%|99.7%|
[openbl_60d](#openbl_60d)|7777|7777|7777|100.0%|78.9%|
[openbl_30d](#openbl_30d)|4446|4446|4446|100.0%|45.1%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|1432|58.9%|14.5%|
[et_compromised](#et_compromised)|2338|2338|1396|59.7%|14.1%|
[blocklist_de](#blocklist_de)|22289|22289|1305|5.8%|13.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2201|2201|1219|55.3%|12.3%|
[openbl_7d](#openbl_7d)|995|995|995|100.0%|10.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|951|0.0%|9.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|511|0.0%|5.1%|
[et_block](#et_block)|975|18056513|455|0.0%|4.6%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|447|0.0%|4.5%|
[openbl_1d](#openbl_1d)|357|357|357|100.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|220|0.0%|2.2%|
[dshield](#dshield)|20|5120|147|2.8%|1.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|228|228|78|34.2%|0.7%|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|66|0.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|14576|14576|64|0.4%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|687|687|50|7.2%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|30710|30710|36|0.1%|0.3%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|26|0.3%|0.2%|
[nixspam](#nixspam)|25659|25659|25|0.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7697|7697|23|0.2%|0.2%|
[et_tor](#et_tor)|6490|6490|21|0.3%|0.2%|
[dm_tor](#dm_tor)|6490|6490|21|0.3%|0.2%|
[bm_tor](#bm_tor)|6492|6492|21|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|19|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|14|0.0%|0.1%|
[voipbl](#voipbl)|10303|10775|12|0.1%|0.1%|
[shunlist](#shunlist)|51|51|11|21.5%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12789|12789|11|0.0%|0.1%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.0%|
[php_bad](#php_bad)|281|281|8|2.8%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|270|270|8|2.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|6|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|5|1.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1483|1483|5|0.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3468|3468|3|0.0%|0.0%|
[zeus](#zeus)|266|266|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[sslbl](#sslbl)|345|345|1|0.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4417|4417|1|0.0%|0.0%|
[ciarmy](#ciarmy)|415|415|1|0.2%|0.0%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Thu May 28 21:54:14 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|975|18056513|13|0.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|11|0.1%|84.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|2|0.0%|15.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|7.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|1|0.0%|7.6%|

## php_bad

[projecthoneypot.org](http://www.projecthoneypot.org/) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1).

The last time downloaded was found to be dated: Thu May 28 20:53:18 UTC 2015.

The ipset `php_bad` has **281** entries, **281** unique IPs.

The following table shows the overlaps of `php_bad` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_bad`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_bad`.
- ` this % ` is the percentage **of this ipset (`php_bad`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[php_commenters](#php_commenters)|281|281|279|99.2%|99.2%|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|202|0.2%|71.8%|
[stopforumspam_7d](#stopforumspam_7d)|30710|30710|190|0.6%|67.6%|
[stopforumspam_1d](#stopforumspam_1d)|7697|7697|111|1.4%|39.5%|
[blocklist_de](#blocklist_de)|22289|22289|75|0.3%|26.6%|
[blocklist_de_bots](#blocklist_de_bots)|3468|3468|61|1.7%|21.7%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|41|0.5%|14.5%|
[php_spammers](#php_spammers)|417|417|32|7.6%|11.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|228|228|32|14.0%|11.3%|
[et_tor](#et_tor)|6490|6490|29|0.4%|10.3%|
[dm_tor](#dm_tor)|6490|6490|29|0.4%|10.3%|
[bm_tor](#bm_tor)|6492|6492|29|0.4%|10.3%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|25|0.0%|8.8%|
[et_block](#et_block)|975|18056513|24|0.0%|8.5%|
[blocklist_de_apache](#blocklist_de_apache)|12789|12789|23|0.1%|8.1%|
[php_dictionary](#php_dictionary)|433|433|22|5.0%|7.8%|
[blocklist_de_mail](#blocklist_de_mail)|14576|14576|22|0.1%|7.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|16|0.0%|5.6%|
[nixspam](#nixspam)|25659|25659|15|0.0%|5.3%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|12|0.0%|4.2%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|9|0.0%|3.2%|
[ri_web_proxies](#ri_web_proxies)|4417|4417|8|0.1%|2.8%|
[openbl_90d](#openbl_90d)|9854|9854|8|0.0%|2.8%|
[openbl_60d](#openbl_60d)|7777|7777|8|0.1%|2.8%|
[openbl](#openbl)|9854|9854|8|0.0%|2.8%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|7|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|5|0.0%|1.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1483|1483|4|0.2%|1.4%|
[xroxy](#xroxy)|1893|1893|3|0.1%|1.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.3%|
[zeus](#zeus)|266|266|1|0.3%|0.3%|
[proxz](#proxz)|65|65|1|1.5%|0.3%|
[proxyrss](#proxyrss)|1722|1722|1|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|

## php_commenters

[projecthoneypot.org](http://www.projecthoneypot.org/) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1).

The last time downloaded was found to be dated: Thu May 28 20:53:20 UTC 2015.

The ipset `php_commenters` has **281** entries, **281** unique IPs.

The following table shows the overlaps of `php_commenters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_commenters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_commenters`.
- ` this % ` is the percentage **of this ipset (`php_commenters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[php_bad](#php_bad)|281|281|279|99.2%|99.2%|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|203|0.2%|72.2%|
[stopforumspam_7d](#stopforumspam_7d)|30710|30710|191|0.6%|67.9%|
[stopforumspam_1d](#stopforumspam_1d)|7697|7697|111|1.4%|39.5%|
[blocklist_de](#blocklist_de)|22289|22289|76|0.3%|27.0%|
[blocklist_de_bots](#blocklist_de_bots)|3468|3468|61|1.7%|21.7%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|40|0.5%|14.2%|
[php_spammers](#php_spammers)|417|417|32|7.6%|11.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|228|228|32|14.0%|11.3%|
[et_tor](#et_tor)|6490|6490|29|0.4%|10.3%|
[dm_tor](#dm_tor)|6490|6490|29|0.4%|10.3%|
[bm_tor](#bm_tor)|6492|6492|29|0.4%|10.3%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|25|0.0%|8.8%|
[et_block](#et_block)|975|18056513|24|0.0%|8.5%|
[blocklist_de_mail](#blocklist_de_mail)|14576|14576|23|0.1%|8.1%|
[blocklist_de_apache](#blocklist_de_apache)|12789|12789|23|0.1%|8.1%|
[php_dictionary](#php_dictionary)|433|433|22|5.0%|7.8%|
[nixspam](#nixspam)|25659|25659|16|0.0%|5.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|15|0.0%|5.3%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|12|0.0%|4.2%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|9|0.0%|3.2%|
[ri_web_proxies](#ri_web_proxies)|4417|4417|8|0.1%|2.8%|
[openbl_90d](#openbl_90d)|9854|9854|8|0.0%|2.8%|
[openbl_60d](#openbl_60d)|7777|7777|8|0.1%|2.8%|
[openbl](#openbl)|9854|9854|8|0.0%|2.8%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|7|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|5|0.0%|1.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1483|1483|4|0.2%|1.4%|
[xroxy](#xroxy)|1893|1893|3|0.1%|1.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.3%|
[zeus](#zeus)|266|266|1|0.3%|0.3%|
[proxz](#proxz)|65|65|1|1.5%|0.3%|
[proxyrss](#proxyrss)|1722|1722|1|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|

## php_dictionary

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1).

The last time downloaded was found to be dated: Thu May 28 20:53:21 UTC 2015.

The ipset `php_dictionary` has **433** entries, **433** unique IPs.

The following table shows the overlaps of `php_dictionary` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_dictionary`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_dictionary`.
- ` this % ` is the percentage **of this ipset (`php_dictionary`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[nixspam](#nixspam)|25659|25659|94|0.3%|21.7%|
[php_spammers](#php_spammers)|417|417|84|20.1%|19.3%|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|74|0.0%|17.0%|
[blocklist_de](#blocklist_de)|22289|22289|73|0.3%|16.8%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|71|0.9%|16.3%|
[blocklist_de_mail](#blocklist_de_mail)|14576|14576|62|0.4%|14.3%|
[stopforumspam_7d](#stopforumspam_7d)|30710|30710|56|0.1%|12.9%|
[stopforumspam_1d](#stopforumspam_1d)|7697|7697|25|0.3%|5.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|24|0.0%|5.5%|
[xroxy](#xroxy)|1893|1893|23|1.2%|5.3%|
[php_commenters](#php_commenters)|281|281|22|7.8%|5.0%|
[php_bad](#php_bad)|281|281|22|7.8%|5.0%|
[ri_web_proxies](#ri_web_proxies)|4417|4417|21|0.4%|4.8%|
[blocklist_de_bots](#blocklist_de_bots)|3468|3468|12|0.3%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|10|0.0%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|9|0.0%|2.0%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|7|0.0%|1.6%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|4|0.0%|0.9%|
[et_block](#et_block)|975|18056513|4|0.0%|0.9%|
[dm_tor](#dm_tor)|6490|6490|4|0.0%|0.9%|
[bm_tor](#bm_tor)|6492|6492|4|0.0%|0.9%|
[ri_connect_proxies](#ri_connect_proxies)|1714|1714|3|0.1%|0.6%|
[et_tor](#et_tor)|6490|6490|3|0.0%|0.6%|
[proxz](#proxz)|65|65|2|3.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.4%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|228|228|1|0.4%|0.2%|

## php_harvesters

[projecthoneypot.org](http://www.projecthoneypot.org/) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1).

The last time downloaded was found to be dated: Thu May 28 20:53:17 UTC 2015.

The ipset `php_harvesters` has **257** entries, **257** unique IPs.

The following table shows the overlaps of `php_harvesters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_harvesters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_harvesters`.
- ` this % ` is the percentage **of this ipset (`php_harvesters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|62|0.0%|24.1%|
[stopforumspam_7d](#stopforumspam_7d)|30710|30710|50|0.1%|19.4%|
[stopforumspam_1d](#stopforumspam_1d)|7697|7697|39|0.5%|15.1%|
[blocklist_de](#blocklist_de)|22289|22289|33|0.1%|12.8%|
[blocklist_de_bots](#blocklist_de_bots)|3468|3468|27|0.7%|10.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|15|0.0%|5.8%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|10|0.1%|3.8%|
[php_commenters](#php_commenters)|281|281|9|3.2%|3.5%|
[php_bad](#php_bad)|281|281|9|3.2%|3.5%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|9|0.0%|3.5%|
[nixspam](#nixspam)|25659|25659|7|0.0%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|7|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|7|0.0%|2.7%|
[et_tor](#et_tor)|6490|6490|7|0.1%|2.7%|
[dm_tor](#dm_tor)|6490|6490|7|0.1%|2.7%|
[bm_tor](#bm_tor)|6492|6492|7|0.1%|2.7%|
[openbl_90d](#openbl_90d)|9854|9854|5|0.0%|1.9%|
[openbl_60d](#openbl_60d)|7777|7777|5|0.0%|1.9%|
[openbl](#openbl)|9854|9854|5|0.0%|1.9%|
[blocklist_de_mail](#blocklist_de_mail)|14576|14576|4|0.0%|1.5%|
[xroxy](#xroxy)|1893|1893|2|0.1%|0.7%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.7%|
[blocklist_de_ftp](#blocklist_de_ftp)|270|270|2|0.7%|0.7%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|1|0.0%|0.3%|
[ri_web_proxies](#ri_web_proxies)|4417|4417|1|0.0%|0.3%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.3%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|
[fullbogons](#fullbogons)|3656|670735064|1|0.0%|0.3%|
[et_block](#et_block)|975|18056513|1|0.0%|0.3%|
[bogons](#bogons)|13|592708608|1|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|228|228|1|0.4%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|12789|12789|1|0.0%|0.3%|

## php_spammers

[projecthoneypot.org](http://www.projecthoneypot.org/) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1).

The last time downloaded was found to be dated: Thu May 28 20:53:18 UTC 2015.

The ipset `php_spammers` has **417** entries, **417** unique IPs.

The following table shows the overlaps of `php_spammers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_spammers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_spammers`.
- ` this % ` is the percentage **of this ipset (`php_spammers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|95|0.1%|22.7%|
[php_dictionary](#php_dictionary)|433|433|84|19.3%|20.1%|
[nixspam](#nixspam)|25659|25659|77|0.3%|18.4%|
[blocklist_de](#blocklist_de)|22289|22289|66|0.2%|15.8%|
[stopforumspam_7d](#stopforumspam_7d)|30710|30710|64|0.2%|15.3%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|60|0.8%|14.3%|
[blocklist_de_mail](#blocklist_de_mail)|14576|14576|46|0.3%|11.0%|
[php_commenters](#php_commenters)|281|281|32|11.3%|7.6%|
[php_bad](#php_bad)|281|281|32|11.3%|7.6%|
[stopforumspam_1d](#stopforumspam_1d)|7697|7697|31|0.4%|7.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|31|0.0%|7.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|26|0.0%|6.2%|
[ri_web_proxies](#ri_web_proxies)|4417|4417|18|0.4%|4.3%|
[xroxy](#xroxy)|1893|1893|17|0.8%|4.0%|
[blocklist_de_bots](#blocklist_de_bots)|3468|3468|16|0.4%|3.8%|
[et_tor](#et_tor)|6490|6490|6|0.0%|1.4%|
[dm_tor](#dm_tor)|6490|6490|6|0.0%|1.4%|
[bm_tor](#bm_tor)|6492|6492|6|0.0%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|5|0.0%|1.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|228|228|5|2.1%|1.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1483|1483|5|0.3%|1.1%|
[blocklist_de_apache](#blocklist_de_apache)|12789|12789|5|0.0%|1.1%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|3|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.4%|
[ri_connect_proxies](#ri_connect_proxies)|1714|1714|2|0.1%|0.4%|
[proxyrss](#proxyrss)|1722|1722|2|0.1%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[et_block](#et_block)|975|18056513|2|0.0%|0.4%|
[proxz](#proxz)|65|65|1|1.5%|0.2%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.2%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Thu May 28 18:51:28 UTC 2015.

The ipset `proxyrss` has **1722** entries, **1722** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[xroxy](#xroxy)|1893|1893|1333|70.4%|77.4%|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|872|0.9%|50.6%|
[stopforumspam_7d](#stopforumspam_7d)|30710|30710|732|2.3%|42.5%|
[ri_web_proxies](#ri_web_proxies)|4417|4417|633|14.3%|36.7%|
[stopforumspam_1d](#stopforumspam_1d)|7697|7697|499|6.4%|28.9%|
[ri_connect_proxies](#ri_connect_proxies)|1714|1714|237|13.8%|13.7%|
[blocklist_de](#blocklist_de)|22289|22289|226|1.0%|13.1%|
[blocklist_de_bots](#blocklist_de_bots)|3468|3468|223|6.4%|12.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|63|0.0%|3.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|61|0.0%|3.5%|
[proxz](#proxz)|65|65|48|73.8%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|41|0.0%|2.3%|
[nixspam](#nixspam)|25659|25659|24|0.0%|1.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|9|1.3%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|228|228|3|1.3%|0.1%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|2|0.0%|0.1%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.1%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|2|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|2|0.0%|0.1%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.0%|
[php_bad](#php_bad)|281|281|1|0.3%|0.0%|
[et_tor](#et_tor)|6490|6490|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2338|2338|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6490|6490|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6492|6492|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2201|2201|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14576|14576|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1483|1483|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12789|12789|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Thu May 28 21:41:36 UTC 2015.

The ipset `proxz` has **65** entries, **65** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[xroxy](#xroxy)|1893|1893|55|2.9%|84.6%|
[proxyrss](#proxyrss)|1722|1722|48|2.7%|73.8%|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|34|0.0%|52.3%|
[stopforumspam_7d](#stopforumspam_7d)|30710|30710|33|0.1%|50.7%|
[stopforumspam_1d](#stopforumspam_1d)|7697|7697|28|0.3%|43.0%|
[ri_web_proxies](#ri_web_proxies)|4417|4417|22|0.4%|33.8%|
[blocklist_de](#blocklist_de)|22289|22289|18|0.0%|27.6%|
[blocklist_de_bots](#blocklist_de_bots)|3468|3468|16|0.4%|24.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|8|0.0%|12.3%|
[nixspam](#nixspam)|25659|25659|5|0.0%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|4|0.0%|6.1%|
[ri_connect_proxies](#ri_connect_proxies)|1714|1714|3|0.1%|4.6%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|3.0%|
[blocklist_de_mail](#blocklist_de_mail)|14576|14576|2|0.0%|3.0%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|1|0.0%|1.5%|
[php_spammers](#php_spammers)|417|417|1|0.2%|1.5%|
[php_commenters](#php_commenters)|281|281|1|0.3%|1.5%|
[php_bad](#php_bad)|281|281|1|0.3%|1.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|1|0.0%|1.5%|
[et_compromised](#et_compromised)|2338|2338|1|0.0%|1.5%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|1|0.0%|1.5%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Thu May 28 15:04:27 UTC 2015.

The ipset `ri_connect_proxies` has **1714** entries, **1714** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|995|1.0%|58.0%|
[ri_web_proxies](#ri_web_proxies)|4417|4417|701|15.8%|40.8%|
[stopforumspam_7d](#stopforumspam_7d)|30710|30710|692|2.2%|40.3%|
[xroxy](#xroxy)|1893|1893|265|13.9%|15.4%|
[proxyrss](#proxyrss)|1722|1722|237|13.7%|13.8%|
[stopforumspam_1d](#stopforumspam_1d)|7697|7697|191|2.4%|11.1%|
[blocklist_de](#blocklist_de)|22289|22289|79|0.3%|4.6%|
[blocklist_de_bots](#blocklist_de_bots)|3468|3468|77|2.2%|4.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|76|0.0%|4.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|61|0.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|41|0.0%|2.3%|
[nixspam](#nixspam)|25659|25659|14|0.0%|0.8%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.3%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|3|0.0%|0.1%|
[proxz](#proxz)|65|65|3|4.6%|0.1%|
[php_dictionary](#php_dictionary)|433|433|3|0.6%|0.1%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.1%|
[et_tor](#et_tor)|6490|6490|2|0.0%|0.1%|
[dm_tor](#dm_tor)|6490|6490|2|0.0%|0.1%|
[bm_tor](#bm_tor)|6492|6492|2|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|14576|14576|2|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Thu May 28 20:37:31 UTC 2015.

The ipset `ri_web_proxies` has **4417** entries, **4417** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|2182|2.3%|49.4%|
[stopforumspam_7d](#stopforumspam_7d)|30710|30710|1619|5.2%|36.6%|
[ri_connect_proxies](#ri_connect_proxies)|1714|1714|701|40.8%|15.8%|
[xroxy](#xroxy)|1893|1893|699|36.9%|15.8%|
[proxyrss](#proxyrss)|1722|1722|633|36.7%|14.3%|
[stopforumspam_1d](#stopforumspam_1d)|7697|7697|583|7.5%|13.1%|
[blocklist_de](#blocklist_de)|22289|22289|388|1.7%|8.7%|
[blocklist_de_bots](#blocklist_de_bots)|3468|3468|357|10.2%|8.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|153|0.0%|3.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|138|0.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|103|0.0%|2.3%|
[nixspam](#nixspam)|25659|25659|73|0.2%|1.6%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|30|0.4%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|14576|14576|30|0.2%|0.6%|
[proxz](#proxz)|65|65|22|33.8%|0.4%|
[php_dictionary](#php_dictionary)|433|433|21|4.8%|0.4%|
[php_spammers](#php_spammers)|417|417|18|4.3%|0.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|10|1.4%|0.2%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.1%|
[php_bad](#php_bad)|281|281|8|2.8%|0.1%|
[et_tor](#et_tor)|6490|6490|5|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6490|6490|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6492|6492|4|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|228|228|3|1.3%|0.0%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[openbl_90d](#openbl_90d)|9854|9854|1|0.0%|0.0%|
[openbl](#openbl)|9854|9854|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2201|2201|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1483|1483|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12789|12789|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Thu May 28 18:30:05 UTC 2015.

The ipset `shunlist` has **51** entries, **51** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|172159|172159|51|0.0%|100.0%|
[blocklist_de](#blocklist_de)|22289|22289|12|0.0%|23.5%|
[openbl_90d](#openbl_90d)|9854|9854|11|0.1%|21.5%|
[openbl_60d](#openbl_60d)|7777|7777|11|0.1%|21.5%|
[openbl](#openbl)|9854|9854|11|0.1%|21.5%|
[openbl_30d](#openbl_30d)|4446|4446|10|0.2%|19.6%|
[et_compromised](#et_compromised)|2338|2338|9|0.3%|17.6%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|9|0.3%|17.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|2201|2201|8|0.3%|15.6%|
[openbl_7d](#openbl_7d)|995|995|5|0.5%|9.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|4|0.0%|7.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|3|0.0%|5.8%|
[voipbl](#voipbl)|10303|10775|2|0.0%|3.9%|
[openbl_1d](#openbl_1d)|357|357|2|0.5%|3.9%|
[ciarmy](#ciarmy)|415|415|2|0.4%|3.9%|
[blocklist_de_mail](#blocklist_de_mail)|14576|14576|2|0.0%|3.9%|
[blocklist_de_imap](#blocklist_de_imap)|687|687|2|0.2%|3.9%|
[blocklist_de_apache](#blocklist_de_apache)|12789|12789|2|0.0%|3.9%|
[nixspam](#nixspam)|25659|25659|1|0.0%|1.9%|

## snort_ipfilter

[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)

Source is downloaded from [this link](http://labs.snort.org/feeds/ip-filter.blf).

The last time downloaded was found to be dated: Thu May 28 13:30:00 UTC 2015.

The ipset `snort_ipfilter` has **7240** entries, **7240** unique IPs.

The following table shows the overlaps of `snort_ipfilter` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `snort_ipfilter`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `snort_ipfilter`.
- ` this % ` is the percentage **of this ipset (`snort_ipfilter`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_tor](#et_tor)|6490|6490|1090|16.7%|15.0%|
[dm_tor](#dm_tor)|6490|6490|1047|16.1%|14.4%|
[bm_tor](#bm_tor)|6492|6492|1047|16.1%|14.4%|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|718|0.7%|9.9%|
[stopforumspam_7d](#stopforumspam_7d)|30710|30710|526|1.7%|7.2%|
[stopforumspam_1d](#stopforumspam_1d)|7697|7697|382|4.9%|5.2%|
[et_block](#et_block)|975|18056513|286|0.0%|3.9%|
[zeus](#zeus)|266|266|226|84.9%|3.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|222|0.0%|3.0%|
[zeus_badips](#zeus_badips)|229|229|201|87.7%|2.7%|
[blocklist_de](#blocklist_de)|22289|22289|186|0.8%|2.5%|
[nixspam](#nixspam)|25659|25659|175|0.6%|2.4%|
[blocklist_de_mail](#blocklist_de_mail)|14576|14576|122|0.8%|1.6%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|121|0.0%|1.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|101|0.0%|1.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|85|0.0%|1.1%|
[php_dictionary](#php_dictionary)|433|433|71|16.3%|0.9%|
[php_spammers](#php_spammers)|417|417|60|14.3%|0.8%|
[feodo](#feodo)|67|67|48|71.6%|0.6%|
[php_bad](#php_bad)|281|281|41|14.5%|0.5%|
[php_commenters](#php_commenters)|281|281|40|14.2%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|12789|12789|40|0.3%|0.5%|
[xroxy](#xroxy)|1893|1893|39|2.0%|0.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1483|1483|37|2.4%|0.5%|
[ri_web_proxies](#ri_web_proxies)|4417|4417|30|0.6%|0.4%|
[openbl_90d](#openbl_90d)|9854|9854|26|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7777|7777|26|0.3%|0.3%|
[openbl](#openbl)|9854|9854|26|0.2%|0.3%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|25|1.9%|0.3%|
[blocklist_de_bots](#blocklist_de_bots)|3468|3468|24|0.6%|0.3%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|20|0.0%|0.2%|
[sslbl](#sslbl)|345|345|17|4.9%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|15|0.0%|0.2%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|10|3.8%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|6|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|509|509|4|0.7%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1714|1714|3|0.1%|0.0%|
[openbl_30d](#openbl_30d)|4446|4446|3|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2201|2201|3|0.1%|0.0%|
[proxyrss](#proxyrss)|1722|1722|2|0.1%|0.0%|
[openbl_7d](#openbl_7d)|995|995|2|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|687|687|2|0.2%|0.0%|
[proxz](#proxz)|65|65|1|1.5%|0.0%|
[malc0de](#malc0de)|411|411|1|0.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2338|2338|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|228|228|1|0.4%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|270|270|1|0.3%|0.0%|

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
[fullbogons](#fullbogons)|3656|670735064|20480|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|1622|0.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|782|0.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|512|0.1%|0.0%|
[dshield](#dshield)|20|5120|512|10.0%|0.0%|
[openbl_90d](#openbl_90d)|9854|9854|447|4.5%|0.0%|
[openbl](#openbl)|9854|9854|447|4.5%|0.0%|
[openbl_60d](#openbl_60d)|7777|7777|281|3.6%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30710|30710|235|0.7%|0.0%|
[openbl_30d](#openbl_30d)|4446|4446|207|4.6%|0.0%|
[blocklist_de](#blocklist_de)|22289|22289|194|0.8%|0.0%|
[nixspam](#nixspam)|25659|25659|151|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2201|2201|114|5.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|102|4.2%|0.0%|
[openbl_7d](#openbl_7d)|995|995|94|9.4%|0.0%|
[et_compromised](#et_compromised)|2338|2338|92|3.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3468|3468|52|1.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7697|7697|45|0.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|28|2.1%|0.0%|
[openbl_1d](#openbl_1d)|357|357|26|7.2%|0.0%|
[php_commenters](#php_commenters)|281|281|25|8.8%|0.0%|
[php_bad](#php_bad)|281|281|25|8.8%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14576|14576|24|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|20|0.2%|0.0%|
[zeus_badips](#zeus_badips)|229|229|16|6.9%|0.0%|
[zeus](#zeus)|266|266|16|6.0%|0.0%|
[voipbl](#voipbl)|10303|10775|14|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|687|687|13|1.8%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|228|228|7|3.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1483|1483|4|0.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12789|12789|4|0.0%|0.0%|
[sslbl](#sslbl)|345|345|3|0.8%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[malc0de](#malc0de)|411|411|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6490|6490|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6490|6490|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6492|6492|2|0.0%|0.0%|
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
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|105|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30710|30710|40|0.1%|0.0%|
[blocklist_de](#blocklist_de)|22289|22289|34|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3468|3468|29|0.8%|0.0%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|15|0.0%|0.0%|
[openbl_90d](#openbl_90d)|9854|9854|14|0.1%|0.0%|
[openbl](#openbl)|9854|9854|14|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7697|7697|13|0.1%|0.0%|
[php_commenters](#php_commenters)|281|281|7|2.4%|0.0%|
[php_bad](#php_bad)|281|281|7|2.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|6|0.0%|0.0%|
[zeus_badips](#zeus_badips)|229|229|5|2.1%|0.0%|
[zeus](#zeus)|266|266|5|1.8%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|228|228|4|1.7%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14576|14576|4|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[openbl_60d](#openbl_60d)|7777|7777|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4446|4446|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|357|357|1|0.2%|0.0%|
[nixspam](#nixspam)|25659|25659|1|0.0%|0.0%|
[malc0de](#malc0de)|411|411|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|687|687|1|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12789|12789|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Thu May 28 22:15:05 UTC 2015.

The ipset `sslbl` has **345** entries, **345** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[feodo](#feodo)|67|67|24|35.8%|6.9%|
[et_block](#et_block)|975|18056513|23|0.0%|6.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|22|0.0%|6.3%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|17|0.2%|4.9%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|7|0.0%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|6|0.0%|1.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|3|0.0%|0.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|3|0.0%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|1|0.0%|0.2%|
[openbl_90d](#openbl_90d)|9854|9854|1|0.0%|0.2%|
[openbl](#openbl)|9854|9854|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Thu May 28 22:00:02 UTC 2015.

The ipset `stopforumspam_1d` has **7697** entries, **7697** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|4904|5.3%|63.7%|
[stopforumspam_7d](#stopforumspam_7d)|30710|30710|4583|14.9%|59.5%|
[blocklist_de](#blocklist_de)|22289|22289|1641|7.3%|21.3%|
[blocklist_de_bots](#blocklist_de_bots)|3468|3468|1546|44.5%|20.0%|
[ri_web_proxies](#ri_web_proxies)|4417|4417|583|13.1%|7.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|550|0.0%|7.1%|
[xroxy](#xroxy)|1893|1893|526|27.7%|6.8%|
[proxyrss](#proxyrss)|1722|1722|499|28.9%|6.4%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|382|5.2%|4.9%|
[dm_tor](#dm_tor)|6490|6490|343|5.2%|4.4%|
[bm_tor](#bm_tor)|6492|6492|343|5.2%|4.4%|
[et_tor](#et_tor)|6490|6490|333|5.1%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|223|0.0%|2.8%|
[ri_connect_proxies](#ri_connect_proxies)|1714|1714|191|11.1%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|143|0.0%|1.8%|
[php_commenters](#php_commenters)|281|281|111|39.5%|1.4%|
[php_bad](#php_bad)|281|281|111|39.5%|1.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|228|228|110|48.2%|1.4%|
[blocklist_de_apache](#blocklist_de_apache)|12789|12789|92|0.7%|1.1%|
[nixspam](#nixspam)|25659|25659|78|0.3%|1.0%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|61|0.0%|0.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1483|1483|55|3.7%|0.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|45|0.0%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|14576|14576|42|0.2%|0.5%|
[php_harvesters](#php_harvesters)|257|257|39|15.1%|0.5%|
[et_block](#et_block)|975|18056513|37|0.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|33|0.0%|0.4%|
[php_spammers](#php_spammers)|417|417|31|7.4%|0.4%|
[proxz](#proxz)|65|65|28|43.0%|0.3%|
[php_dictionary](#php_dictionary)|433|433|25|5.7%|0.3%|
[openbl_90d](#openbl_90d)|9854|9854|23|0.2%|0.2%|
[openbl](#openbl)|9854|9854|23|0.2%|0.2%|
[openbl_60d](#openbl_60d)|7777|7777|21|0.2%|0.2%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|13|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|7|1.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|6|0.0%|0.0%|
[voipbl](#voipbl)|10303|10775|4|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|2|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4446|4446|1|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2338|2338|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2201|2201|1|0.0%|0.0%|

## stopforumspam_30d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip).

The last time downloaded was found to be dated: Thu May 28 00:00:49 UTC 2015.

The ipset `stopforumspam_30d` has **92103** entries, **92103** unique IPs.

The following table shows the overlaps of `stopforumspam_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_30d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_7d](#stopforumspam_7d)|30710|30710|30535|99.4%|33.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|6117|0.0%|6.6%|
[stopforumspam_1d](#stopforumspam_1d)|7697|7697|4904|63.7%|5.3%|
[blocklist_de](#blocklist_de)|22289|22289|2588|11.6%|2.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|2467|0.0%|2.6%|
[blocklist_de_bots](#blocklist_de_bots)|3468|3468|2283|65.8%|2.4%|
[ri_web_proxies](#ri_web_proxies)|4417|4417|2182|49.4%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|1511|0.0%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|1714|1714|995|58.0%|1.0%|
[xroxy](#xroxy)|1893|1893|959|50.6%|1.0%|
[proxyrss](#proxyrss)|1722|1722|872|50.6%|0.9%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|782|0.0%|0.8%|
[et_block](#et_block)|975|18056513|762|0.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|741|0.0%|0.8%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|718|9.9%|0.7%|
[et_tor](#et_tor)|6490|6490|591|9.1%|0.6%|
[dm_tor](#dm_tor)|6490|6490|582|8.9%|0.6%|
[bm_tor](#bm_tor)|6492|6492|582|8.9%|0.6%|
[nixspam](#nixspam)|25659|25659|236|0.9%|0.2%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|227|0.1%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|12789|12789|221|1.7%|0.2%|
[php_commenters](#php_commenters)|281|281|203|72.2%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|14576|14576|203|1.3%|0.2%|
[php_bad](#php_bad)|281|281|202|71.8%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|228|228|127|55.7%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|105|0.0%|0.1%|
[php_spammers](#php_spammers)|417|417|95|22.7%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1483|1483|84|5.6%|0.0%|
[php_dictionary](#php_dictionary)|433|433|74|17.0%|0.0%|
[openbl_90d](#openbl_90d)|9854|9854|66|0.6%|0.0%|
[openbl](#openbl)|9854|9854|66|0.6%|0.0%|
[php_harvesters](#php_harvesters)|257|257|62|24.1%|0.0%|
[openbl_60d](#openbl_60d)|7777|7777|59|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|44|0.0%|0.0%|
[voipbl](#voipbl)|10303|10775|40|0.3%|0.0%|
[proxz](#proxz)|65|65|34|52.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|22|3.2%|0.0%|
[openbl_30d](#openbl_30d)|4446|4446|18|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|16|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2201|2201|8|0.3%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|270|270|7|2.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|6|0.2%|0.0%|
[et_compromised](#et_compromised)|2338|2338|5|0.2%|0.0%|
[zeus_badips](#zeus_badips)|229|229|3|1.3%|0.0%|
[zeus](#zeus)|266|266|3|1.1%|0.0%|
[openbl_7d](#openbl_7d)|995|995|2|0.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|2|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3656|670735064|2|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|687|687|2|0.2%|0.0%|
[sslbl](#sslbl)|345|345|1|0.2%|0.0%|
[openbl_1d](#openbl_1d)|357|357|1|0.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|509|509|1|0.1%|0.0%|
[ciarmy](#ciarmy)|415|415|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|

## stopforumspam_7d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip).

The last time downloaded was found to be dated: Thu May 28 02:00:08 UTC 2015.

The ipset `stopforumspam_7d` has **30710** entries, **30710** unique IPs.

The following table shows the overlaps of `stopforumspam_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_7d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|30535|33.1%|99.4%|
[stopforumspam_1d](#stopforumspam_1d)|7697|7697|4583|59.5%|14.9%|
[blocklist_de](#blocklist_de)|22289|22289|2208|9.9%|7.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|2079|0.0%|6.7%|
[blocklist_de_bots](#blocklist_de_bots)|3468|3468|2032|58.5%|6.6%|
[ri_web_proxies](#ri_web_proxies)|4417|4417|1619|36.6%|5.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|927|0.0%|3.0%|
[xroxy](#xroxy)|1893|1893|802|42.3%|2.6%|
[proxyrss](#proxyrss)|1722|1722|732|42.5%|2.3%|
[ri_connect_proxies](#ri_connect_proxies)|1714|1714|692|40.3%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|581|0.0%|1.8%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|526|7.2%|1.7%|
[et_tor](#et_tor)|6490|6490|442|6.8%|1.4%|
[dm_tor](#dm_tor)|6490|6490|434|6.6%|1.4%|
[bm_tor](#bm_tor)|6492|6492|434|6.6%|1.4%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|235|0.0%|0.7%|
[et_block](#et_block)|975|18056513|214|0.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|195|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|191|67.9%|0.6%|
[php_bad](#php_bad)|281|281|190|67.6%|0.6%|
[nixspam](#nixspam)|25659|25659|138|0.5%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|12789|12789|133|1.0%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|228|228|116|50.8%|0.3%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|116|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|14576|14576|98|0.6%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1483|1483|73|4.9%|0.2%|
[php_spammers](#php_spammers)|417|417|64|15.3%|0.2%|
[php_dictionary](#php_dictionary)|433|433|56|12.9%|0.1%|
[php_harvesters](#php_harvesters)|257|257|50|19.4%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|40|0.0%|0.1%|
[openbl_90d](#openbl_90d)|9854|9854|36|0.3%|0.1%|
[openbl](#openbl)|9854|9854|36|0.3%|0.1%|
[openbl_60d](#openbl_60d)|7777|7777|34|0.4%|0.1%|
[proxz](#proxz)|65|65|33|50.7%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|22|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|12|1.7%|0.0%|
[voipbl](#voipbl)|10303|10775|11|0.1%|0.0%|
[openbl_30d](#openbl_30d)|4446|4446|7|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[et_compromised](#et_compromised)|2338|2338|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2201|2201|2|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|687|687|2|0.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|270|270|2|0.7%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Thu May 28 22:05:28 UTC 2015.

The ipset `voipbl` has **10303** entries, **10775** unique IPs.

The following table shows the overlaps of `voipbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `voipbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `voipbl`.
- ` this % ` is the percentage **of this ipset (`voipbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|1588|0.0%|14.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|428|0.0%|3.9%|
[fullbogons](#fullbogons)|3656|670735064|351|0.0%|3.2%|
[bogons](#bogons)|13|592708608|351|0.0%|3.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|301|0.0%|2.7%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|197|0.1%|1.8%|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|40|0.0%|0.3%|
[blocklist_de](#blocklist_de)|22289|22289|35|0.1%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|93|93|27|29.0%|0.2%|
[et_block](#et_block)|975|18056513|20|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|14|0.0%|0.1%|
[openbl_90d](#openbl_90d)|9854|9854|12|0.1%|0.1%|
[openbl](#openbl)|9854|9854|12|0.1%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30710|30710|11|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7777|7777|9|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7697|7697|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4446|4446|4|0.0%|0.0%|
[nixspam](#nixspam)|25659|25659|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|4|0.0%|0.0%|
[openbl_7d](#openbl_7d)|995|995|3|0.3%|0.0%|
[ciarmy](#ciarmy)|415|415|3|0.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2201|2201|3|0.1%|0.0%|
[shunlist](#shunlist)|51|51|2|3.9%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3468|3468|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12789|12789|2|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[et_tor](#et_tor)|6490|6490|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2338|2338|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6490|6490|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6492|6492|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14576|14576|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|687|687|1|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1483|1483|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Thu May 28 21:33:01 UTC 2015.

The ipset `xroxy` has **1893** entries, **1893** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[proxyrss](#proxyrss)|1722|1722|1333|77.4%|70.4%|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|959|1.0%|50.6%|
[stopforumspam_7d](#stopforumspam_7d)|30710|30710|802|2.6%|42.3%|
[ri_web_proxies](#ri_web_proxies)|4417|4417|699|15.8%|36.9%|
[stopforumspam_1d](#stopforumspam_1d)|7697|7697|526|6.8%|27.7%|
[blocklist_de](#blocklist_de)|22289|22289|296|1.3%|15.6%|
[ri_connect_proxies](#ri_connect_proxies)|1714|1714|265|15.4%|13.9%|
[blocklist_de_bots](#blocklist_de_bots)|3468|3468|249|7.1%|13.1%|
[nixspam](#nixspam)|25659|25659|92|0.3%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|85|0.0%|4.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|72|0.0%|3.8%|
[proxz](#proxz)|65|65|55|84.6%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|51|0.0%|2.6%|
[blocklist_de_mail](#blocklist_de_mail)|14576|14576|45|0.3%|2.3%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|39|0.5%|2.0%|
[php_dictionary](#php_dictionary)|433|433|23|5.3%|1.2%|
[php_spammers](#php_spammers)|417|417|17|4.0%|0.8%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|12|1.7%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|228|228|6|2.6%|0.3%|
[php_commenters](#php_commenters)|281|281|3|1.0%|0.1%|
[php_bad](#php_bad)|281|281|3|1.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.1%|
[dm_tor](#dm_tor)|6490|6490|2|0.0%|0.1%|
[bm_tor](#bm_tor)|6492|6492|2|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.0%|
[et_tor](#et_tor)|6490|6490|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2201|2201|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1483|1483|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12789|12789|1|0.0%|0.0%|

## zeus

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist).

The last time downloaded was found to be dated: Thu May 28 21:06:36 UTC 2015.

The ipset `zeus` has **266** entries, **266** unique IPs.

The following table shows the overlaps of `zeus` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus`.
- ` this % ` is the percentage **of this ipset (`zeus`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|975|18056513|262|0.0%|98.4%|
[zeus_badips](#zeus_badips)|229|229|229|100.0%|86.0%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|226|3.1%|84.9%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|67|0.0%|25.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|19|0.0%|7.1%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|16|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|9|0.0%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|8|0.0%|3.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|5|0.0%|1.8%|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|3|0.0%|1.1%|
[openbl_90d](#openbl_90d)|9854|9854|2|0.0%|0.7%|
[openbl_60d](#openbl_60d)|7777|7777|2|0.0%|0.7%|
[openbl_30d](#openbl_30d)|4446|4446|2|0.0%|0.7%|
[openbl](#openbl)|9854|9854|2|0.0%|0.7%|
[stopforumspam_7d](#stopforumspam_7d)|30710|30710|1|0.0%|0.3%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.3%|
[php_bad](#php_bad)|281|281|1|0.3%|0.3%|
[openbl_7d](#openbl_7d)|995|995|1|0.1%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.3%|
[et_compromised](#et_compromised)|2338|2338|1|0.0%|0.3%|
[cleanmx_viruses](#cleanmx_viruses)|509|509|1|0.1%|0.3%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|1|0.0%|0.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|2201|2201|1|0.0%|0.3%|
[blocklist_de](#blocklist_de)|22289|22289|1|0.0%|0.3%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Thu May 28 21:54:13 UTC 2015.

The ipset `zeus_badips` has **229** entries, **229** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|266|266|229|86.0%|100.0%|
[et_block](#et_block)|975|18056513|228|0.0%|99.5%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|201|2.7%|87.7%|
[alienvault_reputation](#alienvault_reputation)|172159|172159|36|0.0%|15.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|16|0.0%|6.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|14|0.0%|6.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|8|0.0%|3.4%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|5|0.0%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|4|0.0%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|92103|92103|3|0.0%|1.3%|
[stopforumspam_7d](#stopforumspam_7d)|30710|30710|1|0.0%|0.4%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.4%|
[php_bad](#php_bad)|281|281|1|0.3%|0.4%|
[openbl_90d](#openbl_90d)|9854|9854|1|0.0%|0.4%|
[openbl_60d](#openbl_60d)|7777|7777|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|4446|4446|1|0.0%|0.4%|
[openbl](#openbl)|9854|9854|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.4%|
[et_compromised](#et_compromised)|2338|2338|1|0.0%|0.4%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|1|0.0%|0.4%|
