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
   
   The team of OpenBL tracks brute force attacks on their hosts. They suggest to use the default blacklist which has a retension policy of 90 days (`openbl`), but they also provide a list with different retension policies (from 1 day to 1 year).
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

The following list was automatically generated on Thu May 28 20:18:16 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|179397 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|22346 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|12794 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|3472 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|1485 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|265 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|690 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|14591 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|97 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|2229 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|226 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6503 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD)|ipv4 hash:ip|2428 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|408 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[clean_mx_viruses](#clean_mx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|509 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6500 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
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
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|29350 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
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
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|46 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1714 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|4396 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|51 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|7240 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|641 subnets, 18117120 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|55 subnets, 421120 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|345 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
[stop_forum_spam_1h](#stop_forum_spam_1h)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|7663 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stop_forum_spam_30d](#stop_forum_spam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|92103 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
[stop_forum_spam_7d](#stop_forum_spam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|30710 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10303 subnets, 10775 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1884 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|265 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|229 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Thu May 28 16:00:28 UTC 2015.

The ipset `alienvault_reputation` has **179397** entries, **179397** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|15214|0.0%|8.4%|
[openbl_90d](#openbl_90d)|9854|9854|9826|99.7%|5.4%|
[openbl](#openbl)|9854|9854|9826|99.7%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|8401|0.0%|4.6%|
[openbl_60d](#openbl_60d)|7777|7777|7752|99.6%|4.3%|
[et_block](#et_block)|975|18056513|5527|0.0%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|5211|0.0%|2.9%|
[openbl_30d](#openbl_30d)|4446|4446|4429|99.6%|2.4%|
[dshield](#dshield)|20|5120|2820|55.0%|1.5%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|1624|0.0%|0.9%|
[blocklist_de](#blocklist_de)|22346|22346|1535|6.8%|0.8%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|1502|61.8%|0.8%|
[et_compromised](#et_compromised)|2338|2338|1468|62.7%|0.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|1312|58.8%|0.7%|
[openbl_7d](#openbl_7d)|995|995|983|98.7%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|519|0.0%|0.2%|
[ciarmy](#ciarmy)|408|408|401|98.2%|0.2%|
[openbl_1d](#openbl_1d)|357|357|355|99.4%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|293|0.0%|0.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|229|0.2%|0.1%|
[voipbl](#voipbl)|10303|10775|200|1.8%|0.1%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|122|1.6%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|116|0.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12794|12794|101|0.7%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|86|38.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14591|14591|81|0.5%|0.0%|
[nixspam](#nixspam)|29350|29350|67|0.2%|0.0%|
[zeus](#zeus)|265|265|66|24.9%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7663|7663|62|0.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|690|690|61|8.8%|0.0%|
[shunlist](#shunlist)|51|51|49|96.0%|0.0%|
[et_tor](#et_tor)|6490|6490|44|0.6%|0.0%|
[dm_tor](#dm_tor)|6500|6500|44|0.6%|0.0%|
[bm_tor](#bm_tor)|6503|6503|44|0.6%|0.0%|
[zeus_badips](#zeus_badips)|229|229|36|15.7%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3472|3472|23|0.6%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|97|97|19|19.5%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1485|1485|18|1.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|15|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|265|265|14|5.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|13|0.0%|0.0%|
[php_commenters](#php_commenters)|281|281|12|4.2%|0.0%|
[php_bad](#php_bad)|281|281|12|4.2%|0.0%|
[malc0de](#malc0de)|411|411|10|2.4%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|509|509|10|1.9%|0.0%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|8|0.5%|0.0%|
[sslbl](#sslbl)|345|345|7|2.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|7|1.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|6|0.4%|0.0%|
[xroxy](#xroxy)|1884|1884|3|0.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4396|4396|3|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|3|0.7%|0.0%|
[et_botnet](#et_botnet)|512|512|3|0.5%|0.0%|
[proxyrss](#proxyrss)|1722|1722|2|0.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1714|1714|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[feodo](#feodo)|67|67|1|1.4%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Thu May 28 19:56:03 UTC 2015.

The ipset `blocklist_de` has **22346** entries, **22346** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|14591|14591|14572|99.8%|65.2%|
[blocklist_de_apache](#blocklist_de_apache)|12794|12794|12794|100.0%|57.2%|
[blocklist_de_bots](#blocklist_de_bots)|3472|3472|3472|100.0%|15.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|2832|0.0%|12.6%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|2597|2.8%|11.6%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|2225|7.2%|9.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|2219|99.5%|9.9%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7663|7663|1628|21.2%|7.2%|
[alienvault_reputation](#alienvault_reputation)|179397|179397|1535|0.8%|6.8%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1485|1485|1485|100.0%|6.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|1479|0.0%|6.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|1455|0.0%|6.5%|
[openbl_90d](#openbl_90d)|9854|9854|1315|13.3%|5.8%|
[openbl](#openbl)|9854|9854|1315|13.3%|5.8%|
[openbl_60d](#openbl_60d)|7777|7777|1256|16.1%|5.6%|
[openbl_30d](#openbl_30d)|4446|4446|1166|26.2%|5.2%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|1114|45.8%|4.9%|
[et_compromised](#et_compromised)|2338|2338|995|42.5%|4.4%|
[nixspam](#nixspam)|29350|29350|765|2.6%|3.4%|
[blocklist_de_imap](#blocklist_de_imap)|690|690|688|99.7%|3.0%|
[openbl_7d](#openbl_7d)|995|995|667|67.0%|2.9%|
[ri_web_proxies](#ri_web_proxies)|4396|4396|383|8.7%|1.7%|
[xroxy](#xroxy)|1884|1884|290|15.3%|1.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|265|265|265|100.0%|1.1%|
[openbl_1d](#openbl_1d)|357|357|240|67.2%|1.0%|
[proxyrss](#proxyrss)|1722|1722|227|13.1%|1.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|226|100.0%|1.0%|
[et_block](#et_block)|975|18056513|195|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|190|0.0%|0.8%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|179|2.4%|0.8%|
[dshield](#dshield)|20|5120|134|2.6%|0.5%|
[ri_connect_proxies](#ri_connect_proxies)|1714|1714|80|4.6%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|97|97|78|80.4%|0.3%|
[php_commenters](#php_commenters)|281|281|77|27.4%|0.3%|
[php_bad](#php_bad)|281|281|76|27.0%|0.3%|
[php_dictionary](#php_dictionary)|433|433|72|16.6%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|72|0.0%|0.3%|
[php_spammers](#php_spammers)|417|417|63|15.1%|0.2%|
[voipbl](#voipbl)|10303|10775|37|0.3%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|35|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|32|12.4%|0.1%|
[ciarmy](#ciarmy)|408|408|29|7.1%|0.1%|
[dm_tor](#dm_tor)|6500|6500|24|0.3%|0.1%|
[bm_tor](#bm_tor)|6503|6503|24|0.3%|0.1%|
[et_tor](#et_tor)|6490|6490|23|0.3%|0.1%|
[shunlist](#shunlist)|51|51|12|23.5%|0.0%|
[proxz](#proxz)|46|46|10|21.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|7|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|509|509|2|0.3%|0.0%|
[zeus](#zeus)|265|265|1|0.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Thu May 28 19:56:07 UTC 2015.

The ipset `blocklist_de_apache` has **12794** entries, **12794** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22346|22346|12794|57.2%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|14591|14591|11059|75.7%|86.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|2227|0.0%|17.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1485|1485|1485|100.0%|11.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|1320|0.0%|10.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|1079|0.0%|8.4%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|225|0.2%|1.7%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|137|0.4%|1.0%|
[alienvault_reputation](#alienvault_reputation)|179397|179397|101|0.0%|0.7%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7663|7663|96|1.2%|0.7%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|40|0.5%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|37|16.3%|0.2%|
[php_commenters](#php_commenters)|281|281|25|8.8%|0.1%|
[php_bad](#php_bad)|281|281|25|8.8%|0.1%|
[dm_tor](#dm_tor)|6500|6500|24|0.3%|0.1%|
[ciarmy](#ciarmy)|408|408|24|5.8%|0.1%|
[bm_tor](#bm_tor)|6503|6503|24|0.3%|0.1%|
[et_tor](#et_tor)|6490|6490|23|0.3%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3472|3472|18|0.5%|0.1%|
[nixspam](#nixspam)|29350|29350|15|0.0%|0.1%|
[openbl_90d](#openbl_90d)|9854|9854|14|0.1%|0.1%|
[openbl](#openbl)|9854|9854|14|0.1%|0.1%|
[openbl_60d](#openbl_60d)|7777|7777|11|0.1%|0.0%|
[openbl_30d](#openbl_30d)|4446|4446|8|0.1%|0.0%|
[et_block](#et_block)|975|18056513|8|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|4|0.0%|0.0%|
[openbl_7d](#openbl_7d)|995|995|4|0.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_compromised](#et_compromised)|2338|2338|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|3|0.1%|0.0%|
[voipbl](#voipbl)|10303|10775|2|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|2|0.0%|0.0%|
[shunlist](#shunlist)|51|51|2|3.9%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|509|509|2|0.3%|0.0%|
[xroxy](#xroxy)|1884|1884|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4396|4396|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1722|1722|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Thu May 28 19:56:09 UTC 2015.

The ipset `blocklist_de_bots` has **3472** entries, **3472** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22346|22346|3472|15.5%|100.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|2295|2.4%|66.1%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|2048|6.6%|58.9%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7663|7663|1529|19.9%|44.0%|
[ri_web_proxies](#ri_web_proxies)|4396|4396|357|8.1%|10.2%|
[xroxy](#xroxy)|1884|1884|247|13.1%|7.1%|
[proxyrss](#proxyrss)|1722|1722|224|13.0%|6.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|152|0.0%|4.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|124|54.8%|3.5%|
[ri_connect_proxies](#ri_connect_proxies)|1714|1714|78|4.5%|2.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|78|0.0%|2.2%|
[php_commenters](#php_commenters)|281|281|60|21.3%|1.7%|
[php_bad](#php_bad)|281|281|60|21.3%|1.7%|
[nixspam](#nixspam)|29350|29350|52|0.1%|1.4%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|50|0.0%|1.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|50|0.0%|1.4%|
[et_block](#et_block)|975|18056513|49|0.0%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|40|0.0%|1.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|29|0.0%|0.8%|
[php_harvesters](#php_harvesters)|257|257|27|10.5%|0.7%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|26|0.3%|0.7%|
[alienvault_reputation](#alienvault_reputation)|179397|179397|23|0.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|14591|14591|18|0.1%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|12794|12794|18|0.1%|0.5%|
[php_spammers](#php_spammers)|417|417|15|3.5%|0.4%|
[php_dictionary](#php_dictionary)|433|433|11|2.5%|0.3%|
[proxz](#proxz)|46|46|8|17.3%|0.2%|
[openbl_90d](#openbl_90d)|9854|9854|3|0.0%|0.0%|
[openbl](#openbl)|9854|9854|3|0.0%|0.0%|
[voipbl](#voipbl)|10303|10775|2|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2338|2338|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Thu May 28 19:42:17 UTC 2015.

The ipset `blocklist_de_bruteforce` has **1485** entries, **1485** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_apache](#blocklist_de_apache)|12794|12794|1485|11.6%|100.0%|
[blocklist_de](#blocklist_de)|22346|22346|1485|6.6%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|138|0.0%|9.2%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|83|0.0%|5.5%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|72|0.2%|4.8%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7663|7663|55|0.7%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|45|0.0%|3.0%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|37|0.5%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|27|0.0%|1.8%|
[dm_tor](#dm_tor)|6500|6500|21|0.3%|1.4%|
[bm_tor](#bm_tor)|6503|6503|21|0.3%|1.4%|
[et_tor](#et_tor)|6490|6490|20|0.3%|1.3%|
[alienvault_reputation](#alienvault_reputation)|179397|179397|18|0.0%|1.2%|
[nixspam](#nixspam)|29350|29350|13|0.0%|0.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|10|4.4%|0.6%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.3%|
[openbl_90d](#openbl_90d)|9854|9854|5|0.0%|0.3%|
[openbl](#openbl)|9854|9854|5|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|4|0.0%|0.2%|
[php_commenters](#php_commenters)|281|281|4|1.4%|0.2%|
[php_bad](#php_bad)|281|281|4|1.4%|0.2%|
[et_block](#et_block)|975|18056513|4|0.0%|0.2%|
[openbl_60d](#openbl_60d)|7777|7777|3|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.1%|
[clean_mx_viruses](#clean_mx_viruses)|509|509|2|0.3%|0.1%|
[xroxy](#xroxy)|1884|1884|1|0.0%|0.0%|
[voipbl](#voipbl)|10303|10775|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4396|4396|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1722|1722|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4446|4446|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2338|2338|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|1|0.0%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Thu May 28 19:56:08 UTC 2015.

The ipset `blocklist_de_ftp` has **265** entries, **265** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22346|22346|265|1.1%|100.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|25|0.0%|9.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|18|0.0%|6.7%|
[alienvault_reputation](#alienvault_reputation)|179397|179397|14|0.0%|5.2%|
[openbl_90d](#openbl_90d)|9854|9854|7|0.0%|2.6%|
[openbl](#openbl)|9854|9854|7|0.0%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|6|0.0%|2.2%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|5|0.0%|1.8%|
[openbl_60d](#openbl_60d)|7777|7777|5|0.0%|1.8%|
[nixspam](#nixspam)|29350|29350|4|0.0%|1.5%|
[openbl_30d](#openbl_30d)|4446|4446|3|0.0%|1.1%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|2|0.0%|0.7%|
[openbl_7d](#openbl_7d)|995|995|2|0.2%|0.7%|
[ciarmy](#ciarmy)|408|408|2|0.4%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|2|0.8%|0.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|1|0.0%|0.3%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.3%|
[openbl_1d](#openbl_1d)|357|357|1|0.2%|0.3%|
[et_compromised](#et_compromised)|2338|2338|1|0.0%|0.3%|
[et_block](#et_block)|975|18056513|1|0.0%|0.3%|
[dshield](#dshield)|20|5120|1|0.0%|0.3%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|1|0.0%|0.3%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Thu May 28 19:42:09 UTC 2015.

The ipset `blocklist_de_imap` has **690** entries, **690** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|14591|14591|690|4.7%|100.0%|
[blocklist_de](#blocklist_de)|22346|22346|688|3.0%|99.7%|
[alienvault_reputation](#alienvault_reputation)|179397|179397|61|0.0%|8.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|49|0.0%|7.1%|
[openbl_90d](#openbl_90d)|9854|9854|48|0.4%|6.9%|
[openbl](#openbl)|9854|9854|48|0.4%|6.9%|
[openbl_60d](#openbl_60d)|7777|7777|44|0.5%|6.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|43|0.0%|6.2%|
[openbl_30d](#openbl_30d)|4446|4446|39|0.8%|5.6%|
[openbl_7d](#openbl_7d)|995|995|22|2.2%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|14|0.0%|2.0%|
[et_compromised](#et_compromised)|2338|2338|14|0.5%|2.0%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|14|0.5%|2.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|12|0.0%|1.7%|
[et_block](#et_block)|975|18056513|12|0.0%|1.7%|
[openbl_1d](#openbl_1d)|357|357|6|1.6%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.5%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|2|0.0%|0.2%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|2|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|2|0.0%|0.2%|
[nixspam](#nixspam)|29350|29350|2|0.0%|0.2%|
[voipbl](#voipbl)|10303|10775|1|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.1%|
[shunlist](#shunlist)|51|51|1|1.9%|0.1%|
[ciarmy](#ciarmy)|408|408|1|0.2%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|1|0.4%|0.1%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Thu May 28 19:42:07 UTC 2015.

The ipset `blocklist_de_mail` has **14591** entries, **14591** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22346|22346|14572|65.2%|99.8%|
[blocklist_de_apache](#blocklist_de_apache)|12794|12794|11059|86.4%|75.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|2273|0.0%|15.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|1343|0.0%|9.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|1167|0.0%|7.9%|
[blocklist_de_imap](#blocklist_de_imap)|690|690|690|100.0%|4.7%|
[nixspam](#nixspam)|29350|29350|687|2.3%|4.7%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|193|0.2%|1.3%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|112|1.5%|0.7%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|92|0.2%|0.6%|
[alienvault_reputation](#alienvault_reputation)|179397|179397|81|0.0%|0.5%|
[openbl_90d](#openbl_90d)|9854|9854|63|0.6%|0.4%|
[openbl](#openbl)|9854|9854|63|0.6%|0.4%|
[php_dictionary](#php_dictionary)|433|433|61|14.0%|0.4%|
[openbl_60d](#openbl_60d)|7777|7777|58|0.7%|0.3%|
[openbl_30d](#openbl_30d)|4446|4446|51|1.1%|0.3%|
[php_spammers](#php_spammers)|417|417|43|10.3%|0.2%|
[xroxy](#xroxy)|1884|1884|41|2.1%|0.2%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7663|7663|40|0.5%|0.2%|
[openbl_7d](#openbl_7d)|995|995|26|2.6%|0.1%|
[ri_web_proxies](#ri_web_proxies)|4396|4396|24|0.5%|0.1%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|22|0.0%|0.1%|
[php_commenters](#php_commenters)|281|281|22|7.8%|0.1%|
[php_bad](#php_bad)|281|281|21|7.4%|0.1%|
[et_compromised](#et_compromised)|2338|2338|20|0.8%|0.1%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|20|0.8%|0.1%|
[et_block](#et_block)|975|18056513|18|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|18|7.9%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3472|3472|18|0.5%|0.1%|
[openbl_1d](#openbl_1d)|357|357|9|2.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|4|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|4|1.5%|0.0%|
[et_tor](#et_tor)|6490|6490|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6500|6500|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6503|6503|3|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1714|1714|2|0.1%|0.0%|
[proxz](#proxz)|46|46|2|4.3%|0.0%|
[voipbl](#voipbl)|10303|10775|1|0.0%|0.0%|
[shunlist](#shunlist)|51|51|1|1.9%|0.0%|
[proxyrss](#proxyrss)|1722|1722|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[ciarmy](#ciarmy)|408|408|1|0.2%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Thu May 28 19:56:08 UTC 2015.

The ipset `blocklist_de_sip` has **97** entries, **97** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22346|22346|78|0.3%|80.4%|
[voipbl](#voipbl)|10303|10775|29|0.2%|29.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|20|0.0%|20.6%|
[alienvault_reputation](#alienvault_reputation)|179397|179397|19|0.0%|19.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|6|0.0%|6.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|4|0.0%|4.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|2|0.0%|2.0%|
[nixspam](#nixspam)|29350|29350|1|0.0%|1.0%|
[et_botnet](#et_botnet)|512|512|1|0.1%|1.0%|
[ciarmy](#ciarmy)|408|408|1|0.2%|1.0%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Thu May 28 19:42:05 UTC 2015.

The ipset `blocklist_de_ssh` has **2229** entries, **2229** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22346|22346|2219|9.9%|99.5%|
[alienvault_reputation](#alienvault_reputation)|179397|179397|1312|0.7%|58.8%|
[openbl_90d](#openbl_90d)|9854|9854|1231|12.4%|55.2%|
[openbl](#openbl)|9854|9854|1231|12.4%|55.2%|
[openbl_60d](#openbl_60d)|7777|7777|1185|15.2%|53.1%|
[openbl_30d](#openbl_30d)|4446|4446|1106|24.8%|49.6%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|1091|44.9%|48.9%|
[et_compromised](#et_compromised)|2338|2338|972|41.5%|43.6%|
[openbl_7d](#openbl_7d)|995|995|636|63.9%|28.5%|
[openbl_1d](#openbl_1d)|357|357|231|64.7%|10.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|218|0.0%|9.7%|
[dshield](#dshield)|20|5120|133|2.5%|5.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|125|0.0%|5.6%|
[et_block](#et_block)|975|18056513|118|0.0%|5.2%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|112|0.0%|5.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|77|34.0%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|49|0.0%|2.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|13|0.0%|0.5%|
[shunlist](#shunlist)|51|51|9|17.6%|0.4%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|8|0.0%|0.3%|
[nixspam](#nixspam)|29350|29350|4|0.0%|0.1%|
[voipbl](#voipbl)|10303|10775|3|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|3|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|3|0.0%|0.1%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus](#zeus)|265|265|1|0.3%|0.0%|
[xroxy](#xroxy)|1884|1884|1|0.0%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7663|7663|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4396|4396|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1722|1722|1|0.0%|0.0%|
[ciarmy](#ciarmy)|408|408|1|0.2%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Thu May 28 19:56:11 UTC 2015.

The ipset `blocklist_de_strongips` has **226** entries, **226** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22346|22346|226|1.0%|100.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|125|0.1%|55.3%|
[blocklist_de_bots](#blocklist_de_bots)|3472|3472|124|3.5%|54.8%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|114|0.3%|50.4%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7663|7663|109|1.4%|48.2%|
[alienvault_reputation](#alienvault_reputation)|179397|179397|86|0.0%|38.0%|
[openbl_90d](#openbl_90d)|9854|9854|78|0.7%|34.5%|
[openbl](#openbl)|9854|9854|78|0.7%|34.5%|
[openbl_60d](#openbl_60d)|7777|7777|77|0.9%|34.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|77|3.4%|34.0%|
[openbl_30d](#openbl_30d)|4446|4446|76|1.7%|33.6%|
[openbl_7d](#openbl_7d)|995|995|75|7.5%|33.1%|
[openbl_1d](#openbl_1d)|357|357|69|19.3%|30.5%|
[blocklist_de_apache](#blocklist_de_apache)|12794|12794|37|0.2%|16.3%|
[php_commenters](#php_commenters)|281|281|32|11.3%|14.1%|
[php_bad](#php_bad)|281|281|32|11.3%|14.1%|
[et_compromised](#et_compromised)|2338|2338|26|1.1%|11.5%|
[dshield](#dshield)|20|5120|24|0.4%|10.6%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|20|0.8%|8.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|18|0.0%|7.9%|
[blocklist_de_mail](#blocklist_de_mail)|14591|14591|18|0.1%|7.9%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1485|1485|10|0.6%|4.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|8|0.0%|3.5%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|7|0.0%|3.0%|
[et_block](#et_block)|975|18056513|7|0.0%|3.0%|
[xroxy](#xroxy)|1884|1884|6|0.3%|2.6%|
[php_spammers](#php_spammers)|417|417|5|1.1%|2.2%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|4|0.0%|1.7%|
[ri_web_proxies](#ri_web_proxies)|4396|4396|3|0.0%|1.3%|
[proxyrss](#proxyrss)|1722|1722|3|0.1%|1.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.3%|
[nixspam](#nixspam)|29350|29350|2|0.0%|0.8%|
[blocklist_de_ftp](#blocklist_de_ftp)|265|265|2|0.7%|0.8%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|1|0.0%|0.4%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.4%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|690|690|1|0.1%|0.4%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Thu May 28 20:09:06 UTC 2015.

The ipset `bm_tor` has **6503** entries, **6503** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[dm_tor](#dm_tor)|6500|6500|6362|97.8%|97.8%|
[et_tor](#et_tor)|6490|6490|5681|87.5%|87.3%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|1054|14.5%|16.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|614|0.0%|9.4%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|581|0.6%|8.9%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|435|1.4%|6.6%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7663|7663|335|4.3%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|186|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|163|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|179397|179397|44|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[php_bad](#php_bad)|281|281|29|10.3%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|12794|12794|24|0.1%|0.3%|
[blocklist_de](#blocklist_de)|22346|22346|24|0.1%|0.3%|
[openbl_90d](#openbl_90d)|9854|9854|21|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7777|7777|21|0.2%|0.3%|
[openbl](#openbl)|9854|9854|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|21|0.0%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1485|1485|21|1.4%|0.3%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4396|4396|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14591|14591|3|0.0%|0.0%|
[xroxy](#xroxy)|1884|1884|2|0.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1714|1714|2|0.1%|0.0%|
[et_block](#et_block)|975|18056513|2|0.0%|0.0%|
[voipbl](#voipbl)|10303|10775|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1722|1722|1|0.0%|0.0%|
[nixspam](#nixspam)|29350|29350|1|0.0%|0.0%|
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
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|1|0.0%|0.0%|
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
[alienvault_reputation](#alienvault_reputation)|179397|179397|1502|0.8%|61.8%|
[openbl_90d](#openbl_90d)|9854|9854|1432|14.5%|58.9%|
[openbl](#openbl)|9854|9854|1432|14.5%|58.9%|
[openbl_60d](#openbl_60d)|7777|7777|1415|18.1%|58.2%|
[openbl_30d](#openbl_30d)|4446|4446|1357|30.5%|55.8%|
[blocklist_de](#blocklist_de)|22346|22346|1114|4.9%|45.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|1091|48.9%|44.9%|
[openbl_7d](#openbl_7d)|995|995|515|51.7%|21.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|233|0.0%|9.5%|
[openbl_1d](#openbl_1d)|357|357|201|56.3%|8.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|146|0.0%|6.0%|
[et_block](#et_block)|975|18056513|103|0.0%|4.2%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|102|0.0%|4.2%|
[dshield](#dshield)|20|5120|98|1.9%|4.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|73|0.0%|3.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|20|8.8%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|14591|14591|20|0.1%|0.8%|
[blocklist_de_imap](#blocklist_de_imap)|690|690|14|2.0%|0.5%|
[shunlist](#shunlist)|51|51|9|17.6%|0.3%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|6|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|12794|12794|3|0.0%|0.1%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|2|0.0%|0.0%|
[proxyrss](#proxyrss)|1722|1722|2|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|265|265|1|0.3%|0.0%|
[xroxy](#xroxy)|1884|1884|1|0.0%|0.0%|
[voipbl](#voipbl)|10303|10775|1|0.0%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7663|7663|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|1|0.0%|0.0%|
[proxz](#proxz)|46|46|1|2.1%|0.0%|
[fullbogons](#fullbogons)|3656|670735064|1|0.0%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|265|265|1|0.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1485|1485|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3472|3472|1|0.0%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Thu May 28 19:15:06 UTC 2015.

The ipset `ciarmy` has **408** entries, **408** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|179397|179397|401|0.2%|98.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|75|0.0%|18.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|40|0.0%|9.8%|
[blocklist_de](#blocklist_de)|22346|22346|29|0.1%|7.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|24|0.0%|5.8%|
[blocklist_de_apache](#blocklist_de_apache)|12794|12794|24|0.1%|5.8%|
[voipbl](#voipbl)|10303|10775|3|0.0%|0.7%|
[shunlist](#shunlist)|51|51|2|3.9%|0.4%|
[blocklist_de_ftp](#blocklist_de_ftp)|265|265|2|0.7%|0.4%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|1|0.0%|0.2%|
[openbl_90d](#openbl_90d)|9854|9854|1|0.0%|0.2%|
[openbl_7d](#openbl_7d)|995|995|1|0.1%|0.2%|
[openbl_60d](#openbl_60d)|7777|7777|1|0.0%|0.2%|
[openbl_30d](#openbl_30d)|4446|4446|1|0.0%|0.2%|
[openbl](#openbl)|9854|9854|1|0.0%|0.2%|
[et_block](#et_block)|975|18056513|1|0.0%|0.2%|
[dshield](#dshield)|20|5120|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|1|0.0%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|97|97|1|1.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|14591|14591|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|690|690|1|0.1%|0.2%|

## clean_mx_viruses

[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses

Source is downloaded from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive).

The last time downloaded was found to be dated: Thu May 28 16:40:36 UTC 2015.

The ipset `clean_mx_viruses` has **509** entries, **509** unique IPs.

The following table shows the overlaps of `clean_mx_viruses` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `clean_mx_viruses`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `clean_mx_viruses`.
- ` this % ` is the percentage **of this ipset (`clean_mx_viruses`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|73|0.0%|14.3%|
[malc0de](#malc0de)|411|411|32|7.7%|6.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|22|0.0%|4.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|14|0.0%|2.7%|
[alienvault_reputation](#alienvault_reputation)|179397|179397|10|0.0%|1.9%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|4|0.0%|0.7%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|3|0.2%|0.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|3|0.0%|0.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1485|1485|2|0.1%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|12794|12794|2|0.0%|0.3%|
[blocklist_de](#blocklist_de)|22346|22346|2|0.0%|0.3%|
[zeus](#zeus)|265|265|1|0.3%|0.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|1|0.0%|0.1%|
[et_block](#et_block)|975|18056513|1|0.0%|0.1%|
[dshield](#dshield)|20|5120|1|0.0%|0.1%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Thu May 28 20:09:04 UTC 2015.

The ipset `dm_tor` has **6500** entries, **6500** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6503|6503|6362|97.8%|97.8%|
[et_tor](#et_tor)|6490|6490|5667|87.3%|87.1%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|1049|14.4%|16.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|610|0.0%|9.3%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|582|0.6%|8.9%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|434|1.4%|6.6%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7663|7663|334|4.3%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|182|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|163|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|179397|179397|44|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[php_bad](#php_bad)|281|281|29|10.3%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|12794|12794|24|0.1%|0.3%|
[blocklist_de](#blocklist_de)|22346|22346|24|0.1%|0.3%|
[openbl_90d](#openbl_90d)|9854|9854|21|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7777|7777|21|0.2%|0.3%|
[openbl](#openbl)|9854|9854|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|21|0.0%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1485|1485|21|1.4%|0.3%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4396|4396|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14591|14591|3|0.0%|0.0%|
[xroxy](#xroxy)|1884|1884|2|0.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1714|1714|2|0.1%|0.0%|
[et_block](#et_block)|975|18056513|2|0.0%|0.0%|
[voipbl](#voipbl)|10303|10775|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1722|1722|1|0.0%|0.0%|
[nixspam](#nixspam)|29350|29350|1|0.0%|0.0%|
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
[alienvault_reputation](#alienvault_reputation)|179397|179397|2820|1.5%|55.0%|
[et_block](#et_block)|975|18056513|1024|0.0%|20.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|512|0.0%|10.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|256|0.0%|5.0%|
[openbl_90d](#openbl_90d)|9854|9854|147|1.4%|2.8%|
[openbl](#openbl)|9854|9854|147|1.4%|2.8%|
[openbl_60d](#openbl_60d)|7777|7777|144|1.8%|2.8%|
[openbl_30d](#openbl_30d)|4446|4446|139|3.1%|2.7%|
[blocklist_de](#blocklist_de)|22346|22346|134|0.5%|2.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|133|5.9%|2.5%|
[openbl_7d](#openbl_7d)|995|995|119|11.9%|2.3%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|98|4.0%|1.9%|
[et_compromised](#et_compromised)|2338|2338|89|3.8%|1.7%|
[openbl_1d](#openbl_1d)|357|357|51|14.2%|0.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|24|10.6%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|4|0.0%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|4|0.0%|0.0%|
[nixspam](#nixspam)|29350|29350|1|0.0%|0.0%|
[malc0de](#malc0de)|411|411|1|0.2%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|509|509|1|0.1%|0.0%|
[ciarmy](#ciarmy)|408|408|1|0.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|265|265|1|0.3%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|179397|179397|5527|3.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1044|0.3%|0.0%|
[dshield](#dshield)|20|5120|1024|20.0%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|762|0.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|517|0.1%|0.0%|
[openbl_90d](#openbl_90d)|9854|9854|455|4.6%|0.0%|
[openbl](#openbl)|9854|9854|455|4.6%|0.0%|
[openbl_60d](#openbl_60d)|7777|7777|287|3.6%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|286|3.9%|0.0%|
[zeus](#zeus)|265|265|262|98.8%|0.0%|
[zeus_badips](#zeus_badips)|229|229|228|99.5%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|214|0.6%|0.0%|
[openbl_30d](#openbl_30d)|4446|4446|212|4.7%|0.0%|
[blocklist_de](#blocklist_de)|22346|22346|195|0.8%|0.0%|
[nixspam](#nixspam)|29350|29350|168|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|118|5.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|103|4.2%|0.0%|
[openbl_7d](#openbl_7d)|995|995|97|9.7%|0.0%|
[et_compromised](#et_compromised)|2338|2338|94|4.0%|0.0%|
[feodo](#feodo)|67|67|61|91.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3472|3472|49|1.4%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7663|7663|40|0.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|28|2.1%|0.0%|
[openbl_1d](#openbl_1d)|357|357|27|7.5%|0.0%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.0%|
[php_bad](#php_bad)|281|281|24|8.5%|0.0%|
[sslbl](#sslbl)|345|345|23|6.6%|0.0%|
[voipbl](#voipbl)|10303|10775|20|0.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14591|14591|18|0.1%|0.0%|
[palevo](#palevo)|13|13|13|100.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|690|690|12|1.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|10|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12794|12794|8|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|7|3.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1485|1485|4|0.2%|0.0%|
[malc0de](#malc0de)|411|411|3|0.7%|0.0%|
[et_tor](#et_tor)|6490|6490|3|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[dm_tor](#dm_tor)|6500|6500|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6503|6503|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[et_botnet](#et_botnet)|512|512|1|0.1%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|509|509|1|0.1%|0.0%|
[ciarmy](#ciarmy)|408|408|1|0.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|265|265|1|0.3%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|179397|179397|3|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[et_block](#et_block)|975|18056513|1|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|97|97|1|1.0%|0.1%|

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
[alienvault_reputation](#alienvault_reputation)|179397|179397|1468|0.8%|62.7%|
[openbl_90d](#openbl_90d)|9854|9854|1396|14.1%|59.7%|
[openbl](#openbl)|9854|9854|1396|14.1%|59.7%|
[openbl_60d](#openbl_60d)|7777|7777|1386|17.8%|59.2%|
[openbl_30d](#openbl_30d)|4446|4446|1328|29.8%|56.8%|
[blocklist_de](#blocklist_de)|22346|22346|995|4.4%|42.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|972|43.6%|41.5%|
[openbl_7d](#openbl_7d)|995|995|495|49.7%|21.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|225|0.0%|9.6%|
[openbl_1d](#openbl_1d)|357|357|207|57.9%|8.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|143|0.0%|6.1%|
[et_block](#et_block)|975|18056513|94|0.0%|4.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|92|0.0%|3.9%|
[dshield](#dshield)|20|5120|89|1.7%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|75|0.0%|3.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|26|11.5%|1.1%|
[blocklist_de_mail](#blocklist_de_mail)|14591|14591|20|0.1%|0.8%|
[blocklist_de_imap](#blocklist_de_imap)|690|690|14|2.0%|0.5%|
[shunlist](#shunlist)|51|51|9|17.6%|0.3%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|5|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|12794|12794|3|0.0%|0.1%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|265|265|1|0.3%|0.0%|
[voipbl](#voipbl)|10303|10775|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|1|0.0%|0.0%|
[proxz](#proxz)|46|46|1|2.1%|0.0%|
[proxyrss](#proxyrss)|1722|1722|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|265|265|1|0.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1485|1485|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3472|3472|1|0.0%|0.0%|

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
[bm_tor](#bm_tor)|6503|6503|5681|87.3%|87.5%|
[dm_tor](#dm_tor)|6500|6500|5667|87.1%|87.3%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|1090|15.0%|16.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|608|0.0%|9.3%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|591|0.6%|9.1%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|442|1.4%|6.8%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7663|7663|327|4.2%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|184|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|165|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|179397|179397|44|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[php_bad](#php_bad)|281|281|29|10.3%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|12794|12794|23|0.1%|0.3%|
[blocklist_de](#blocklist_de)|22346|22346|23|0.1%|0.3%|
[openbl_90d](#openbl_90d)|9854|9854|21|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7777|7777|21|0.2%|0.3%|
[openbl](#openbl)|9854|9854|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|21|0.0%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1485|1485|20|1.3%|0.3%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4396|4396|5|0.1%|0.0%|
[php_dictionary](#php_dictionary)|433|433|3|0.6%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|975|18056513|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14591|14591|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1714|1714|2|0.1%|0.0%|
[xroxy](#xroxy)|1884|1884|1|0.0%|0.0%|
[voipbl](#voipbl)|10303|10775|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1722|1722|1|0.0%|0.0%|
[nixspam](#nixspam)|29350|29350|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Thu May 28 20:09:22 UTC 2015.

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
[alienvault_reputation](#alienvault_reputation)|179397|179397|1|0.0%|1.4%|

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
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|2|0.0%|0.0%|
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
[nixspam](#nixspam)|29350|29350|20|0.0%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|16|0.0%|0.0%|
[fullbogons](#fullbogons)|3656|670735064|14|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|179397|179397|13|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.0%|
[et_block](#et_block)|975|18056513|10|0.0%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|6|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|6|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|6|0.0%|0.0%|
[xroxy](#xroxy)|1884|1884|3|0.1%|0.0%|
[voipbl](#voipbl)|10303|10775|2|0.0%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7663|7663|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[blocklist_de](#blocklist_de)|22346|22346|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4396|4396|1|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14591|14591|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3472|3472|1|0.0%|0.0%|

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
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|741|0.8%|0.0%|
[alienvault_reputation](#alienvault_reputation)|179397|179397|519|0.2%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|195|0.6%|0.0%|
[nixspam](#nixspam)|29350|29350|168|0.5%|0.0%|
[blocklist_de](#blocklist_de)|22346|22346|72|0.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3472|3472|50|1.4%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7663|7663|34|0.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|27|2.1%|0.0%|
[openbl_90d](#openbl_90d)|9854|9854|19|0.1%|0.0%|
[openbl](#openbl)|9854|9854|19|0.1%|0.0%|
[openbl_60d](#openbl_60d)|7777|7777|18|0.2%|0.0%|
[openbl_30d](#openbl_30d)|4446|4446|13|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|13|0.5%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|11|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|10|4.3%|0.0%|
[zeus](#zeus)|265|265|10|3.7%|0.0%|
[openbl_7d](#openbl_7d)|995|995|9|0.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14591|14591|6|0.0%|0.0%|
[openbl_1d](#openbl_1d)|357|357|5|1.4%|0.0%|
[et_compromised](#et_compromised)|2338|2338|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|5|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|690|690|4|0.5%|0.0%|
[et_tor](#et_tor)|6490|6490|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6500|6500|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6503|6503|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|3|1.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12794|12794|3|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1485|1485|2|0.1%|0.0%|
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
[alienvault_reputation](#alienvault_reputation)|179397|179397|5211|2.9%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|1511|1.6%|0.0%|
[blocklist_de](#blocklist_de)|22346|22346|1479|6.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14591|14591|1343|9.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12794|12794|1320|10.3%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|581|1.8%|0.0%|
[nixspam](#nixspam)|29350|29350|521|1.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|432|0.8%|0.0%|
[voipbl](#voipbl)|10303|10775|301|2.7%|0.0%|
[openbl_90d](#openbl_90d)|9854|9854|220|2.2%|0.0%|
[openbl](#openbl)|9854|9854|220|2.2%|0.0%|
[openbl_60d](#openbl_60d)|7777|7777|181|2.3%|0.0%|
[et_tor](#et_tor)|6490|6490|165|2.5%|0.0%|
[dm_tor](#dm_tor)|6500|6500|163|2.5%|0.0%|
[bm_tor](#bm_tor)|6503|6503|163|2.5%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7663|7663|150|1.9%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4396|4396|102|2.3%|0.0%|
[openbl_30d](#openbl_30d)|4446|4446|100|2.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|98|6.7%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|85|1.1%|0.0%|
[et_compromised](#et_compromised)|2338|2338|75|3.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|73|3.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|66|5.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1714|1714|61|3.5%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|58|8.6%|0.0%|
[xroxy](#xroxy)|1884|1884|51|2.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|49|2.1%|0.0%|
[et_botnet](#et_botnet)|512|512|43|8.3%|0.0%|
[proxyrss](#proxyrss)|1722|1722|41|2.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3472|3472|40|1.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1485|1485|27|1.8%|0.0%|
[ciarmy](#ciarmy)|408|408|24|5.8%|0.0%|
[openbl_7d](#openbl_7d)|995|995|16|1.6%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|509|509|14|2.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|690|690|14|2.0%|0.0%|
[malc0de](#malc0de)|411|411|12|2.9%|0.0%|
[php_dictionary](#php_dictionary)|433|433|9|2.0%|0.0%|
[zeus](#zeus)|265|265|7|2.6%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[openbl_1d](#openbl_1d)|357|357|7|1.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|265|265|6|2.2%|0.0%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.0%|
[php_commenters](#php_commenters)|281|281|5|1.7%|0.0%|
[php_bad](#php_bad)|281|281|5|1.7%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[zeus_badips](#zeus_badips)|229|229|4|1.7%|0.0%|
[dshield](#dshield)|20|5120|4|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|97|97|4|4.1%|0.0%|
[sslbl](#sslbl)|345|345|3|0.8%|0.0%|
[feodo](#feodo)|67|67|3|4.4%|0.0%|
[proxz](#proxz)|46|46|1|2.1%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|179397|179397|8401|4.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|7752|2.2%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|2467|2.6%|0.0%|
[blocklist_de](#blocklist_de)|22346|22346|1455|6.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14591|14591|1167|7.9%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12794|12794|1079|8.4%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|927|3.0%|0.0%|
[nixspam](#nixspam)|29350|29350|740|2.5%|0.0%|
[openbl_90d](#openbl_90d)|9854|9854|511|5.1%|0.0%|
[openbl](#openbl)|9854|9854|511|5.1%|0.0%|
[voipbl](#voipbl)|10303|10775|428|3.9%|0.0%|
[openbl_60d](#openbl_60d)|7777|7777|361|4.6%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|233|0.4%|0.0%|
[openbl_30d](#openbl_30d)|4446|4446|229|5.1%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7663|7663|220|2.8%|0.0%|
[bm_tor](#bm_tor)|6503|6503|186|2.8%|0.0%|
[et_tor](#et_tor)|6490|6490|184|2.8%|0.0%|
[dm_tor](#dm_tor)|6500|6500|182|2.8%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4396|4396|153|3.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|146|6.0%|0.0%|
[et_compromised](#et_compromised)|2338|2338|143|6.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|125|5.6%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|101|1.3%|0.0%|
[xroxy](#xroxy)|1884|1884|83|4.4%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3472|3472|78|2.2%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1714|1714|76|4.4%|0.0%|
[proxyrss](#proxyrss)|1722|1722|63|3.6%|0.0%|
[openbl_7d](#openbl_7d)|995|995|53|5.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|690|690|49|7.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|45|3.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1485|1485|45|3.0%|0.0%|
[ciarmy](#ciarmy)|408|408|40|9.8%|0.0%|
[php_spammers](#php_spammers)|417|417|31|7.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|28|4.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|26|2.0%|0.0%|
[malc0de](#malc0de)|411|411|26|6.3%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|265|265|25|9.4%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|509|509|22|4.3%|0.0%|
[et_botnet](#et_botnet)|512|512|21|4.1%|0.0%|
[openbl_1d](#openbl_1d)|357|357|17|4.7%|0.0%|
[php_dictionary](#php_dictionary)|433|433|10|2.3%|0.0%|
[zeus](#zeus)|265|265|9|3.3%|0.0%|
[php_commenters](#php_commenters)|281|281|9|3.2%|0.0%|
[php_bad](#php_bad)|281|281|9|3.2%|0.0%|
[zeus_badips](#zeus_badips)|229|229|8|3.4%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|8|3.5%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[sslbl](#sslbl)|345|345|6|1.7%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|97|97|6|6.1%|0.0%|
[shunlist](#shunlist)|51|51|3|5.8%|0.0%|
[proxz](#proxz)|46|46|3|6.5%|0.0%|
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
[alienvault_reputation](#alienvault_reputation)|179397|179397|15214|8.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|9278|2.7%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|6117|6.6%|0.0%|
[blocklist_de](#blocklist_de)|22346|22346|2832|12.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14591|14591|2273|15.5%|0.0%|
[nixspam](#nixspam)|29350|29350|2227|7.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12794|12794|2227|17.4%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|2079|6.7%|0.0%|
[voipbl](#voipbl)|10303|10775|1588|14.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1172|2.4%|0.0%|
[openbl_90d](#openbl_90d)|9854|9854|951|9.6%|0.0%|
[openbl](#openbl)|9854|9854|951|9.6%|0.0%|
[openbl_60d](#openbl_60d)|7777|7777|719|9.2%|0.0%|
[bm_tor](#bm_tor)|6503|6503|614|9.4%|0.0%|
[dm_tor](#dm_tor)|6500|6500|610|9.3%|0.0%|
[et_tor](#et_tor)|6490|6490|608|9.3%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7663|7663|546|7.1%|0.0%|
[openbl_30d](#openbl_30d)|4446|4446|445|10.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|233|9.5%|0.0%|
[et_compromised](#et_compromised)|2338|2338|225|9.6%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|222|3.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|218|9.7%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3472|3472|152|4.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|146|11.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1485|1485|138|9.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4396|4396|136|3.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|110|7.5%|0.0%|
[openbl_7d](#openbl_7d)|995|995|90|9.0%|0.0%|
[malc0de](#malc0de)|411|411|76|18.4%|0.0%|
[et_botnet](#et_botnet)|512|512|75|14.6%|0.0%|
[ciarmy](#ciarmy)|408|408|75|18.3%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|509|509|73|14.3%|0.0%|
[xroxy](#xroxy)|1884|1884|71|3.7%|0.0%|
[proxyrss](#proxyrss)|1722|1722|61|3.5%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|51|7.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|690|690|43|6.2%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1714|1714|41|2.3%|0.0%|
[php_spammers](#php_spammers)|417|417|26|6.2%|0.0%|
[php_dictionary](#php_dictionary)|433|433|24|5.5%|0.0%|
[sslbl](#sslbl)|345|345|22|6.3%|0.0%|
[openbl_1d](#openbl_1d)|357|357|20|5.6%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|97|97|20|20.6%|0.0%|
[zeus](#zeus)|265|265|19|7.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|18|7.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|265|265|18|6.7%|0.0%|
[php_bad](#php_bad)|281|281|16|5.6%|0.0%|
[php_harvesters](#php_harvesters)|257|257|15|5.8%|0.0%|
[php_commenters](#php_commenters)|281|281|15|5.3%|0.0%|
[zeus_badips](#zeus_badips)|229|229|14|6.1%|0.0%|
[proxz](#proxz)|46|46|5|10.8%|0.0%|
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
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|22|0.0%|3.2%|
[xroxy](#xroxy)|1884|1884|12|0.6%|1.7%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|12|0.0%|1.7%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|11|0.0%|1.6%|
[ri_web_proxies](#ri_web_proxies)|4396|4396|10|0.2%|1.4%|
[proxyrss](#proxyrss)|1722|1722|9|0.5%|1.3%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7663|7663|6|0.0%|0.8%|
[ri_connect_proxies](#ri_connect_proxies)|1714|1714|6|0.3%|0.8%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.2%|
[nixspam](#nixspam)|29350|29350|2|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.2%|
[et_block](#et_block)|975|18056513|2|0.0%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3472|3472|2|0.0%|0.2%|
[blocklist_de](#blocklist_de)|22346|22346|2|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|1|0.0%|0.1%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.1%|
[alienvault_reputation](#alienvault_reputation)|179397|179397|1|0.0%|0.1%|

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
[alienvault_reputation](#alienvault_reputation)|179397|179397|293|0.1%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|44|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|25|1.9%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|22|0.0%|0.0%|
[et_tor](#et_tor)|6490|6490|21|0.3%|0.0%|
[dm_tor](#dm_tor)|6500|6500|21|0.3%|0.0%|
[bm_tor](#bm_tor)|6503|6503|21|0.3%|0.0%|
[nixspam](#nixspam)|29350|29350|19|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|19|1.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|15|0.2%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7663|7663|7|0.0%|0.0%|
[blocklist_de](#blocklist_de)|22346|22346|7|0.0%|0.0%|
[openbl_90d](#openbl_90d)|9854|9854|6|0.0%|0.0%|
[openbl](#openbl)|9854|9854|6|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7777|7777|5|0.0%|0.0%|
[voipbl](#voipbl)|10303|10775|4|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4396|4396|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4446|4446|4|0.0%|0.0%|
[dshield](#dshield)|20|5120|4|0.0%|0.0%|
[malc0de](#malc0de)|411|411|3|0.7%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|509|509|3|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|3|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12794|12794|3|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|97|97|2|2.0%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|265|265|1|0.3%|0.0%|
[xroxy](#xroxy)|1884|1884|1|0.0%|0.0%|
[sslbl](#sslbl)|345|345|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|
[openbl_7d](#openbl_7d)|995|995|1|0.1%|0.0%|
[feodo](#feodo)|67|67|1|1.4%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14591|14591|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1485|1485|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3472|3472|1|0.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|179397|179397|8|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|6|0.0%|0.4%|
[et_block](#et_block)|975|18056513|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|3|0.2%|0.2%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|2|0.0%|0.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|2|0.0%|0.1%|
[openbl_90d](#openbl_90d)|9854|9854|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7777|7777|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|4446|4446|2|0.0%|0.1%|
[openbl](#openbl)|9854|9854|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.1%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|2|0.0%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|2|0.0%|0.1%|
[blocklist_de](#blocklist_de)|22346|22346|2|0.0%|0.1%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7663|7663|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4396|4396|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|995|995|1|0.1%|0.0%|
[openbl_1d](#openbl_1d)|357|357|1|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_tor](#et_tor)|6490|6490|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2338|2338|1|0.0%|0.0%|
[et_botnet](#et_botnet)|512|512|1|0.1%|0.0%|
[dm_tor](#dm_tor)|6500|6500|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6503|6503|1|0.0%|0.0%|

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
[clean_mx_viruses](#clean_mx_viruses)|509|509|32|6.2%|7.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|26|0.0%|6.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|12|0.0%|2.9%|
[alienvault_reputation](#alienvault_reputation)|179397|179397|10|0.0%|2.4%|
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
[alienvault_reputation](#alienvault_reputation)|179397|179397|6|0.0%|0.4%|
[malc0de](#malc0de)|411|411|4|0.9%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.2%|
[clean_mx_viruses](#clean_mx_viruses)|509|509|3|0.5%|0.2%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|2|0.0%|0.1%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|1|0.0%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7663|7663|1|0.0%|0.0%|
[nixspam](#nixspam)|29350|29350|1|0.0%|0.0%|
[et_botnet](#et_botnet)|512|512|1|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3472|3472|1|0.0%|0.0%|
[blocklist_de](#blocklist_de)|22346|22346|1|0.0%|0.0%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Thu May 28 20:00:02 UTC 2015.

The ipset `nixspam` has **29350** entries, **29350** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|2227|0.0%|7.5%|
[blocklist_de](#blocklist_de)|22346|22346|765|3.4%|2.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|740|0.0%|2.5%|
[blocklist_de_mail](#blocklist_de_mail)|14591|14591|687|4.7%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|521|0.0%|1.7%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|260|0.2%|0.8%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|199|2.7%|0.6%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|173|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|168|0.0%|0.5%|
[et_block](#et_block)|975|18056513|168|0.0%|0.5%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|142|0.4%|0.4%|
[php_dictionary](#php_dictionary)|433|433|97|22.4%|0.3%|
[xroxy](#xroxy)|1884|1884|92|4.8%|0.3%|
[ri_web_proxies](#ri_web_proxies)|4396|4396|79|1.7%|0.2%|
[php_spammers](#php_spammers)|417|417|77|18.4%|0.2%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7663|7663|74|0.9%|0.2%|
[alienvault_reputation](#alienvault_reputation)|179397|179397|67|0.0%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3472|3472|52|1.4%|0.1%|
[openbl_90d](#openbl_90d)|9854|9854|27|0.2%|0.0%|
[openbl](#openbl)|9854|9854|27|0.2%|0.0%|
[openbl_60d](#openbl_60d)|7777|7777|26|0.3%|0.0%|
[proxyrss](#proxyrss)|1722|1722|23|1.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|20|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|19|0.0%|0.0%|
[php_commenters](#php_commenters)|281|281|16|5.6%|0.0%|
[php_bad](#php_bad)|281|281|15|5.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12794|12794|15|0.1%|0.0%|
[openbl_30d](#openbl_30d)|4446|4446|13|0.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1485|1485|13|0.8%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1714|1714|11|0.6%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[proxz](#proxz)|46|46|5|10.8%|0.0%|
[voipbl](#voipbl)|10303|10775|4|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|4|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|265|265|4|1.5%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|2|0.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|690|690|2|0.2%|0.0%|
[openbl_7d](#openbl_7d)|995|995|1|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|
[et_tor](#et_tor)|6490|6490|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6500|6500|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6503|6503|1|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|97|97|1|1.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|179397|179397|9826|5.4%|99.7%|
[openbl_60d](#openbl_60d)|7777|7777|7777|100.0%|78.9%|
[openbl_30d](#openbl_30d)|4446|4446|4446|100.0%|45.1%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|1432|58.9%|14.5%|
[et_compromised](#et_compromised)|2338|2338|1396|59.7%|14.1%|
[blocklist_de](#blocklist_de)|22346|22346|1315|5.8%|13.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|1231|55.2%|12.4%|
[openbl_7d](#openbl_7d)|995|995|995|100.0%|10.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|951|0.0%|9.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|511|0.0%|5.1%|
[et_block](#et_block)|975|18056513|455|0.0%|4.6%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|447|0.0%|4.5%|
[openbl_1d](#openbl_1d)|357|357|357|100.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|220|0.0%|2.2%|
[dshield](#dshield)|20|5120|147|2.8%|1.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|78|34.5%|0.7%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|66|0.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|14591|14591|63|0.4%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|690|690|48|6.9%|0.4%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|36|0.1%|0.3%|
[nixspam](#nixspam)|29350|29350|27|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|26|0.3%|0.2%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7663|7663|23|0.3%|0.2%|
[et_tor](#et_tor)|6490|6490|21|0.3%|0.2%|
[dm_tor](#dm_tor)|6500|6500|21|0.3%|0.2%|
[bm_tor](#bm_tor)|6503|6503|21|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|19|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|14|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12794|12794|14|0.1%|0.1%|
[voipbl](#voipbl)|10303|10775|12|0.1%|0.1%|
[shunlist](#shunlist)|51|51|11|21.5%|0.1%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.0%|
[php_bad](#php_bad)|281|281|8|2.8%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|265|265|7|2.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|6|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|5|1.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1485|1485|5|0.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3472|3472|3|0.0%|0.0%|
[zeus](#zeus)|265|265|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[sslbl](#sslbl)|345|345|1|0.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4396|4396|1|0.0%|0.0%|
[ciarmy](#ciarmy)|408|408|1|0.2%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|179397|179397|355|0.1%|99.4%|
[blocklist_de](#blocklist_de)|22346|22346|240|1.0%|67.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|231|10.3%|64.7%|
[et_compromised](#et_compromised)|2338|2338|207|8.8%|57.9%|
[openbl_7d](#openbl_7d)|995|995|206|20.7%|57.7%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|201|8.2%|56.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|69|30.5%|19.3%|
[dshield](#dshield)|20|5120|51|0.9%|14.2%|
[et_block](#et_block)|975|18056513|27|0.0%|7.5%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|26|0.0%|7.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|20|0.0%|5.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|17|0.0%|4.7%|
[blocklist_de_mail](#blocklist_de_mail)|14591|14591|9|0.0%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|7|0.0%|1.9%|
[blocklist_de_imap](#blocklist_de_imap)|690|690|6|0.8%|1.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|1.4%|
[shunlist](#shunlist)|51|51|2|3.9%|0.5%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|1|0.0%|0.2%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|265|265|1|0.3%|0.2%|

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
[alienvault_reputation](#alienvault_reputation)|179397|179397|4429|2.4%|99.6%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|1357|55.8%|30.5%|
[et_compromised](#et_compromised)|2338|2338|1328|56.8%|29.8%|
[blocklist_de](#blocklist_de)|22346|22346|1166|5.2%|26.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|1106|49.6%|24.8%|
[openbl_7d](#openbl_7d)|995|995|995|100.0%|22.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|445|0.0%|10.0%|
[openbl_1d](#openbl_1d)|357|357|357|100.0%|8.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|229|0.0%|5.1%|
[et_block](#et_block)|975|18056513|212|0.0%|4.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|207|0.0%|4.6%|
[dshield](#dshield)|20|5120|139|2.7%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|100|0.0%|2.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|76|33.6%|1.7%|
[blocklist_de_mail](#blocklist_de_mail)|14591|14591|51|0.3%|1.1%|
[blocklist_de_imap](#blocklist_de_imap)|690|690|39|5.6%|0.8%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|18|0.0%|0.4%|
[nixspam](#nixspam)|29350|29350|13|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|13|0.0%|0.2%|
[shunlist](#shunlist)|51|51|10|19.6%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|12794|12794|8|0.0%|0.1%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|7|0.0%|0.1%|
[voipbl](#voipbl)|10303|10775|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|4|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|3|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|265|265|3|1.1%|0.0%|
[zeus](#zeus)|265|265|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7663|7663|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|408|408|1|0.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1485|1485|1|0.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|179397|179397|7752|4.3%|99.6%|
[openbl_30d](#openbl_30d)|4446|4446|4446|100.0%|57.1%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|1415|58.2%|18.1%|
[et_compromised](#et_compromised)|2338|2338|1386|59.2%|17.8%|
[blocklist_de](#blocklist_de)|22346|22346|1256|5.6%|16.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|1185|53.1%|15.2%|
[openbl_7d](#openbl_7d)|995|995|995|100.0%|12.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|719|0.0%|9.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|361|0.0%|4.6%|
[openbl_1d](#openbl_1d)|357|357|357|100.0%|4.5%|
[et_block](#et_block)|975|18056513|287|0.0%|3.6%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|281|0.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|181|0.0%|2.3%|
[dshield](#dshield)|20|5120|144|2.8%|1.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|77|34.0%|0.9%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|59|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|14591|14591|58|0.3%|0.7%|
[blocklist_de_imap](#blocklist_de_imap)|690|690|44|6.3%|0.5%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|34|0.1%|0.4%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|26|0.3%|0.3%|
[nixspam](#nixspam)|29350|29350|26|0.0%|0.3%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7663|7663|21|0.2%|0.2%|
[et_tor](#et_tor)|6490|6490|21|0.3%|0.2%|
[dm_tor](#dm_tor)|6500|6500|21|0.3%|0.2%|
[bm_tor](#bm_tor)|6503|6503|21|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|18|0.0%|0.2%|
[shunlist](#shunlist)|51|51|11|21.5%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12794|12794|11|0.0%|0.1%|
[voipbl](#voipbl)|10303|10775|9|0.0%|0.1%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.1%|
[php_bad](#php_bad)|281|281|8|2.8%|0.1%|
[php_harvesters](#php_harvesters)|257|257|5|1.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|5|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|265|265|5|1.8%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1485|1485|3|0.2%|0.0%|
[zeus](#zeus)|265|265|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|408|408|1|0.2%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|179397|179397|983|0.5%|98.7%|
[blocklist_de](#blocklist_de)|22346|22346|667|2.9%|67.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|636|28.5%|63.9%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|515|21.2%|51.7%|
[et_compromised](#et_compromised)|2338|2338|495|21.1%|49.7%|
[openbl_1d](#openbl_1d)|357|357|206|57.7%|20.7%|
[dshield](#dshield)|20|5120|119|2.3%|11.9%|
[et_block](#et_block)|975|18056513|97|0.0%|9.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|94|0.0%|9.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|90|0.0%|9.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|75|33.1%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|53|0.0%|5.3%|
[blocklist_de_mail](#blocklist_de_mail)|14591|14591|26|0.1%|2.6%|
[blocklist_de_imap](#blocklist_de_imap)|690|690|22|3.1%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|16|0.0%|1.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|9|0.0%|0.9%|
[shunlist](#shunlist)|51|51|5|9.8%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|12794|12794|4|0.0%|0.4%|
[voipbl](#voipbl)|10303|10775|3|0.0%|0.3%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|2|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|2|0.0%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|265|265|2|0.7%|0.2%|
[zeus](#zeus)|265|265|1|0.3%|0.1%|
[nixspam](#nixspam)|29350|29350|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.1%|
[ciarmy](#ciarmy)|408|408|1|0.2%|0.1%|

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
[alienvault_reputation](#alienvault_reputation)|179397|179397|9826|5.4%|99.7%|
[openbl_60d](#openbl_60d)|7777|7777|7777|100.0%|78.9%|
[openbl_30d](#openbl_30d)|4446|4446|4446|100.0%|45.1%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|1432|58.9%|14.5%|
[et_compromised](#et_compromised)|2338|2338|1396|59.7%|14.1%|
[blocklist_de](#blocklist_de)|22346|22346|1315|5.8%|13.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|1231|55.2%|12.4%|
[openbl_7d](#openbl_7d)|995|995|995|100.0%|10.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|951|0.0%|9.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|511|0.0%|5.1%|
[et_block](#et_block)|975|18056513|455|0.0%|4.6%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|447|0.0%|4.5%|
[openbl_1d](#openbl_1d)|357|357|357|100.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|220|0.0%|2.2%|
[dshield](#dshield)|20|5120|147|2.8%|1.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|78|34.5%|0.7%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|66|0.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|14591|14591|63|0.4%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|690|690|48|6.9%|0.4%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|36|0.1%|0.3%|
[nixspam](#nixspam)|29350|29350|27|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|26|0.3%|0.2%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7663|7663|23|0.3%|0.2%|
[et_tor](#et_tor)|6490|6490|21|0.3%|0.2%|
[dm_tor](#dm_tor)|6500|6500|21|0.3%|0.2%|
[bm_tor](#bm_tor)|6503|6503|21|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|19|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|14|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12794|12794|14|0.1%|0.1%|
[voipbl](#voipbl)|10303|10775|12|0.1%|0.1%|
[shunlist](#shunlist)|51|51|11|21.5%|0.1%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.0%|
[php_bad](#php_bad)|281|281|8|2.8%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|265|265|7|2.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|6|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|5|1.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1485|1485|5|0.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3472|3472|3|0.0%|0.0%|
[zeus](#zeus)|265|265|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[sslbl](#sslbl)|345|345|1|0.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4396|4396|1|0.0%|0.0%|
[ciarmy](#ciarmy)|408|408|1|0.2%|0.0%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Thu May 28 20:09:19 UTC 2015.

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

The last time downloaded was found to be dated: Thu May 28 19:45:10 UTC 2015.

The ipset `php_bad` has **281** entries, **281** unique IPs.

The following table shows the overlaps of `php_bad` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_bad`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_bad`.
- ` this % ` is the percentage **of this ipset (`php_bad`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[php_commenters](#php_commenters)|281|281|279|99.2%|99.2%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|202|0.2%|71.8%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|190|0.6%|67.6%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7663|7663|108|1.4%|38.4%|
[blocklist_de](#blocklist_de)|22346|22346|76|0.3%|27.0%|
[blocklist_de_bots](#blocklist_de_bots)|3472|3472|60|1.7%|21.3%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|41|0.5%|14.5%|
[php_spammers](#php_spammers)|417|417|32|7.6%|11.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|32|14.1%|11.3%|
[et_tor](#et_tor)|6490|6490|29|0.4%|10.3%|
[dm_tor](#dm_tor)|6500|6500|29|0.4%|10.3%|
[bm_tor](#bm_tor)|6503|6503|29|0.4%|10.3%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|25|0.0%|8.8%|
[blocklist_de_apache](#blocklist_de_apache)|12794|12794|25|0.1%|8.8%|
[et_block](#et_block)|975|18056513|24|0.0%|8.5%|
[php_dictionary](#php_dictionary)|433|433|22|5.0%|7.8%|
[blocklist_de_mail](#blocklist_de_mail)|14591|14591|21|0.1%|7.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|16|0.0%|5.6%|
[nixspam](#nixspam)|29350|29350|15|0.0%|5.3%|
[alienvault_reputation](#alienvault_reputation)|179397|179397|12|0.0%|4.2%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|9|0.0%|3.2%|
[ri_web_proxies](#ri_web_proxies)|4396|4396|8|0.1%|2.8%|
[openbl_90d](#openbl_90d)|9854|9854|8|0.0%|2.8%|
[openbl_60d](#openbl_60d)|7777|7777|8|0.1%|2.8%|
[openbl](#openbl)|9854|9854|8|0.0%|2.8%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|7|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|5|0.0%|1.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1485|1485|4|0.2%|1.4%|
[xroxy](#xroxy)|1884|1884|2|0.1%|0.7%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.3%|
[zeus](#zeus)|265|265|1|0.3%|0.3%|
[proxyrss](#proxyrss)|1722|1722|1|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|

## php_commenters

[projecthoneypot.org](http://www.projecthoneypot.org/) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1).

The last time downloaded was found to be dated: Thu May 28 19:45:12 UTC 2015.

The ipset `php_commenters` has **281** entries, **281** unique IPs.

The following table shows the overlaps of `php_commenters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_commenters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_commenters`.
- ` this % ` is the percentage **of this ipset (`php_commenters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[php_bad](#php_bad)|281|281|279|99.2%|99.2%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|203|0.2%|72.2%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|191|0.6%|67.9%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7663|7663|108|1.4%|38.4%|
[blocklist_de](#blocklist_de)|22346|22346|77|0.3%|27.4%|
[blocklist_de_bots](#blocklist_de_bots)|3472|3472|60|1.7%|21.3%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|40|0.5%|14.2%|
[php_spammers](#php_spammers)|417|417|32|7.6%|11.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|32|14.1%|11.3%|
[et_tor](#et_tor)|6490|6490|29|0.4%|10.3%|
[dm_tor](#dm_tor)|6500|6500|29|0.4%|10.3%|
[bm_tor](#bm_tor)|6503|6503|29|0.4%|10.3%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|25|0.0%|8.8%|
[blocklist_de_apache](#blocklist_de_apache)|12794|12794|25|0.1%|8.8%|
[et_block](#et_block)|975|18056513|24|0.0%|8.5%|
[php_dictionary](#php_dictionary)|433|433|22|5.0%|7.8%|
[blocklist_de_mail](#blocklist_de_mail)|14591|14591|22|0.1%|7.8%|
[nixspam](#nixspam)|29350|29350|16|0.0%|5.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|15|0.0%|5.3%|
[alienvault_reputation](#alienvault_reputation)|179397|179397|12|0.0%|4.2%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|9|0.0%|3.2%|
[ri_web_proxies](#ri_web_proxies)|4396|4396|8|0.1%|2.8%|
[openbl_90d](#openbl_90d)|9854|9854|8|0.0%|2.8%|
[openbl_60d](#openbl_60d)|7777|7777|8|0.1%|2.8%|
[openbl](#openbl)|9854|9854|8|0.0%|2.8%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|7|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|5|0.0%|1.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1485|1485|4|0.2%|1.4%|
[xroxy](#xroxy)|1884|1884|2|0.1%|0.7%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.3%|
[zeus](#zeus)|265|265|1|0.3%|0.3%|
[proxyrss](#proxyrss)|1722|1722|1|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|

## php_dictionary

[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1).

The last time downloaded was found to be dated: Thu May 28 19:45:13 UTC 2015.

The ipset `php_dictionary` has **433** entries, **433** unique IPs.

The following table shows the overlaps of `php_dictionary` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_dictionary`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_dictionary`.
- ` this % ` is the percentage **of this ipset (`php_dictionary`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[nixspam](#nixspam)|29350|29350|97|0.3%|22.4%|
[php_spammers](#php_spammers)|417|417|84|20.1%|19.3%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|74|0.0%|17.0%|
[blocklist_de](#blocklist_de)|22346|22346|72|0.3%|16.6%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|71|0.9%|16.3%|
[blocklist_de_mail](#blocklist_de_mail)|14591|14591|61|0.4%|14.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|56|0.1%|12.9%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7663|7663|27|0.3%|6.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|24|0.0%|5.5%|
[xroxy](#xroxy)|1884|1884|23|1.2%|5.3%|
[php_commenters](#php_commenters)|281|281|22|7.8%|5.0%|
[php_bad](#php_bad)|281|281|22|7.8%|5.0%|
[ri_web_proxies](#ri_web_proxies)|4396|4396|21|0.4%|4.8%|
[blocklist_de_bots](#blocklist_de_bots)|3472|3472|11|0.3%|2.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|10|0.0%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|9|0.0%|2.0%|
[alienvault_reputation](#alienvault_reputation)|179397|179397|7|0.0%|1.6%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|4|0.0%|0.9%|
[et_block](#et_block)|975|18056513|4|0.0%|0.9%|
[dm_tor](#dm_tor)|6500|6500|4|0.0%|0.9%|
[bm_tor](#bm_tor)|6503|6503|4|0.0%|0.9%|
[ri_connect_proxies](#ri_connect_proxies)|1714|1714|3|0.1%|0.6%|
[et_tor](#et_tor)|6490|6490|3|0.0%|0.6%|
[proxz](#proxz)|46|46|2|4.3%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.4%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|1|0.4%|0.2%|

## php_harvesters

[projecthoneypot.org](http://www.projecthoneypot.org/) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1).

The last time downloaded was found to be dated: Thu May 28 19:45:08 UTC 2015.

The ipset `php_harvesters` has **257** entries, **257** unique IPs.

The following table shows the overlaps of `php_harvesters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_harvesters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_harvesters`.
- ` this % ` is the percentage **of this ipset (`php_harvesters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|62|0.0%|24.1%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|50|0.1%|19.4%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7663|7663|39|0.5%|15.1%|
[blocklist_de](#blocklist_de)|22346|22346|32|0.1%|12.4%|
[blocklist_de_bots](#blocklist_de_bots)|3472|3472|27|0.7%|10.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|15|0.0%|5.8%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|10|0.1%|3.8%|
[php_commenters](#php_commenters)|281|281|9|3.2%|3.5%|
[php_bad](#php_bad)|281|281|9|3.2%|3.5%|
[alienvault_reputation](#alienvault_reputation)|179397|179397|9|0.0%|3.5%|
[nixspam](#nixspam)|29350|29350|7|0.0%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|7|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|7|0.0%|2.7%|
[et_tor](#et_tor)|6490|6490|7|0.1%|2.7%|
[dm_tor](#dm_tor)|6500|6500|7|0.1%|2.7%|
[bm_tor](#bm_tor)|6503|6503|7|0.1%|2.7%|
[openbl_90d](#openbl_90d)|9854|9854|5|0.0%|1.9%|
[openbl_60d](#openbl_60d)|7777|7777|5|0.0%|1.9%|
[openbl](#openbl)|9854|9854|5|0.0%|1.9%|
[blocklist_de_mail](#blocklist_de_mail)|14591|14591|4|0.0%|1.5%|
[xroxy](#xroxy)|1884|1884|2|0.1%|0.7%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.7%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|1|0.0%|0.3%|
[ri_web_proxies](#ri_web_proxies)|4396|4396|1|0.0%|0.3%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.3%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|
[fullbogons](#fullbogons)|3656|670735064|1|0.0%|0.3%|
[et_block](#et_block)|975|18056513|1|0.0%|0.3%|
[bogons](#bogons)|13|592708608|1|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|1|0.4%|0.3%|
[blocklist_de_ftp](#blocklist_de_ftp)|265|265|1|0.3%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|12794|12794|1|0.0%|0.3%|

## php_spammers

[projecthoneypot.org](http://www.projecthoneypot.org/) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1).

The last time downloaded was found to be dated: Thu May 28 19:45:09 UTC 2015.

The ipset `php_spammers` has **417** entries, **417** unique IPs.

The following table shows the overlaps of `php_spammers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_spammers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_spammers`.
- ` this % ` is the percentage **of this ipset (`php_spammers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|95|0.1%|22.7%|
[php_dictionary](#php_dictionary)|433|433|84|19.3%|20.1%|
[nixspam](#nixspam)|29350|29350|77|0.2%|18.4%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|64|0.2%|15.3%|
[blocklist_de](#blocklist_de)|22346|22346|63|0.2%|15.1%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|60|0.8%|14.3%|
[blocklist_de_mail](#blocklist_de_mail)|14591|14591|43|0.2%|10.3%|
[php_commenters](#php_commenters)|281|281|32|11.3%|7.6%|
[php_bad](#php_bad)|281|281|32|11.3%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|31|0.0%|7.4%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7663|7663|30|0.3%|7.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|26|0.0%|6.2%|
[ri_web_proxies](#ri_web_proxies)|4396|4396|18|0.4%|4.3%|
[xroxy](#xroxy)|1884|1884|17|0.9%|4.0%|
[blocklist_de_bots](#blocklist_de_bots)|3472|3472|15|0.4%|3.5%|
[et_tor](#et_tor)|6490|6490|6|0.0%|1.4%|
[dm_tor](#dm_tor)|6500|6500|6|0.0%|1.4%|
[bm_tor](#bm_tor)|6503|6503|6|0.0%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|5|0.0%|1.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|5|2.2%|1.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1485|1485|5|0.3%|1.1%|
[blocklist_de_apache](#blocklist_de_apache)|12794|12794|5|0.0%|1.1%|
[alienvault_reputation](#alienvault_reputation)|179397|179397|3|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.4%|
[ri_connect_proxies](#ri_connect_proxies)|1714|1714|2|0.1%|0.4%|
[proxyrss](#proxyrss)|1722|1722|2|0.1%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[et_block](#et_block)|975|18056513|2|0.0%|0.4%|
[proxz](#proxz)|46|46|1|2.1%|0.2%|
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
[xroxy](#xroxy)|1884|1884|1333|70.7%|77.4%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|872|0.9%|50.6%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|732|2.3%|42.5%|
[ri_web_proxies](#ri_web_proxies)|4396|4396|622|14.1%|36.1%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7663|7663|488|6.3%|28.3%|
[ri_connect_proxies](#ri_connect_proxies)|1714|1714|237|13.8%|13.7%|
[blocklist_de](#blocklist_de)|22346|22346|227|1.0%|13.1%|
[blocklist_de_bots](#blocklist_de_bots)|3472|3472|224|6.4%|13.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|63|0.0%|3.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|61|0.0%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|41|0.0%|2.3%|
[proxz](#proxz)|46|46|36|78.2%|2.0%|
[nixspam](#nixspam)|29350|29350|23|0.0%|1.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|9|1.3%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|3|1.3%|0.1%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|2|0.0%|0.1%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.1%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|2|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|179397|179397|2|0.0%|0.1%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.0%|
[php_bad](#php_bad)|281|281|1|0.3%|0.0%|
[et_tor](#et_tor)|6490|6490|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2338|2338|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6500|6500|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6503|6503|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14591|14591|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1485|1485|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12794|12794|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Thu May 28 18:51:34 UTC 2015.

The ipset `proxz` has **46** entries, **46** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[xroxy](#xroxy)|1884|1884|41|2.1%|89.1%|
[proxyrss](#proxyrss)|1722|1722|36|2.0%|78.2%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|19|0.0%|41.3%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7663|7663|19|0.2%|41.3%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|18|0.0%|39.1%|
[ri_web_proxies](#ri_web_proxies)|4396|4396|11|0.2%|23.9%|
[blocklist_de](#blocklist_de)|22346|22346|10|0.0%|21.7%|
[blocklist_de_bots](#blocklist_de_bots)|3472|3472|8|0.2%|17.3%|
[nixspam](#nixspam)|29350|29350|5|0.0%|10.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|5|0.0%|10.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|3|0.0%|6.5%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|4.3%|
[blocklist_de_mail](#blocklist_de_mail)|14591|14591|2|0.0%|4.3%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|1|0.0%|2.1%|
[ri_connect_proxies](#ri_connect_proxies)|1714|1714|1|0.0%|2.1%|
[php_spammers](#php_spammers)|417|417|1|0.2%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|1|0.0%|2.1%|
[et_compromised](#et_compromised)|2338|2338|1|0.0%|2.1%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|1|0.0%|2.1%|

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
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|995|1.0%|58.0%|
[ri_web_proxies](#ri_web_proxies)|4396|4396|698|15.8%|40.7%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|692|2.2%|40.3%|
[xroxy](#xroxy)|1884|1884|263|13.9%|15.3%|
[proxyrss](#proxyrss)|1722|1722|237|13.7%|13.8%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7663|7663|191|2.4%|11.1%|
[blocklist_de](#blocklist_de)|22346|22346|80|0.3%|4.6%|
[blocklist_de_bots](#blocklist_de_bots)|3472|3472|78|2.2%|4.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|76|0.0%|4.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|61|0.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|41|0.0%|2.3%|
[nixspam](#nixspam)|29350|29350|11|0.0%|0.6%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.3%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|3|0.0%|0.1%|
[php_dictionary](#php_dictionary)|433|433|3|0.6%|0.1%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.1%|
[et_tor](#et_tor)|6490|6490|2|0.0%|0.1%|
[dm_tor](#dm_tor)|6500|6500|2|0.0%|0.1%|
[bm_tor](#bm_tor)|6503|6503|2|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|14591|14591|2|0.0%|0.1%|
[proxz](#proxz)|46|46|1|2.1%|0.0%|
[alienvault_reputation](#alienvault_reputation)|179397|179397|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Thu May 28 17:26:08 UTC 2015.

The ipset `ri_web_proxies` has **4396** entries, **4396** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|2178|2.3%|49.5%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|1618|5.2%|36.8%|
[ri_connect_proxies](#ri_connect_proxies)|1714|1714|698|40.7%|15.8%|
[xroxy](#xroxy)|1884|1884|689|36.5%|15.6%|
[proxyrss](#proxyrss)|1722|1722|622|36.1%|14.1%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7663|7663|568|7.4%|12.9%|
[blocklist_de](#blocklist_de)|22346|22346|383|1.7%|8.7%|
[blocklist_de_bots](#blocklist_de_bots)|3472|3472|357|10.2%|8.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|153|0.0%|3.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|136|0.0%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|102|0.0%|2.3%|
[nixspam](#nixspam)|29350|29350|79|0.2%|1.7%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|30|0.4%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|14591|14591|24|0.1%|0.5%|
[php_dictionary](#php_dictionary)|433|433|21|4.8%|0.4%|
[php_spammers](#php_spammers)|417|417|18|4.3%|0.4%|
[proxz](#proxz)|46|46|11|23.9%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|10|1.4%|0.2%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.1%|
[php_bad](#php_bad)|281|281|8|2.8%|0.1%|
[et_tor](#et_tor)|6490|6490|5|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6500|6500|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6503|6503|4|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|3|1.3%|0.0%|
[alienvault_reputation](#alienvault_reputation)|179397|179397|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[openbl_90d](#openbl_90d)|9854|9854|1|0.0%|0.0%|
[openbl](#openbl)|9854|9854|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1485|1485|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12794|12794|1|0.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|179397|179397|49|0.0%|96.0%|
[blocklist_de](#blocklist_de)|22346|22346|12|0.0%|23.5%|
[openbl_90d](#openbl_90d)|9854|9854|11|0.1%|21.5%|
[openbl_60d](#openbl_60d)|7777|7777|11|0.1%|21.5%|
[openbl](#openbl)|9854|9854|11|0.1%|21.5%|
[openbl_30d](#openbl_30d)|4446|4446|10|0.2%|19.6%|
[et_compromised](#et_compromised)|2338|2338|9|0.3%|17.6%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|9|0.3%|17.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|9|0.4%|17.6%|
[openbl_7d](#openbl_7d)|995|995|5|0.5%|9.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|4|0.0%|7.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|3|0.0%|5.8%|
[voipbl](#voipbl)|10303|10775|2|0.0%|3.9%|
[openbl_1d](#openbl_1d)|357|357|2|0.5%|3.9%|
[ciarmy](#ciarmy)|408|408|2|0.4%|3.9%|
[blocklist_de_apache](#blocklist_de_apache)|12794|12794|2|0.0%|3.9%|
[blocklist_de_mail](#blocklist_de_mail)|14591|14591|1|0.0%|1.9%|
[blocklist_de_imap](#blocklist_de_imap)|690|690|1|0.1%|1.9%|

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
[bm_tor](#bm_tor)|6503|6503|1054|16.2%|14.5%|
[dm_tor](#dm_tor)|6500|6500|1049|16.1%|14.4%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|718|0.7%|9.9%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|526|1.7%|7.2%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7663|7663|372|4.8%|5.1%|
[et_block](#et_block)|975|18056513|286|0.0%|3.9%|
[zeus](#zeus)|265|265|226|85.2%|3.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|222|0.0%|3.0%|
[zeus_badips](#zeus_badips)|229|229|201|87.7%|2.7%|
[nixspam](#nixspam)|29350|29350|199|0.6%|2.7%|
[blocklist_de](#blocklist_de)|22346|22346|179|0.8%|2.4%|
[alienvault_reputation](#alienvault_reputation)|179397|179397|122|0.0%|1.6%|
[blocklist_de_mail](#blocklist_de_mail)|14591|14591|112|0.7%|1.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|101|0.0%|1.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|85|0.0%|1.1%|
[php_dictionary](#php_dictionary)|433|433|71|16.3%|0.9%|
[php_spammers](#php_spammers)|417|417|60|14.3%|0.8%|
[feodo](#feodo)|67|67|48|71.6%|0.6%|
[php_bad](#php_bad)|281|281|41|14.5%|0.5%|
[php_commenters](#php_commenters)|281|281|40|14.2%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|12794|12794|40|0.3%|0.5%|
[xroxy](#xroxy)|1884|1884|39|2.0%|0.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1485|1485|37|2.4%|0.5%|
[ri_web_proxies](#ri_web_proxies)|4396|4396|30|0.6%|0.4%|
[openbl_90d](#openbl_90d)|9854|9854|26|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7777|7777|26|0.3%|0.3%|
[openbl](#openbl)|9854|9854|26|0.2%|0.3%|
[blocklist_de_bots](#blocklist_de_bots)|3472|3472|26|0.7%|0.3%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|25|1.9%|0.3%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|20|0.0%|0.2%|
[sslbl](#sslbl)|345|345|17|4.9%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|15|0.0%|0.2%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|10|3.8%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|6|0.0%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|509|509|4|0.7%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1714|1714|3|0.1%|0.0%|
[openbl_30d](#openbl_30d)|4446|4446|3|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|3|0.1%|0.0%|
[proxyrss](#proxyrss)|1722|1722|2|0.1%|0.0%|
[openbl_7d](#openbl_7d)|995|995|2|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|690|690|2|0.2%|0.0%|
[proxz](#proxz)|46|46|1|2.1%|0.0%|
[malc0de](#malc0de)|411|411|1|0.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2338|2338|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|1|0.4%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|179397|179397|1624|0.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1037|0.3%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|782|0.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|512|0.1%|0.0%|
[dshield](#dshield)|20|5120|512|10.0%|0.0%|
[openbl_90d](#openbl_90d)|9854|9854|447|4.5%|0.0%|
[openbl](#openbl)|9854|9854|447|4.5%|0.0%|
[openbl_60d](#openbl_60d)|7777|7777|281|3.6%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|235|0.7%|0.0%|
[openbl_30d](#openbl_30d)|4446|4446|207|4.6%|0.0%|
[blocklist_de](#blocklist_de)|22346|22346|190|0.8%|0.0%|
[nixspam](#nixspam)|29350|29350|173|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|112|5.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|102|4.2%|0.0%|
[openbl_7d](#openbl_7d)|995|995|94|9.4%|0.0%|
[et_compromised](#et_compromised)|2338|2338|92|3.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3472|3472|50|1.4%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7663|7663|47|0.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|28|2.1%|0.0%|
[openbl_1d](#openbl_1d)|357|357|26|7.2%|0.0%|
[php_commenters](#php_commenters)|281|281|25|8.8%|0.0%|
[php_bad](#php_bad)|281|281|25|8.8%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14591|14591|22|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|20|0.2%|0.0%|
[zeus_badips](#zeus_badips)|229|229|16|6.9%|0.0%|
[zeus](#zeus)|265|265|16|6.0%|0.0%|
[voipbl](#voipbl)|10303|10775|14|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|690|690|12|1.7%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|7|3.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1485|1485|4|0.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12794|12794|4|0.0%|0.0%|
[sslbl](#sslbl)|345|345|3|0.8%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[malc0de](#malc0de)|411|411|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6490|6490|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6500|6500|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6503|6503|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[et_botnet](#et_botnet)|512|512|1|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|265|265|1|0.3%|0.0%|

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
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|105|0.1%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|40|0.1%|0.0%|
[blocklist_de](#blocklist_de)|22346|22346|35|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3472|3472|29|0.8%|0.0%|
[alienvault_reputation](#alienvault_reputation)|179397|179397|15|0.0%|0.0%|
[openbl_90d](#openbl_90d)|9854|9854|14|0.1%|0.0%|
[openbl](#openbl)|9854|9854|14|0.1%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7663|7663|11|0.1%|0.0%|
[php_commenters](#php_commenters)|281|281|7|2.4%|0.0%|
[php_bad](#php_bad)|281|281|7|2.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|6|0.0%|0.0%|
[zeus_badips](#zeus_badips)|229|229|5|2.1%|0.0%|
[zeus](#zeus)|265|265|5|1.8%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|4|1.7%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14591|14591|4|0.0%|0.0%|
[nixspam](#nixspam)|29350|29350|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12794|12794|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[openbl_60d](#openbl_60d)|7777|7777|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4446|4446|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|357|357|1|0.2%|0.0%|
[malc0de](#malc0de)|411|411|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|690|690|1|0.1%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Thu May 28 19:45:06 UTC 2015.

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
[alienvault_reputation](#alienvault_reputation)|179397|179397|7|0.0%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|6|0.0%|1.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|3|0.0%|0.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|3|0.0%|0.8%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|1|0.0%|0.2%|
[openbl_90d](#openbl_90d)|9854|9854|1|0.0%|0.2%|
[openbl](#openbl)|9854|9854|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.2%|

## stop_forum_spam_1h

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Thu May 28 20:00:02 UTC 2015.

The ipset `stop_forum_spam_1h` has **7663** entries, **7663** unique IPs.

The following table shows the overlaps of `stop_forum_spam_1h` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stop_forum_spam_1h`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stop_forum_spam_1h`.
- ` this % ` is the percentage **of this ipset (`stop_forum_spam_1h`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|5073|5.5%|66.2%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|4805|15.6%|62.7%|
[blocklist_de](#blocklist_de)|22346|22346|1628|7.2%|21.2%|
[blocklist_de_bots](#blocklist_de_bots)|3472|3472|1529|44.0%|19.9%|
[ri_web_proxies](#ri_web_proxies)|4396|4396|568|12.9%|7.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|546|0.0%|7.1%|
[xroxy](#xroxy)|1884|1884|516|27.3%|6.7%|
[proxyrss](#proxyrss)|1722|1722|488|28.3%|6.3%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|372|5.1%|4.8%|
[bm_tor](#bm_tor)|6503|6503|335|5.1%|4.3%|
[dm_tor](#dm_tor)|6500|6500|334|5.1%|4.3%|
[et_tor](#et_tor)|6490|6490|327|5.0%|4.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|220|0.0%|2.8%|
[ri_connect_proxies](#ri_connect_proxies)|1714|1714|191|11.1%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|150|0.0%|1.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|109|48.2%|1.4%|
[php_commenters](#php_commenters)|281|281|108|38.4%|1.4%|
[php_bad](#php_bad)|281|281|108|38.4%|1.4%|
[blocklist_de_apache](#blocklist_de_apache)|12794|12794|96|0.7%|1.2%|
[nixspam](#nixspam)|29350|29350|74|0.2%|0.9%|
[alienvault_reputation](#alienvault_reputation)|179397|179397|62|0.0%|0.8%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1485|1485|55|3.7%|0.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|47|0.0%|0.6%|
[et_block](#et_block)|975|18056513|40|0.0%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|14591|14591|40|0.2%|0.5%|
[php_harvesters](#php_harvesters)|257|257|39|15.1%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|34|0.0%|0.4%|
[php_spammers](#php_spammers)|417|417|30|7.1%|0.3%|
[php_dictionary](#php_dictionary)|433|433|27|6.2%|0.3%|
[openbl_90d](#openbl_90d)|9854|9854|23|0.2%|0.3%|
[openbl](#openbl)|9854|9854|23|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7777|7777|21|0.2%|0.2%|
[proxz](#proxz)|46|46|19|41.3%|0.2%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|11|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|7|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.0%|
[voipbl](#voipbl)|10303|10775|3|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4446|4446|1|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|1|0.0%|0.0%|

## stop_forum_spam_30d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip).

The last time downloaded was found to be dated: Thu May 28 00:00:49 UTC 2015.

The ipset `stop_forum_spam_30d` has **92103** entries, **92103** unique IPs.

The following table shows the overlaps of `stop_forum_spam_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stop_forum_spam_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stop_forum_spam_30d`.
- ` this % ` is the percentage **of this ipset (`stop_forum_spam_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|30535|99.4%|33.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|6117|0.0%|6.6%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7663|7663|5073|66.2%|5.5%|
[blocklist_de](#blocklist_de)|22346|22346|2597|11.6%|2.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|2467|0.0%|2.6%|
[blocklist_de_bots](#blocklist_de_bots)|3472|3472|2295|66.1%|2.4%|
[ri_web_proxies](#ri_web_proxies)|4396|4396|2178|49.5%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|1511|0.0%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|1714|1714|995|58.0%|1.0%|
[xroxy](#xroxy)|1884|1884|954|50.6%|1.0%|
[proxyrss](#proxyrss)|1722|1722|872|50.6%|0.9%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|782|0.0%|0.8%|
[et_block](#et_block)|975|18056513|762|0.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|741|0.0%|0.8%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|718|9.9%|0.7%|
[et_tor](#et_tor)|6490|6490|591|9.1%|0.6%|
[dm_tor](#dm_tor)|6500|6500|582|8.9%|0.6%|
[bm_tor](#bm_tor)|6503|6503|581|8.9%|0.6%|
[nixspam](#nixspam)|29350|29350|260|0.8%|0.2%|
[alienvault_reputation](#alienvault_reputation)|179397|179397|229|0.1%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|12794|12794|225|1.7%|0.2%|
[php_commenters](#php_commenters)|281|281|203|72.2%|0.2%|
[php_bad](#php_bad)|281|281|202|71.8%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|14591|14591|193|1.3%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|125|55.3%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|105|0.0%|0.1%|
[php_spammers](#php_spammers)|417|417|95|22.7%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1485|1485|83|5.5%|0.0%|
[php_dictionary](#php_dictionary)|433|433|74|17.0%|0.0%|
[openbl_90d](#openbl_90d)|9854|9854|66|0.6%|0.0%|
[openbl](#openbl)|9854|9854|66|0.6%|0.0%|
[php_harvesters](#php_harvesters)|257|257|62|24.1%|0.0%|
[openbl_60d](#openbl_60d)|7777|7777|59|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|44|0.0%|0.0%|
[voipbl](#voipbl)|10303|10775|40|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|22|3.2%|0.0%|
[proxz](#proxz)|46|46|19|41.3%|0.0%|
[openbl_30d](#openbl_30d)|4446|4446|18|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|16|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|8|0.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|6|0.2%|0.0%|
[et_compromised](#et_compromised)|2338|2338|5|0.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|265|265|5|1.8%|0.0%|
[zeus_badips](#zeus_badips)|229|229|3|1.3%|0.0%|
[zeus](#zeus)|265|265|3|1.1%|0.0%|
[openbl_7d](#openbl_7d)|995|995|2|0.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|2|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3656|670735064|2|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|690|690|2|0.2%|0.0%|
[sslbl](#sslbl)|345|345|1|0.2%|0.0%|
[openbl_1d](#openbl_1d)|357|357|1|0.2%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|509|509|1|0.1%|0.0%|
[ciarmy](#ciarmy)|408|408|1|0.2%|0.0%|
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
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|30535|33.1%|99.4%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7663|7663|4805|62.7%|15.6%|
[blocklist_de](#blocklist_de)|22346|22346|2225|9.9%|7.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|2079|0.0%|6.7%|
[blocklist_de_bots](#blocklist_de_bots)|3472|3472|2048|58.9%|6.6%|
[ri_web_proxies](#ri_web_proxies)|4396|4396|1618|36.8%|5.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|927|0.0%|3.0%|
[xroxy](#xroxy)|1884|1884|798|42.3%|2.5%|
[proxyrss](#proxyrss)|1722|1722|732|42.5%|2.3%|
[ri_connect_proxies](#ri_connect_proxies)|1714|1714|692|40.3%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|581|0.0%|1.8%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|526|7.2%|1.7%|
[et_tor](#et_tor)|6490|6490|442|6.8%|1.4%|
[bm_tor](#bm_tor)|6503|6503|435|6.6%|1.4%|
[dm_tor](#dm_tor)|6500|6500|434|6.6%|1.4%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|235|0.0%|0.7%|
[et_block](#et_block)|975|18056513|214|0.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|195|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|191|67.9%|0.6%|
[php_bad](#php_bad)|281|281|190|67.6%|0.6%|
[nixspam](#nixspam)|29350|29350|142|0.4%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|12794|12794|137|1.0%|0.4%|
[alienvault_reputation](#alienvault_reputation)|179397|179397|116|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|114|50.4%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|14591|14591|92|0.6%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1485|1485|72|4.8%|0.2%|
[php_spammers](#php_spammers)|417|417|64|15.3%|0.2%|
[php_dictionary](#php_dictionary)|433|433|56|12.9%|0.1%|
[php_harvesters](#php_harvesters)|257|257|50|19.4%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|40|0.0%|0.1%|
[openbl_90d](#openbl_90d)|9854|9854|36|0.3%|0.1%|
[openbl](#openbl)|9854|9854|36|0.3%|0.1%|
[openbl_60d](#openbl_60d)|7777|7777|34|0.4%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|22|0.0%|0.0%|
[proxz](#proxz)|46|46|18|39.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|12|1.7%|0.0%|
[voipbl](#voipbl)|10303|10775|11|0.1%|0.0%|
[openbl_30d](#openbl_30d)|4446|4446|7|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[et_compromised](#et_compromised)|2338|2338|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|2|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|690|690|2|0.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|265|265|2|0.7%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|265|265|1|0.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Thu May 28 18:00:27 UTC 2015.

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
[alienvault_reputation](#alienvault_reputation)|179397|179397|200|0.1%|1.8%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|40|0.0%|0.3%|
[blocklist_de](#blocklist_de)|22346|22346|37|0.1%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|97|97|29|29.8%|0.2%|
[et_block](#et_block)|975|18056513|20|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|14|0.0%|0.1%|
[openbl_90d](#openbl_90d)|9854|9854|12|0.1%|0.1%|
[openbl](#openbl)|9854|9854|12|0.1%|0.1%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|11|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7777|7777|9|0.1%|0.0%|
[openbl_30d](#openbl_30d)|4446|4446|4|0.0%|0.0%|
[nixspam](#nixspam)|29350|29350|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|4|0.0%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7663|7663|3|0.0%|0.0%|
[openbl_7d](#openbl_7d)|995|995|3|0.3%|0.0%|
[ciarmy](#ciarmy)|408|408|3|0.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|3|0.1%|0.0%|
[shunlist](#shunlist)|51|51|2|3.9%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3472|3472|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12794|12794|2|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[et_tor](#et_tor)|6490|6490|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2338|2338|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6500|6500|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6503|6503|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14591|14591|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|690|690|1|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1485|1485|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Thu May 28 19:33:01 UTC 2015.

The ipset `xroxy` has **1884** entries, **1884** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[proxyrss](#proxyrss)|1722|1722|1333|77.4%|70.7%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|954|1.0%|50.6%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|798|2.5%|42.3%|
[ri_web_proxies](#ri_web_proxies)|4396|4396|689|15.6%|36.5%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7663|7663|516|6.7%|27.3%|
[blocklist_de](#blocklist_de)|22346|22346|290|1.2%|15.3%|
[ri_connect_proxies](#ri_connect_proxies)|1714|1714|263|15.3%|13.9%|
[blocklist_de_bots](#blocklist_de_bots)|3472|3472|247|7.1%|13.1%|
[nixspam](#nixspam)|29350|29350|92|0.3%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|83|0.0%|4.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|71|0.0%|3.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|51|0.0%|2.7%|
[proxz](#proxz)|46|46|41|89.1%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|14591|14591|41|0.2%|2.1%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|39|0.5%|2.0%|
[php_dictionary](#php_dictionary)|433|433|23|5.3%|1.2%|
[php_spammers](#php_spammers)|417|417|17|4.0%|0.9%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|12|1.7%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|226|226|6|2.6%|0.3%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|179397|179397|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.1%|
[php_commenters](#php_commenters)|281|281|2|0.7%|0.1%|
[php_bad](#php_bad)|281|281|2|0.7%|0.1%|
[dm_tor](#dm_tor)|6500|6500|2|0.0%|0.1%|
[bm_tor](#bm_tor)|6503|6503|2|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.0%|
[et_tor](#et_tor)|6490|6490|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1485|1485|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12794|12794|1|0.0%|0.0%|

## zeus

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist).

The last time downloaded was found to be dated: Thu May 28 13:33:06 UTC 2015.

The ipset `zeus` has **265** entries, **265** unique IPs.

The following table shows the overlaps of `zeus` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus`.
- ` this % ` is the percentage **of this ipset (`zeus`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|975|18056513|262|0.0%|98.8%|
[zeus_badips](#zeus_badips)|229|229|229|100.0%|86.4%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|226|3.1%|85.2%|
[alienvault_reputation](#alienvault_reputation)|179397|179397|66|0.0%|24.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|19|0.0%|7.1%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|16|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|9|0.0%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|7|0.0%|2.6%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|5|0.0%|1.8%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|3|0.0%|1.1%|
[openbl_90d](#openbl_90d)|9854|9854|2|0.0%|0.7%|
[openbl_60d](#openbl_60d)|7777|7777|2|0.0%|0.7%|
[openbl_30d](#openbl_30d)|4446|4446|2|0.0%|0.7%|
[openbl](#openbl)|9854|9854|2|0.0%|0.7%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|1|0.0%|0.3%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.3%|
[php_bad](#php_bad)|281|281|1|0.3%|0.3%|
[openbl_7d](#openbl_7d)|995|995|1|0.1%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.3%|
[et_compromised](#et_compromised)|2338|2338|1|0.0%|0.3%|
[clean_mx_viruses](#clean_mx_viruses)|509|509|1|0.1%|0.3%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|1|0.0%|0.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|2229|2229|1|0.0%|0.3%|
[blocklist_de](#blocklist_de)|22346|22346|1|0.0%|0.3%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Thu May 28 20:09:17 UTC 2015.

The ipset `zeus_badips` has **229** entries, **229** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|265|265|229|86.4%|100.0%|
[et_block](#et_block)|975|18056513|228|0.0%|99.5%|
[snort_ipfilter](#snort_ipfilter)|7240|7240|201|2.7%|87.7%|
[alienvault_reputation](#alienvault_reputation)|179397|179397|36|0.0%|15.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|16|0.0%|6.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|14|0.0%|6.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|8|0.0%|3.4%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|5|0.0%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|4|0.0%|1.7%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92103|92103|3|0.0%|1.3%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30710|30710|1|0.0%|0.4%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.4%|
[php_bad](#php_bad)|281|281|1|0.3%|0.4%|
[openbl_90d](#openbl_90d)|9854|9854|1|0.0%|0.4%|
[openbl_60d](#openbl_60d)|7777|7777|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|4446|4446|1|0.0%|0.4%|
[openbl](#openbl)|9854|9854|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.4%|
[et_compromised](#et_compromised)|2338|2338|1|0.0%|0.4%|
[bruteforceblocker](#bruteforceblocker)|2428|2428|1|0.0%|0.4%|
