### Contents

- [About this repo](#about-this-repo)

- [Using these ipsets](#using-these-ipsets)
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

3. I have included the TOR network in these lists (`danmetor`, `tor`, `tor_servers`). The TOR network is not necessarily bad and you should not block it if you want to allow your users be anonymous. I have included it because for certain cases, allowing an anonymity network might be a risky thing (such as eCommerce).

4. Apply any blacklist at the internet side of your firewall. Be very carefull. The `bogons` and `fullbogons` lists contain private, unroutable IPs that should not be routed on the internet. If you apply such a blocklist on your DMZ or LAN side, you will be blocked out of your firewall.

5. Always have a whitelist too, containing the IP addresses or subnets you trust. Try to build the rules in such a way that if an IP is in the whitelist, it should not be blocked by these blocklists.

---

## Using them in FireHOL

### Adding the ipsets in your firehol.conf

I use something like this. Keep in mind that you have to have the `whitelist` ipset created before all these.
iptables will log each match, together with the name of the ipset that matched the packet.

```sh
	# our wan interface
	wan="dsl0"
	
	# our whitelist
	ipset4 create whitelist hash:net
	ipset4 add whitelist A.B.C.D/E # A.B.C.D/E is whitelisted
	
	# subnets
	for x in fullbogons dshield spamhaus_drop spamhaus_edrop
	do
		ipset4 create  ${x} hash:net
		ipset4 addfile ${x} ipsets/${x}.netset
		blacklist4 full inface "${wan}" log "BLACKLIST ${x^^}" ipset:${x} \
			except src ipset:whitelist
	done

	# individual IPs
	for x in zeus feodo palevo autoshun openbl blocklist_de malc0de ciarmy \
		malwaredomainlist snort_ipfilter stop_forum_spam_1h stop_forum_spam_7d \
		bruteforceblocker rosi_connect_proxies rosi_web_proxies compromised
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

The following list was automatically generated on Wed May 27 10:22:57 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|178186 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|23619 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6428 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD)|ipv4 hash:ip|2366 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|392 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[clean_mx_viruses](#clean_mx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|452 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6425 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
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
[ib_bluetack_level1](#ib_bluetack_level1)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Level 1 (for use in p2p): Companies or organizations who are clearly involved with trying to stop filesharing (e.g. Baytsp, MediaDefender, Mediasentry a.o.). Companies which anti-p2p activity has been seen from. Companies that produce or have a strong financial interest in copyrighted material (e.g. music, movie, software industries a.o.). Government ranges or companies that have a strong financial interest in doing work for governments. Legal industry ranges. IPs or ranges of ISPs from which anti-p2p activity has been observed. Basically this list will block all kinds of internet connections that most people would rather not have during their internet travels.|ipv4 hash:net|215693 subnets, 765044590 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz)
[ib_bluetack_level2](#ib_bluetack_level2)|[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 2 (for use in p2p). General corporate ranges. Ranges used by labs or researchers. Proxies.|ipv4 hash:net|75927 subnets, 348729520 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw&fileformat=p2p&archiveformat=gz)
[ib_bluetack_level3](#ib_bluetack_level3)|[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 3 (for use in p2p). Many portal-type websites. ISP ranges that may be dodgy for some reason. Ranges that belong to an individual, but which have not been determined to be used by a particular company. Ranges for things that are unusual in some way. The L3 list is aka the paranoid list.|ipv4 hash:net|18550 subnets, 139108857 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh&fileformat=p2p&archiveformat=gz)
[ib_bluetack_proxies](#ib_bluetack_proxies)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Open Proxies IPs list (without TOR)|ipv4 hash:ip|673 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=xoebmbyexwuiogmbyprb&fileformat=p2p&archiveformat=gz)
[ib_bluetack_spyware](#ib_bluetack_spyware)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) known malicious SPYWARE and ADWARE IP Address ranges|ipv4 hash:net|898 subnets, 336971 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=llvtlsjyoyiczbkjsxpf&fileformat=p2p&archiveformat=gz)
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) web server hack and exploit attempts|ipv4 hash:ip|1460 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=ghlzqtqxnzctvvajwwag&fileformat=p2p&archiveformat=gz)
[infiltrated](#infiltrated)|[infiltrated.net](http://www.infiltrated.net) (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|10520 unique IPs|updated every 12 hours  from [this link](http://www.infiltrated.net/blacklisted)
[malc0de](#malc0de)|[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days|ipv4 hash:ip|418 unique IPs|updated every 1 day  from [this link](http://malc0de.com/bl/IP_Blacklist.txt)
[malwaredomainlist](#malwaredomainlist)|[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses|ipv4 hash:ip|1283 unique IPs|updated every 12 hours  from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt)
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|23624 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
[openbl](#openbl)|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|9909 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt.gz)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|357 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_1days.txt.gz)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|4441 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt.gz)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7833 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt.gz)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|970 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt.gz)
[openbl_90d](#openbl_90d)|[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|9909 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt.gz)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
[php_bad](#php_bad)|[projecthoneypot.org](http://www.projecthoneypot.org/) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|246 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|246 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|357 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|235 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|378 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1585 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|4012 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|51 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|7065 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|641 subnets, 18117120 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|55 subnets, 421120 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|331 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
[stop_forum_spam_1h](#stop_forum_spam_1h)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|7508 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stop_forum_spam_30d](#stop_forum_spam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|92800 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
[stop_forum_spam_7d](#stop_forum_spam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|30172 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10277 subnets, 10748 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) default blocklist including hijacked sites and web hosting providers - **excellent list**|ipv4 hash:ip|265 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) includes IPv4 addresses that are used by the ZeuS trojan|ipv4 hash:ip|228 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Wed May 27 04:30:32 UTC 2015.

The ipset `alienvault_reputation` has **178186** entries, **178186** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|14703|0.0%|8.2%|
[openbl_90d](#openbl_90d)|9909|9909|9882|99.7%|5.5%|
[openbl](#openbl)|9909|9909|9882|99.7%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|8409|0.0%|4.7%|
[openbl_60d](#openbl_60d)|7833|7833|7810|99.7%|4.3%|
[et_block](#et_block)|974|18056767|5528|0.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|5176|0.0%|2.9%|
[openbl_30d](#openbl_30d)|4441|4441|4426|99.6%|2.4%|
[dshield](#dshield)|20|5120|4355|85.0%|2.4%|
[blocklist_de](#blocklist_de)|23619|23619|1626|6.8%|0.9%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|1624|0.0%|0.9%|
[bruteforceblocker](#bruteforceblocker)|2366|2366|1459|61.6%|0.8%|
[et_compromised](#et_compromised)|2292|2292|1448|63.1%|0.8%|
[openbl_7d](#openbl_7d)|970|970|960|98.9%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|519|0.0%|0.2%|
[ciarmy](#ciarmy)|392|392|374|95.4%|0.2%|
[openbl_1d](#openbl_1d)|357|357|355|99.4%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|280|0.0%|0.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|239|0.2%|0.1%|
[voipbl](#voipbl)|10277|10748|201|1.8%|0.1%|
[infiltrated](#infiltrated)|10520|10520|146|1.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7065|7065|120|1.6%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|116|0.3%|0.0%|
[zeus](#zeus)|265|265|65|24.5%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7508|7508|56|0.7%|0.0%|
[shunlist](#shunlist)|51|51|51|100.0%|0.0%|
[et_tor](#et_tor)|6400|6400|44|0.6%|0.0%|
[dm_tor](#dm_tor)|6425|6425|44|0.6%|0.0%|
[bm_tor](#bm_tor)|6428|6428|44|0.6%|0.0%|
[zeus_badips](#zeus_badips)|228|228|36|15.7%|0.0%|
[nixspam](#nixspam)|23624|23624|26|0.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|15|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|13|0.0%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|452|452|13|2.8%|0.0%|
[php_commenters](#php_commenters)|246|246|12|4.8%|0.0%|
[php_bad](#php_bad)|246|246|12|4.8%|0.0%|
[malc0de](#malc0de)|418|418|11|2.6%|0.0%|
[php_harvesters](#php_harvesters)|235|235|9|3.8%|0.0%|
[sslbl](#sslbl)|331|331|7|2.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[php_dictionary](#php_dictionary)|357|357|6|1.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|6|0.4%|0.0%|
[php_spammers](#php_spammers)|378|378|4|1.0%|0.0%|
[et_botnet](#et_botnet)|505|505|3|0.5%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4012|4012|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1585|1585|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[feodo](#feodo)|62|62|1|1.6%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Wed May 27 10:10:03 UTC 2015.

The ipset `blocklist_de` has **23619** entries, **23619** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|2852|0.0%|12.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|2583|2.7%|10.9%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|2359|7.8%|9.9%|
[alienvault_reputation](#alienvault_reputation)|178186|178186|1626|0.9%|6.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|1473|0.0%|6.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|1443|0.0%|6.1%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7508|7508|1397|18.6%|5.9%|
[openbl_90d](#openbl_90d)|9909|9909|1352|13.6%|5.7%|
[openbl](#openbl)|9909|9909|1352|13.6%|5.7%|
[openbl_60d](#openbl_60d)|7833|7833|1302|16.6%|5.5%|
[openbl_30d](#openbl_30d)|4441|4441|1181|26.5%|5.0%|
[bruteforceblocker](#bruteforceblocker)|2366|2366|1109|46.8%|4.6%|
[et_compromised](#et_compromised)|2292|2292|1028|44.8%|4.3%|
[nixspam](#nixspam)|23624|23624|837|3.5%|3.5%|
[openbl_7d](#openbl_7d)|970|970|642|66.1%|2.7%|
[ri_web_proxies](#ri_web_proxies)|4012|4012|361|8.9%|1.5%|
[openbl_1d](#openbl_1d)|357|357|252|70.5%|1.0%|
[infiltrated](#infiltrated)|10520|10520|241|2.2%|1.0%|
[snort_ipfilter](#snort_ipfilter)|7065|7065|198|2.8%|0.8%|
[et_block](#et_block)|974|18056767|190|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|188|0.0%|0.7%|
[ri_connect_proxies](#ri_connect_proxies)|1585|1585|86|5.4%|0.3%|
[php_dictionary](#php_dictionary)|357|357|80|22.4%|0.3%|
[php_commenters](#php_commenters)|246|246|77|31.3%|0.3%|
[php_bad](#php_bad)|246|246|77|31.3%|0.3%|
[php_spammers](#php_spammers)|378|378|76|20.1%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|64|0.0%|0.2%|
[ciarmy](#ciarmy)|392|392|44|11.2%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|42|0.0%|0.1%|
[dshield](#dshield)|20|5120|40|0.7%|0.1%|
[voipbl](#voipbl)|10277|10748|38|0.3%|0.1%|
[et_tor](#et_tor)|6400|6400|28|0.4%|0.1%|
[php_harvesters](#php_harvesters)|235|235|26|11.0%|0.1%|
[dm_tor](#dm_tor)|6425|6425|25|0.3%|0.1%|
[bm_tor](#bm_tor)|6428|6428|25|0.3%|0.1%|
[shunlist](#shunlist)|51|51|12|23.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|5|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[zeus](#zeus)|265|265|1|0.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Wed May 27 10:00:12 UTC 2015.

The ipset `bm_tor` has **6428** entries, **6428** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[dm_tor](#dm_tor)|6425|6425|6347|98.7%|98.7%|
[et_tor](#et_tor)|6400|6400|5758|89.9%|89.5%|
[snort_ipfilter](#snort_ipfilter)|7065|7065|1028|14.5%|15.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|607|0.0%|9.4%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|568|0.6%|8.8%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|427|1.4%|6.6%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7508|7508|271|3.6%|4.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|173|0.0%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|154|0.0%|2.3%|
[infiltrated](#infiltrated)|10520|10520|66|0.6%|1.0%|
[alienvault_reputation](#alienvault_reputation)|178186|178186|44|0.0%|0.6%|
[php_commenters](#php_commenters)|246|246|28|11.3%|0.4%|
[php_bad](#php_bad)|246|246|28|11.3%|0.4%|
[blocklist_de](#blocklist_de)|23619|23619|25|0.1%|0.3%|
[openbl_90d](#openbl_90d)|9909|9909|20|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7833|7833|20|0.2%|0.3%|
[openbl](#openbl)|9909|9909|20|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|20|0.0%|0.3%|
[php_harvesters](#php_harvesters)|235|235|7|2.9%|0.1%|
[php_spammers](#php_spammers)|378|378|5|1.3%|0.0%|
[nixspam](#nixspam)|23624|23624|5|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4012|4012|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|357|357|3|0.8%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|974|18056767|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1585|1585|2|0.1%|0.0%|
[voipbl](#voipbl)|10277|10748|1|0.0%|0.0%|
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
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|4194304|3.0%|0.7%|
[voipbl](#voipbl)|10277|10748|351|3.2%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|235|235|1|0.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2366|2366|1|0.0%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD)

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Wed May 27 09:00:09 UTC 2015.

The ipset `bruteforceblocker` has **2366** entries, **2366** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_compromised](#et_compromised)|2292|2292|2264|98.7%|95.6%|
[alienvault_reputation](#alienvault_reputation)|178186|178186|1459|0.8%|61.6%|
[openbl_90d](#openbl_90d)|9909|9909|1383|13.9%|58.4%|
[openbl](#openbl)|9909|9909|1383|13.9%|58.4%|
[openbl_60d](#openbl_60d)|7833|7833|1372|17.5%|57.9%|
[openbl_30d](#openbl_30d)|4441|4441|1315|29.6%|55.5%|
[blocklist_de](#blocklist_de)|23619|23619|1109|4.6%|46.8%|
[openbl_7d](#openbl_7d)|970|970|480|49.4%|20.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|227|0.0%|9.5%|
[openbl_1d](#openbl_1d)|357|357|206|57.7%|8.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|147|0.0%|6.2%|
[et_block](#et_block)|974|18056767|93|0.0%|3.9%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|92|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|74|0.0%|3.1%|
[dshield](#dshield)|20|5120|33|0.6%|1.3%|
[shunlist](#shunlist)|51|51|9|17.6%|0.3%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|5|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|2|0.0%|0.0%|
[infiltrated](#infiltrated)|10520|10520|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|228|228|1|0.4%|0.0%|
[zeus](#zeus)|265|265|1|0.3%|0.0%|
[voipbl](#voipbl)|10277|10748|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7065|7065|1|0.0%|0.0%|
[nixspam](#nixspam)|23624|23624|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3666|670786520|1|0.0%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Wed May 27 09:15:06 UTC 2015.

The ipset `ciarmy` has **392** entries, **392** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|178186|178186|374|0.2%|95.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|65|0.0%|16.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|46|0.0%|11.7%|
[blocklist_de](#blocklist_de)|23619|23619|44|0.1%|11.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|25|0.0%|6.3%|
[voipbl](#voipbl)|10277|10748|3|0.0%|0.7%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|1|0.0%|0.2%|
[openbl_90d](#openbl_90d)|9909|9909|1|0.0%|0.2%|
[openbl_7d](#openbl_7d)|970|970|1|0.1%|0.2%|
[openbl_60d](#openbl_60d)|7833|7833|1|0.0%|0.2%|
[openbl_30d](#openbl_30d)|4441|4441|1|0.0%|0.2%|
[openbl](#openbl)|9909|9909|1|0.0%|0.2%|
[nixspam](#nixspam)|23624|23624|1|0.0%|0.2%|
[et_block](#et_block)|974|18056767|1|0.0%|0.2%|
[dshield](#dshield)|20|5120|1|0.0%|0.2%|

## clean_mx_viruses

[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses

Source is downloaded from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive).

The last time downloaded was found to be dated: Wed May 27 03:40:35 UTC 2015.

The ipset `clean_mx_viruses` has **452** entries, **452** unique IPs.

The following table shows the overlaps of `clean_mx_viruses` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `clean_mx_viruses`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `clean_mx_viruses`.
- ` this % ` is the percentage **of this ipset (`clean_mx_viruses`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|51|0.0%|11.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|21|0.0%|4.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|16|0.0%|3.5%|
[malc0de](#malc0de)|418|418|13|3.1%|2.8%|
[alienvault_reputation](#alienvault_reputation)|178186|178186|13|0.0%|2.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|5|0.0%|1.1%|
[snort_ipfilter](#snort_ipfilter)|7065|7065|4|0.0%|0.8%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|3|0.2%|0.6%|
[et_block](#et_block)|974|18056767|3|0.0%|0.6%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|
[dshield](#dshield)|20|5120|1|0.0%|0.2%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Wed May 27 10:00:10 UTC 2015.

The ipset `dm_tor` has **6425** entries, **6425** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6428|6428|6347|98.7%|98.7%|
[et_tor](#et_tor)|6400|6400|5734|89.5%|89.2%|
[snort_ipfilter](#snort_ipfilter)|7065|7065|1025|14.5%|15.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|606|0.0%|9.4%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|567|0.6%|8.8%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|425|1.4%|6.6%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7508|7508|271|3.6%|4.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|174|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|153|0.0%|2.3%|
[infiltrated](#infiltrated)|10520|10520|66|0.6%|1.0%|
[alienvault_reputation](#alienvault_reputation)|178186|178186|44|0.0%|0.6%|
[php_commenters](#php_commenters)|246|246|28|11.3%|0.4%|
[php_bad](#php_bad)|246|246|28|11.3%|0.4%|
[blocklist_de](#blocklist_de)|23619|23619|25|0.1%|0.3%|
[openbl_90d](#openbl_90d)|9909|9909|20|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7833|7833|20|0.2%|0.3%|
[openbl](#openbl)|9909|9909|20|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|20|0.0%|0.3%|
[php_harvesters](#php_harvesters)|235|235|7|2.9%|0.1%|
[nixspam](#nixspam)|23624|23624|6|0.0%|0.0%|
[php_spammers](#php_spammers)|378|378|5|1.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4012|4012|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|357|357|3|0.8%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|974|18056767|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1585|1585|2|0.1%|0.0%|
[voipbl](#voipbl)|10277|10748|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Wed May 27 06:26:39 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|178186|178186|4355|2.4%|85.0%|
[et_block](#et_block)|974|18056767|3072|0.0%|60.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|512|0.0%|10.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|256|0.0%|5.0%|
[openbl_90d](#openbl_90d)|9909|9909|40|0.4%|0.7%|
[openbl](#openbl)|9909|9909|40|0.4%|0.7%|
[blocklist_de](#blocklist_de)|23619|23619|40|0.1%|0.7%|
[openbl_60d](#openbl_60d)|7833|7833|38|0.4%|0.7%|
[openbl_30d](#openbl_30d)|4441|4441|38|0.8%|0.7%|
[openbl_7d](#openbl_7d)|970|970|36|3.7%|0.7%|
[bruteforceblocker](#bruteforceblocker)|2366|2366|33|1.3%|0.6%|
[et_compromised](#et_compromised)|2292|2292|32|1.3%|0.6%|
[openbl_1d](#openbl_1d)|357|357|22|6.1%|0.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|19|0.0%|0.3%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|8|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|4|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[voipbl](#voipbl)|10277|10748|3|0.0%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|3|0.0%|0.0%|
[infiltrated](#infiltrated)|10520|10520|2|0.0%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7508|7508|1|0.0%|0.0%|
[malc0de](#malc0de)|418|418|1|0.2%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|452|452|1|0.2%|0.0%|
[ciarmy](#ciarmy)|392|392|1|0.2%|0.0%|

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
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|8401958|2.4%|46.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7211008|78.5%|39.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|2132995|0.2%|11.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|196439|0.1%|1.0%|
[fullbogons](#fullbogons)|3666|670786520|20480|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|178186|178186|5528|3.1%|0.0%|
[dshield](#dshield)|20|5120|3072|60.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|1285|0.3%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|771|0.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|517|0.1%|0.0%|
[openbl_90d](#openbl_90d)|9909|9909|452|4.5%|0.0%|
[openbl](#openbl)|9909|9909|452|4.5%|0.0%|
[openbl_60d](#openbl_60d)|7833|7833|308|3.9%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7065|7065|286|4.0%|0.0%|
[zeus](#zeus)|265|265|261|98.4%|0.0%|
[zeus_badips](#zeus_badips)|228|228|227|99.5%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|225|0.7%|0.0%|
[nixspam](#nixspam)|23624|23624|221|0.9%|0.0%|
[openbl_30d](#openbl_30d)|4441|4441|213|4.7%|0.0%|
[blocklist_de](#blocklist_de)|23619|23619|190|0.8%|0.0%|
[openbl_7d](#openbl_7d)|970|970|94|9.6%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2366|2366|93|3.9%|0.0%|
[et_compromised](#et_compromised)|2292|2292|91|3.9%|0.0%|
[infiltrated](#infiltrated)|10520|10520|67|0.6%|0.0%|
[feodo](#feodo)|62|62|59|95.1%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7508|7508|52|0.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|28|2.1%|0.0%|
[openbl_1d](#openbl_1d)|357|357|26|7.2%|0.0%|
[php_commenters](#php_commenters)|246|246|24|9.7%|0.0%|
[php_bad](#php_bad)|246|246|24|9.7%|0.0%|
[sslbl](#sslbl)|331|331|22|6.6%|0.0%|
[voipbl](#voipbl)|10277|10748|18|0.1%|0.0%|
[palevo](#palevo)|13|13|12|92.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6425|6425|3|0.0%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|452|452|3|0.6%|0.0%|
[bm_tor](#bm_tor)|6428|6428|3|0.0%|0.0%|
[php_spammers](#php_spammers)|378|378|2|0.5%|0.0%|
[php_dictionary](#php_dictionary)|357|357|2|0.5%|0.0%|
[malc0de](#malc0de)|418|418|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[php_harvesters](#php_harvesters)|235|235|1|0.4%|0.0%|
[et_botnet](#et_botnet)|505|505|1|0.1%|0.0%|
[ciarmy](#ciarmy)|392|392|1|0.2%|0.0%|

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
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|73|0.0%|14.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|42|0.0%|8.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|21|0.0%|4.1%|
[alienvault_reputation](#alienvault_reputation)|178186|178186|3|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[et_block](#et_block)|974|18056767|1|0.0%|0.1%|

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
[bruteforceblocker](#bruteforceblocker)|2366|2366|2264|95.6%|98.7%|
[alienvault_reputation](#alienvault_reputation)|178186|178186|1448|0.8%|63.1%|
[openbl_90d](#openbl_90d)|9909|9909|1370|13.8%|59.7%|
[openbl](#openbl)|9909|9909|1370|13.8%|59.7%|
[openbl_60d](#openbl_60d)|7833|7833|1360|17.3%|59.3%|
[openbl_30d](#openbl_30d)|4441|4441|1301|29.2%|56.7%|
[blocklist_de](#blocklist_de)|23619|23619|1028|4.3%|44.8%|
[openbl_7d](#openbl_7d)|970|970|473|48.7%|20.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|222|0.0%|9.6%|
[openbl_1d](#openbl_1d)|357|357|204|57.1%|8.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|144|0.0%|6.2%|
[et_block](#et_block)|974|18056767|91|0.0%|3.9%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|90|0.0%|3.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|69|0.0%|3.0%|
[dshield](#dshield)|20|5120|32|0.6%|1.3%|
[shunlist](#shunlist)|51|51|9|17.6%|0.3%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|5|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.1%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|2|0.0%|0.0%|
[infiltrated](#infiltrated)|10520|10520|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|228|228|1|0.4%|0.0%|
[zeus](#zeus)|265|265|1|0.3%|0.0%|
[voipbl](#voipbl)|10277|10748|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7065|7065|1|0.0%|0.0%|
[nixspam](#nixspam)|23624|23624|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

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
[bm_tor](#bm_tor)|6428|6428|5758|89.5%|89.9%|
[dm_tor](#dm_tor)|6425|6425|5734|89.2%|89.5%|
[snort_ipfilter](#snort_ipfilter)|7065|7065|1086|15.3%|16.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|609|0.0%|9.5%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|580|0.6%|9.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|440|1.4%|6.8%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7508|7508|278|3.7%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|176|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|153|0.0%|2.3%|
[infiltrated](#infiltrated)|10520|10520|68|0.6%|1.0%|
[alienvault_reputation](#alienvault_reputation)|178186|178186|44|0.0%|0.6%|
[php_commenters](#php_commenters)|246|246|28|11.3%|0.4%|
[php_bad](#php_bad)|246|246|28|11.3%|0.4%|
[blocklist_de](#blocklist_de)|23619|23619|28|0.1%|0.4%|
[openbl_90d](#openbl_90d)|9909|9909|20|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7833|7833|20|0.2%|0.3%|
[openbl](#openbl)|9909|9909|20|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|20|0.0%|0.3%|
[nixspam](#nixspam)|23624|23624|8|0.0%|0.1%|
[php_harvesters](#php_harvesters)|235|235|7|2.9%|0.1%|
[php_spammers](#php_spammers)|378|378|6|1.5%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4012|4012|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|357|357|3|0.8%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|974|18056767|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1585|1585|2|0.1%|0.0%|
[voipbl](#voipbl)|10277|10748|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Wed May 27 10:00:25 UTC 2015.

The ipset `feodo` has **62** entries, **62** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|974|18056767|59|0.0%|95.1%|
[snort_ipfilter](#snort_ipfilter)|7065|7065|47|0.6%|75.8%|
[sslbl](#sslbl)|331|331|20|6.0%|32.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|3|0.0%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|3|0.0%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|3|0.0%|4.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|1|0.0%|1.6%|
[alienvault_reputation](#alienvault_reputation)|178186|178186|1|0.0%|1.6%|

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
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|4233774|3.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|565248|6.1%|0.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|248322|0.0%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|235379|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|20480|0.1%|0.0%|
[et_block](#et_block)|974|18056767|20480|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|871|0.2%|0.0%|
[voipbl](#voipbl)|10277|10748|351|3.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|33|2.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|9|0.7%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|235|235|1|0.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2366|2366|1|0.0%|0.0%|

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
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|1172|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|366|0.0%|0.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|233|0.0%|0.4%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|14|0.0%|0.0%|
[fullbogons](#fullbogons)|3666|670786520|14|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178186|178186|13|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.0%|
[infiltrated](#infiltrated)|10520|10520|10|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|6|0.0%|0.0%|
[et_block](#et_block)|974|18056767|6|0.0%|0.0%|
[nixspam](#nixspam)|23624|23624|5|0.0%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|4|0.0%|0.0%|
[dshield](#dshield)|20|5120|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|23619|23619|3|0.0%|0.0%|
[voipbl](#voipbl)|10277|10748|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|235|235|2|0.8%|0.0%|
[php_dictionary](#php_dictionary)|357|357|2|0.5%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7508|7508|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7065|7065|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4012|4012|1|0.0%|0.0%|
[php_spammers](#php_spammers)|378|378|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

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
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|2526624|0.7%|27.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|904787|0.1%|9.8%|
[fullbogons](#fullbogons)|3666|670786520|565248|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|145472|0.1%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|1024|0.3%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|737|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178186|178186|519|0.2%|0.0%|
[nixspam](#nixspam)|23624|23624|223|0.9%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|209|0.6%|0.0%|
[blocklist_de](#blocklist_de)|23619|23619|64|0.2%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7508|7508|28|0.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|27|2.1%|0.0%|
[openbl_90d](#openbl_90d)|9909|9909|19|0.1%|0.0%|
[openbl](#openbl)|9909|9909|19|0.1%|0.0%|
[openbl_60d](#openbl_60d)|7833|7833|18|0.2%|0.0%|
[openbl_30d](#openbl_30d)|4441|4441|13|0.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7065|7065|11|0.1%|0.0%|
[zeus_badips](#zeus_badips)|228|228|10|4.3%|0.0%|
[zeus](#zeus)|265|265|10|3.7%|0.0%|
[openbl_7d](#openbl_7d)|970|970|9|0.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[infiltrated](#infiltrated)|10520|10520|6|0.0%|0.0%|
[openbl_1d](#openbl_1d)|357|357|5|1.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2366|2366|5|0.2%|0.0%|
[et_compromised](#et_compromised)|2292|2292|4|0.1%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6425|6425|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6428|6428|3|0.0%|0.0%|
[php_spammers](#php_spammers)|378|378|2|0.5%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[voipbl](#voipbl)|10277|10748|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|235|235|1|0.4%|0.0%|
[php_commenters](#php_commenters)|246|246|1|0.4%|0.0%|
[php_bad](#php_bad)|246|246|1|0.4%|0.0%|
[et_botnet](#et_botnet)|505|505|1|0.1%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|452|452|1|0.2%|0.0%|

## ib_bluetack_level1

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Level 1 (for use in p2p): Companies or organizations who are clearly involved with trying to stop filesharing (e.g. Baytsp, MediaDefender, Mediasentry a.o.). Companies which anti-p2p activity has been seen from. Companies that produce or have a strong financial interest in copyrighted material (e.g. music, movie, software industries a.o.). Government ranges or companies that have a strong financial interest in doing work for governments. Legal industry ranges. IPs or ranges of ISPs from which anti-p2p activity has been observed. Basically this list will block all kinds of internet connections that most people would rather not have during their internet travels.

Source is downloaded from [this link](http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Wed May 27 09:29:59 UTC 2015.

The ipset `ib_bluetack_level1` has **215693** entries, **765044590** unique IPs.

The following table shows the overlaps of `ib_bluetack_level1` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level1`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level1`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level1`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|16309487|4.6%|2.1%|
[et_block](#et_block)|974|18056767|2132995|11.8%|0.2%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2132981|11.7%|0.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|1357462|0.9%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904787|9.8%|0.1%|
[fullbogons](#fullbogons)|3666|670786520|235379|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|33152|7.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|12921|3.8%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178186|178186|5176|2.9%|0.0%|
[blocklist_de](#blocklist_de)|23619|23619|1473|6.2%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|1329|1.4%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|494|1.6%|0.0%|
[nixspam](#nixspam)|23624|23624|425|1.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|366|0.7%|0.0%|
[infiltrated](#infiltrated)|10520|10520|318|3.0%|0.0%|
[voipbl](#voipbl)|10277|10748|283|2.6%|0.0%|
[openbl_90d](#openbl_90d)|9909|9909|218|2.2%|0.0%|
[openbl](#openbl)|9909|9909|218|2.2%|0.0%|
[openbl_60d](#openbl_60d)|7833|7833|179|2.2%|0.0%|
[bm_tor](#bm_tor)|6428|6428|154|2.3%|0.0%|
[et_tor](#et_tor)|6400|6400|153|2.3%|0.0%|
[dm_tor](#dm_tor)|6425|6425|153|2.3%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7508|7508|110|1.4%|0.0%|
[openbl_30d](#openbl_30d)|4441|4441|101|2.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|90|6.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7065|7065|81|1.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2366|2366|74|3.1%|0.0%|
[et_compromised](#et_compromised)|2292|2292|69|3.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4012|4012|61|1.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|60|4.6%|0.0%|
[et_botnet](#et_botnet)|505|505|42|8.3%|0.0%|
[ciarmy](#ciarmy)|392|392|25|6.3%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1585|1585|23|1.4%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|452|452|21|4.6%|0.0%|
[openbl_7d](#openbl_7d)|970|970|19|1.9%|0.0%|
[dshield](#dshield)|20|5120|19|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|18|2.6%|0.0%|
[malc0de](#malc0de)|418|418|11|2.6%|0.0%|
[php_dictionary](#php_dictionary)|357|357|8|2.2%|0.0%|
[zeus](#zeus)|265|265|7|2.6%|0.0%|
[openbl_1d](#openbl_1d)|357|357|7|1.9%|0.0%|
[zeus_badips](#zeus_badips)|228|228|4|1.7%|0.0%|
[php_spammers](#php_spammers)|378|378|4|1.0%|0.0%|
[sslbl](#sslbl)|331|331|3|0.9%|0.0%|
[php_harvesters](#php_harvesters)|235|235|3|1.2%|0.0%|
[php_commenters](#php_commenters)|246|246|3|1.2%|0.0%|
[php_bad](#php_bad)|246|246|3|1.2%|0.0%|
[feodo](#feodo)|62|62|3|4.8%|0.0%|

## ib_bluetack_level2

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 2 (for use in p2p). General corporate ranges. Ranges used by labs or researchers. Proxies.

Source is downloaded from [this link](http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Wed May 27 03:41:02 UTC 2015.

The ipset `ib_bluetack_level2` has **75927** entries, **348729520** unique IPs.

The following table shows the overlaps of `ib_bluetack_level2` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level2`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level2`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level2`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|16309487|2.1%|4.6%|
[et_block](#et_block)|974|18056767|8401958|46.5%|2.4%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|8401433|46.3%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|2831962|2.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2526624|27.5%|0.7%|
[fullbogons](#fullbogons)|3666|670786520|248322|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|33368|7.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178186|178186|8409|4.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|7629|2.2%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|2450|2.6%|0.0%|
[blocklist_de](#blocklist_de)|23619|23619|1443|6.1%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|892|2.9%|0.0%|
[nixspam](#nixspam)|23624|23624|561|2.3%|0.0%|
[openbl_90d](#openbl_90d)|9909|9909|517|5.2%|0.0%|
[openbl](#openbl)|9909|9909|517|5.2%|0.0%|
[voipbl](#voipbl)|10277|10748|428|3.9%|0.0%|
[infiltrated](#infiltrated)|10520|10520|412|3.9%|0.0%|
[openbl_60d](#openbl_60d)|7833|7833|367|4.6%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7508|7508|258|3.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|233|0.4%|0.0%|
[openbl_30d](#openbl_30d)|4441|4441|229|5.1%|0.0%|
[et_tor](#et_tor)|6400|6400|176|2.7%|0.0%|
[dm_tor](#dm_tor)|6425|6425|174|2.7%|0.0%|
[bm_tor](#bm_tor)|6428|6428|173|2.6%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2366|2366|147|6.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4012|4012|145|3.6%|0.0%|
[et_compromised](#et_compromised)|2292|2292|144|6.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7065|7065|99|1.4%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1585|1585|73|4.6%|0.0%|
[ciarmy](#ciarmy)|392|392|46|11.7%|0.0%|
[openbl_7d](#openbl_7d)|970|970|45|4.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|43|2.9%|0.0%|
[php_spammers](#php_spammers)|378|378|29|7.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|28|4.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|26|2.0%|0.0%|
[malc0de](#malc0de)|418|418|26|6.2%|0.0%|
[et_botnet](#et_botnet)|505|505|21|4.1%|0.0%|
[openbl_1d](#openbl_1d)|357|357|17|4.7%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|452|452|16|3.5%|0.0%|
[zeus](#zeus)|265|265|9|3.3%|0.0%|
[php_dictionary](#php_dictionary)|357|357|9|2.5%|0.0%|
[zeus_badips](#zeus_badips)|228|228|8|3.5%|0.0%|
[php_commenters](#php_commenters)|246|246|8|3.2%|0.0%|
[php_bad](#php_bad)|246|246|8|3.2%|0.0%|
[php_harvesters](#php_harvesters)|235|235|7|2.9%|0.0%|
[sslbl](#sslbl)|331|331|5|1.5%|0.0%|
[shunlist](#shunlist)|51|51|3|5.8%|0.0%|
[feodo](#feodo)|62|62|3|4.8%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|

## ib_bluetack_level3

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 3 (for use in p2p). Many portal-type websites. ISP ranges that may be dodgy for some reason. Ranges that belong to an individual, but which have not been determined to be used by a particular company. Ranges for things that are unusual in some way. The L3 list is aka the paranoid list.

Source is downloaded from [this link](http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Wed May 27 03:40:30 UTC 2015.

The ipset `ib_bluetack_level3` has **18550** entries, **139108857** unique IPs.

The following table shows the overlaps of `ib_bluetack_level3` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level3`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level3`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level3`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[fullbogons](#fullbogons)|3666|670786520|4233774|0.6%|3.0%|
[bogons](#bogons)|13|592708608|4194304|0.7%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|2831962|0.8%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|1357462|0.1%|0.9%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|270785|64.3%|0.1%|
[et_block](#et_block)|974|18056767|196439|1.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|195904|1.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[alienvault_reputation](#alienvault_reputation)|178186|178186|14703|8.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|8958|2.6%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|6226|6.7%|0.0%|
[blocklist_de](#blocklist_de)|23619|23619|2852|12.0%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|2067|6.8%|0.0%|
[nixspam](#nixspam)|23624|23624|1698|7.1%|0.0%|
[voipbl](#voipbl)|10277|10748|1584|14.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1172|2.4%|0.0%|
[openbl_90d](#openbl_90d)|9909|9909|962|9.7%|0.0%|
[openbl](#openbl)|9909|9909|962|9.7%|0.0%|
[openbl_60d](#openbl_60d)|7833|7833|717|9.1%|0.0%|
[infiltrated](#infiltrated)|10520|10520|655|6.2%|0.0%|
[et_tor](#et_tor)|6400|6400|609|9.5%|0.0%|
[bm_tor](#bm_tor)|6428|6428|607|9.4%|0.0%|
[dm_tor](#dm_tor)|6425|6425|606|9.4%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7508|7508|558|7.4%|0.0%|
[dshield](#dshield)|20|5120|512|10.0%|0.0%|
[openbl_30d](#openbl_30d)|4441|4441|440|9.9%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2366|2366|227|9.5%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7065|7065|222|3.1%|0.0%|
[et_compromised](#et_compromised)|2292|2292|222|9.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|146|11.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4012|4012|131|3.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|110|7.5%|0.0%|
[openbl_7d](#openbl_7d)|970|970|87|8.9%|0.0%|
[malc0de](#malc0de)|418|418|77|18.4%|0.0%|
[et_botnet](#et_botnet)|505|505|73|14.4%|0.0%|
[ciarmy](#ciarmy)|392|392|65|16.5%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|51|7.5%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|452|452|51|11.2%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1585|1585|36|2.2%|0.0%|
[php_spammers](#php_spammers)|378|378|24|6.3%|0.0%|
[zeus](#zeus)|265|265|20|7.5%|0.0%|
[openbl_1d](#openbl_1d)|357|357|20|5.6%|0.0%|
[php_dictionary](#php_dictionary)|357|357|19|5.3%|0.0%|
[sslbl](#sslbl)|331|331|17|5.1%|0.0%|
[zeus_badips](#zeus_badips)|228|228|14|6.1%|0.0%|
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
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|51|0.0%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|28|0.0%|4.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|24|0.0%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|18|0.0%|2.6%|
[infiltrated](#infiltrated)|10520|10520|13|0.1%|1.9%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|12|0.0%|1.7%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|11|0.0%|1.6%|
[ri_web_proxies](#ri_web_proxies)|4012|4012|10|0.2%|1.4%|
[ri_connect_proxies](#ri_connect_proxies)|1585|1585|6|0.3%|0.8%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7508|7508|2|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.2%|
[nixspam](#nixspam)|23624|23624|2|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.2%|
[et_block](#et_block)|974|18056767|2|0.0%|0.2%|
[blocklist_de](#blocklist_de)|23619|23619|2|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|7065|7065|1|0.0%|0.1%|
[php_dictionary](#php_dictionary)|357|357|1|0.2%|0.1%|
[alienvault_reputation](#alienvault_reputation)|178186|178186|1|0.0%|0.1%|

## ib_bluetack_spyware

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) known malicious SPYWARE and ADWARE IP Address ranges

Source is downloaded from [this link](http://list.iblocklist.com/?list=llvtlsjyoyiczbkjsxpf&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Wed May 27 03:10:11 UTC 2015.

The ipset `ib_bluetack_spyware` has **898** entries, **336971** unique IPs.

The following table shows the overlaps of `ib_bluetack_spyware` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_spyware`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_spyware`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_spyware`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|12921|0.0%|3.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|8958|0.0%|2.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|7629|0.0%|2.2%|
[et_block](#et_block)|974|18056767|1285|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|1024|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1024|0.0%|0.3%|
[fullbogons](#fullbogons)|3666|670786520|871|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|178186|178186|280|0.1%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|43|0.0%|0.0%|
[infiltrated](#infiltrated)|10520|10520|26|0.2%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|20|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|20|0.3%|0.0%|
[dm_tor](#dm_tor)|6425|6425|20|0.3%|0.0%|
[bm_tor](#bm_tor)|6428|6428|20|0.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|14|1.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7065|7065|11|0.1%|0.0%|
[nixspam](#nixspam)|23624|23624|10|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7508|7508|6|0.0%|0.0%|
[openbl_90d](#openbl_90d)|9909|9909|5|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7833|7833|5|0.0%|0.0%|
[openbl](#openbl)|9909|9909|5|0.0%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|452|452|5|1.1%|0.0%|
[blocklist_de](#blocklist_de)|23619|23619|5|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4012|4012|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4441|4441|4|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[dshield](#dshield)|20|5120|4|0.0%|0.0%|
[voipbl](#voipbl)|10277|10748|3|0.0%|0.0%|
[malc0de](#malc0de)|418|418|3|0.7%|0.0%|
[sslbl](#sslbl)|331|331|1|0.3%|0.0%|
[php_harvesters](#php_harvesters)|235|235|1|0.4%|0.0%|
[php_dictionary](#php_dictionary)|357|357|1|0.2%|0.0%|
[openbl_7d](#openbl_7d)|970|970|1|0.1%|0.0%|
[feodo](#feodo)|62|62|1|1.6%|0.0%|

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
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|110|0.0%|7.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|90|0.0%|6.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|43|0.0%|2.9%|
[fullbogons](#fullbogons)|3666|670786520|33|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|7|0.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[et_block](#et_block)|974|18056767|7|0.0%|0.4%|
[alienvault_reputation](#alienvault_reputation)|178186|178186|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|3|0.2%|0.2%|
[infiltrated](#infiltrated)|10520|10520|3|0.0%|0.2%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|2|0.0%|0.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|2|0.0%|0.1%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7508|7508|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|7065|7065|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.1%|
[bruteforceblocker](#bruteforceblocker)|2366|2366|2|0.0%|0.1%|
[blocklist_de](#blocklist_de)|23619|23619|2|0.0%|0.1%|
[ri_web_proxies](#ri_web_proxies)|4012|4012|1|0.0%|0.0%|
[openbl_90d](#openbl_90d)|9909|9909|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|970|970|1|0.1%|0.0%|
[openbl_60d](#openbl_60d)|7833|7833|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4441|4441|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|357|357|1|0.2%|0.0%|
[openbl](#openbl)|9909|9909|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2292|2292|1|0.0%|0.0%|
[et_botnet](#et_botnet)|505|505|1|0.1%|0.0%|
[dm_tor](#dm_tor)|6425|6425|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6428|6428|1|0.0%|0.0%|

## infiltrated

[infiltrated.net](http://www.infiltrated.net) (this list seems to be updated frequently, but we found no information about it)

Source is downloaded from [this link](http://www.infiltrated.net/blacklisted).

The last time downloaded was found to be dated: Wed May 27 05:20:13 UTC 2015.

The ipset `infiltrated` has **10520** entries, **10520** unique IPs.

The following table shows the overlaps of `infiltrated` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `infiltrated`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `infiltrated`.
- ` this % ` is the percentage **of this ipset (`infiltrated`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|655|0.0%|6.2%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|606|0.6%|5.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|412|0.0%|3.9%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|320|1.0%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|318|0.0%|3.0%|
[blocklist_de](#blocklist_de)|23619|23619|241|1.0%|2.2%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7508|7508|195|2.5%|1.8%|
[nixspam](#nixspam)|23624|23624|148|0.6%|1.4%|
[alienvault_reputation](#alienvault_reputation)|178186|178186|146|0.0%|1.3%|
[snort_ipfilter](#snort_ipfilter)|7065|7065|128|1.8%|1.2%|
[php_dictionary](#php_dictionary)|357|357|106|29.6%|1.0%|
[php_spammers](#php_spammers)|378|378|104|27.5%|0.9%|
[php_harvesters](#php_harvesters)|235|235|84|35.7%|0.7%|
[et_tor](#et_tor)|6400|6400|68|1.0%|0.6%|
[et_block](#et_block)|974|18056767|67|0.0%|0.6%|
[dm_tor](#dm_tor)|6425|6425|66|1.0%|0.6%|
[bm_tor](#bm_tor)|6428|6428|66|1.0%|0.6%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|64|0.0%|0.6%|
[ri_web_proxies](#ri_web_proxies)|4012|4012|60|1.4%|0.5%|
[php_bad](#php_bad)|246|246|44|17.8%|0.4%|
[php_commenters](#php_commenters)|246|246|43|17.4%|0.4%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|37|0.0%|0.3%|
[openbl_90d](#openbl_90d)|9909|9909|29|0.2%|0.2%|
[openbl](#openbl)|9909|9909|29|0.2%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|26|0.0%|0.2%|
[openbl_60d](#openbl_60d)|7833|7833|25|0.3%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|13|1.9%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|10|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1585|1585|8|0.5%|0.0%|
[voipbl](#voipbl)|10277|10748|6|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4441|4441|4|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.0%|
[openbl_7d](#openbl_7d)|970|970|2|0.2%|0.0%|
[et_compromised](#et_compromised)|2292|2292|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2366|2366|2|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|

## malc0de

[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days

Source is downloaded from [this link](http://malc0de.com/bl/IP_Blacklist.txt).

The last time downloaded was found to be dated: Tue May 26 13:17:02 UTC 2015.

The ipset `malc0de` has **418** entries, **418** unique IPs.

The following table shows the overlaps of `malc0de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `malc0de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `malc0de`.
- ` this % ` is the percentage **of this ipset (`malc0de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|77|0.0%|18.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|26|0.0%|6.2%|
[clean_mx_viruses](#clean_mx_viruses)|452|452|13|2.8%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|11|0.0%|2.6%|
[alienvault_reputation](#alienvault_reputation)|178186|178186|11|0.0%|2.6%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|4|0.3%|0.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|3|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.4%|
[et_block](#et_block)|974|18056767|2|0.0%|0.4%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.2%|
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
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|146|0.0%|11.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|60|0.0%|4.6%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|28|0.0%|2.1%|
[et_block](#et_block)|974|18056767|28|0.0%|2.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|26|0.0%|2.0%|
[snort_ipfilter](#snort_ipfilter)|7065|7065|24|0.3%|1.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|14|0.0%|1.0%|
[fullbogons](#fullbogons)|3666|670786520|9|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|178186|178186|6|0.0%|0.4%|
[malc0de](#malc0de)|418|418|4|0.9%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.2%|
[clean_mx_viruses](#clean_mx_viruses)|452|452|3|0.6%|0.2%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|2|0.0%|0.1%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|1|0.0%|0.0%|
[nixspam](#nixspam)|23624|23624|1|0.0%|0.0%|
[infiltrated](#infiltrated)|10520|10520|1|0.0%|0.0%|
[et_botnet](#et_botnet)|505|505|1|0.1%|0.0%|
[blocklist_de](#blocklist_de)|23619|23619|1|0.0%|0.0%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Wed May 27 10:15:03 UTC 2015.

The ipset `nixspam` has **23624** entries, **23624** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|1698|0.0%|7.1%|
[blocklist_de](#blocklist_de)|23619|23619|837|3.5%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|561|0.0%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|425|0.0%|1.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|223|0.0%|0.9%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|221|0.0%|0.9%|
[et_block](#et_block)|974|18056767|221|0.0%|0.9%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|207|0.2%|0.8%|
[snort_ipfilter](#snort_ipfilter)|7065|7065|196|2.7%|0.8%|
[infiltrated](#infiltrated)|10520|10520|148|1.4%|0.6%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|132|0.4%|0.5%|
[php_dictionary](#php_dictionary)|357|357|88|24.6%|0.3%|
[php_spammers](#php_spammers)|378|378|77|20.3%|0.3%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7508|7508|64|0.8%|0.2%|
[ri_web_proxies](#ri_web_proxies)|4012|4012|63|1.5%|0.2%|
[alienvault_reputation](#alienvault_reputation)|178186|178186|26|0.0%|0.1%|
[php_bad](#php_bad)|246|246|14|5.6%|0.0%|
[php_commenters](#php_commenters)|246|246|13|5.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|10|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|8|0.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1585|1585|6|0.3%|0.0%|
[dm_tor](#dm_tor)|6425|6425|6|0.0%|0.0%|
[openbl_90d](#openbl_90d)|9909|9909|5|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7833|7833|5|0.0%|0.0%|
[openbl](#openbl)|9909|9909|5|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|5|0.0%|0.0%|
[bm_tor](#bm_tor)|6428|6428|5|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4441|4441|4|0.0%|0.0%|
[voipbl](#voipbl)|10277|10748|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|235|235|3|1.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2292|2292|1|0.0%|0.0%|
[ciarmy](#ciarmy)|392|392|1|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2366|2366|1|0.0%|0.0%|

## openbl

[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**

Source is downloaded from [this link](http://www.openbl.org/lists/base.txt.gz).

The last time downloaded was found to be dated: Wed May 27 06:57:00 UTC 2015.

The ipset `openbl` has **9909** entries, **9909** unique IPs.

The following table shows the overlaps of `openbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl`.
- ` this % ` is the percentage **of this ipset (`openbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9909|9909|9909|100.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|178186|178186|9882|5.5%|99.7%|
[openbl_60d](#openbl_60d)|7833|7833|7833|100.0%|79.0%|
[openbl_30d](#openbl_30d)|4441|4441|4441|100.0%|44.8%|
[bruteforceblocker](#bruteforceblocker)|2366|2366|1383|58.4%|13.9%|
[et_compromised](#et_compromised)|2292|2292|1370|59.7%|13.8%|
[blocklist_de](#blocklist_de)|23619|23619|1352|5.7%|13.6%|
[openbl_7d](#openbl_7d)|970|970|970|100.0%|9.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|962|0.0%|9.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|517|0.0%|5.2%|
[et_block](#et_block)|974|18056767|452|0.0%|4.5%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|447|0.0%|4.5%|
[openbl_1d](#openbl_1d)|357|357|357|100.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|218|0.0%|2.2%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|70|0.0%|0.7%|
[dshield](#dshield)|20|5120|40|0.7%|0.4%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|38|0.1%|0.3%|
[infiltrated](#infiltrated)|10520|10520|29|0.2%|0.2%|
[snort_ipfilter](#snort_ipfilter)|7065|7065|24|0.3%|0.2%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7508|7508|22|0.2%|0.2%|
[et_tor](#et_tor)|6400|6400|20|0.3%|0.2%|
[dm_tor](#dm_tor)|6425|6425|20|0.3%|0.2%|
[bm_tor](#bm_tor)|6428|6428|20|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|19|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|14|0.0%|0.1%|
[shunlist](#shunlist)|51|51|11|21.5%|0.1%|
[voipbl](#voipbl)|10277|10748|10|0.0%|0.1%|
[php_commenters](#php_commenters)|246|246|8|3.2%|0.0%|
[php_bad](#php_bad)|246|246|8|3.2%|0.0%|
[nixspam](#nixspam)|23624|23624|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|5|0.0%|0.0%|
[php_harvesters](#php_harvesters)|235|235|4|1.7%|0.0%|
[zeus_badips](#zeus_badips)|228|228|1|0.4%|0.0%|
[zeus](#zeus)|265|265|1|0.3%|0.0%|
[sslbl](#sslbl)|331|331|1|0.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4012|4012|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ciarmy](#ciarmy)|392|392|1|0.2%|0.0%|

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
[openbl_90d](#openbl_90d)|9909|9909|357|3.6%|100.0%|
[openbl_60d](#openbl_60d)|7833|7833|357|4.5%|100.0%|
[openbl_30d](#openbl_30d)|4441|4441|357|8.0%|100.0%|
[openbl](#openbl)|9909|9909|357|3.6%|100.0%|
[alienvault_reputation](#alienvault_reputation)|178186|178186|355|0.1%|99.4%|
[blocklist_de](#blocklist_de)|23619|23619|252|1.0%|70.5%|
[openbl_7d](#openbl_7d)|970|970|236|24.3%|66.1%|
[bruteforceblocker](#bruteforceblocker)|2366|2366|206|8.7%|57.7%|
[et_compromised](#et_compromised)|2292|2292|204|8.9%|57.1%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|26|0.0%|7.2%|
[et_block](#et_block)|974|18056767|26|0.0%|7.2%|
[dshield](#dshield)|20|5120|22|0.4%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|20|0.0%|5.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|17|0.0%|4.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|7|0.0%|1.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|1.4%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|1|0.0%|0.2%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.2%|
[shunlist](#shunlist)|51|51|1|1.9%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.2%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt.gz).

The last time downloaded was found to be dated: Wed May 27 06:57:00 UTC 2015.

The ipset `openbl_30d` has **4441** entries, **4441** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9909|9909|4441|44.8%|100.0%|
[openbl_60d](#openbl_60d)|7833|7833|4441|56.6%|100.0%|
[openbl](#openbl)|9909|9909|4441|44.8%|100.0%|
[alienvault_reputation](#alienvault_reputation)|178186|178186|4426|2.4%|99.6%|
[bruteforceblocker](#bruteforceblocker)|2366|2366|1315|55.5%|29.6%|
[et_compromised](#et_compromised)|2292|2292|1301|56.7%|29.2%|
[blocklist_de](#blocklist_de)|23619|23619|1181|5.0%|26.5%|
[openbl_7d](#openbl_7d)|970|970|970|100.0%|21.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|440|0.0%|9.9%|
[openbl_1d](#openbl_1d)|357|357|357|100.0%|8.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|229|0.0%|5.1%|
[et_block](#et_block)|974|18056767|213|0.0%|4.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|211|0.0%|4.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|101|0.0%|2.2%|
[dshield](#dshield)|20|5120|38|0.7%|0.8%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|21|0.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|13|0.0%|0.2%|
[shunlist](#shunlist)|51|51|10|19.6%|0.2%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|7|0.0%|0.1%|
[nixspam](#nixspam)|23624|23624|4|0.0%|0.0%|
[infiltrated](#infiltrated)|10520|10520|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|4|0.0%|0.0%|
[voipbl](#voipbl)|10277|10748|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|228|228|1|0.4%|0.0%|
[zeus](#zeus)|265|265|1|0.3%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7508|7508|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7065|7065|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ciarmy](#ciarmy)|392|392|1|0.2%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt.gz).

The last time downloaded was found to be dated: Wed May 27 06:57:00 UTC 2015.

The ipset `openbl_60d` has **7833** entries, **7833** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9909|9909|7833|79.0%|100.0%|
[openbl](#openbl)|9909|9909|7833|79.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|178186|178186|7810|4.3%|99.7%|
[openbl_30d](#openbl_30d)|4441|4441|4441|100.0%|56.6%|
[bruteforceblocker](#bruteforceblocker)|2366|2366|1372|57.9%|17.5%|
[et_compromised](#et_compromised)|2292|2292|1360|59.3%|17.3%|
[blocklist_de](#blocklist_de)|23619|23619|1302|5.5%|16.6%|
[openbl_7d](#openbl_7d)|970|970|970|100.0%|12.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|717|0.0%|9.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|367|0.0%|4.6%|
[openbl_1d](#openbl_1d)|357|357|357|100.0%|4.5%|
[et_block](#et_block)|974|18056767|308|0.0%|3.9%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|306|0.0%|3.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|179|0.0%|2.2%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|63|0.0%|0.8%|
[dshield](#dshield)|20|5120|38|0.7%|0.4%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|35|0.1%|0.4%|
[infiltrated](#infiltrated)|10520|10520|25|0.2%|0.3%|
[snort_ipfilter](#snort_ipfilter)|7065|7065|24|0.3%|0.3%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7508|7508|20|0.2%|0.2%|
[et_tor](#et_tor)|6400|6400|20|0.3%|0.2%|
[dm_tor](#dm_tor)|6425|6425|20|0.3%|0.2%|
[bm_tor](#bm_tor)|6428|6428|20|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|18|0.0%|0.2%|
[shunlist](#shunlist)|51|51|11|21.5%|0.1%|
[voipbl](#voipbl)|10277|10748|8|0.0%|0.1%|
[php_commenters](#php_commenters)|246|246|8|3.2%|0.1%|
[php_bad](#php_bad)|246|246|8|3.2%|0.1%|
[nixspam](#nixspam)|23624|23624|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|5|0.0%|0.0%|
[php_harvesters](#php_harvesters)|235|235|4|1.7%|0.0%|
[zeus_badips](#zeus_badips)|228|228|1|0.4%|0.0%|
[zeus](#zeus)|265|265|1|0.3%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ciarmy](#ciarmy)|392|392|1|0.2%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt.gz).

The last time downloaded was found to be dated: Wed May 27 06:57:00 UTC 2015.

The ipset `openbl_7d` has **970** entries, **970** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9909|9909|970|9.7%|100.0%|
[openbl_60d](#openbl_60d)|7833|7833|970|12.3%|100.0%|
[openbl_30d](#openbl_30d)|4441|4441|970|21.8%|100.0%|
[openbl](#openbl)|9909|9909|970|9.7%|100.0%|
[alienvault_reputation](#alienvault_reputation)|178186|178186|960|0.5%|98.9%|
[blocklist_de](#blocklist_de)|23619|23619|642|2.7%|66.1%|
[bruteforceblocker](#bruteforceblocker)|2366|2366|480|20.2%|49.4%|
[et_compromised](#et_compromised)|2292|2292|473|20.6%|48.7%|
[openbl_1d](#openbl_1d)|357|357|236|66.1%|24.3%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|94|0.0%|9.6%|
[et_block](#et_block)|974|18056767|94|0.0%|9.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|87|0.0%|8.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|45|0.0%|4.6%|
[dshield](#dshield)|20|5120|36|0.7%|3.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|19|0.0%|1.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|9|0.0%|0.9%|
[shunlist](#shunlist)|51|51|3|5.8%|0.3%|
[infiltrated](#infiltrated)|10520|10520|2|0.0%|0.2%|
[voipbl](#voipbl)|10277|10748|1|0.0%|0.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|1|0.0%|0.1%|
[ciarmy](#ciarmy)|392|392|1|0.2%|0.1%|

## openbl_90d

[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_90days.txt.gz).

The last time downloaded was found to be dated: Wed May 27 06:57:00 UTC 2015.

The ipset `openbl_90d` has **9909** entries, **9909** unique IPs.

The following table shows the overlaps of `openbl_90d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_90d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_90d`.
- ` this % ` is the percentage **of this ipset (`openbl_90d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl](#openbl)|9909|9909|9909|100.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|178186|178186|9882|5.5%|99.7%|
[openbl_60d](#openbl_60d)|7833|7833|7833|100.0%|79.0%|
[openbl_30d](#openbl_30d)|4441|4441|4441|100.0%|44.8%|
[bruteforceblocker](#bruteforceblocker)|2366|2366|1383|58.4%|13.9%|
[et_compromised](#et_compromised)|2292|2292|1370|59.7%|13.8%|
[blocklist_de](#blocklist_de)|23619|23619|1352|5.7%|13.6%|
[openbl_7d](#openbl_7d)|970|970|970|100.0%|9.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|962|0.0%|9.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|517|0.0%|5.2%|
[et_block](#et_block)|974|18056767|452|0.0%|4.5%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|447|0.0%|4.5%|
[openbl_1d](#openbl_1d)|357|357|357|100.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|218|0.0%|2.2%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|70|0.0%|0.7%|
[dshield](#dshield)|20|5120|40|0.7%|0.4%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|38|0.1%|0.3%|
[infiltrated](#infiltrated)|10520|10520|29|0.2%|0.2%|
[snort_ipfilter](#snort_ipfilter)|7065|7065|24|0.3%|0.2%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7508|7508|22|0.2%|0.2%|
[et_tor](#et_tor)|6400|6400|20|0.3%|0.2%|
[dm_tor](#dm_tor)|6425|6425|20|0.3%|0.2%|
[bm_tor](#bm_tor)|6428|6428|20|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|19|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|14|0.0%|0.1%|
[shunlist](#shunlist)|51|51|11|21.5%|0.1%|
[voipbl](#voipbl)|10277|10748|10|0.0%|0.1%|
[php_commenters](#php_commenters)|246|246|8|3.2%|0.0%|
[php_bad](#php_bad)|246|246|8|3.2%|0.0%|
[nixspam](#nixspam)|23624|23624|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|5|0.0%|0.0%|
[php_harvesters](#php_harvesters)|235|235|4|1.7%|0.0%|
[zeus_badips](#zeus_badips)|228|228|1|0.4%|0.0%|
[zeus](#zeus)|265|265|1|0.3%|0.0%|
[sslbl](#sslbl)|331|331|1|0.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4012|4012|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ciarmy](#ciarmy)|392|392|1|0.2%|0.0%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Wed May 27 10:00:23 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|974|18056767|12|0.0%|92.3%|
[snort_ipfilter](#snort_ipfilter)|7065|7065|11|0.1%|84.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|2|0.0%|15.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|1|0.0%|7.6%|

## php_bad

[projecthoneypot.org](http://www.projecthoneypot.org/) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1).

The last time downloaded was found to be dated: Wed May 27 09:20:40 UTC 2015.

The ipset `php_bad` has **246** entries, **246** unique IPs.

The following table shows the overlaps of `php_bad` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_bad`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_bad`.
- ` this % ` is the percentage **of this ipset (`php_bad`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[php_commenters](#php_commenters)|246|246|245|99.5%|99.5%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|180|0.1%|73.1%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|175|0.5%|71.1%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7508|7508|123|1.6%|50.0%|
[blocklist_de](#blocklist_de)|23619|23619|77|0.3%|31.3%|
[infiltrated](#infiltrated)|10520|10520|44|0.4%|17.8%|
[snort_ipfilter](#snort_ipfilter)|7065|7065|37|0.5%|15.0%|
[et_tor](#et_tor)|6400|6400|28|0.4%|11.3%|
[dm_tor](#dm_tor)|6425|6425|28|0.4%|11.3%|
[bm_tor](#bm_tor)|6428|6428|28|0.4%|11.3%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|25|0.0%|10.1%|
[php_spammers](#php_spammers)|378|378|25|6.6%|10.1%|
[et_block](#et_block)|974|18056767|24|0.0%|9.7%|
[php_dictionary](#php_dictionary)|357|357|14|3.9%|5.6%|
[nixspam](#nixspam)|23624|23624|14|0.0%|5.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|12|0.0%|4.8%|
[alienvault_reputation](#alienvault_reputation)|178186|178186|12|0.0%|4.8%|
[php_harvesters](#php_harvesters)|235|235|9|3.8%|3.6%|
[openbl_90d](#openbl_90d)|9909|9909|8|0.0%|3.2%|
[openbl_60d](#openbl_60d)|7833|7833|8|0.1%|3.2%|
[openbl](#openbl)|9909|9909|8|0.0%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|8|0.0%|3.2%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|7|0.0%|2.8%|
[ri_web_proxies](#ri_web_proxies)|4012|4012|7|0.1%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|3|0.0%|1.2%|
[zeus_badips](#zeus_badips)|228|228|1|0.4%|0.4%|
[zeus](#zeus)|265|265|1|0.3%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.4%|

## php_commenters

[projecthoneypot.org](http://www.projecthoneypot.org/) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1).

The last time downloaded was found to be dated: Wed May 27 09:20:42 UTC 2015.

The ipset `php_commenters` has **246** entries, **246** unique IPs.

The following table shows the overlaps of `php_commenters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_commenters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_commenters`.
- ` this % ` is the percentage **of this ipset (`php_commenters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[php_bad](#php_bad)|246|246|245|99.5%|99.5%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|181|0.1%|73.5%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|176|0.5%|71.5%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7508|7508|124|1.6%|50.4%|
[blocklist_de](#blocklist_de)|23619|23619|77|0.3%|31.3%|
[infiltrated](#infiltrated)|10520|10520|43|0.4%|17.4%|
[snort_ipfilter](#snort_ipfilter)|7065|7065|36|0.5%|14.6%|
[et_tor](#et_tor)|6400|6400|28|0.4%|11.3%|
[dm_tor](#dm_tor)|6425|6425|28|0.4%|11.3%|
[bm_tor](#bm_tor)|6428|6428|28|0.4%|11.3%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|25|0.0%|10.1%|
[php_spammers](#php_spammers)|378|378|24|6.3%|9.7%|
[et_block](#et_block)|974|18056767|24|0.0%|9.7%|
[php_dictionary](#php_dictionary)|357|357|13|3.6%|5.2%|
[nixspam](#nixspam)|23624|23624|13|0.0%|5.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|12|0.0%|4.8%|
[alienvault_reputation](#alienvault_reputation)|178186|178186|12|0.0%|4.8%|
[php_harvesters](#php_harvesters)|235|235|9|3.8%|3.6%|
[openbl_90d](#openbl_90d)|9909|9909|8|0.0%|3.2%|
[openbl_60d](#openbl_60d)|7833|7833|8|0.1%|3.2%|
[openbl](#openbl)|9909|9909|8|0.0%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|8|0.0%|3.2%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|7|0.0%|2.8%|
[ri_web_proxies](#ri_web_proxies)|4012|4012|7|0.1%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|3|0.0%|1.2%|
[zeus_badips](#zeus_badips)|228|228|1|0.4%|0.4%|
[zeus](#zeus)|265|265|1|0.3%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.4%|

## php_dictionary

[projecthoneypot.org](http://www.projecthoneypot.org/) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1).

The last time downloaded was found to be dated: Wed May 27 09:20:44 UTC 2015.

The ipset `php_dictionary` has **357** entries, **357** unique IPs.

The following table shows the overlaps of `php_dictionary` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_dictionary`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_dictionary`.
- ` this % ` is the percentage **of this ipset (`php_dictionary`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[infiltrated](#infiltrated)|10520|10520|106|1.0%|29.6%|
[nixspam](#nixspam)|23624|23624|88|0.3%|24.6%|
[blocklist_de](#blocklist_de)|23619|23619|80|0.3%|22.4%|
[snort_ipfilter](#snort_ipfilter)|7065|7065|74|1.0%|20.7%|
[php_spammers](#php_spammers)|378|378|71|18.7%|19.8%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|55|0.0%|15.4%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|43|0.1%|12.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7508|7508|29|0.3%|8.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|19|0.0%|5.3%|
[ri_web_proxies](#ri_web_proxies)|4012|4012|17|0.4%|4.7%|
[php_bad](#php_bad)|246|246|14|5.6%|3.9%|
[php_commenters](#php_commenters)|246|246|13|5.2%|3.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|9|0.0%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|8|0.0%|2.2%|
[alienvault_reputation](#alienvault_reputation)|178186|178186|6|0.0%|1.6%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.8%|
[dm_tor](#dm_tor)|6425|6425|3|0.0%|0.8%|
[bm_tor](#bm_tor)|6428|6428|3|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.5%|
[ri_connect_proxies](#ri_connect_proxies)|1585|1585|2|0.1%|0.5%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.5%|
[et_block](#et_block)|974|18056767|2|0.0%|0.5%|
[php_harvesters](#php_harvesters)|235|235|1|0.4%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|1|0.0%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.2%|

## php_harvesters

[projecthoneypot.org](http://www.projecthoneypot.org/) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1).

The last time downloaded was found to be dated: Wed May 27 09:20:23 UTC 2015.

The ipset `php_harvesters` has **235** entries, **235** unique IPs.

The following table shows the overlaps of `php_harvesters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_harvesters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_harvesters`.
- ` this % ` is the percentage **of this ipset (`php_harvesters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[infiltrated](#infiltrated)|10520|10520|84|0.7%|35.7%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|59|0.0%|25.1%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|48|0.1%|20.4%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7508|7508|34|0.4%|14.4%|
[blocklist_de](#blocklist_de)|23619|23619|26|0.1%|11.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|14|0.0%|5.9%|
[snort_ipfilter](#snort_ipfilter)|7065|7065|9|0.1%|3.8%|
[php_commenters](#php_commenters)|246|246|9|3.6%|3.8%|
[php_bad](#php_bad)|246|246|9|3.6%|3.8%|
[alienvault_reputation](#alienvault_reputation)|178186|178186|9|0.0%|3.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|7|0.0%|2.9%|
[et_tor](#et_tor)|6400|6400|7|0.1%|2.9%|
[dm_tor](#dm_tor)|6425|6425|7|0.1%|2.9%|
[bm_tor](#bm_tor)|6428|6428|7|0.1%|2.9%|
[openbl_90d](#openbl_90d)|9909|9909|4|0.0%|1.7%|
[openbl_60d](#openbl_60d)|7833|7833|4|0.0%|1.7%|
[openbl](#openbl)|9909|9909|4|0.0%|1.7%|
[nixspam](#nixspam)|23624|23624|3|0.0%|1.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|3|0.0%|1.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.8%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|1|0.0%|0.4%|
[ri_web_proxies](#ri_web_proxies)|4012|4012|1|0.0%|0.4%|
[php_spammers](#php_spammers)|378|378|1|0.2%|0.4%|
[php_dictionary](#php_dictionary)|357|357|1|0.2%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|1|0.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.4%|
[fullbogons](#fullbogons)|3666|670786520|1|0.0%|0.4%|
[et_block](#et_block)|974|18056767|1|0.0%|0.4%|
[bogons](#bogons)|13|592708608|1|0.0%|0.4%|

## php_spammers

[projecthoneypot.org](http://www.projecthoneypot.org/) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1).

The last time downloaded was found to be dated: Wed May 27 09:20:32 UTC 2015.

The ipset `php_spammers` has **378** entries, **378** unique IPs.

The following table shows the overlaps of `php_spammers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_spammers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_spammers`.
- ` this % ` is the percentage **of this ipset (`php_spammers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[infiltrated](#infiltrated)|10520|10520|104|0.9%|27.5%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|81|0.0%|21.4%|
[nixspam](#nixspam)|23624|23624|77|0.3%|20.3%|
[blocklist_de](#blocklist_de)|23619|23619|76|0.3%|20.1%|
[snort_ipfilter](#snort_ipfilter)|7065|7065|72|1.0%|19.0%|
[php_dictionary](#php_dictionary)|357|357|71|19.8%|18.7%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|57|0.1%|15.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7508|7508|38|0.5%|10.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|29|0.0%|7.6%|
[php_bad](#php_bad)|246|246|25|10.1%|6.6%|
[php_commenters](#php_commenters)|246|246|24|9.7%|6.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|24|0.0%|6.3%|
[ri_web_proxies](#ri_web_proxies)|4012|4012|16|0.3%|4.2%|
[et_tor](#et_tor)|6400|6400|6|0.0%|1.5%|
[dm_tor](#dm_tor)|6425|6425|5|0.0%|1.3%|
[bm_tor](#bm_tor)|6428|6428|5|0.0%|1.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|4|0.0%|1.0%|
[alienvault_reputation](#alienvault_reputation)|178186|178186|4|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.5%|
[ri_connect_proxies](#ri_connect_proxies)|1585|1585|2|0.1%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.5%|
[et_block](#et_block)|974|18056767|2|0.0%|0.5%|
[php_harvesters](#php_harvesters)|235|235|1|0.4%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.2%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Wed May 27 05:05:55 UTC 2015.

The ipset `ri_connect_proxies` has **1585** entries, **1585** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|926|0.9%|58.4%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|688|2.2%|43.4%|
[ri_web_proxies](#ri_web_proxies)|4012|4012|643|16.0%|40.5%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7508|7508|164|2.1%|10.3%|
[blocklist_de](#blocklist_de)|23619|23619|86|0.3%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|73|0.0%|4.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|36|0.0%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|23|0.0%|1.4%|
[infiltrated](#infiltrated)|10520|10520|8|0.0%|0.5%|
[nixspam](#nixspam)|23624|23624|6|0.0%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.3%|
[snort_ipfilter](#snort_ipfilter)|7065|7065|4|0.0%|0.2%|
[php_spammers](#php_spammers)|378|378|2|0.5%|0.1%|
[php_dictionary](#php_dictionary)|357|357|2|0.5%|0.1%|
[et_tor](#et_tor)|6400|6400|2|0.0%|0.1%|
[dm_tor](#dm_tor)|6425|6425|2|0.0%|0.1%|
[bm_tor](#bm_tor)|6428|6428|2|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|178186|178186|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Wed May 27 06:42:33 UTC 2015.

The ipset `ri_web_proxies` has **4012** entries, **4012** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|1955|2.1%|48.7%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|1546|5.1%|38.5%|
[ri_connect_proxies](#ri_connect_proxies)|1585|1585|643|40.5%|16.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7508|7508|492|6.5%|12.2%|
[blocklist_de](#blocklist_de)|23619|23619|361|1.5%|8.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|145|0.0%|3.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|131|0.0%|3.2%|
[nixspam](#nixspam)|23624|23624|63|0.2%|1.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|61|0.0%|1.5%|
[infiltrated](#infiltrated)|10520|10520|60|0.5%|1.4%|
[snort_ipfilter](#snort_ipfilter)|7065|7065|34|0.4%|0.8%|
[php_dictionary](#php_dictionary)|357|357|17|4.7%|0.4%|
[php_spammers](#php_spammers)|378|378|16|4.2%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|10|1.4%|0.2%|
[php_commenters](#php_commenters)|246|246|7|2.8%|0.1%|
[php_bad](#php_bad)|246|246|7|2.8%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|4|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6425|6425|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6428|6428|3|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178186|178186|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|235|235|1|0.4%|0.0%|
[openbl_90d](#openbl_90d)|9909|9909|1|0.0%|0.0%|
[openbl](#openbl)|9909|9909|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Wed May 27 06:30:03 UTC 2015.

The ipset `shunlist` has **51** entries, **51** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|178186|178186|51|0.0%|100.0%|
[blocklist_de](#blocklist_de)|23619|23619|12|0.0%|23.5%|
[openbl_90d](#openbl_90d)|9909|9909|11|0.1%|21.5%|
[openbl_60d](#openbl_60d)|7833|7833|11|0.1%|21.5%|
[openbl](#openbl)|9909|9909|11|0.1%|21.5%|
[openbl_30d](#openbl_30d)|4441|4441|10|0.2%|19.6%|
[et_compromised](#et_compromised)|2292|2292|9|0.3%|17.6%|
[bruteforceblocker](#bruteforceblocker)|2366|2366|9|0.3%|17.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|6|0.0%|11.7%|
[voipbl](#voipbl)|10277|10748|3|0.0%|5.8%|
[openbl_7d](#openbl_7d)|970|970|3|0.3%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|3|0.0%|5.8%|
[openbl_1d](#openbl_1d)|357|357|1|0.2%|1.9%|

## snort_ipfilter

[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)

Source is downloaded from [this link](http://labs.snort.org/feeds/ip-filter.blf).

The last time downloaded was found to be dated: Wed May 27 00:30:00 UTC 2015.

The ipset `snort_ipfilter` has **7065** entries, **7065** unique IPs.

The following table shows the overlaps of `snort_ipfilter` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `snort_ipfilter`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `snort_ipfilter`.
- ` this % ` is the percentage **of this ipset (`snort_ipfilter`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_tor](#et_tor)|6400|6400|1086|16.9%|15.3%|
[bm_tor](#bm_tor)|6428|6428|1028|15.9%|14.5%|
[dm_tor](#dm_tor)|6425|6425|1025|15.9%|14.5%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|703|0.7%|9.9%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|529|1.7%|7.4%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7508|7508|319|4.2%|4.5%|
[et_block](#et_block)|974|18056767|286|0.0%|4.0%|
[zeus](#zeus)|265|265|225|84.9%|3.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|222|0.0%|3.1%|
[zeus_badips](#zeus_badips)|228|228|200|87.7%|2.8%|
[blocklist_de](#blocklist_de)|23619|23619|198|0.8%|2.8%|
[nixspam](#nixspam)|23624|23624|196|0.8%|2.7%|
[infiltrated](#infiltrated)|10520|10520|128|1.2%|1.8%|
[alienvault_reputation](#alienvault_reputation)|178186|178186|120|0.0%|1.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|99|0.0%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|81|0.0%|1.1%|
[php_dictionary](#php_dictionary)|357|357|74|20.7%|1.0%|
[php_spammers](#php_spammers)|378|378|72|19.0%|1.0%|
[feodo](#feodo)|62|62|47|75.8%|0.6%|
[php_bad](#php_bad)|246|246|37|15.0%|0.5%|
[php_commenters](#php_commenters)|246|246|36|14.6%|0.5%|
[ri_web_proxies](#ri_web_proxies)|4012|4012|34|0.8%|0.4%|
[openbl_90d](#openbl_90d)|9909|9909|24|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7833|7833|24|0.3%|0.3%|
[openbl](#openbl)|9909|9909|24|0.2%|0.3%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|24|1.8%|0.3%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|20|0.0%|0.2%|
[sslbl](#sslbl)|331|331|17|5.1%|0.2%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|11|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.1%|
[php_harvesters](#php_harvesters)|235|235|9|3.8%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|6|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1585|1585|4|0.2%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|452|452|4|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[voipbl](#voipbl)|10277|10748|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4441|4441|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2292|2292|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2366|2366|1|0.0%|0.0%|

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
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|8401433|2.4%|46.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7211008|78.5%|39.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|2132981|0.2%|11.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|195904|0.1%|1.0%|
[fullbogons](#fullbogons)|3666|670786520|20480|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|178186|178186|1624|0.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|1024|0.3%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|788|0.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|512|0.1%|0.0%|
[openbl_90d](#openbl_90d)|9909|9909|447|4.5%|0.0%|
[openbl](#openbl)|9909|9909|447|4.5%|0.0%|
[openbl_60d](#openbl_60d)|7833|7833|306|3.9%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|246|0.8%|0.0%|
[nixspam](#nixspam)|23624|23624|221|0.9%|0.0%|
[openbl_30d](#openbl_30d)|4441|4441|211|4.7%|0.0%|
[blocklist_de](#blocklist_de)|23619|23619|188|0.7%|0.0%|
[openbl_7d](#openbl_7d)|970|970|94|9.6%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2366|2366|92|3.8%|0.0%|
[et_compromised](#et_compromised)|2292|2292|90|3.9%|0.0%|
[infiltrated](#infiltrated)|10520|10520|64|0.6%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7508|7508|53|0.7%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|28|2.1%|0.0%|
[openbl_1d](#openbl_1d)|357|357|26|7.2%|0.0%|
[php_commenters](#php_commenters)|246|246|25|10.1%|0.0%|
[php_bad](#php_bad)|246|246|25|10.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7065|7065|20|0.2%|0.0%|
[zeus_badips](#zeus_badips)|228|228|16|7.0%|0.0%|
[zeus](#zeus)|265|265|16|6.0%|0.0%|
[voipbl](#voipbl)|10277|10748|14|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[sslbl](#sslbl)|331|331|2|0.6%|0.0%|
[php_spammers](#php_spammers)|378|378|2|0.5%|0.0%|
[php_dictionary](#php_dictionary)|357|357|2|0.5%|0.0%|
[malc0de](#malc0de)|418|418|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6400|6400|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6425|6425|2|0.0%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|452|452|2|0.4%|0.0%|
[bm_tor](#bm_tor)|6428|6428|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|235|235|1|0.4%|0.0%|
[et_botnet](#et_botnet)|505|505|1|0.1%|0.0%|

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
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|270785|0.1%|64.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|33368|0.0%|7.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|33152|0.0%|7.8%|
[et_block](#et_block)|974|18056767|517|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|512|0.0%|0.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|109|0.1%|0.0%|
[blocklist_de](#blocklist_de)|23619|23619|42|0.1%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|41|0.1%|0.0%|
[infiltrated](#infiltrated)|10520|10520|37|0.3%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178186|178186|15|0.0%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7508|7508|14|0.1%|0.0%|
[openbl_90d](#openbl_90d)|9909|9909|14|0.1%|0.0%|
[openbl](#openbl)|9909|9909|14|0.1%|0.0%|
[php_commenters](#php_commenters)|246|246|7|2.8%|0.0%|
[php_bad](#php_bad)|246|246|7|2.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7065|7065|6|0.0%|0.0%|
[zeus_badips](#zeus_badips)|228|228|5|2.1%|0.0%|
[zeus](#zeus)|265|265|5|1.8%|0.0%|
[php_harvesters](#php_harvesters)|235|235|1|0.4%|0.0%|
[openbl_60d](#openbl_60d)|7833|7833|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4441|4441|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|357|357|1|0.2%|0.0%|
[malc0de](#malc0de)|418|418|1|0.2%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Wed May 27 10:00:06 UTC 2015.

The ipset `sslbl` has **331** entries, **331** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|974|18056767|22|0.0%|6.6%|
[feodo](#feodo)|62|62|20|32.2%|6.0%|
[snort_ipfilter](#snort_ipfilter)|7065|7065|17|0.2%|5.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|17|0.0%|5.1%|
[alienvault_reputation](#alienvault_reputation)|178186|178186|7|0.0%|2.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|5|0.0%|1.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|3|0.0%|0.9%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.6%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|1|0.0%|0.3%|
[openbl_90d](#openbl_90d)|9909|9909|1|0.0%|0.3%|
[openbl](#openbl)|9909|9909|1|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|1|0.0%|0.3%|

## stop_forum_spam_1h

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Wed May 27 10:00:26 UTC 2015.

The ipset `stop_forum_spam_1h` has **7508** entries, **7508** unique IPs.

The following table shows the overlaps of `stop_forum_spam_1h` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stop_forum_spam_1h`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stop_forum_spam_1h`.
- ` this % ` is the percentage **of this ipset (`stop_forum_spam_1h`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|6637|21.9%|88.3%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|4930|5.3%|65.6%|
[blocklist_de](#blocklist_de)|23619|23619|1397|5.9%|18.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|558|0.0%|7.4%|
[ri_web_proxies](#ri_web_proxies)|4012|4012|492|12.2%|6.5%|
[snort_ipfilter](#snort_ipfilter)|7065|7065|319|4.5%|4.2%|
[et_tor](#et_tor)|6400|6400|278|4.3%|3.7%|
[dm_tor](#dm_tor)|6425|6425|271|4.2%|3.6%|
[bm_tor](#bm_tor)|6428|6428|271|4.2%|3.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|258|0.0%|3.4%|
[infiltrated](#infiltrated)|10520|10520|195|1.8%|2.5%|
[ri_connect_proxies](#ri_connect_proxies)|1585|1585|164|10.3%|2.1%|
[php_commenters](#php_commenters)|246|246|124|50.4%|1.6%|
[php_bad](#php_bad)|246|246|123|50.0%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|110|0.0%|1.4%|
[nixspam](#nixspam)|23624|23624|64|0.2%|0.8%|
[alienvault_reputation](#alienvault_reputation)|178186|178186|56|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|53|0.0%|0.7%|
[et_block](#et_block)|974|18056767|52|0.0%|0.6%|
[php_spammers](#php_spammers)|378|378|38|10.0%|0.5%|
[php_harvesters](#php_harvesters)|235|235|34|14.4%|0.4%|
[php_dictionary](#php_dictionary)|357|357|29|8.1%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|28|0.0%|0.3%|
[openbl_90d](#openbl_90d)|9909|9909|22|0.2%|0.2%|
[openbl](#openbl)|9909|9909|22|0.2%|0.2%|
[openbl_60d](#openbl_60d)|7833|7833|20|0.2%|0.2%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|14|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|6|0.0%|0.0%|
[voipbl](#voipbl)|10277|10748|4|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[openbl_30d](#openbl_30d)|4441|4441|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|

## stop_forum_spam_30d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip).

The last time downloaded was found to be dated: Tue May 26 12:00:46 UTC 2015.

The ipset `stop_forum_spam_30d` has **92800** entries, **92800** unique IPs.

The following table shows the overlaps of `stop_forum_spam_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stop_forum_spam_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stop_forum_spam_30d`.
- ` this % ` is the percentage **of this ipset (`stop_forum_spam_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|28354|93.9%|30.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|6226|0.0%|6.7%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7508|7508|4930|65.6%|5.3%|
[blocklist_de](#blocklist_de)|23619|23619|2583|10.9%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|2450|0.0%|2.6%|
[ri_web_proxies](#ri_web_proxies)|4012|4012|1955|48.7%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|1329|0.0%|1.4%|
[ri_connect_proxies](#ri_connect_proxies)|1585|1585|926|58.4%|0.9%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|788|0.0%|0.8%|
[et_block](#et_block)|974|18056767|771|0.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|737|0.0%|0.7%|
[snort_ipfilter](#snort_ipfilter)|7065|7065|703|9.9%|0.7%|
[infiltrated](#infiltrated)|10520|10520|606|5.7%|0.6%|
[et_tor](#et_tor)|6400|6400|580|9.0%|0.6%|
[bm_tor](#bm_tor)|6428|6428|568|8.8%|0.6%|
[dm_tor](#dm_tor)|6425|6425|567|8.8%|0.6%|
[alienvault_reputation](#alienvault_reputation)|178186|178186|239|0.1%|0.2%|
[nixspam](#nixspam)|23624|23624|207|0.8%|0.2%|
[php_commenters](#php_commenters)|246|246|181|73.5%|0.1%|
[php_bad](#php_bad)|246|246|180|73.1%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|109|0.0%|0.1%|
[php_spammers](#php_spammers)|378|378|81|21.4%|0.0%|
[openbl_90d](#openbl_90d)|9909|9909|70|0.7%|0.0%|
[openbl](#openbl)|9909|9909|70|0.7%|0.0%|
[openbl_60d](#openbl_60d)|7833|7833|63|0.8%|0.0%|
[php_harvesters](#php_harvesters)|235|235|59|25.1%|0.0%|
[php_dictionary](#php_dictionary)|357|357|55|15.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|43|0.0%|0.0%|
[voipbl](#voipbl)|10277|10748|39|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|24|3.5%|0.0%|
[openbl_30d](#openbl_30d)|4441|4441|21|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[dshield](#dshield)|20|5120|8|0.1%|0.0%|
[et_compromised](#et_compromised)|2292|2292|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2366|2366|5|0.2%|0.0%|
[zeus](#zeus)|265|265|4|1.5%|0.0%|
[zeus_badips](#zeus_badips)|228|228|3|1.3%|0.0%|
[fullbogons](#fullbogons)|3666|670786520|3|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|2|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[sslbl](#sslbl)|331|331|1|0.3%|0.0%|
[openbl_7d](#openbl_7d)|970|970|1|0.1%|0.0%|
[openbl_1d](#openbl_1d)|357|357|1|0.2%|0.0%|
[ciarmy](#ciarmy)|392|392|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|

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
[stop_forum_spam_1h](#stop_forum_spam_1h)|7508|7508|6637|88.3%|21.9%|
[blocklist_de](#blocklist_de)|23619|23619|2359|9.9%|7.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|2067|0.0%|6.8%|
[ri_web_proxies](#ri_web_proxies)|4012|4012|1546|38.5%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|892|0.0%|2.9%|
[ri_connect_proxies](#ri_connect_proxies)|1585|1585|688|43.4%|2.2%|
[snort_ipfilter](#snort_ipfilter)|7065|7065|529|7.4%|1.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|494|0.0%|1.6%|
[et_tor](#et_tor)|6400|6400|440|6.8%|1.4%|
[bm_tor](#bm_tor)|6428|6428|427|6.6%|1.4%|
[dm_tor](#dm_tor)|6425|6425|425|6.6%|1.4%|
[infiltrated](#infiltrated)|10520|10520|320|3.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|246|0.0%|0.8%|
[et_block](#et_block)|974|18056767|225|0.0%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|209|0.0%|0.6%|
[php_commenters](#php_commenters)|246|246|176|71.5%|0.5%|
[php_bad](#php_bad)|246|246|175|71.1%|0.5%|
[nixspam](#nixspam)|23624|23624|132|0.5%|0.4%|
[alienvault_reputation](#alienvault_reputation)|178186|178186|116|0.0%|0.3%|
[php_spammers](#php_spammers)|378|378|57|15.0%|0.1%|
[php_harvesters](#php_harvesters)|235|235|48|20.4%|0.1%|
[php_dictionary](#php_dictionary)|357|357|43|12.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|41|0.0%|0.1%|
[openbl_90d](#openbl_90d)|9909|9909|38|0.3%|0.1%|
[openbl](#openbl)|9909|9909|38|0.3%|0.1%|
[openbl_60d](#openbl_60d)|7833|7833|35|0.4%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|20|0.0%|0.0%|
[voipbl](#voipbl)|10277|10748|12|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|12|1.7%|0.0%|
[openbl_30d](#openbl_30d)|4441|4441|7|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[dshield](#dshield)|20|5120|3|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[et_compromised](#et_compromised)|2292|2292|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2366|2366|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|228|228|1|0.4%|0.0%|
[zeus](#zeus)|265|265|1|0.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Wed May 27 08:20:26 UTC 2015.

The ipset `voipbl` has **10277** entries, **10748** unique IPs.

The following table shows the overlaps of `voipbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `voipbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `voipbl`.
- ` this % ` is the percentage **of this ipset (`voipbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|1584|0.0%|14.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|428|0.0%|3.9%|
[fullbogons](#fullbogons)|3666|670786520|351|0.0%|3.2%|
[bogons](#bogons)|13|592708608|351|0.0%|3.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|283|0.0%|2.6%|
[alienvault_reputation](#alienvault_reputation)|178186|178186|201|0.1%|1.8%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|39|0.0%|0.3%|
[blocklist_de](#blocklist_de)|23619|23619|38|0.1%|0.3%|
[et_block](#et_block)|974|18056767|18|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|14|0.0%|0.1%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|12|0.0%|0.1%|
[openbl_90d](#openbl_90d)|9909|9909|10|0.1%|0.0%|
[openbl](#openbl)|9909|9909|10|0.1%|0.0%|
[openbl_60d](#openbl_60d)|7833|7833|8|0.1%|0.0%|
[infiltrated](#infiltrated)|10520|10520|6|0.0%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7508|7508|4|0.0%|0.0%|
[shunlist](#shunlist)|51|51|3|5.8%|0.0%|
[nixspam](#nixspam)|23624|23624|3|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|3|0.0%|0.0%|
[dshield](#dshield)|20|5120|3|0.0%|0.0%|
[ciarmy](#ciarmy)|392|392|3|0.7%|0.0%|
[openbl_30d](#openbl_30d)|4441|4441|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7065|7065|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|970|970|1|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2292|2292|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6425|6425|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2366|2366|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6428|6428|1|0.0%|0.0%|

## zeus

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) default blocklist including hijacked sites and web hosting providers - **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist).

The last time downloaded was found to be dated: Wed May 27 10:09:01 UTC 2015.

The ipset `zeus` has **265** entries, **265** unique IPs.

The following table shows the overlaps of `zeus` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus`.
- ` this % ` is the percentage **of this ipset (`zeus`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|974|18056767|261|0.0%|98.4%|
[zeus_badips](#zeus_badips)|228|228|228|100.0%|86.0%|
[snort_ipfilter](#snort_ipfilter)|7065|7065|225|3.1%|84.9%|
[alienvault_reputation](#alienvault_reputation)|178186|178186|65|0.0%|24.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|20|0.0%|7.5%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|16|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|9|0.0%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|7|0.0%|2.6%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|5|0.0%|1.8%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|4|0.0%|1.5%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|1|0.0%|0.3%|
[php_commenters](#php_commenters)|246|246|1|0.4%|0.3%|
[php_bad](#php_bad)|246|246|1|0.4%|0.3%|
[openbl_90d](#openbl_90d)|9909|9909|1|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7833|7833|1|0.0%|0.3%|
[openbl_30d](#openbl_30d)|4441|4441|1|0.0%|0.3%|
[openbl](#openbl)|9909|9909|1|0.0%|0.3%|
[et_compromised](#et_compromised)|2292|2292|1|0.0%|0.3%|
[bruteforceblocker](#bruteforceblocker)|2366|2366|1|0.0%|0.3%|
[blocklist_de](#blocklist_de)|23619|23619|1|0.0%|0.3%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) includes IPv4 addresses that are used by the ZeuS trojan

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Wed May 27 10:00:20 UTC 2015.

The ipset `zeus_badips` has **228** entries, **228** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|265|265|228|86.0%|100.0%|
[et_block](#et_block)|974|18056767|227|0.0%|99.5%|
[snort_ipfilter](#snort_ipfilter)|7065|7065|200|2.8%|87.7%|
[alienvault_reputation](#alienvault_reputation)|178186|178186|36|0.0%|15.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|16|0.0%|7.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|14|0.0%|6.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|8|0.0%|3.5%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|5|0.0%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|4|0.0%|1.7%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|3|0.0%|1.3%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|1|0.0%|0.4%|
[php_commenters](#php_commenters)|246|246|1|0.4%|0.4%|
[php_bad](#php_bad)|246|246|1|0.4%|0.4%|
[openbl_90d](#openbl_90d)|9909|9909|1|0.0%|0.4%|
[openbl_60d](#openbl_60d)|7833|7833|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|4441|4441|1|0.0%|0.4%|
[openbl](#openbl)|9909|9909|1|0.0%|0.4%|
[et_compromised](#et_compromised)|2292|2292|1|0.0%|0.4%|
[bruteforceblocker](#bruteforceblocker)|2366|2366|1|0.0%|0.4%|
