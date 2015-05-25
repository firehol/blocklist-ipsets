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

The following list was automatically generated on Mon May 25 11:43:29 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|180998 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[autoshun](#autoshun)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|51 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|26020 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[botnet](#botnet)|[EmergingThreats.net](http://www.emergingthreats.net/) botnet IPs (at the time of writing includes any abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:ip|515 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD)|ipv4 hash:ip|2289 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|391 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[clean_mx_viruses](#clean_mx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|301 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[compromised](#compromised)|[EmergingThreats.net](http://www.emergingthreats.net/) distribution of IPs that have beed compromised (at the time of writing includes openbl, bruteforceblocker and sidreporter)|ipv4 hash:ip|2436 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
[danmetor](#danmetor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6499 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[emerging_block](#emerging_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|965 subnets, 18065466 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[feodo](#feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|59 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
[fullbogons](#fullbogons)|[Team-Cymru.org](http://www.team-cymru.org) IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user - **excellent list - use it only your internet interface**|ipv4 hash:net|3646 subnets, 670922200 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt)
geolite2_country|[MaxMind GeoLite2](http://dev.maxmind.com/geoip/geoip2/geolite2/) databases are free IP geolocation databases comparable to, but less accurate than, MaxMind’s GeoIP2 databases. They include IPs per country, IPs per continent, IPs used by anonymous services (VPNs, Proxies, etc) and Satellite Providers.|ipv4 hash:net|All the world|updated every 7 days  from [this link](http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country-CSV.zip)
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) IPs that have been reported for bad deeds in p2p|ipv4 hash:ip|48134 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=cwworuawihqvocglcoss&fileformat=p2p&archiveformat=gz)
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) hijacked IP-Blocks Hijacked IP space are IP blocks that are being used without permission|ipv4 hash:net|535 subnets, 9177856 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=usrcshglbiilevmyfhse&fileformat=p2p&archiveformat=gz)
[ib_bluetack_level1](#ib_bluetack_level1)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Level 1 (for use in p2p): Companies or organizations who are clearly involved with trying to stop filesharing (e.g. Baytsp, MediaDefender, Mediasentry a.o.). Companies which anti-p2p activity has been seen from. Companies that produce or have a strong financial interest in copyrighted material (e.g. music, movie, software industries a.o.). Government ranges or companies that have a strong financial interest in doing work for governments. Legal industry ranges. IPs or ranges of ISPs from which anti-p2p activity has been observed. Basically this list will block all kinds of internet connections that most people would rather not have during their internet travels.|ipv4 hash:net|215693 subnets, 765044590 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz)
[ib_bluetack_level2](#ib_bluetack_level2)|[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 2 (for use in p2p). General corporate ranges. Ranges used by labs or researchers. Proxies.|ipv4 hash:net|75927 subnets, 348729520 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw&fileformat=p2p&archiveformat=gz)
[ib_bluetack_level3](#ib_bluetack_level3)|[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 3 (for use in p2p). Many portal-type websites. ISP ranges that may be dodgy for some reason. Ranges that belong to an individual, but which have not been determined to be used by a particular company. Ranges for things that are unusual in some way. The L3 list is aka the paranoid list.|ipv4 hash:net|18550 subnets, 139108857 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh&fileformat=p2p&archiveformat=gz)
[ib_bluetack_proxies](#ib_bluetack_proxies)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Open Proxies IPs list (without TOR)|ipv4 hash:ip|673 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=xoebmbyexwuiogmbyprb&fileformat=p2p&archiveformat=gz)
[ib_bluetack_spyware](#ib_bluetack_spyware)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) known malicious SPYWARE and ADWARE IP Address ranges|ipv4 hash:net|898 subnets, 336971 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=llvtlsjyoyiczbkjsxpf&fileformat=p2p&archiveformat=gz)
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) web server hack and exploit attempts|ipv4 hash:ip|1460 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=ghlzqtqxnzctvvajwwag&fileformat=p2p&archiveformat=gz)
infiltrated|[infiltrated.net](http://www.infiltrated.net) (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|10520 unique IPs|updated every 12 hours  from [this link](http://www.infiltrated.net/blacklisted)
[malc0de](#malc0de)|[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days|ipv4 hash:ip|426 unique IPs|updated every 1 day  from [this link](http://malc0de.com/bl/IP_Blacklist.txt)
[malwaredomainlist](#malwaredomainlist)|[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses|ipv4 hash:ip|1283 unique IPs|updated every 12 hours  from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt)
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|20904 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
[openbl](#openbl)|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|9963 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt.gz)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|357 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_1days.txt.gz)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|4483 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt.gz)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7887 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt.gz)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|1405 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt.gz)
[openbl_90d](#openbl_90d)|[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|9963 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt.gz)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
[php_bad](#php_bad)|[projecthoneypot.org](http://www.projecthoneypot.org/) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|201 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|201 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|275 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|199 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|300 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[rosi_connect_proxies](#rosi_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1393 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[rosi_web_proxies](#rosi_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|3441 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|6448 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|641 subnets, 18117120 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|55 subnets, 421120 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|325 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
[stop_forum_spam_1h](#stop_forum_spam_1h)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|7164 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stop_forum_spam_30d](#stop_forum_spam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|92481 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
[stop_forum_spam_7d](#stop_forum_spam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|29531 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
[tor](#tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6340 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[tor_servers](#tor_servers)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6501 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) default blocklist including hijacked sites and web hosting providers - **excellent list**|ipv4 hash:ip|262 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) includes IPv4 addresses that are used by the ZeuS trojan|ipv4 hash:ip|230 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Mon May 25 11:01:26 UTC 2015.

The ipset `alienvault_reputation` has **180998** entries, **180998** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|15503|0.0%|8.5%|
[openbl_90d](#openbl_90d)|9963|9963|9940|99.7%|5.4%|
[openbl](#openbl)|9963|9963|9940|99.7%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|8668|0.0%|4.7%|
[openbl_60d](#openbl_60d)|7887|7887|7870|99.7%|4.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|5130|0.0%|2.8%|
[emerging_block](#emerging_block)|965|18065466|5017|0.0%|2.7%|
[openbl_30d](#openbl_30d)|4483|4483|4474|99.7%|2.4%|
[dshield](#dshield)|20|5120|4356|85.0%|2.4%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|1878|0.0%|1.0%|
[compromised](#compromised)|2436|2436|1592|65.3%|0.8%|
[blocklist_de](#blocklist_de)|26020|26020|1579|6.0%|0.8%|
[bruteforceblocker](#bruteforceblocker)|2289|2289|1442|62.9%|0.7%|
[openbl_7d](#openbl_7d)|1405|1405|1398|99.5%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|519|0.0%|0.2%|
[ciarmy](#ciarmy)|391|391|387|98.9%|0.2%|
[openbl_1d](#openbl_1d)|357|357|355|99.4%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|282|0.0%|0.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92481|92481|253|0.2%|0.1%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29531|29531|118|0.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6448|6448|117|1.8%|0.0%|
[zeus](#zeus)|262|262|64|24.4%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7164|7164|59|0.8%|0.0%|
[autoshun](#autoshun)|51|51|51|100.0%|0.0%|
[tor_servers](#tor_servers)|6501|6501|45|0.6%|0.0%|
[tor](#tor)|6340|6340|45|0.7%|0.0%|
[danmetor](#danmetor)|6499|6499|45|0.6%|0.0%|
[zeus_badips](#zeus_badips)|230|230|38|16.5%|0.0%|
[nixspam](#nixspam)|20904|20904|35|0.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|16|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|15|0.0%|0.0%|
[malc0de](#malc0de)|426|426|11|2.5%|0.0%|
[php_commenters](#php_commenters)|201|201|10|4.9%|0.0%|
[php_bad](#php_bad)|201|201|10|4.9%|0.0%|
[sslbl](#sslbl)|325|325|7|2.1%|0.0%|
[php_harvesters](#php_harvesters)|199|199|7|3.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|6|0.4%|0.0%|
[php_spammers](#php_spammers)|300|300|3|1.0%|0.0%|
[php_dictionary](#php_dictionary)|275|275|3|1.0%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|301|301|3|0.9%|0.0%|
[botnet](#botnet)|515|515|3|0.5%|0.0%|
[rosi_web_proxies](#rosi_web_proxies)|3441|3441|2|0.0%|0.0%|
[rosi_connect_proxies](#rosi_connect_proxies)|1393|1393|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[feodo](#feodo)|59|59|1|1.6%|0.0%|

## autoshun

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Mon May 25 10:30:04 UTC 2015.

The ipset `autoshun` has **51** entries, **51** unique IPs.

The following table shows the overlaps of `autoshun` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `autoshun`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `autoshun`.
- ` this % ` is the percentage **of this ipset (`autoshun`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|180998|180998|51|0.0%|100.0%|
[openbl_90d](#openbl_90d)|9963|9963|11|0.1%|21.5%|
[openbl_60d](#openbl_60d)|7887|7887|11|0.1%|21.5%|
[openbl](#openbl)|9963|9963|11|0.1%|21.5%|
[openbl_30d](#openbl_30d)|4483|4483|10|0.2%|19.6%|
[bruteforceblocker](#bruteforceblocker)|2289|2289|10|0.4%|19.6%|
[compromised](#compromised)|2436|2436|9|0.3%|17.6%|
[openbl_7d](#openbl_7d)|1405|1405|8|0.5%|15.6%|
[blocklist_de](#blocklist_de)|26020|26020|8|0.0%|15.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|6|0.0%|11.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|3|0.0%|5.8%|
[openbl_1d](#openbl_1d)|357|357|2|0.5%|3.9%|
[dshield](#dshield)|20|5120|1|0.0%|1.9%|
[ciarmy](#ciarmy)|391|391|1|0.2%|1.9%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Mon May 25 11:30:07 UTC 2015.

The ipset `blocklist_de` has **26020** entries, **26020** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|3213|0.0%|12.3%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92481|92481|2473|2.6%|9.5%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29531|29531|2187|7.4%|8.4%|
[alienvault_reputation](#alienvault_reputation)|180998|180998|1579|0.8%|6.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|1520|0.0%|5.8%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7164|7164|1488|20.7%|5.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|1407|0.0%|5.4%|
[openbl_90d](#openbl_90d)|9963|9963|1313|13.1%|5.0%|
[openbl](#openbl)|9963|9963|1313|13.1%|5.0%|
[openbl_60d](#openbl_60d)|7887|7887|1268|16.0%|4.8%|
[openbl_30d](#openbl_30d)|4483|4483|1102|24.5%|4.2%|
[bruteforceblocker](#bruteforceblocker)|2289|2289|898|39.2%|3.4%|
[compromised](#compromised)|2436|2436|818|33.5%|3.1%|
[openbl_7d](#openbl_7d)|1405|1405|790|56.2%|3.0%|
[nixspam](#nixspam)|20904|20904|682|3.2%|2.6%|
[rosi_web_proxies](#rosi_web_proxies)|3441|3441|376|10.9%|1.4%|
[openbl_1d](#openbl_1d)|357|357|248|69.4%|0.9%|
[snort_ipfilter](#snort_ipfilter)|6448|6448|225|3.4%|0.8%|
[emerging_block](#emerging_block)|965|18065466|184|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|183|0.0%|0.7%|
[rosi_connect_proxies](#rosi_connect_proxies)|1393|1393|83|5.9%|0.3%|
[php_dictionary](#php_dictionary)|275|275|80|29.0%|0.3%|
[php_spammers](#php_spammers)|300|300|76|25.3%|0.2%|
[php_commenters](#php_commenters)|201|201|72|35.8%|0.2%|
[php_bad](#php_bad)|201|201|72|35.8%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|58|0.0%|0.2%|
[ciarmy](#ciarmy)|391|391|45|11.5%|0.1%|
[dshield](#dshield)|20|5120|42|0.8%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|41|0.0%|0.1%|
[php_harvesters](#php_harvesters)|199|199|23|11.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|9|0.0%|0.0%|
[autoshun](#autoshun)|51|51|8|15.6%|0.0%|
[tor_servers](#tor_servers)|6501|6501|4|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[danmetor](#danmetor)|6499|6499|4|0.0%|0.0%|
[tor](#tor)|6340|6340|3|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|3|0.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|3|0.4%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|

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
[fullbogons](#fullbogons)|3646|670922200|592708608|88.3%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|4194304|3.0%|0.7%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92481|92481|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|199|199|1|0.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2289|2289|1|0.0%|0.0%|

## botnet

[EmergingThreats.net](http://www.emergingthreats.net/) botnet IPs (at the time of writing includes any abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)

Source is downloaded from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules).

The last time downloaded was found to be dated: Fri May 22 04:30:01 UTC 2015.

The ipset `botnet` has **515** entries, **515** unique IPs.

The following table shows the overlaps of `botnet` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `botnet`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `botnet`.
- ` this % ` is the percentage **of this ipset (`botnet`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|76|0.0%|14.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|42|0.0%|8.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|24|0.0%|4.6%|
[alienvault_reputation](#alienvault_reputation)|180998|180998|3|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[emerging_block](#emerging_block)|965|18065466|1|0.0%|0.1%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD)

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Mon May 25 08:40:36 UTC 2015.

The ipset `bruteforceblocker` has **2289** entries, **2289** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[compromised](#compromised)|2436|2436|2130|87.4%|93.0%|
[alienvault_reputation](#alienvault_reputation)|180998|180998|1442|0.7%|62.9%|
[openbl_90d](#openbl_90d)|9963|9963|1353|13.5%|59.1%|
[openbl](#openbl)|9963|9963|1353|13.5%|59.1%|
[openbl_60d](#openbl_60d)|7887|7887|1344|17.0%|58.7%|
[openbl_30d](#openbl_30d)|4483|4483|1287|28.7%|56.2%|
[blocklist_de](#blocklist_de)|26020|26020|898|3.4%|39.2%|
[openbl_7d](#openbl_7d)|1405|1405|711|50.6%|31.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|222|0.0%|9.6%|
[openbl_1d](#openbl_1d)|357|357|203|56.8%|8.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|144|0.0%|6.2%|
[emerging_block](#emerging_block)|965|18065466|91|0.0%|3.9%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|89|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|67|0.0%|2.9%|
[dshield](#dshield)|20|5120|31|0.6%|1.3%|
[autoshun](#autoshun)|51|51|10|19.6%|0.4%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92481|92481|4|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.1%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[zeus](#zeus)|262|262|1|0.3%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29531|29531|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6448|6448|1|0.0%|0.0%|
[nixspam](#nixspam)|20904|20904|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3646|670922200|1|0.0%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Mon May 25 09:15:06 UTC 2015.

The ipset `ciarmy` has **391** entries, **391** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|180998|180998|387|0.2%|98.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|70|0.0%|17.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|49|0.0%|12.5%|
[blocklist_de](#blocklist_de)|26020|26020|45|0.1%|11.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|26|0.0%|6.6%|
[emerging_block](#emerging_block)|965|18065466|3|0.0%|0.7%|
[dshield](#dshield)|20|5120|2|0.0%|0.5%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92481|92481|1|0.0%|0.2%|
[nixspam](#nixspam)|20904|20904|1|0.0%|0.2%|
[autoshun](#autoshun)|51|51|1|1.9%|0.2%|

## clean_mx_viruses

[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses

Source is downloaded from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive).

The last time downloaded was found to be dated: Mon May 25 02:21:35 UTC 2015.

The ipset `clean_mx_viruses` has **301** entries, **301** unique IPs.

The following table shows the overlaps of `clean_mx_viruses` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `clean_mx_viruses`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `clean_mx_viruses`.
- ` this % ` is the percentage **of this ipset (`clean_mx_viruses`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|31|0.0%|10.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|29|0.0%|9.6%|
[malc0de](#malc0de)|426|426|15|3.5%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|11|0.0%|3.6%|
[snort_ipfilter](#snort_ipfilter)|6448|6448|4|0.0%|1.3%|
[alienvault_reputation](#alienvault_reputation)|180998|180998|3|0.0%|0.9%|
[sslbl](#sslbl)|325|325|1|0.3%|0.3%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|1|0.0%|0.3%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|1|0.0%|0.3%|
[emerging_block](#emerging_block)|965|18065466|1|0.0%|0.3%|

## compromised

[EmergingThreats.net](http://www.emergingthreats.net/) distribution of IPs that have beed compromised (at the time of writing includes openbl, bruteforceblocker and sidreporter)

Source is downloaded from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt).

The last time downloaded was found to be dated: Fri May 22 04:30:09 UTC 2015.

The ipset `compromised` has **2436** entries, **2436** unique IPs.

The following table shows the overlaps of `compromised` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `compromised`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `compromised`.
- ` this % ` is the percentage **of this ipset (`compromised`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bruteforceblocker](#bruteforceblocker)|2289|2289|2130|93.0%|87.4%|
[alienvault_reputation](#alienvault_reputation)|180998|180998|1592|0.8%|65.3%|
[openbl_90d](#openbl_90d)|9963|9963|1474|14.7%|60.5%|
[openbl](#openbl)|9963|9963|1474|14.7%|60.5%|
[openbl_60d](#openbl_60d)|7887|7887|1464|18.5%|60.0%|
[openbl_30d](#openbl_30d)|4483|4483|1324|29.5%|54.3%|
[blocklist_de](#blocklist_de)|26020|26020|818|3.1%|33.5%|
[openbl_7d](#openbl_7d)|1405|1405|683|48.6%|28.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|243|0.0%|9.9%|
[openbl_1d](#openbl_1d)|357|357|198|55.4%|8.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|153|0.0%|6.2%|
[emerging_block](#emerging_block)|965|18065466|77|0.0%|3.1%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|76|0.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|75|0.0%|3.0%|
[dshield](#dshield)|20|5120|22|0.4%|0.9%|
[autoshun](#autoshun)|51|51|9|17.6%|0.3%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92481|92481|4|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.1%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29531|29531|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[zeus](#zeus)|262|262|1|0.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6448|6448|1|0.0%|0.0%|
[nixspam](#nixspam)|20904|20904|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|1|0.0%|0.0%|

## danmetor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Mon May 25 11:20:04 UTC 2015.

The ipset `danmetor` has **6499** entries, **6499** unique IPs.

The following table shows the overlaps of `danmetor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `danmetor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `danmetor`.
- ` this % ` is the percentage **of this ipset (`danmetor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[tor_servers](#tor_servers)|6501|6501|6499|99.9%|100.0%|
[tor](#tor)|6340|6340|5550|87.5%|85.3%|
[snort_ipfilter](#snort_ipfilter)|6448|6448|1046|16.2%|16.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|612|0.0%|9.4%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92481|92481|565|0.6%|8.6%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29531|29531|416|1.4%|6.4%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7164|7164|244|3.4%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|174|0.0%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|153|0.0%|2.3%|
[alienvault_reputation](#alienvault_reputation)|180998|180998|45|0.0%|0.6%|
[openbl_90d](#openbl_90d)|9963|9963|21|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7887|7887|21|0.2%|0.3%|
[openbl](#openbl)|9963|9963|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|20|0.0%|0.3%|
[php_commenters](#php_commenters)|201|201|19|9.4%|0.2%|
[php_bad](#php_bad)|201|201|19|9.4%|0.2%|
[php_harvesters](#php_harvesters)|199|199|7|3.5%|0.1%|
[rosi_web_proxies](#rosi_web_proxies)|3441|3441|4|0.1%|0.0%|
[php_spammers](#php_spammers)|300|300|4|1.3%|0.0%|
[emerging_block](#emerging_block)|965|18065466|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|26020|26020|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|275|275|3|1.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.0%|
[nixspam](#nixspam)|20904|20904|2|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.0%|
[rosi_connect_proxies](#rosi_connect_proxies)|1393|1393|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Mon May 25 10:26:34 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|180998|180998|4356|2.4%|85.0%|
[emerging_block](#emerging_block)|965|18065466|1792|0.0%|35.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|784|0.0%|15.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|512|0.0%|10.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|256|0.0%|5.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|132|0.0%|2.5%|
[blocklist_de](#blocklist_de)|26020|26020|42|0.1%|0.8%|
[openbl_90d](#openbl_90d)|9963|9963|37|0.3%|0.7%|
[openbl](#openbl)|9963|9963|37|0.3%|0.7%|
[openbl_60d](#openbl_60d)|7887|7887|36|0.4%|0.7%|
[openbl_7d](#openbl_7d)|1405|1405|35|2.4%|0.6%|
[openbl_30d](#openbl_30d)|4483|4483|35|0.7%|0.6%|
[bruteforceblocker](#bruteforceblocker)|2289|2289|31|1.3%|0.6%|
[compromised](#compromised)|2436|2436|22|0.9%|0.4%|
[openbl_1d](#openbl_1d)|357|357|21|5.8%|0.4%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92481|92481|11|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|4|0.0%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29531|29531|3|0.0%|0.0%|
[ciarmy](#ciarmy)|391|391|2|0.5%|0.0%|
[malc0de](#malc0de)|426|426|1|0.2%|0.0%|
[autoshun](#autoshun)|51|51|1|1.9%|0.0%|

## emerging_block

[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)

Source is downloaded from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt).

The last time downloaded was found to be dated: Fri May 22 04:30:01 UTC 2015.

The ipset `emerging_block` has **965** entries, **18065466** unique IPs.

The following table shows the overlaps of `emerging_block` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `emerging_block`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `emerging_block`.
- ` this % ` is the percentage **of this ipset (`emerging_block`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[spamhaus_drop](#spamhaus_drop)|641|18117120|17994240|99.3%|99.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|8401701|2.4%|46.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7277056|79.2%|40.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|2133264|0.2%|11.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|192343|0.1%|1.0%|
[fullbogons](#fullbogons)|3646|670922200|20480|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|180998|180998|5017|2.7%|0.0%|
[dshield](#dshield)|20|5120|1792|35.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|1029|0.3%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92481|92481|756|0.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|517|0.1%|0.0%|
[openbl_90d](#openbl_90d)|9963|9963|453|4.5%|0.0%|
[openbl](#openbl)|9963|9963|453|4.5%|0.0%|
[openbl_60d](#openbl_60d)|7887|7887|321|4.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6448|6448|282|4.3%|0.0%|
[zeus](#zeus)|262|262|258|98.4%|0.0%|
[nixspam](#nixspam)|20904|20904|236|1.1%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29531|29531|229|0.7%|0.0%|
[zeus_badips](#zeus_badips)|230|230|226|98.2%|0.0%|
[openbl_30d](#openbl_30d)|4483|4483|214|4.7%|0.0%|
[blocklist_de](#blocklist_de)|26020|26020|184|0.7%|0.0%|
[openbl_7d](#openbl_7d)|1405|1405|104|7.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2289|2289|91|3.9%|0.0%|
[compromised](#compromised)|2436|2436|77|3.1%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7164|7164|65|0.9%|0.0%|
[feodo](#feodo)|59|59|56|94.9%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|28|2.1%|0.0%|
[openbl_1d](#openbl_1d)|357|357|27|7.5%|0.0%|
[php_commenters](#php_commenters)|201|201|24|11.9%|0.0%|
[php_bad](#php_bad)|201|201|24|11.9%|0.0%|
[sslbl](#sslbl)|325|325|23|7.0%|0.0%|
[palevo](#palevo)|13|13|13|100.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|10|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[tor_servers](#tor_servers)|6501|6501|4|0.0%|0.0%|
[tor](#tor)|6340|6340|4|0.0%|0.0%|
[danmetor](#danmetor)|6499|6499|4|0.0%|0.0%|
[ciarmy](#ciarmy)|391|391|3|0.7%|0.0%|
[php_spammers](#php_spammers)|300|300|2|0.6%|0.0%|
[malc0de](#malc0de)|426|426|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[php_harvesters](#php_harvesters)|199|199|1|0.5%|0.0%|
[php_dictionary](#php_dictionary)|275|275|1|0.3%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|301|301|1|0.3%|0.0%|
[botnet](#botnet)|515|515|1|0.1%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Mon May 25 11:20:19 UTC 2015.

The ipset `feodo` has **59** entries, **59** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[emerging_block](#emerging_block)|965|18065466|56|0.0%|94.9%|
[snort_ipfilter](#snort_ipfilter)|6448|6448|46|0.7%|77.9%|
[sslbl](#sslbl)|325|325|21|6.4%|35.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|3|0.0%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|3|0.0%|5.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|3|0.0%|5.0%|
[openbl_90d](#openbl_90d)|9963|9963|1|0.0%|1.6%|
[openbl](#openbl)|9963|9963|1|0.0%|1.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|1|0.0%|1.6%|
[alienvault_reputation](#alienvault_reputation)|180998|180998|1|0.0%|1.6%|

## fullbogons

[Team-Cymru.org](http://www.team-cymru.org) IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user - **excellent list - use it only your internet interface**

Source is downloaded from [this link](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt).

The last time downloaded was found to be dated: Mon May 25 09:35:45 UTC 2015.

The ipset `fullbogons` has **3646** entries, **670922200** unique IPs.

The following table shows the overlaps of `fullbogons` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `fullbogons`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `fullbogons`.
- ` this % ` is the percentage **of this ipset (`fullbogons`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bogons](#bogons)|13|592708608|592708608|100.0%|88.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|4233774|3.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|565248|6.1%|0.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|247298|0.0%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|232563|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|20480|0.1%|0.0%|
[emerging_block](#emerging_block)|965|18065466|20480|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|871|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|33|2.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|9|0.7%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92481|92481|3|0.0%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29531|29531|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|199|199|1|0.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2289|2289|1|0.0%|0.0%|

## ib_bluetack_badpeers

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) IPs that have been reported for bad deeds in p2p

Source is downloaded from [this link](http://list.iblocklist.com/?list=cwworuawihqvocglcoss&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Mon May 25 02:51:00 UTC 2015.

The ipset `ib_bluetack_badpeers` has **48134** entries, **48134** unique IPs.

The following table shows the overlaps of `ib_bluetack_badpeers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_badpeers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_badpeers`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_badpeers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|1172|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|366|0.0%|0.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|233|0.0%|0.4%|
[alienvault_reputation](#alienvault_reputation)|180998|180998|15|0.0%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92481|92481|14|0.0%|0.0%|
[fullbogons](#fullbogons)|3646|670922200|14|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.0%|
[emerging_block](#emerging_block)|965|18065466|10|0.0%|0.0%|
[nixspam](#nixspam)|20904|20904|8|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|6|0.0%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29531|29531|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|26020|26020|4|0.0%|0.0%|
[php_harvesters](#php_harvesters)|199|199|2|1.0%|0.0%|
[php_dictionary](#php_dictionary)|275|275|2|0.7%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6448|6448|1|0.0%|0.0%|
[rosi_web_proxies](#rosi_web_proxies)|3441|3441|1|0.0%|0.0%|
[php_spammers](#php_spammers)|300|300|1|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## ib_bluetack_hijacked

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) hijacked IP-Blocks Hijacked IP space are IP blocks that are being used without permission

Source is downloaded from [this link](http://list.iblocklist.com/?list=usrcshglbiilevmyfhse&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Mon May 25 03:20:07 UTC 2015.

The ipset `ib_bluetack_hijacked` has **535** entries, **9177856** unique IPs.

The following table shows the overlaps of `ib_bluetack_hijacked` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_hijacked`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_hijacked`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_hijacked`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[emerging_block](#emerging_block)|965|18065466|7277056|40.2%|79.2%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|7211008|39.8%|78.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|2526624|0.7%|27.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|904787|0.1%|9.8%|
[fullbogons](#fullbogons)|3646|670922200|565248|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|145472|0.1%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|1024|0.3%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92481|92481|716|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|180998|180998|519|0.2%|0.0%|
[nixspam](#nixspam)|20904|20904|235|1.1%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29531|29531|210|0.7%|0.0%|
[blocklist_de](#blocklist_de)|26020|26020|58|0.2%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7164|7164|47|0.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|27|2.1%|0.0%|
[openbl_90d](#openbl_90d)|9963|9963|19|0.1%|0.0%|
[openbl](#openbl)|9963|9963|19|0.1%|0.0%|
[openbl_60d](#openbl_60d)|7887|7887|18|0.2%|0.0%|
[openbl_30d](#openbl_30d)|4483|4483|13|0.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6448|6448|11|0.1%|0.0%|
[openbl_7d](#openbl_7d)|1405|1405|11|0.7%|0.0%|
[zeus_badips](#zeus_badips)|230|230|10|4.3%|0.0%|
[zeus](#zeus)|262|262|10|3.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[openbl_1d](#openbl_1d)|357|357|5|1.4%|0.0%|
[compromised](#compromised)|2436|2436|4|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2289|2289|4|0.1%|0.0%|
[tor_servers](#tor_servers)|6501|6501|2|0.0%|0.0%|
[tor](#tor)|6340|6340|2|0.0%|0.0%|
[php_spammers](#php_spammers)|300|300|2|0.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[danmetor](#danmetor)|6499|6499|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|199|199|1|0.5%|0.0%|
[botnet](#botnet)|515|515|1|0.1%|0.0%|

## ib_bluetack_level1

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Level 1 (for use in p2p): Companies or organizations who are clearly involved with trying to stop filesharing (e.g. Baytsp, MediaDefender, Mediasentry a.o.). Companies which anti-p2p activity has been seen from. Companies that produce or have a strong financial interest in copyrighted material (e.g. music, movie, software industries a.o.). Government ranges or companies that have a strong financial interest in doing work for governments. Legal industry ranges. IPs or ranges of ISPs from which anti-p2p activity has been observed. Basically this list will block all kinds of internet connections that most people would rather not have during their internet travels.

Source is downloaded from [this link](http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Mon May 25 09:23:03 UTC 2015.

The ipset `ib_bluetack_level1` has **215693** entries, **765044590** unique IPs.

The following table shows the overlaps of `ib_bluetack_level1` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level1`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level1`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level1`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|16309487|4.6%|2.1%|
[emerging_block](#emerging_block)|965|18065466|2133264|11.8%|0.2%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2132981|11.7%|0.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|1357462|0.9%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904787|9.8%|0.1%|
[fullbogons](#fullbogons)|3646|670922200|232563|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|33152|7.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|12921|3.8%|0.0%|
[alienvault_reputation](#alienvault_reputation)|180998|180998|5130|2.8%|0.0%|
[blocklist_de](#blocklist_de)|26020|26020|1520|5.8%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92481|92481|1272|1.3%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29531|29531|473|1.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|366|0.7%|0.0%|
[nixspam](#nixspam)|20904|20904|350|1.6%|0.0%|
[openbl_90d](#openbl_90d)|9963|9963|218|2.1%|0.0%|
[openbl](#openbl)|9963|9963|218|2.1%|0.0%|
[openbl_60d](#openbl_60d)|7887|7887|177|2.2%|0.0%|
[tor_servers](#tor_servers)|6501|6501|153|2.3%|0.0%|
[danmetor](#danmetor)|6499|6499|153|2.3%|0.0%|
[tor](#tor)|6340|6340|148|2.3%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7164|7164|138|1.9%|0.0%|
[dshield](#dshield)|20|5120|132|2.5%|0.0%|
[openbl_30d](#openbl_30d)|4483|4483|97|2.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|90|6.1%|0.0%|
[compromised](#compromised)|2436|2436|75|3.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2289|2289|67|2.9%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|60|4.6%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6448|6448|59|0.9%|0.0%|
[rosi_web_proxies](#rosi_web_proxies)|3441|3441|58|1.6%|0.0%|
[botnet](#botnet)|515|515|42|8.1%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|301|301|31|10.2%|0.0%|
[openbl_7d](#openbl_7d)|1405|1405|27|1.9%|0.0%|
[ciarmy](#ciarmy)|391|391|26|6.6%|0.0%|
[rosi_connect_proxies](#rosi_connect_proxies)|1393|1393|22|1.5%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|18|2.6%|0.0%|
[malc0de](#malc0de)|426|426|11|2.5%|0.0%|
[zeus](#zeus)|262|262|7|2.6%|0.0%|
[php_dictionary](#php_dictionary)|275|275|7|2.5%|0.0%|
[openbl_1d](#openbl_1d)|357|357|7|1.9%|0.0%|
[zeus_badips](#zeus_badips)|230|230|5|2.1%|0.0%|
[sslbl](#sslbl)|325|325|3|0.9%|0.0%|
[php_harvesters](#php_harvesters)|199|199|3|1.5%|0.0%|
[php_commenters](#php_commenters)|201|201|3|1.4%|0.0%|
[php_bad](#php_bad)|201|201|3|1.4%|0.0%|
[feodo](#feodo)|59|59|3|5.0%|0.0%|
[php_spammers](#php_spammers)|300|300|2|0.6%|0.0%|

## ib_bluetack_level2

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 2 (for use in p2p). General corporate ranges. Ranges used by labs or researchers. Proxies.

Source is downloaded from [this link](http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Mon May 25 03:20:45 UTC 2015.

The ipset `ib_bluetack_level2` has **75927** entries, **348729520** unique IPs.

The following table shows the overlaps of `ib_bluetack_level2` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level2`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level2`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level2`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|16309487|2.1%|4.6%|
[emerging_block](#emerging_block)|965|18065466|8401701|46.5%|2.4%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|8401433|46.3%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|2831962|2.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2526624|27.5%|0.7%|
[fullbogons](#fullbogons)|3646|670922200|247298|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|33368|7.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|180998|180998|8668|4.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|7629|2.2%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92481|92481|2418|2.6%|0.0%|
[blocklist_de](#blocklist_de)|26020|26020|1407|5.4%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29531|29531|832|2.8%|0.0%|
[dshield](#dshield)|20|5120|784|15.3%|0.0%|
[nixspam](#nixspam)|20904|20904|629|3.0%|0.0%|
[openbl_90d](#openbl_90d)|9963|9963|529|5.3%|0.0%|
[openbl](#openbl)|9963|9963|529|5.3%|0.0%|
[openbl_60d](#openbl_60d)|7887|7887|378|4.7%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7164|7164|240|3.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|233|0.4%|0.0%|
[openbl_30d](#openbl_30d)|4483|4483|226|5.0%|0.0%|
[tor_servers](#tor_servers)|6501|6501|174|2.6%|0.0%|
[danmetor](#danmetor)|6499|6499|174|2.6%|0.0%|
[tor](#tor)|6340|6340|171|2.6%|0.0%|
[compromised](#compromised)|2436|2436|153|6.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2289|2289|144|6.2%|0.0%|
[rosi_web_proxies](#rosi_web_proxies)|3441|3441|129|3.7%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6448|6448|107|1.6%|0.0%|
[openbl_7d](#openbl_7d)|1405|1405|76|5.4%|0.0%|
[rosi_connect_proxies](#rosi_connect_proxies)|1393|1393|66|4.7%|0.0%|
[ciarmy](#ciarmy)|391|391|49|12.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|43|2.9%|0.0%|
[malc0de](#malc0de)|426|426|28|6.5%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|28|4.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|26|2.0%|0.0%|
[php_spammers](#php_spammers)|300|300|24|8.0%|0.0%|
[botnet](#botnet)|515|515|24|4.6%|0.0%|
[openbl_1d](#openbl_1d)|357|357|17|4.7%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|301|301|11|3.6%|0.0%|
[zeus_badips](#zeus_badips)|230|230|7|3.0%|0.0%|
[zeus](#zeus)|262|262|7|2.6%|0.0%|
[php_dictionary](#php_dictionary)|275|275|7|2.5%|0.0%|
[php_harvesters](#php_harvesters)|199|199|6|3.0%|0.0%|
[sslbl](#sslbl)|325|325|5|1.5%|0.0%|
[php_commenters](#php_commenters)|201|201|4|1.9%|0.0%|
[php_bad](#php_bad)|201|201|4|1.9%|0.0%|
[feodo](#feodo)|59|59|3|5.0%|0.0%|
[autoshun](#autoshun)|51|51|3|5.8%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|

## ib_bluetack_level3

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 3 (for use in p2p). Many portal-type websites. ISP ranges that may be dodgy for some reason. Ranges that belong to an individual, but which have not been determined to be used by a particular company. Ranges for things that are unusual in some way. The L3 list is aka the paranoid list.

Source is downloaded from [this link](http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Mon May 25 03:20:32 UTC 2015.

The ipset `ib_bluetack_level3` has **18550** entries, **139108857** unique IPs.

The following table shows the overlaps of `ib_bluetack_level3` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level3`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level3`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level3`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[fullbogons](#fullbogons)|3646|670922200|4233774|0.6%|3.0%|
[bogons](#bogons)|13|592708608|4194304|0.7%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|2831962|0.8%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|1357462|0.1%|0.9%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|270785|64.3%|0.1%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|195904|1.0%|0.1%|
[emerging_block](#emerging_block)|965|18065466|192343|1.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[alienvault_reputation](#alienvault_reputation)|180998|180998|15503|8.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|8958|2.6%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92481|92481|6272|6.7%|0.0%|
[blocklist_de](#blocklist_de)|26020|26020|3213|12.3%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29531|29531|1978|6.6%|0.0%|
[nixspam](#nixspam)|20904|20904|1495|7.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1172|2.4%|0.0%|
[openbl_90d](#openbl_90d)|9963|9963|969|9.7%|0.0%|
[openbl](#openbl)|9963|9963|969|9.7%|0.0%|
[openbl_60d](#openbl_60d)|7887|7887|718|9.1%|0.0%|
[tor_servers](#tor_servers)|6501|6501|612|9.4%|0.0%|
[danmetor](#danmetor)|6499|6499|612|9.4%|0.0%|
[tor](#tor)|6340|6340|602|9.4%|0.0%|
[dshield](#dshield)|20|5120|512|10.0%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7164|7164|493|6.8%|0.0%|
[openbl_30d](#openbl_30d)|4483|4483|441|9.8%|0.0%|
[compromised](#compromised)|2436|2436|243|9.9%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2289|2289|222|9.6%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6448|6448|202|3.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|146|11.3%|0.0%|
[openbl_7d](#openbl_7d)|1405|1405|119|8.4%|0.0%|
[rosi_web_proxies](#rosi_web_proxies)|3441|3441|117|3.4%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|110|7.5%|0.0%|
[malc0de](#malc0de)|426|426|80|18.7%|0.0%|
[botnet](#botnet)|515|515|76|14.7%|0.0%|
[ciarmy](#ciarmy)|391|391|70|17.9%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|51|7.5%|0.0%|
[rosi_connect_proxies](#rosi_connect_proxies)|1393|1393|29|2.0%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|301|301|29|9.6%|0.0%|
[openbl_1d](#openbl_1d)|357|357|20|5.6%|0.0%|
[zeus](#zeus)|262|262|19|7.2%|0.0%|
[php_spammers](#php_spammers)|300|300|19|6.3%|0.0%|
[sslbl](#sslbl)|325|325|16|4.9%|0.0%|
[zeus_badips](#zeus_badips)|230|230|15|6.5%|0.0%|
[php_harvesters](#php_harvesters)|199|199|13|6.5%|0.0%|
[php_dictionary](#php_dictionary)|275|275|13|4.7%|0.0%|
[php_commenters](#php_commenters)|201|201|9|4.4%|0.0%|
[php_bad](#php_bad)|201|201|9|4.4%|0.0%|
[autoshun](#autoshun)|51|51|6|11.7%|0.0%|
[feodo](#feodo)|59|59|3|5.0%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|

## ib_bluetack_proxies

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Open Proxies IPs list (without TOR)

Source is downloaded from [this link](http://list.iblocklist.com/?list=xoebmbyexwuiogmbyprb&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Mon May 25 03:20:15 UTC 2015.

The ipset `ib_bluetack_proxies` has **673** entries, **673** unique IPs.

The following table shows the overlaps of `ib_bluetack_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_proxies`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|51|0.0%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|28|0.0%|4.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92481|92481|24|0.0%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|18|0.0%|2.6%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29531|29531|14|0.0%|2.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|11|0.0%|1.6%|
[rosi_web_proxies](#rosi_web_proxies)|3441|3441|10|0.2%|1.4%|
[rosi_connect_proxies](#rosi_connect_proxies)|1393|1393|6|0.4%|0.8%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7164|7164|5|0.0%|0.7%|
[nixspam](#nixspam)|20904|20904|3|0.0%|0.4%|
[blocklist_de](#blocklist_de)|26020|26020|3|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.2%|
[emerging_block](#emerging_block)|965|18065466|2|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|6448|6448|1|0.0%|0.1%|
[php_dictionary](#php_dictionary)|275|275|1|0.3%|0.1%|
[alienvault_reputation](#alienvault_reputation)|180998|180998|1|0.0%|0.1%|

## ib_bluetack_spyware

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) known malicious SPYWARE and ADWARE IP Address ranges

Source is downloaded from [this link](http://list.iblocklist.com/?list=llvtlsjyoyiczbkjsxpf&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Mon May 25 02:50:15 UTC 2015.

The ipset `ib_bluetack_spyware` has **898** entries, **336971** unique IPs.

The following table shows the overlaps of `ib_bluetack_spyware` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_spyware`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_spyware`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_spyware`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|12921|0.0%|3.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|8958|0.0%|2.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|7629|0.0%|2.2%|
[emerging_block](#emerging_block)|965|18065466|1029|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|1024|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1024|0.0%|0.3%|
[fullbogons](#fullbogons)|3646|670922200|871|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|180998|180998|282|0.1%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92481|92481|41|0.0%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29531|29531|23|0.0%|0.0%|
[tor_servers](#tor_servers)|6501|6501|20|0.3%|0.0%|
[tor](#tor)|6340|6340|20|0.3%|0.0%|
[danmetor](#danmetor)|6499|6499|20|0.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|14|1.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6448|6448|12|0.1%|0.0%|
[nixspam](#nixspam)|20904|20904|12|0.0%|0.0%|
[blocklist_de](#blocklist_de)|26020|26020|9|0.0%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7164|7164|8|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[openbl_90d](#openbl_90d)|9963|9963|6|0.0%|0.0%|
[openbl](#openbl)|9963|9963|6|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7887|7887|5|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4483|4483|4|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[dshield](#dshield)|20|5120|4|0.0%|0.0%|
[rosi_web_proxies](#rosi_web_proxies)|3441|3441|3|0.0%|0.0%|
[malc0de](#malc0de)|426|426|3|0.7%|0.0%|
[openbl_7d](#openbl_7d)|1405|1405|2|0.1%|0.0%|
[sslbl](#sslbl)|325|325|1|0.3%|0.0%|
[php_harvesters](#php_harvesters)|199|199|1|0.5%|0.0%|
[php_dictionary](#php_dictionary)|275|275|1|0.3%|0.0%|
[feodo](#feodo)|59|59|1|1.6%|0.0%|
[compromised](#compromised)|2436|2436|1|0.0%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|301|301|1|0.3%|0.0%|

## ib_bluetack_webexploit

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) web server hack and exploit attempts

Source is downloaded from [this link](http://list.iblocklist.com/?list=ghlzqtqxnzctvvajwwag&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Mon May 25 02:50:03 UTC 2015.

The ipset `ib_bluetack_webexploit` has **1460** entries, **1460** unique IPs.

The following table shows the overlaps of `ib_bluetack_webexploit` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_webexploit`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_webexploit`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_webexploit`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|110|0.0%|7.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|90|0.0%|6.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|43|0.0%|2.9%|
[fullbogons](#fullbogons)|3646|670922200|33|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|7|0.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[alienvault_reputation](#alienvault_reputation)|180998|180998|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|6|0.0%|0.4%|
[emerging_block](#emerging_block)|965|18065466|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|3|0.2%|0.2%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29531|29531|2|0.0%|0.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92481|92481|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|6448|6448|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.1%|
[blocklist_de](#blocklist_de)|26020|26020|2|0.0%|0.1%|
[tor_servers](#tor_servers)|6501|6501|1|0.0%|0.0%|
[tor](#tor)|6340|6340|1|0.0%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7164|7164|1|0.0%|0.0%|
[rosi_web_proxies](#rosi_web_proxies)|3441|3441|1|0.0%|0.0%|
[openbl_90d](#openbl_90d)|9963|9963|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|1405|1405|1|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7887|7887|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4483|4483|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|357|357|1|0.2%|0.0%|
[openbl](#openbl)|9963|9963|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[danmetor](#danmetor)|6499|6499|1|0.0%|0.0%|
[compromised](#compromised)|2436|2436|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2289|2289|1|0.0%|0.0%|
[botnet](#botnet)|515|515|1|0.1%|0.0%|

## malc0de

[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days

Source is downloaded from [this link](http://malc0de.com/bl/IP_Blacklist.txt).

The last time downloaded was found to be dated: Sun May 24 13:17:04 UTC 2015.

The ipset `malc0de` has **426** entries, **426** unique IPs.

The following table shows the overlaps of `malc0de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `malc0de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `malc0de`.
- ` this % ` is the percentage **of this ipset (`malc0de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|80|0.0%|18.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|28|0.0%|6.5%|
[clean_mx_viruses](#clean_mx_viruses)|301|301|15|4.9%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|11|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|180998|180998|11|0.0%|2.5%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|4|0.3%|0.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|3|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.4%|
[emerging_block](#emerging_block)|965|18065466|2|0.0%|0.4%|
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
[emerging_block](#emerging_block)|965|18065466|28|0.0%|2.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|26|0.0%|2.0%|
[snort_ipfilter](#snort_ipfilter)|6448|6448|24|0.3%|1.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|14|0.0%|1.0%|
[fullbogons](#fullbogons)|3646|670922200|9|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|180998|180998|6|0.0%|0.4%|
[malc0de](#malc0de)|426|426|4|0.9%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.2%|
[blocklist_de](#blocklist_de)|26020|26020|3|0.0%|0.2%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92481|92481|2|0.0%|0.1%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7164|7164|1|0.0%|0.0%|
[nixspam](#nixspam)|20904|20904|1|0.0%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|301|301|1|0.3%|0.0%|
[botnet](#botnet)|515|515|1|0.1%|0.0%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Mon May 25 11:30:02 UTC 2015.

The ipset `nixspam` has **20904** entries, **20904** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|1495|0.0%|7.1%|
[blocklist_de](#blocklist_de)|26020|26020|682|2.6%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|629|0.0%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|350|0.0%|1.6%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92481|92481|246|0.2%|1.1%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|244|0.0%|1.1%|
[emerging_block](#emerging_block)|965|18065466|236|0.0%|1.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|235|0.0%|1.1%|
[snort_ipfilter](#snort_ipfilter)|6448|6448|214|3.3%|1.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29531|29531|148|0.5%|0.7%|
[rosi_web_proxies](#rosi_web_proxies)|3441|3441|79|2.2%|0.3%|
[php_dictionary](#php_dictionary)|275|275|78|28.3%|0.3%|
[php_spammers](#php_spammers)|300|300|73|24.3%|0.3%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7164|7164|67|0.9%|0.3%|
[alienvault_reputation](#alienvault_reputation)|180998|180998|35|0.0%|0.1%|
[rosi_connect_proxies](#rosi_connect_proxies)|1393|1393|18|1.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|12|0.0%|0.0%|
[php_commenters](#php_commenters)|201|201|9|4.4%|0.0%|
[php_bad](#php_bad)|201|201|9|4.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|8|0.0%|0.0%|
[openbl_90d](#openbl_90d)|9963|9963|7|0.0%|0.0%|
[openbl](#openbl)|9963|9963|7|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7887|7887|6|0.0%|0.0%|
[php_harvesters](#php_harvesters)|199|199|5|2.5%|0.0%|
[openbl_30d](#openbl_30d)|4483|4483|5|0.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|3|0.4%|0.0%|
[tor_servers](#tor_servers)|6501|6501|2|0.0%|0.0%|
[openbl_7d](#openbl_7d)|1405|1405|2|0.1%|0.0%|
[danmetor](#danmetor)|6499|6499|2|0.0%|0.0%|
[tor](#tor)|6340|6340|1|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|
[compromised](#compromised)|2436|2436|1|0.0%|0.0%|
[ciarmy](#ciarmy)|391|391|1|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2289|2289|1|0.0%|0.0%|

## openbl

[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**

Source is downloaded from [this link](http://www.openbl.org/lists/base.txt.gz).

The last time downloaded was found to be dated: Mon May 25 10:37:00 UTC 2015.

The ipset `openbl` has **9963** entries, **9963** unique IPs.

The following table shows the overlaps of `openbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl`.
- ` this % ` is the percentage **of this ipset (`openbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9963|9963|9963|100.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|180998|180998|9940|5.4%|99.7%|
[openbl_60d](#openbl_60d)|7887|7887|7887|100.0%|79.1%|
[openbl_30d](#openbl_30d)|4483|4483|4483|100.0%|44.9%|
[compromised](#compromised)|2436|2436|1474|60.5%|14.7%|
[openbl_7d](#openbl_7d)|1405|1405|1405|100.0%|14.1%|
[bruteforceblocker](#bruteforceblocker)|2289|2289|1353|59.1%|13.5%|
[blocklist_de](#blocklist_de)|26020|26020|1313|5.0%|13.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|969|0.0%|9.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|529|0.0%|5.3%|
[emerging_block](#emerging_block)|965|18065466|453|0.0%|4.5%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|447|0.0%|4.4%|
[openbl_1d](#openbl_1d)|357|357|357|100.0%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|218|0.0%|2.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92481|92481|73|0.0%|0.7%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29531|29531|38|0.1%|0.3%|
[dshield](#dshield)|20|5120|37|0.7%|0.3%|
[snort_ipfilter](#snort_ipfilter)|6448|6448|25|0.3%|0.2%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7164|7164|24|0.3%|0.2%|
[tor_servers](#tor_servers)|6501|6501|21|0.3%|0.2%|
[danmetor](#danmetor)|6499|6499|21|0.3%|0.2%|
[tor](#tor)|6340|6340|20|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|19|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|14|0.0%|0.1%|
[autoshun](#autoshun)|51|51|11|21.5%|0.1%|
[nixspam](#nixspam)|20904|20904|7|0.0%|0.0%|
[php_commenters](#php_commenters)|201|201|6|2.9%|0.0%|
[php_bad](#php_bad)|201|201|6|2.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|6|0.0%|0.0%|
[php_harvesters](#php_harvesters)|199|199|4|2.0%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[zeus](#zeus)|262|262|1|0.3%|0.0%|
[sslbl](#sslbl)|325|325|1|0.3%|0.0%|
[rosi_web_proxies](#rosi_web_proxies)|3441|3441|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[feodo](#feodo)|59|59|1|1.6%|0.0%|

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
[openbl_90d](#openbl_90d)|9963|9963|357|3.5%|100.0%|
[openbl_7d](#openbl_7d)|1405|1405|357|25.4%|100.0%|
[openbl_60d](#openbl_60d)|7887|7887|357|4.5%|100.0%|
[openbl_30d](#openbl_30d)|4483|4483|357|7.9%|100.0%|
[openbl](#openbl)|9963|9963|357|3.5%|100.0%|
[alienvault_reputation](#alienvault_reputation)|180998|180998|355|0.1%|99.4%|
[blocklist_de](#blocklist_de)|26020|26020|248|0.9%|69.4%|
[bruteforceblocker](#bruteforceblocker)|2289|2289|203|8.8%|56.8%|
[compromised](#compromised)|2436|2436|198|8.1%|55.4%|
[emerging_block](#emerging_block)|965|18065466|27|0.0%|7.5%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|26|0.0%|7.2%|
[dshield](#dshield)|20|5120|21|0.4%|5.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|20|0.0%|5.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|17|0.0%|4.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|7|0.0%|1.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|1.4%|
[autoshun](#autoshun)|51|51|2|3.9%|0.5%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92481|92481|1|0.0%|0.2%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.2%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt.gz).

The last time downloaded was found to be dated: Mon May 25 10:37:00 UTC 2015.

The ipset `openbl_30d` has **4483** entries, **4483** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9963|9963|4483|44.9%|100.0%|
[openbl_60d](#openbl_60d)|7887|7887|4483|56.8%|100.0%|
[openbl](#openbl)|9963|9963|4483|44.9%|100.0%|
[alienvault_reputation](#alienvault_reputation)|180998|180998|4474|2.4%|99.7%|
[openbl_7d](#openbl_7d)|1405|1405|1405|100.0%|31.3%|
[compromised](#compromised)|2436|2436|1324|54.3%|29.5%|
[bruteforceblocker](#bruteforceblocker)|2289|2289|1287|56.2%|28.7%|
[blocklist_de](#blocklist_de)|26020|26020|1102|4.2%|24.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|441|0.0%|9.8%|
[openbl_1d](#openbl_1d)|357|357|357|100.0%|7.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|226|0.0%|5.0%|
[emerging_block](#emerging_block)|965|18065466|214|0.0%|4.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|211|0.0%|4.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|97|0.0%|2.1%|
[dshield](#dshield)|20|5120|35|0.6%|0.7%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92481|92481|24|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|13|0.0%|0.2%|
[autoshun](#autoshun)|51|51|10|19.6%|0.2%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29531|29531|6|0.0%|0.1%|
[nixspam](#nixspam)|20904|20904|5|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|4|0.0%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7164|7164|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[zeus](#zeus)|262|262|1|0.3%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6448|6448|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt.gz).

The last time downloaded was found to be dated: Mon May 25 10:37:00 UTC 2015.

The ipset `openbl_60d` has **7887** entries, **7887** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9963|9963|7887|79.1%|100.0%|
[openbl](#openbl)|9963|9963|7887|79.1%|100.0%|
[alienvault_reputation](#alienvault_reputation)|180998|180998|7870|4.3%|99.7%|
[openbl_30d](#openbl_30d)|4483|4483|4483|100.0%|56.8%|
[compromised](#compromised)|2436|2436|1464|60.0%|18.5%|
[openbl_7d](#openbl_7d)|1405|1405|1405|100.0%|17.8%|
[bruteforceblocker](#bruteforceblocker)|2289|2289|1344|58.7%|17.0%|
[blocklist_de](#blocklist_de)|26020|26020|1268|4.8%|16.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|718|0.0%|9.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|378|0.0%|4.7%|
[openbl_1d](#openbl_1d)|357|357|357|100.0%|4.5%|
[emerging_block](#emerging_block)|965|18065466|321|0.0%|4.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|317|0.0%|4.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|177|0.0%|2.2%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92481|92481|65|0.0%|0.8%|
[dshield](#dshield)|20|5120|36|0.7%|0.4%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29531|29531|34|0.1%|0.4%|
[snort_ipfilter](#snort_ipfilter)|6448|6448|24|0.3%|0.3%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7164|7164|22|0.3%|0.2%|
[tor_servers](#tor_servers)|6501|6501|21|0.3%|0.2%|
[danmetor](#danmetor)|6499|6499|21|0.3%|0.2%|
[tor](#tor)|6340|6340|20|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|18|0.0%|0.2%|
[autoshun](#autoshun)|51|51|11|21.5%|0.1%|
[php_commenters](#php_commenters)|201|201|6|2.9%|0.0%|
[php_bad](#php_bad)|201|201|6|2.9%|0.0%|
[nixspam](#nixspam)|20904|20904|6|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|5|0.0%|0.0%|
[php_harvesters](#php_harvesters)|199|199|4|2.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[zeus](#zeus)|262|262|1|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt.gz).

The last time downloaded was found to be dated: Mon May 25 10:37:00 UTC 2015.

The ipset `openbl_7d` has **1405** entries, **1405** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9963|9963|1405|14.1%|100.0%|
[openbl_60d](#openbl_60d)|7887|7887|1405|17.8%|100.0%|
[openbl_30d](#openbl_30d)|4483|4483|1405|31.3%|100.0%|
[openbl](#openbl)|9963|9963|1405|14.1%|100.0%|
[alienvault_reputation](#alienvault_reputation)|180998|180998|1398|0.7%|99.5%|
[blocklist_de](#blocklist_de)|26020|26020|790|3.0%|56.2%|
[bruteforceblocker](#bruteforceblocker)|2289|2289|711|31.0%|50.6%|
[compromised](#compromised)|2436|2436|683|28.0%|48.6%|
[openbl_1d](#openbl_1d)|357|357|357|100.0%|25.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|119|0.0%|8.4%|
[emerging_block](#emerging_block)|965|18065466|104|0.0%|7.4%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|102|0.0%|7.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|76|0.0%|5.4%|
[dshield](#dshield)|20|5120|35|0.6%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|27|0.0%|1.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.7%|
[autoshun](#autoshun)|51|51|8|15.6%|0.5%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92481|92481|2|0.0%|0.1%|
[nixspam](#nixspam)|20904|20904|2|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|2|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## openbl_90d

[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_90days.txt.gz).

The last time downloaded was found to be dated: Mon May 25 10:37:00 UTC 2015.

The ipset `openbl_90d` has **9963** entries, **9963** unique IPs.

The following table shows the overlaps of `openbl_90d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_90d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_90d`.
- ` this % ` is the percentage **of this ipset (`openbl_90d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl](#openbl)|9963|9963|9963|100.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|180998|180998|9940|5.4%|99.7%|
[openbl_60d](#openbl_60d)|7887|7887|7887|100.0%|79.1%|
[openbl_30d](#openbl_30d)|4483|4483|4483|100.0%|44.9%|
[compromised](#compromised)|2436|2436|1474|60.5%|14.7%|
[openbl_7d](#openbl_7d)|1405|1405|1405|100.0%|14.1%|
[bruteforceblocker](#bruteforceblocker)|2289|2289|1353|59.1%|13.5%|
[blocklist_de](#blocklist_de)|26020|26020|1313|5.0%|13.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|969|0.0%|9.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|529|0.0%|5.3%|
[emerging_block](#emerging_block)|965|18065466|453|0.0%|4.5%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|447|0.0%|4.4%|
[openbl_1d](#openbl_1d)|357|357|357|100.0%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|218|0.0%|2.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92481|92481|73|0.0%|0.7%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29531|29531|38|0.1%|0.3%|
[dshield](#dshield)|20|5120|37|0.7%|0.3%|
[snort_ipfilter](#snort_ipfilter)|6448|6448|25|0.3%|0.2%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7164|7164|24|0.3%|0.2%|
[tor_servers](#tor_servers)|6501|6501|21|0.3%|0.2%|
[danmetor](#danmetor)|6499|6499|21|0.3%|0.2%|
[tor](#tor)|6340|6340|20|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|19|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|14|0.0%|0.1%|
[autoshun](#autoshun)|51|51|11|21.5%|0.1%|
[nixspam](#nixspam)|20904|20904|7|0.0%|0.0%|
[php_commenters](#php_commenters)|201|201|6|2.9%|0.0%|
[php_bad](#php_bad)|201|201|6|2.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|6|0.0%|0.0%|
[php_harvesters](#php_harvesters)|199|199|4|2.0%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[zeus](#zeus)|262|262|1|0.3%|0.0%|
[sslbl](#sslbl)|325|325|1|0.3%|0.0%|
[rosi_web_proxies](#rosi_web_proxies)|3441|3441|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[feodo](#feodo)|59|59|1|1.6%|0.0%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Mon May 25 11:20:16 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[emerging_block](#emerging_block)|965|18065466|13|0.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|6448|6448|11|0.1%|84.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|2|0.0%|15.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|1|0.0%|7.6%|

## php_bad

[projecthoneypot.org](http://www.projecthoneypot.org/) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1).

The last time downloaded was found to be dated: Mon May 25 10:40:46 UTC 2015.

The ipset `php_bad` has **201** entries, **201** unique IPs.

The following table shows the overlaps of `php_bad` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_bad`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_bad`.
- ` this % ` is the percentage **of this ipset (`php_bad`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[php_commenters](#php_commenters)|201|201|201|100.0%|100.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92481|92481|144|0.1%|71.6%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29531|29531|140|0.4%|69.6%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7164|7164|100|1.3%|49.7%|
[blocklist_de](#blocklist_de)|26020|26020|72|0.2%|35.8%|
[snort_ipfilter](#snort_ipfilter)|6448|6448|28|0.4%|13.9%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|25|0.0%|12.4%|
[emerging_block](#emerging_block)|965|18065466|24|0.0%|11.9%|
[tor_servers](#tor_servers)|6501|6501|19|0.2%|9.4%|
[tor](#tor)|6340|6340|19|0.2%|9.4%|
[danmetor](#danmetor)|6499|6499|19|0.2%|9.4%|
[php_spammers](#php_spammers)|300|300|16|5.3%|7.9%|
[php_dictionary](#php_dictionary)|275|275|10|3.6%|4.9%|
[alienvault_reputation](#alienvault_reputation)|180998|180998|10|0.0%|4.9%|
[nixspam](#nixspam)|20904|20904|9|0.0%|4.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|9|0.0%|4.4%|
[php_harvesters](#php_harvesters)|199|199|8|4.0%|3.9%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|6|0.0%|2.9%|
[rosi_web_proxies](#rosi_web_proxies)|3441|3441|6|0.1%|2.9%|
[openbl_90d](#openbl_90d)|9963|9963|6|0.0%|2.9%|
[openbl_60d](#openbl_60d)|7887|7887|6|0.0%|2.9%|
[openbl](#openbl)|9963|9963|6|0.0%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|4|0.0%|1.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|3|0.0%|1.4%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.4%|
[zeus](#zeus)|262|262|1|0.3%|0.4%|

## php_commenters

[projecthoneypot.org](http://www.projecthoneypot.org/) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1).

The last time downloaded was found to be dated: Mon May 25 10:40:47 UTC 2015.

The ipset `php_commenters` has **201** entries, **201** unique IPs.

The following table shows the overlaps of `php_commenters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_commenters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_commenters`.
- ` this % ` is the percentage **of this ipset (`php_commenters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[php_bad](#php_bad)|201|201|201|100.0%|100.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92481|92481|144|0.1%|71.6%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29531|29531|140|0.4%|69.6%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7164|7164|100|1.3%|49.7%|
[blocklist_de](#blocklist_de)|26020|26020|72|0.2%|35.8%|
[snort_ipfilter](#snort_ipfilter)|6448|6448|28|0.4%|13.9%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|25|0.0%|12.4%|
[emerging_block](#emerging_block)|965|18065466|24|0.0%|11.9%|
[tor_servers](#tor_servers)|6501|6501|19|0.2%|9.4%|
[tor](#tor)|6340|6340|19|0.2%|9.4%|
[danmetor](#danmetor)|6499|6499|19|0.2%|9.4%|
[php_spammers](#php_spammers)|300|300|16|5.3%|7.9%|
[php_dictionary](#php_dictionary)|275|275|10|3.6%|4.9%|
[alienvault_reputation](#alienvault_reputation)|180998|180998|10|0.0%|4.9%|
[nixspam](#nixspam)|20904|20904|9|0.0%|4.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|9|0.0%|4.4%|
[php_harvesters](#php_harvesters)|199|199|8|4.0%|3.9%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|6|0.0%|2.9%|
[rosi_web_proxies](#rosi_web_proxies)|3441|3441|6|0.1%|2.9%|
[openbl_90d](#openbl_90d)|9963|9963|6|0.0%|2.9%|
[openbl_60d](#openbl_60d)|7887|7887|6|0.0%|2.9%|
[openbl](#openbl)|9963|9963|6|0.0%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|4|0.0%|1.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|3|0.0%|1.4%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.4%|
[zeus](#zeus)|262|262|1|0.3%|0.4%|

## php_dictionary

[projecthoneypot.org](http://www.projecthoneypot.org/) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1).

The last time downloaded was found to be dated: Mon May 25 10:40:48 UTC 2015.

The ipset `php_dictionary` has **275** entries, **275** unique IPs.

The following table shows the overlaps of `php_dictionary` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_dictionary`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_dictionary`.
- ` this % ` is the percentage **of this ipset (`php_dictionary`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|26020|26020|80|0.3%|29.0%|
[nixspam](#nixspam)|20904|20904|78|0.3%|28.3%|
[snort_ipfilter](#snort_ipfilter)|6448|6448|75|1.1%|27.2%|
[php_spammers](#php_spammers)|300|300|49|16.3%|17.8%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92481|92481|48|0.0%|17.4%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29531|29531|30|0.1%|10.9%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7164|7164|17|0.2%|6.1%|
[rosi_web_proxies](#rosi_web_proxies)|3441|3441|14|0.4%|5.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|13|0.0%|4.7%|
[php_commenters](#php_commenters)|201|201|10|4.9%|3.6%|
[php_bad](#php_bad)|201|201|10|4.9%|3.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|7|0.0%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|7|0.0%|2.5%|
[tor](#tor)|6340|6340|4|0.0%|1.4%|
[tor_servers](#tor_servers)|6501|6501|3|0.0%|1.0%|
[danmetor](#danmetor)|6499|6499|3|0.0%|1.0%|
[alienvault_reputation](#alienvault_reputation)|180998|180998|3|0.0%|1.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|1|0.0%|0.3%|
[rosi_connect_proxies](#rosi_connect_proxies)|1393|1393|1|0.0%|0.3%|
[php_harvesters](#php_harvesters)|199|199|1|0.5%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|1|0.0%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.3%|
[emerging_block](#emerging_block)|965|18065466|1|0.0%|0.3%|

## php_harvesters

[projecthoneypot.org](http://www.projecthoneypot.org/) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1).

The last time downloaded was found to be dated: Mon May 25 10:40:43 UTC 2015.

The ipset `php_harvesters` has **199** entries, **199** unique IPs.

The following table shows the overlaps of `php_harvesters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_harvesters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_harvesters`.
- ` this % ` is the percentage **of this ipset (`php_harvesters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92481|92481|51|0.0%|25.6%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29531|29531|44|0.1%|22.1%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7164|7164|28|0.3%|14.0%|
[blocklist_de](#blocklist_de)|26020|26020|23|0.0%|11.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|13|0.0%|6.5%|
[snort_ipfilter](#snort_ipfilter)|6448|6448|10|0.1%|5.0%|
[php_commenters](#php_commenters)|201|201|8|3.9%|4.0%|
[php_bad](#php_bad)|201|201|8|3.9%|4.0%|
[tor_servers](#tor_servers)|6501|6501|7|0.1%|3.5%|
[tor](#tor)|6340|6340|7|0.1%|3.5%|
[danmetor](#danmetor)|6499|6499|7|0.1%|3.5%|
[alienvault_reputation](#alienvault_reputation)|180998|180998|7|0.0%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|6|0.0%|3.0%|
[nixspam](#nixspam)|20904|20904|5|0.0%|2.5%|
[openbl_90d](#openbl_90d)|9963|9963|4|0.0%|2.0%|
[openbl_60d](#openbl_60d)|7887|7887|4|0.0%|2.0%|
[openbl](#openbl)|9963|9963|4|0.0%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|3|0.0%|1.5%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|1.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|1|0.0%|0.5%|
[rosi_web_proxies](#rosi_web_proxies)|3441|3441|1|0.0%|0.5%|
[php_spammers](#php_spammers)|300|300|1|0.3%|0.5%|
[php_dictionary](#php_dictionary)|275|275|1|0.3%|0.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|1|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.5%|
[fullbogons](#fullbogons)|3646|670922200|1|0.0%|0.5%|
[emerging_block](#emerging_block)|965|18065466|1|0.0%|0.5%|
[bogons](#bogons)|13|592708608|1|0.0%|0.5%|

## php_spammers

[projecthoneypot.org](http://www.projecthoneypot.org/) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1).

The last time downloaded was found to be dated: Mon May 25 10:40:44 UTC 2015.

The ipset `php_spammers` has **300** entries, **300** unique IPs.

The following table shows the overlaps of `php_spammers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_spammers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_spammers`.
- ` this % ` is the percentage **of this ipset (`php_spammers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|26020|26020|76|0.2%|25.3%|
[nixspam](#nixspam)|20904|20904|73|0.3%|24.3%|
[snort_ipfilter](#snort_ipfilter)|6448|6448|67|1.0%|22.3%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92481|92481|63|0.0%|21.0%|
[php_dictionary](#php_dictionary)|275|275|49|17.8%|16.3%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29531|29531|46|0.1%|15.3%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7164|7164|26|0.3%|8.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|24|0.0%|8.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|19|0.0%|6.3%|
[php_commenters](#php_commenters)|201|201|16|7.9%|5.3%|
[php_bad](#php_bad)|201|201|16|7.9%|5.3%|
[rosi_web_proxies](#rosi_web_proxies)|3441|3441|10|0.2%|3.3%|
[tor](#tor)|6340|6340|5|0.0%|1.6%|
[tor_servers](#tor_servers)|6501|6501|4|0.0%|1.3%|
[danmetor](#danmetor)|6499|6499|4|0.0%|1.3%|
[alienvault_reputation](#alienvault_reputation)|180998|180998|3|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|2|0.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.6%|
[emerging_block](#emerging_block)|965|18065466|2|0.0%|0.6%|
[rosi_connect_proxies](#rosi_connect_proxies)|1393|1393|1|0.0%|0.3%|
[php_harvesters](#php_harvesters)|199|199|1|0.5%|0.3%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.3%|

## rosi_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Mon May 25 05:18:24 UTC 2015.

The ipset `rosi_connect_proxies` has **1393** entries, **1393** unique IPs.

The following table shows the overlaps of `rosi_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `rosi_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `rosi_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`rosi_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92481|92481|828|0.8%|59.4%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29531|29531|684|2.3%|49.1%|
[rosi_web_proxies](#rosi_web_proxies)|3441|3441|543|15.7%|38.9%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7164|7164|175|2.4%|12.5%|
[blocklist_de](#blocklist_de)|26020|26020|83|0.3%|5.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|66|0.0%|4.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|29|0.0%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|22|0.0%|1.5%|
[nixspam](#nixspam)|20904|20904|18|0.0%|1.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.4%|
[snort_ipfilter](#snort_ipfilter)|6448|6448|4|0.0%|0.2%|
[tor_servers](#tor_servers)|6501|6501|1|0.0%|0.0%|
[tor](#tor)|6340|6340|1|0.0%|0.0%|
[php_spammers](#php_spammers)|300|300|1|0.3%|0.0%|
[php_dictionary](#php_dictionary)|275|275|1|0.3%|0.0%|
[danmetor](#danmetor)|6499|6499|1|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|180998|180998|1|0.0%|0.0%|

## rosi_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Mon May 25 06:55:07 UTC 2015.

The ipset `rosi_web_proxies` has **3441** entries, **3441** unique IPs.

The following table shows the overlaps of `rosi_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `rosi_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `rosi_web_proxies`.
- ` this % ` is the percentage **of this ipset (`rosi_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92481|92481|1680|1.8%|48.8%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29531|29531|1418|4.8%|41.2%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7164|7164|543|7.5%|15.7%|
[rosi_connect_proxies](#rosi_connect_proxies)|1393|1393|543|38.9%|15.7%|
[blocklist_de](#blocklist_de)|26020|26020|376|1.4%|10.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|129|0.0%|3.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|117|0.0%|3.4%|
[nixspam](#nixspam)|20904|20904|79|0.3%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|58|0.0%|1.6%|
[snort_ipfilter](#snort_ipfilter)|6448|6448|33|0.5%|0.9%|
[php_dictionary](#php_dictionary)|275|275|14|5.0%|0.4%|
[php_spammers](#php_spammers)|300|300|10|3.3%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|10|1.4%|0.2%|
[php_commenters](#php_commenters)|201|201|6|2.9%|0.1%|
[php_bad](#php_bad)|201|201|6|2.9%|0.1%|
[tor_servers](#tor_servers)|6501|6501|4|0.0%|0.1%|
[tor](#tor)|6340|6340|4|0.0%|0.1%|
[danmetor](#danmetor)|6499|6499|4|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|3|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|180998|180998|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|199|199|1|0.5%|0.0%|
[openbl_90d](#openbl_90d)|9963|9963|1|0.0%|0.0%|
[openbl](#openbl)|9963|9963|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|

## snort_ipfilter

[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)

Source is downloaded from [this link](http://labs.snort.org/feeds/ip-filter.blf).

The last time downloaded was found to be dated: Mon May 25 00:30:00 UTC 2015.

The ipset `snort_ipfilter` has **6448** entries, **6448** unique IPs.

The following table shows the overlaps of `snort_ipfilter` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `snort_ipfilter`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `snort_ipfilter`.
- ` this % ` is the percentage **of this ipset (`snort_ipfilter`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[tor_servers](#tor_servers)|6501|6501|1046|16.0%|16.2%|
[danmetor](#danmetor)|6499|6499|1046|16.0%|16.2%|
[tor](#tor)|6340|6340|1026|16.1%|15.9%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92481|92481|686|0.7%|10.6%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29531|29531|504|1.7%|7.8%|
[emerging_block](#emerging_block)|965|18065466|282|0.0%|4.3%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7164|7164|271|3.7%|4.2%|
[blocklist_de](#blocklist_de)|26020|26020|225|0.8%|3.4%|
[zeus](#zeus)|262|262|223|85.1%|3.4%|
[nixspam](#nixspam)|20904|20904|214|1.0%|3.3%|
[zeus_badips](#zeus_badips)|230|230|202|87.8%|3.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|202|0.0%|3.1%|
[alienvault_reputation](#alienvault_reputation)|180998|180998|117|0.0%|1.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|107|0.0%|1.6%|
[php_dictionary](#php_dictionary)|275|275|75|27.2%|1.1%|
[php_spammers](#php_spammers)|300|300|67|22.3%|1.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|59|0.0%|0.9%|
[feodo](#feodo)|59|59|46|77.9%|0.7%|
[rosi_web_proxies](#rosi_web_proxies)|3441|3441|33|0.9%|0.5%|
[php_commenters](#php_commenters)|201|201|28|13.9%|0.4%|
[php_bad](#php_bad)|201|201|28|13.9%|0.4%|
[openbl_90d](#openbl_90d)|9963|9963|25|0.2%|0.3%|
[openbl](#openbl)|9963|9963|25|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7887|7887|24|0.3%|0.3%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|24|1.8%|0.3%|
[sslbl](#sslbl)|325|325|18|5.5%|0.2%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|18|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|12|0.0%|0.1%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.1%|
[php_harvesters](#php_harvesters)|199|199|10|5.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|6|0.0%|0.0%|
[rosi_connect_proxies](#rosi_connect_proxies)|1393|1393|4|0.2%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|301|301|4|1.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[openbl_30d](#openbl_30d)|4483|4483|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[compromised](#compromised)|2436|2436|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2289|2289|1|0.0%|0.0%|

## spamhaus_drop

[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**

Source is downloaded from [this link](http://www.spamhaus.org/drop/drop.txt).

The last time downloaded was found to be dated: Mon May 25 04:52:52 UTC 2015.

The ipset `spamhaus_drop` has **641** entries, **18117120** unique IPs.

The following table shows the overlaps of `spamhaus_drop` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `spamhaus_drop`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `spamhaus_drop`.
- ` this % ` is the percentage **of this ipset (`spamhaus_drop`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[emerging_block](#emerging_block)|965|18065466|17994240|99.6%|99.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|8401433|2.4%|46.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7211008|78.5%|39.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|2132981|0.2%|11.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|195904|0.1%|1.0%|
[fullbogons](#fullbogons)|3646|670922200|20480|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|180998|180998|1878|1.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|1024|0.3%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92481|92481|774|0.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|512|0.1%|0.0%|
[openbl_90d](#openbl_90d)|9963|9963|447|4.4%|0.0%|
[openbl](#openbl)|9963|9963|447|4.4%|0.0%|
[openbl_60d](#openbl_60d)|7887|7887|317|4.0%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29531|29531|248|0.8%|0.0%|
[nixspam](#nixspam)|20904|20904|244|1.1%|0.0%|
[openbl_30d](#openbl_30d)|4483|4483|211|4.7%|0.0%|
[blocklist_de](#blocklist_de)|26020|26020|183|0.7%|0.0%|
[openbl_7d](#openbl_7d)|1405|1405|102|7.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2289|2289|89|3.8%|0.0%|
[compromised](#compromised)|2436|2436|76|3.1%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7164|7164|72|1.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|28|2.1%|0.0%|
[openbl_1d](#openbl_1d)|357|357|26|7.2%|0.0%|
[php_commenters](#php_commenters)|201|201|25|12.4%|0.0%|
[php_bad](#php_bad)|201|201|25|12.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6448|6448|18|0.2%|0.0%|
[zeus_badips](#zeus_badips)|230|230|17|7.3%|0.0%|
[zeus](#zeus)|262|262|17|6.4%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[tor_servers](#tor_servers)|6501|6501|2|0.0%|0.0%|
[tor](#tor)|6340|6340|2|0.0%|0.0%|
[sslbl](#sslbl)|325|325|2|0.6%|0.0%|
[php_spammers](#php_spammers)|300|300|2|0.6%|0.0%|
[malc0de](#malc0de)|426|426|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[danmetor](#danmetor)|6499|6499|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|199|199|1|0.5%|0.0%|
[php_dictionary](#php_dictionary)|275|275|1|0.3%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|301|301|1|0.3%|0.0%|
[botnet](#botnet)|515|515|1|0.1%|0.0%|

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
[emerging_block](#emerging_block)|965|18065466|517|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|512|0.0%|0.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92481|92481|109|0.1%|0.0%|
[blocklist_de](#blocklist_de)|26020|26020|41|0.1%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29531|29531|34|0.1%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7164|7164|19|0.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|180998|180998|16|0.0%|0.0%|
[openbl_90d](#openbl_90d)|9963|9963|14|0.1%|0.0%|
[openbl](#openbl)|9963|9963|14|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6448|6448|6|0.0%|0.0%|
[php_commenters](#php_commenters)|201|201|6|2.9%|0.0%|
[php_bad](#php_bad)|201|201|6|2.9%|0.0%|
[zeus_badips](#zeus_badips)|230|230|5|2.1%|0.0%|
[zeus](#zeus)|262|262|5|1.9%|0.0%|
[nixspam](#nixspam)|20904|20904|3|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7887|7887|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|199|199|1|0.5%|0.0%|
[openbl_7d](#openbl_7d)|1405|1405|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4483|4483|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|357|357|1|0.2%|0.0%|
[malc0de](#malc0de)|426|426|1|0.2%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Mon May 25 11:30:05 UTC 2015.

The ipset `sslbl` has **325** entries, **325** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[emerging_block](#emerging_block)|965|18065466|23|0.0%|7.0%|
[feodo](#feodo)|59|59|21|35.5%|6.4%|
[snort_ipfilter](#snort_ipfilter)|6448|6448|18|0.2%|5.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|16|0.0%|4.9%|
[alienvault_reputation](#alienvault_reputation)|180998|180998|7|0.0%|2.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|5|0.0%|1.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|3|0.0%|0.9%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92481|92481|2|0.0%|0.6%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.6%|
[openbl_90d](#openbl_90d)|9963|9963|1|0.0%|0.3%|
[openbl](#openbl)|9963|9963|1|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|1|0.0%|0.3%|
[clean_mx_viruses](#clean_mx_viruses)|301|301|1|0.3%|0.3%|

## stop_forum_spam_1h

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Mon May 25 11:00:01 UTC 2015.

The ipset `stop_forum_spam_1h` has **7164** entries, **7164** unique IPs.

The following table shows the overlaps of `stop_forum_spam_1h` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stop_forum_spam_1h`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stop_forum_spam_1h`.
- ` this % ` is the percentage **of this ipset (`stop_forum_spam_1h`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29531|29531|6316|21.3%|88.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92481|92481|4627|5.0%|64.5%|
[blocklist_de](#blocklist_de)|26020|26020|1488|5.7%|20.7%|
[rosi_web_proxies](#rosi_web_proxies)|3441|3441|543|15.7%|7.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|493|0.0%|6.8%|
[snort_ipfilter](#snort_ipfilter)|6448|6448|271|4.2%|3.7%|
[tor_servers](#tor_servers)|6501|6501|244|3.7%|3.4%|
[danmetor](#danmetor)|6499|6499|244|3.7%|3.4%|
[tor](#tor)|6340|6340|241|3.8%|3.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|240|0.0%|3.3%|
[rosi_connect_proxies](#rosi_connect_proxies)|1393|1393|175|12.5%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|138|0.0%|1.9%|
[php_commenters](#php_commenters)|201|201|100|49.7%|1.3%|
[php_bad](#php_bad)|201|201|100|49.7%|1.3%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|72|0.0%|1.0%|
[nixspam](#nixspam)|20904|20904|67|0.3%|0.9%|
[emerging_block](#emerging_block)|965|18065466|65|0.0%|0.9%|
[alienvault_reputation](#alienvault_reputation)|180998|180998|59|0.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|47|0.0%|0.6%|
[php_harvesters](#php_harvesters)|199|199|28|14.0%|0.3%|
[php_spammers](#php_spammers)|300|300|26|8.6%|0.3%|
[openbl_90d](#openbl_90d)|9963|9963|24|0.2%|0.3%|
[openbl](#openbl)|9963|9963|24|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7887|7887|22|0.2%|0.3%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|19|0.0%|0.2%|
[php_dictionary](#php_dictionary)|275|275|17|6.1%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|8|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|5|0.7%|0.0%|
[openbl_30d](#openbl_30d)|4483|4483|2|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## stop_forum_spam_30d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip).

The last time downloaded was found to be dated: Sun May 24 12:00:43 UTC 2015.

The ipset `stop_forum_spam_30d` has **92481** entries, **92481** unique IPs.

The following table shows the overlaps of `stop_forum_spam_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stop_forum_spam_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stop_forum_spam_30d`.
- ` this % ` is the percentage **of this ipset (`stop_forum_spam_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29531|29531|27697|93.7%|29.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|6272|0.0%|6.7%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7164|7164|4627|64.5%|5.0%|
[blocklist_de](#blocklist_de)|26020|26020|2473|9.5%|2.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|2418|0.0%|2.6%|
[rosi_web_proxies](#rosi_web_proxies)|3441|3441|1680|48.8%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|1272|0.0%|1.3%|
[rosi_connect_proxies](#rosi_connect_proxies)|1393|1393|828|59.4%|0.8%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|774|0.0%|0.8%|
[emerging_block](#emerging_block)|965|18065466|756|0.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|716|0.0%|0.7%|
[snort_ipfilter](#snort_ipfilter)|6448|6448|686|10.6%|0.7%|
[tor](#tor)|6340|6340|571|9.0%|0.6%|
[tor_servers](#tor_servers)|6501|6501|565|8.6%|0.6%|
[danmetor](#danmetor)|6499|6499|565|8.6%|0.6%|
[alienvault_reputation](#alienvault_reputation)|180998|180998|253|0.1%|0.2%|
[nixspam](#nixspam)|20904|20904|246|1.1%|0.2%|
[php_commenters](#php_commenters)|201|201|144|71.6%|0.1%|
[php_bad](#php_bad)|201|201|144|71.6%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|109|0.0%|0.1%|
[openbl_90d](#openbl_90d)|9963|9963|73|0.7%|0.0%|
[openbl](#openbl)|9963|9963|73|0.7%|0.0%|
[openbl_60d](#openbl_60d)|7887|7887|65|0.8%|0.0%|
[php_spammers](#php_spammers)|300|300|63|21.0%|0.0%|
[php_harvesters](#php_harvesters)|199|199|51|25.6%|0.0%|
[php_dictionary](#php_dictionary)|275|275|48|17.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|41|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4483|4483|24|0.5%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|24|3.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[dshield](#dshield)|20|5120|11|0.2%|0.0%|
[zeus_badips](#zeus_badips)|230|230|4|1.7%|0.0%|
[zeus](#zeus)|262|262|4|1.5%|0.0%|
[compromised](#compromised)|2436|2436|4|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2289|2289|4|0.1%|0.0%|
[fullbogons](#fullbogons)|3646|670922200|3|0.0%|0.0%|
[sslbl](#sslbl)|325|325|2|0.6%|0.0%|
[openbl_7d](#openbl_7d)|1405|1405|2|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|2|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[openbl_1d](#openbl_1d)|357|357|1|0.2%|0.0%|
[ciarmy](#ciarmy)|391|391|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|

## stop_forum_spam_7d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip).

The last time downloaded was found to be dated: Mon May 25 04:00:09 UTC 2015.

The ipset `stop_forum_spam_7d` has **29531** entries, **29531** unique IPs.

The following table shows the overlaps of `stop_forum_spam_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stop_forum_spam_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stop_forum_spam_7d`.
- ` this % ` is the percentage **of this ipset (`stop_forum_spam_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92481|92481|27697|29.9%|93.7%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7164|7164|6316|88.1%|21.3%|
[blocklist_de](#blocklist_de)|26020|26020|2187|8.4%|7.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|1978|0.0%|6.6%|
[rosi_web_proxies](#rosi_web_proxies)|3441|3441|1418|41.2%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|832|0.0%|2.8%|
[rosi_connect_proxies](#rosi_connect_proxies)|1393|1393|684|49.1%|2.3%|
[snort_ipfilter](#snort_ipfilter)|6448|6448|504|7.8%|1.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|473|0.0%|1.6%|
[tor](#tor)|6340|6340|422|6.6%|1.4%|
[tor_servers](#tor_servers)|6501|6501|416|6.3%|1.4%|
[danmetor](#danmetor)|6499|6499|416|6.4%|1.4%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|248|0.0%|0.8%|
[emerging_block](#emerging_block)|965|18065466|229|0.0%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|210|0.0%|0.7%|
[nixspam](#nixspam)|20904|20904|148|0.7%|0.5%|
[php_commenters](#php_commenters)|201|201|140|69.6%|0.4%|
[php_bad](#php_bad)|201|201|140|69.6%|0.4%|
[alienvault_reputation](#alienvault_reputation)|180998|180998|118|0.0%|0.3%|
[php_spammers](#php_spammers)|300|300|46|15.3%|0.1%|
[php_harvesters](#php_harvesters)|199|199|44|22.1%|0.1%|
[openbl_90d](#openbl_90d)|9963|9963|38|0.3%|0.1%|
[openbl](#openbl)|9963|9963|38|0.3%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|34|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7887|7887|34|0.4%|0.1%|
[php_dictionary](#php_dictionary)|275|275|30|10.9%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|23|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|14|2.0%|0.0%|
[openbl_30d](#openbl_30d)|4483|4483|6|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|5|0.0%|0.0%|
[dshield](#dshield)|20|5120|3|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[compromised](#compromised)|2436|2436|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[zeus](#zeus)|262|262|1|0.3%|0.0%|
[fullbogons](#fullbogons)|3646|670922200|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2289|2289|1|0.0%|0.0%|

## tor

[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs

Source is downloaded from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules).

The last time downloaded was found to be dated: Fri May 22 04:30:09 UTC 2015.

The ipset `tor` has **6340** entries, **6340** unique IPs.

The following table shows the overlaps of `tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `tor`.
- ` this % ` is the percentage **of this ipset (`tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[tor_servers](#tor_servers)|6501|6501|5552|85.4%|87.5%|
[danmetor](#danmetor)|6499|6499|5550|85.3%|87.5%|
[snort_ipfilter](#snort_ipfilter)|6448|6448|1026|15.9%|16.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|602|0.0%|9.4%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92481|92481|571|0.6%|9.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29531|29531|422|1.4%|6.6%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7164|7164|241|3.3%|3.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|171|0.0%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|148|0.0%|2.3%|
[alienvault_reputation](#alienvault_reputation)|180998|180998|45|0.0%|0.7%|
[openbl_90d](#openbl_90d)|9963|9963|20|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7887|7887|20|0.2%|0.3%|
[openbl](#openbl)|9963|9963|20|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|20|0.0%|0.3%|
[php_commenters](#php_commenters)|201|201|19|9.4%|0.2%|
[php_bad](#php_bad)|201|201|19|9.4%|0.2%|
[php_harvesters](#php_harvesters)|199|199|7|3.5%|0.1%|
[php_spammers](#php_spammers)|300|300|5|1.6%|0.0%|
[rosi_web_proxies](#rosi_web_proxies)|3441|3441|4|0.1%|0.0%|
[php_dictionary](#php_dictionary)|275|275|4|1.4%|0.0%|
[emerging_block](#emerging_block)|965|18065466|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|26020|26020|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.0%|
[rosi_connect_proxies](#rosi_connect_proxies)|1393|1393|1|0.0%|0.0%|
[nixspam](#nixspam)|20904|20904|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## tor_servers

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Mon May 25 11:20:06 UTC 2015.

The ipset `tor_servers` has **6501** entries, **6501** unique IPs.

The following table shows the overlaps of `tor_servers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `tor_servers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `tor_servers`.
- ` this % ` is the percentage **of this ipset (`tor_servers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[danmetor](#danmetor)|6499|6499|6499|100.0%|99.9%|
[tor](#tor)|6340|6340|5552|87.5%|85.4%|
[snort_ipfilter](#snort_ipfilter)|6448|6448|1046|16.2%|16.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|612|0.0%|9.4%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92481|92481|565|0.6%|8.6%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29531|29531|416|1.4%|6.3%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7164|7164|244|3.4%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|174|0.0%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|153|0.0%|2.3%|
[alienvault_reputation](#alienvault_reputation)|180998|180998|45|0.0%|0.6%|
[openbl_90d](#openbl_90d)|9963|9963|21|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7887|7887|21|0.2%|0.3%|
[openbl](#openbl)|9963|9963|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|20|0.0%|0.3%|
[php_commenters](#php_commenters)|201|201|19|9.4%|0.2%|
[php_bad](#php_bad)|201|201|19|9.4%|0.2%|
[php_harvesters](#php_harvesters)|199|199|7|3.5%|0.1%|
[rosi_web_proxies](#rosi_web_proxies)|3441|3441|4|0.1%|0.0%|
[php_spammers](#php_spammers)|300|300|4|1.3%|0.0%|
[emerging_block](#emerging_block)|965|18065466|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|26020|26020|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|275|275|3|1.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.0%|
[nixspam](#nixspam)|20904|20904|2|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.0%|
[rosi_connect_proxies](#rosi_connect_proxies)|1393|1393|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## zeus

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) default blocklist including hijacked sites and web hosting providers - **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist).

The last time downloaded was found to be dated: Mon May 25 11:35:58 UTC 2015.

The ipset `zeus` has **262** entries, **262** unique IPs.

The following table shows the overlaps of `zeus` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus`.
- ` this % ` is the percentage **of this ipset (`zeus`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[emerging_block](#emerging_block)|965|18065466|258|0.0%|98.4%|
[zeus_badips](#zeus_badips)|230|230|230|100.0%|87.7%|
[snort_ipfilter](#snort_ipfilter)|6448|6448|223|3.4%|85.1%|
[alienvault_reputation](#alienvault_reputation)|180998|180998|64|0.0%|24.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|19|0.0%|7.2%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|17|0.0%|6.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|3.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|7|0.0%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|7|0.0%|2.6%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|5|0.0%|1.9%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92481|92481|4|0.0%|1.5%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29531|29531|1|0.0%|0.3%|
[php_commenters](#php_commenters)|201|201|1|0.4%|0.3%|
[php_bad](#php_bad)|201|201|1|0.4%|0.3%|
[openbl_90d](#openbl_90d)|9963|9963|1|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7887|7887|1|0.0%|0.3%|
[openbl_30d](#openbl_30d)|4483|4483|1|0.0%|0.3%|
[openbl](#openbl)|9963|9963|1|0.0%|0.3%|
[compromised](#compromised)|2436|2436|1|0.0%|0.3%|
[bruteforceblocker](#bruteforceblocker)|2289|2289|1|0.0%|0.3%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) includes IPv4 addresses that are used by the ZeuS trojan

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Mon May 25 11:20:13 UTC 2015.

The ipset `zeus_badips` has **230** entries, **230** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|262|262|230|87.7%|100.0%|
[emerging_block](#emerging_block)|965|18065466|226|0.0%|98.2%|
[snort_ipfilter](#snort_ipfilter)|6448|6448|202|3.1%|87.8%|
[alienvault_reputation](#alienvault_reputation)|180998|180998|38|0.0%|16.5%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|17|0.0%|7.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|15|0.0%|6.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|7|0.0%|3.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|5|0.0%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|5|0.0%|2.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92481|92481|4|0.0%|1.7%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29531|29531|1|0.0%|0.4%|
[php_commenters](#php_commenters)|201|201|1|0.4%|0.4%|
[php_bad](#php_bad)|201|201|1|0.4%|0.4%|
[openbl_90d](#openbl_90d)|9963|9963|1|0.0%|0.4%|
[openbl_60d](#openbl_60d)|7887|7887|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|4483|4483|1|0.0%|0.4%|
[openbl](#openbl)|9963|9963|1|0.0%|0.4%|
[compromised](#compromised)|2436|2436|1|0.0%|0.4%|
[bruteforceblocker](#bruteforceblocker)|2289|2289|1|0.0%|0.4%|
