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

The following list was automatically generated on Tue May 26 19:23:02 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|181161 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|24092 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[tor_servers](#tor_servers)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6587 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD)|ipv4 hash:ip|2302 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|420 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[clean_mx_viruses](#clean_mx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|174 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6579 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|965 subnets, 18065466 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botnet](#et_botnet)|[EmergingThreats.net](http://www.emergingthreats.net/) botnet IPs|ipv4 hash:ip|515 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net](http://www.emergingthreats.net/) compromised hosts (seems to be a derivate of other lists)|ipv4 hash:ip|2436 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6340 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[feodo](#feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|61 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
[fullbogons](#fullbogons)|[Team-Cymru.org](http://www.team-cymru.org) IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user - **excellent list - use it only your internet interface**|ipv4 hash:net|3669 subnets, 670926040 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt)
geolite2_country|[MaxMind GeoLite2](http://dev.maxmind.com/geoip/geoip2/geolite2/) databases are free IP geolocation databases comparable to, but less accurate than, MaxMind’s GeoIP2 databases. They include IPs per country, IPs per continent, IPs used by anonymous services (VPNs, Proxies, etc) and Satellite Providers.|ipv4 hash:net|All the world|updated every 7 days  from [this link](http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country-CSV.zip)
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
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|25443 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
[openbl](#openbl)|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|9910 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt.gz)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|357 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_1days.txt.gz)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|4467 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt.gz)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7835 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt.gz)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|1038 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt.gz)
[openbl_90d](#openbl_90d)|[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|9910 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt.gz)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
[php_bad](#php_bad)|[projecthoneypot.org](http://www.projecthoneypot.org/) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|222 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|222 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|357 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|216 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|339 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1530 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|3850 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|51 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|6978 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|641 subnets, 18117120 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|55 subnets, 421120 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|328 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
[stop_forum_spam_1h](#stop_forum_spam_1h)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|7504 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stop_forum_spam_30d](#stop_forum_spam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|91335 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
[stop_forum_spam_7d](#stop_forum_spam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|29881 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10277 subnets, 10748 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) default blocklist including hijacked sites and web hosting providers - **excellent list**|ipv4 hash:ip|264 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) includes IPv4 addresses that are used by the ZeuS trojan|ipv4 hash:ip|228 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Tue May 26 17:00:27 UTC 2015.

The ipset `alienvault_reputation` has **181161** entries, **181161** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|15220|0.0%|8.4%|
[openbl_90d](#openbl_90d)|9910|9910|9883|99.7%|5.4%|
[openbl](#openbl)|9910|9910|9883|99.7%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|8411|0.0%|4.6%|
[openbl_60d](#openbl_60d)|7835|7835|7813|99.7%|4.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|5382|0.0%|2.9%|
[et_block](#et_block)|965|18065466|4763|0.0%|2.6%|
[openbl_30d](#openbl_30d)|4467|4467|4453|99.6%|2.4%|
[dshield](#dshield)|20|5120|4100|80.0%|2.2%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|1624|0.0%|0.8%|
[et_compromised](#et_compromised)|2436|2436|1592|65.3%|0.8%|
[bruteforceblocker](#bruteforceblocker)|2302|2302|1442|62.6%|0.7%|
[blocklist_de](#blocklist_de)|24092|24092|1298|5.3%|0.7%|
[openbl_7d](#openbl_7d)|1038|1038|1029|99.1%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|519|0.0%|0.2%|
[ciarmy](#ciarmy)|420|420|410|97.6%|0.2%|
[openbl_1d](#openbl_1d)|357|357|355|99.4%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|282|0.0%|0.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|91335|91335|236|0.2%|0.1%|
[voipbl](#voipbl)|10277|10748|200|1.8%|0.1%|
[infiltrated](#infiltrated)|10520|10520|146|1.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6978|6978|118|1.6%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29881|29881|115|0.3%|0.0%|
[zeus](#zeus)|264|264|65|24.6%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7504|7504|56|0.7%|0.0%|
[shunlist](#shunlist)|51|51|50|98.0%|0.0%|
[nixspam](#nixspam)|25443|25443|47|0.1%|0.0%|
[dm_tor](#dm_tor)|6579|6579|45|0.6%|0.0%|
[et_tor](#et_tor)|6340|6340|44|0.6%|0.0%|
[zeus_badips](#zeus_badips)|228|228|36|15.7%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|16|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[php_commenters](#php_commenters)|222|222|11|4.9%|0.0%|
[php_bad](#php_bad)|222|222|11|4.9%|0.0%|
[malc0de](#malc0de)|418|418|11|2.6%|0.0%|
[php_harvesters](#php_harvesters)|216|216|9|4.1%|0.0%|
[sslbl](#sslbl)|328|328|7|2.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[php_dictionary](#php_dictionary)|357|357|6|1.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|6|0.4%|0.0%|
[php_spammers](#php_spammers)|339|339|3|0.8%|0.0%|
[et_botnet](#et_botnet)|515|515|3|0.5%|0.0%|
[ri_web_proxies](#ri_web_proxies)|3850|3850|2|0.0%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|174|174|2|1.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1530|1530|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[feodo](#feodo)|61|61|1|1.6%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Tue May 26 19:10:03 UTC 2015.

The ipset `blocklist_de` has **24092** entries, **24092** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|2861|0.0%|11.8%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|91335|91335|2699|2.9%|11.2%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29881|29881|2309|7.7%|9.5%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7504|7504|1481|19.7%|6.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|1475|0.0%|6.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|1423|0.0%|5.9%|
[alienvault_reputation](#alienvault_reputation)|181161|181161|1298|0.7%|5.3%|
[nixspam](#nixspam)|25443|25443|1082|4.2%|4.4%|
[openbl_90d](#openbl_90d)|9910|9910|1049|10.5%|4.3%|
[openbl](#openbl)|9910|9910|1049|10.5%|4.3%|
[openbl_60d](#openbl_60d)|7835|7835|1018|12.9%|4.2%|
[openbl_30d](#openbl_30d)|4467|4467|932|20.8%|3.8%|
[bruteforceblocker](#bruteforceblocker)|2302|2302|807|35.0%|3.3%|
[et_compromised](#et_compromised)|2436|2436|707|29.0%|2.9%|
[openbl_7d](#openbl_7d)|1038|1038|612|58.9%|2.5%|
[ri_web_proxies](#ri_web_proxies)|3850|3850|395|10.2%|1.6%|
[infiltrated](#infiltrated)|10520|10520|258|2.4%|1.0%|
[snort_ipfilter](#snort_ipfilter)|6978|6978|245|3.5%|1.0%|
[openbl_1d](#openbl_1d)|357|357|220|61.6%|0.9%|
[et_block](#et_block)|965|18065466|182|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|181|0.0%|0.7%|
[ri_connect_proxies](#ri_connect_proxies)|1530|1530|95|6.2%|0.3%|
[php_dictionary](#php_dictionary)|357|357|95|26.6%|0.3%|
[php_spammers](#php_spammers)|339|339|83|24.4%|0.3%|
[php_commenters](#php_commenters)|222|222|73|32.8%|0.3%|
[php_bad](#php_bad)|222|222|73|32.8%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|54|0.0%|0.2%|
[dshield](#dshield)|20|5120|52|1.0%|0.2%|
[ciarmy](#ciarmy)|420|420|47|11.1%|0.1%|
[voipbl](#voipbl)|10277|10748|46|0.4%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|40|0.0%|0.1%|
[php_harvesters](#php_harvesters)|216|216|28|12.9%|0.1%|
[dm_tor](#dm_tor)|6579|6579|23|0.3%|0.0%|
[et_tor](#et_tor)|6340|6340|21|0.3%|0.0%|
[shunlist](#shunlist)|51|51|11|21.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|5|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|3|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|

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
[fullbogons](#fullbogons)|3669|670926040|592708608|88.3%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|4194304|3.0%|0.7%|
[voipbl](#voipbl)|10277|10748|351|3.2%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|91335|91335|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|216|216|1|0.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2302|2302|1|0.0%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD)

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Tue May 26 17:00:23 UTC 2015.

The ipset `bruteforceblocker` has **2302** entries, **2302** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_compromised](#et_compromised)|2436|2436|2103|86.3%|91.3%|
[alienvault_reputation](#alienvault_reputation)|181161|181161|1442|0.7%|62.6%|
[openbl_90d](#openbl_90d)|9910|9910|1362|13.7%|59.1%|
[openbl](#openbl)|9910|9910|1362|13.7%|59.1%|
[openbl_60d](#openbl_60d)|7835|7835|1352|17.2%|58.7%|
[openbl_30d](#openbl_30d)|4467|4467|1297|29.0%|56.3%|
[blocklist_de](#blocklist_de)|24092|24092|807|3.3%|35.0%|
[openbl_7d](#openbl_7d)|1038|1038|519|50.0%|22.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|221|0.0%|9.6%|
[openbl_1d](#openbl_1d)|357|357|206|57.7%|8.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|143|0.0%|6.2%|
[et_block](#et_block)|965|18065466|94|0.0%|4.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|92|0.0%|3.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|71|0.0%|3.0%|
[dshield](#dshield)|20|5120|33|0.6%|1.4%|
[shunlist](#shunlist)|51|51|10|19.6%|0.4%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|91335|91335|5|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29881|29881|2|0.0%|0.0%|
[infiltrated](#infiltrated)|10520|10520|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|228|228|1|0.4%|0.0%|
[zeus](#zeus)|264|264|1|0.3%|0.0%|
[voipbl](#voipbl)|10277|10748|1|0.0%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7504|7504|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6978|6978|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3669|670926040|1|0.0%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Tue May 26 18:15:06 UTC 2015.

The ipset `ciarmy` has **420** entries, **420** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|181161|181161|410|0.2%|97.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|75|0.0%|17.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|52|0.0%|12.3%|
[blocklist_de](#blocklist_de)|24092|24092|47|0.1%|11.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|26|0.0%|6.1%|
[voipbl](#voipbl)|10277|10748|3|0.0%|0.7%|
[et_block](#et_block)|965|18065466|3|0.0%|0.7%|
[dshield](#dshield)|20|5120|2|0.0%|0.4%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|91335|91335|1|0.0%|0.2%|
[openbl_90d](#openbl_90d)|9910|9910|1|0.0%|0.2%|
[openbl_7d](#openbl_7d)|1038|1038|1|0.0%|0.2%|
[openbl_60d](#openbl_60d)|7835|7835|1|0.0%|0.2%|
[openbl_30d](#openbl_30d)|4467|4467|1|0.0%|0.2%|
[openbl](#openbl)|9910|9910|1|0.0%|0.2%|
[nixspam](#nixspam)|25443|25443|1|0.0%|0.2%|

## clean_mx_viruses

[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses

Source is downloaded from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive).

The last time downloaded was found to be dated: Tue May 26 15:20:39 UTC 2015.

The ipset `clean_mx_viruses` has **174** entries, **174** unique IPs.

The following table shows the overlaps of `clean_mx_viruses` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `clean_mx_viruses`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `clean_mx_viruses`.
- ` this % ` is the percentage **of this ipset (`clean_mx_viruses`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|25|0.0%|14.3%|
[malc0de](#malc0de)|418|418|13|3.1%|7.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|6|0.0%|3.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|4|0.0%|2.2%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|3|0.2%|1.7%|
[alienvault_reputation](#alienvault_reputation)|181161|181161|2|0.0%|1.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|1|0.0%|0.5%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Tue May 26 18:53:16 UTC 2015.

The ipset `dm_tor` has **6579** entries, **6579** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_tor](#et_tor)|6340|6340|5437|85.7%|82.6%|
[snort_ipfilter](#snort_ipfilter)|6978|6978|1051|15.0%|15.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|604|0.0%|9.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|91335|91335|565|0.6%|8.5%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29881|29881|423|1.4%|6.4%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7504|7504|259|3.4%|3.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|174|0.0%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|155|0.0%|2.3%|
[infiltrated](#infiltrated)|10520|10520|67|0.6%|1.0%|
[alienvault_reputation](#alienvault_reputation)|181161|181161|45|0.0%|0.6%|
[php_commenters](#php_commenters)|222|222|25|11.2%|0.3%|
[php_bad](#php_bad)|222|222|25|11.2%|0.3%|
[blocklist_de](#blocklist_de)|24092|24092|23|0.0%|0.3%|
[openbl_90d](#openbl_90d)|9910|9910|21|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7835|7835|21|0.2%|0.3%|
[openbl](#openbl)|9910|9910|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|20|0.0%|0.3%|
[php_harvesters](#php_harvesters)|216|216|7|3.2%|0.1%|
[php_spammers](#php_spammers)|339|339|5|1.4%|0.0%|
[nixspam](#nixspam)|25443|25443|5|0.0%|0.0%|
[et_block](#et_block)|965|18065466|4|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|3850|3850|3|0.0%|0.0%|
[php_dictionary](#php_dictionary)|357|357|3|0.8%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1530|1530|2|0.1%|0.0%|
[voipbl](#voipbl)|10277|10748|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Tue May 26 18:26:30 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|181161|181161|4100|2.2%|80.0%|
[et_block](#et_block)|965|18065466|1281|0.0%|25.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|1280|0.0%|25.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|256|0.0%|5.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|78|0.0%|1.5%|
[openbl_90d](#openbl_90d)|9910|9910|58|0.5%|1.1%|
[openbl](#openbl)|9910|9910|58|0.5%|1.1%|
[blocklist_de](#blocklist_de)|24092|24092|52|0.2%|1.0%|
[openbl_60d](#openbl_60d)|7835|7835|46|0.5%|0.8%|
[openbl_30d](#openbl_30d)|4467|4467|44|0.9%|0.8%|
[openbl_7d](#openbl_7d)|1038|1038|38|3.6%|0.7%|
[bruteforceblocker](#bruteforceblocker)|2302|2302|33|1.4%|0.6%|
[et_compromised](#et_compromised)|2436|2436|23|0.9%|0.4%|
[openbl_1d](#openbl_1d)|357|357|22|6.1%|0.4%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|91335|91335|6|0.0%|0.1%|
[infiltrated](#infiltrated)|10520|10520|6|0.0%|0.1%|
[voipbl](#voipbl)|10277|10748|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|4|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29881|29881|3|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6978|6978|3|0.0%|0.0%|
[ciarmy](#ciarmy)|420|420|2|0.4%|0.0%|
[zeus](#zeus)|264|264|1|0.3%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7504|7504|1|0.0%|0.0%|
[nixspam](#nixspam)|25443|25443|1|0.0%|0.0%|
[malc0de](#malc0de)|418|418|1|0.2%|0.0%|
[et_tor](#et_tor)|6340|6340|1|0.0%|0.0%|
[et_botnet](#et_botnet)|515|515|1|0.1%|0.0%|
[dm_tor](#dm_tor)|6579|6579|1|0.0%|0.0%|

## et_block

[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)

Source is downloaded from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt).

The last time downloaded was found to be dated: Fri May 22 04:30:01 UTC 2015.

The ipset `et_block` has **965** entries, **18065466** unique IPs.

The following table shows the overlaps of `et_block` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_block`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_block`.
- ` this % ` is the percentage **of this ipset (`et_block`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[spamhaus_drop](#spamhaus_drop)|641|18117120|17994240|99.3%|99.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|8401701|2.4%|46.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7277056|79.2%|40.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|2133264|0.2%|11.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|192343|0.1%|1.0%|
[fullbogons](#fullbogons)|3669|670926040|20480|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|181161|181161|4763|2.6%|0.0%|
[dshield](#dshield)|20|5120|1281|25.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|1029|0.3%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|91335|91335|758|0.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|517|0.1%|0.0%|
[openbl_90d](#openbl_90d)|9910|9910|452|4.5%|0.0%|
[openbl](#openbl)|9910|9910|452|4.5%|0.0%|
[openbl_60d](#openbl_60d)|7835|7835|312|3.9%|0.0%|
[nixspam](#nixspam)|25443|25443|299|1.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6978|6978|282|4.0%|0.0%|
[zeus](#zeus)|264|264|256|96.9%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29881|29881|227|0.7%|0.0%|
[zeus_badips](#zeus_badips)|228|228|224|98.2%|0.0%|
[openbl_30d](#openbl_30d)|4467|4467|215|4.8%|0.0%|
[blocklist_de](#blocklist_de)|24092|24092|182|0.7%|0.0%|
[openbl_7d](#openbl_7d)|1038|1038|95|9.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2302|2302|94|4.0%|0.0%|
[et_compromised](#et_compromised)|2436|2436|77|3.1%|0.0%|
[infiltrated](#infiltrated)|10520|10520|65|0.6%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7504|7504|59|0.7%|0.0%|
[feodo](#feodo)|61|61|56|91.8%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|28|2.1%|0.0%|
[openbl_1d](#openbl_1d)|357|357|27|7.5%|0.0%|
[php_commenters](#php_commenters)|222|222|24|10.8%|0.0%|
[php_bad](#php_bad)|222|222|24|10.8%|0.0%|
[sslbl](#sslbl)|328|328|22|6.7%|0.0%|
[voipbl](#voipbl)|10277|10748|18|0.1%|0.0%|
[palevo](#palevo)|13|13|13|100.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|10|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[et_tor](#et_tor)|6340|6340|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6579|6579|4|0.0%|0.0%|
[ciarmy](#ciarmy)|420|420|3|0.7%|0.0%|
[php_spammers](#php_spammers)|339|339|2|0.5%|0.0%|
[php_harvesters](#php_harvesters)|216|216|2|0.9%|0.0%|
[php_dictionary](#php_dictionary)|357|357|2|0.5%|0.0%|
[malc0de](#malc0de)|418|418|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_botnet](#et_botnet)|515|515|1|0.1%|0.0%|

## et_botnet

[EmergingThreats.net](http://www.emergingthreats.net/) botnet IPs

Source is downloaded from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules).

The last time downloaded was found to be dated: Fri May 22 04:30:01 UTC 2015.

The ipset `et_botnet` has **515** entries, **515** unique IPs.

The following table shows the overlaps of `et_botnet` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_botnet`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_botnet`.
- ` this % ` is the percentage **of this ipset (`et_botnet`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|76|0.0%|14.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|42|0.0%|8.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|24|0.0%|4.6%|
[alienvault_reputation](#alienvault_reputation)|181161|181161|3|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[et_block](#et_block)|965|18065466|1|0.0%|0.1%|
[dshield](#dshield)|20|5120|1|0.0%|0.1%|

## et_compromised

[EmergingThreats.net](http://www.emergingthreats.net/) compromised hosts (seems to be a derivate of other lists)

Source is downloaded from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt).

The last time downloaded was found to be dated: Fri May 22 04:30:09 UTC 2015.

The ipset `et_compromised` has **2436** entries, **2436** unique IPs.

The following table shows the overlaps of `et_compromised` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_compromised`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_compromised`.
- ` this % ` is the percentage **of this ipset (`et_compromised`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bruteforceblocker](#bruteforceblocker)|2302|2302|2103|91.3%|86.3%|
[alienvault_reputation](#alienvault_reputation)|181161|181161|1592|0.8%|65.3%|
[openbl_90d](#openbl_90d)|9910|9910|1482|14.9%|60.8%|
[openbl](#openbl)|9910|9910|1482|14.9%|60.8%|
[openbl_60d](#openbl_60d)|7835|7835|1471|18.7%|60.3%|
[openbl_30d](#openbl_30d)|4467|4467|1328|29.7%|54.5%|
[blocklist_de](#blocklist_de)|24092|24092|707|2.9%|29.0%|
[openbl_7d](#openbl_7d)|1038|1038|475|45.7%|19.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|243|0.0%|9.9%|
[openbl_1d](#openbl_1d)|357|357|198|55.4%|8.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|153|0.0%|6.2%|
[et_block](#et_block)|965|18065466|77|0.0%|3.1%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|76|0.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|75|0.0%|3.0%|
[dshield](#dshield)|20|5120|23|0.4%|0.9%|
[shunlist](#shunlist)|51|51|9|17.6%|0.3%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|91335|91335|5|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.1%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29881|29881|3|0.0%|0.1%|
[infiltrated](#infiltrated)|10520|10520|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|228|228|1|0.4%|0.0%|
[zeus](#zeus)|264|264|1|0.3%|0.0%|
[voipbl](#voipbl)|10277|10748|1|0.0%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7504|7504|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6978|6978|1|0.0%|0.0%|
[nixspam](#nixspam)|25443|25443|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|1|0.0%|0.0%|

## et_tor

[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs

Source is downloaded from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules).

The last time downloaded was found to be dated: Fri May 22 04:30:09 UTC 2015.

The ipset `et_tor` has **6340** entries, **6340** unique IPs.

The following table shows the overlaps of `et_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_tor`.
- ` this % ` is the percentage **of this ipset (`et_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[dm_tor](#dm_tor)|6579|6579|5437|82.6%|85.7%|
[snort_ipfilter](#snort_ipfilter)|6978|6978|991|14.2%|15.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|602|0.0%|9.4%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|91335|91335|570|0.6%|8.9%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29881|29881|427|1.4%|6.7%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7504|7504|251|3.3%|3.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|171|0.0%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|148|0.0%|2.3%|
[infiltrated](#infiltrated)|10520|10520|69|0.6%|1.0%|
[alienvault_reputation](#alienvault_reputation)|181161|181161|44|0.0%|0.6%|
[php_commenters](#php_commenters)|222|222|24|10.8%|0.3%|
[php_bad](#php_bad)|222|222|24|10.8%|0.3%|
[blocklist_de](#blocklist_de)|24092|24092|21|0.0%|0.3%|
[openbl_90d](#openbl_90d)|9910|9910|20|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7835|7835|20|0.2%|0.3%|
[openbl](#openbl)|9910|9910|20|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|20|0.0%|0.3%|
[php_harvesters](#php_harvesters)|216|216|7|3.2%|0.1%|
[php_spammers](#php_spammers)|339|339|5|1.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|3850|3850|4|0.1%|0.0%|
[php_dictionary](#php_dictionary)|357|357|4|1.1%|0.0%|
[et_block](#et_block)|965|18065466|4|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.0%|
[nixspam](#nixspam)|25443|25443|2|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.0%|
[voipbl](#voipbl)|10277|10748|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1530|1530|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Tue May 26 18:53:30 UTC 2015.

The ipset `feodo` has **61** entries, **61** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|965|18065466|56|0.0%|91.8%|
[snort_ipfilter](#snort_ipfilter)|6978|6978|47|0.6%|77.0%|
[sslbl](#sslbl)|328|328|20|6.0%|32.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|3|0.0%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|3|0.0%|4.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|3|0.0%|4.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|1|0.0%|1.6%|
[alienvault_reputation](#alienvault_reputation)|181161|181161|1|0.0%|1.6%|

## fullbogons

[Team-Cymru.org](http://www.team-cymru.org) IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user - **excellent list - use it only your internet interface**

Source is downloaded from [this link](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt).

The last time downloaded was found to be dated: Tue May 26 09:35:09 UTC 2015.

The ipset `fullbogons` has **3669** entries, **670926040** unique IPs.

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
[et_block](#et_block)|965|18065466|20480|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|871|0.2%|0.0%|
[voipbl](#voipbl)|10277|10748|351|3.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|33|2.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|9|0.7%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|91335|91335|3|0.0%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29881|29881|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|216|216|1|0.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2302|2302|1|0.0%|0.0%|

## ib_bluetack_badpeers

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) IPs that have been reported for bad deeds in p2p

Source is downloaded from [this link](http://list.iblocklist.com/?list=cwworuawihqvocglcoss&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Tue May 26 03:01:09 UTC 2015.

The ipset `ib_bluetack_badpeers` has **48134** entries, **48134** unique IPs.

The following table shows the overlaps of `ib_bluetack_badpeers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_badpeers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_badpeers`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_badpeers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|1172|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|366|0.0%|0.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|233|0.0%|0.4%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|91335|91335|14|0.0%|0.0%|
[fullbogons](#fullbogons)|3669|670926040|14|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|181161|181161|14|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.0%|
[nixspam](#nixspam)|25443|25443|10|0.0%|0.0%|
[infiltrated](#infiltrated)|10520|10520|10|0.0%|0.0%|
[et_block](#et_block)|965|18065466|10|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|6|0.0%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29881|29881|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|4|0.0%|0.0%|
[dshield](#dshield)|20|5120|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|24092|24092|3|0.0%|0.0%|
[voipbl](#voipbl)|10277|10748|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|216|216|2|0.9%|0.0%|
[php_dictionary](#php_dictionary)|357|357|2|0.5%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6978|6978|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|3850|3850|1|0.0%|0.0%|
[php_spammers](#php_spammers)|339|339|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## ib_bluetack_hijacked

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) hijacked IP-Blocks Hijacked IP space are IP blocks that are being used without permission

Source is downloaded from [this link](http://list.iblocklist.com/?list=usrcshglbiilevmyfhse&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Tue May 26 03:30:08 UTC 2015.

The ipset `ib_bluetack_hijacked` has **535** entries, **9177856** unique IPs.

The following table shows the overlaps of `ib_bluetack_hijacked` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_hijacked`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_hijacked`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_hijacked`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|965|18065466|7277056|40.2%|79.2%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|7211008|39.8%|78.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|2526624|0.7%|27.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|904787|0.1%|9.8%|
[fullbogons](#fullbogons)|3669|670926040|565248|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|145472|0.1%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|1024|0.3%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|91335|91335|725|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|181161|181161|519|0.2%|0.0%|
[nixspam](#nixspam)|25443|25443|299|1.1%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29881|29881|207|0.6%|0.0%|
[blocklist_de](#blocklist_de)|24092|24092|54|0.2%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7504|7504|34|0.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|27|2.1%|0.0%|
[openbl_90d](#openbl_90d)|9910|9910|19|0.1%|0.0%|
[openbl](#openbl)|9910|9910|19|0.1%|0.0%|
[openbl_60d](#openbl_60d)|7835|7835|18|0.2%|0.0%|
[openbl_30d](#openbl_30d)|4467|4467|13|0.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6978|6978|11|0.1%|0.0%|
[zeus_badips](#zeus_badips)|228|228|10|4.3%|0.0%|
[zeus](#zeus)|264|264|10|3.7%|0.0%|
[openbl_7d](#openbl_7d)|1038|1038|9|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[infiltrated](#infiltrated)|10520|10520|6|0.0%|0.0%|
[openbl_1d](#openbl_1d)|357|357|5|1.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2302|2302|5|0.2%|0.0%|
[et_compromised](#et_compromised)|2436|2436|4|0.1%|0.0%|
[dm_tor](#dm_tor)|6579|6579|3|0.0%|0.0%|
[php_spammers](#php_spammers)|339|339|2|0.5%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6340|6340|2|0.0%|0.0%|
[voipbl](#voipbl)|10277|10748|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|216|216|1|0.4%|0.0%|
[et_botnet](#et_botnet)|515|515|1|0.1%|0.0%|

## ib_bluetack_level1

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Level 1 (for use in p2p): Companies or organizations who are clearly involved with trying to stop filesharing (e.g. Baytsp, MediaDefender, Mediasentry a.o.). Companies which anti-p2p activity has been seen from. Companies that produce or have a strong financial interest in copyrighted material (e.g. music, movie, software industries a.o.). Government ranges or companies that have a strong financial interest in doing work for governments. Legal industry ranges. IPs or ranges of ISPs from which anti-p2p activity has been observed. Basically this list will block all kinds of internet connections that most people would rather not have during their internet travels.

Source is downloaded from [this link](http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Tue May 26 09:37:32 UTC 2015.

The ipset `ib_bluetack_level1` has **215693** entries, **765044590** unique IPs.

The following table shows the overlaps of `ib_bluetack_level1` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level1`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level1`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level1`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|16309487|4.6%|2.1%|
[et_block](#et_block)|965|18065466|2133264|11.8%|0.2%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2132981|11.7%|0.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|1357462|0.9%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904787|9.8%|0.1%|
[fullbogons](#fullbogons)|3669|670926040|235379|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|33152|7.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|12921|3.8%|0.0%|
[alienvault_reputation](#alienvault_reputation)|181161|181161|5382|2.9%|0.0%|
[blocklist_de](#blocklist_de)|24092|24092|1475|6.1%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|91335|91335|1312|1.4%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29881|29881|493|1.6%|0.0%|
[nixspam](#nixspam)|25443|25443|424|1.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|366|0.7%|0.0%|
[infiltrated](#infiltrated)|10520|10520|318|3.0%|0.0%|
[voipbl](#voipbl)|10277|10748|283|2.6%|0.0%|
[openbl_90d](#openbl_90d)|9910|9910|216|2.1%|0.0%|
[openbl](#openbl)|9910|9910|216|2.1%|0.0%|
[openbl_60d](#openbl_60d)|7835|7835|178|2.2%|0.0%|
[dm_tor](#dm_tor)|6579|6579|155|2.3%|0.0%|
[et_tor](#et_tor)|6340|6340|148|2.3%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7504|7504|112|1.4%|0.0%|
[openbl_30d](#openbl_30d)|4467|4467|99|2.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|90|6.1%|0.0%|
[dshield](#dshield)|20|5120|78|1.5%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6978|6978|77|1.1%|0.0%|
[et_compromised](#et_compromised)|2436|2436|75|3.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2302|2302|71|3.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|3850|3850|61|1.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|60|4.6%|0.0%|
[et_botnet](#et_botnet)|515|515|42|8.1%|0.0%|
[ciarmy](#ciarmy)|420|420|26|6.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1530|1530|23|1.5%|0.0%|
[openbl_7d](#openbl_7d)|1038|1038|20|1.9%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|18|2.6%|0.0%|
[malc0de](#malc0de)|418|418|11|2.6%|0.0%|
[php_dictionary](#php_dictionary)|357|357|8|2.2%|0.0%|
[zeus](#zeus)|264|264|7|2.6%|0.0%|
[openbl_1d](#openbl_1d)|357|357|7|1.9%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|174|174|6|3.4%|0.0%|
[zeus_badips](#zeus_badips)|228|228|4|1.7%|0.0%|
[sslbl](#sslbl)|328|328|3|0.9%|0.0%|
[php_harvesters](#php_harvesters)|216|216|3|1.3%|0.0%|
[php_commenters](#php_commenters)|222|222|3|1.3%|0.0%|
[php_bad](#php_bad)|222|222|3|1.3%|0.0%|
[feodo](#feodo)|61|61|3|4.9%|0.0%|
[php_spammers](#php_spammers)|339|339|2|0.5%|0.0%|

## ib_bluetack_level2

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 2 (for use in p2p). General corporate ranges. Ranges used by labs or researchers. Proxies.

Source is downloaded from [this link](http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Tue May 26 03:30:32 UTC 2015.

The ipset `ib_bluetack_level2` has **75927** entries, **348729520** unique IPs.

The following table shows the overlaps of `ib_bluetack_level2` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level2`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level2`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level2`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|16309487|2.1%|4.6%|
[et_block](#et_block)|965|18065466|8401701|46.5%|2.4%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|8401433|46.3%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|2831962|2.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2526624|27.5%|0.7%|
[fullbogons](#fullbogons)|3669|670926040|248322|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|33368|7.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|181161|181161|8411|4.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|7629|2.2%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|91335|91335|2423|2.6%|0.0%|
[blocklist_de](#blocklist_de)|24092|24092|1423|5.9%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29881|29881|864|2.8%|0.0%|
[nixspam](#nixspam)|25443|25443|731|2.8%|0.0%|
[openbl_90d](#openbl_90d)|9910|9910|516|5.2%|0.0%|
[openbl](#openbl)|9910|9910|516|5.2%|0.0%|
[voipbl](#voipbl)|10277|10748|428|3.9%|0.0%|
[infiltrated](#infiltrated)|10520|10520|412|3.9%|0.0%|
[openbl_60d](#openbl_60d)|7835|7835|368|4.6%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7504|7504|265|3.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|233|0.4%|0.0%|
[openbl_30d](#openbl_30d)|4467|4467|227|5.0%|0.0%|
[dm_tor](#dm_tor)|6579|6579|174|2.6%|0.0%|
[et_tor](#et_tor)|6340|6340|171|2.6%|0.0%|
[et_compromised](#et_compromised)|2436|2436|153|6.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2302|2302|143|6.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|3850|3850|141|3.6%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6978|6978|104|1.4%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1530|1530|72|4.7%|0.0%|
[ciarmy](#ciarmy)|420|420|52|12.3%|0.0%|
[openbl_7d](#openbl_7d)|1038|1038|47|4.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|43|2.9%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|28|4.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|26|2.0%|0.0%|
[malc0de](#malc0de)|418|418|26|6.2%|0.0%|
[php_spammers](#php_spammers)|339|339|25|7.3%|0.0%|
[et_botnet](#et_botnet)|515|515|24|4.6%|0.0%|
[openbl_1d](#openbl_1d)|357|357|17|4.7%|0.0%|
[zeus](#zeus)|264|264|9|3.4%|0.0%|
[php_dictionary](#php_dictionary)|357|357|9|2.5%|0.0%|
[zeus_badips](#zeus_badips)|228|228|8|3.5%|0.0%|
[php_harvesters](#php_harvesters)|216|216|7|3.2%|0.0%|
[php_commenters](#php_commenters)|222|222|6|2.7%|0.0%|
[php_bad](#php_bad)|222|222|6|2.7%|0.0%|
[sslbl](#sslbl)|328|328|5|1.5%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|174|174|4|2.2%|0.0%|
[shunlist](#shunlist)|51|51|3|5.8%|0.0%|
[feodo](#feodo)|61|61|3|4.9%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|

## ib_bluetack_level3

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 3 (for use in p2p). Many portal-type websites. ISP ranges that may be dodgy for some reason. Ranges that belong to an individual, but which have not been determined to be used by a particular company. Ranges for things that are unusual in some way. The L3 list is aka the paranoid list.

Source is downloaded from [this link](http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Tue May 26 03:30:41 UTC 2015.

The ipset `ib_bluetack_level3` has **18550** entries, **139108857** unique IPs.

The following table shows the overlaps of `ib_bluetack_level3` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level3`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level3`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level3`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[fullbogons](#fullbogons)|3669|670926040|4233774|0.6%|3.0%|
[bogons](#bogons)|13|592708608|4194304|0.7%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|2831962|0.8%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|1357462|0.1%|0.9%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|270785|64.3%|0.1%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|195904|1.0%|0.1%|
[et_block](#et_block)|965|18065466|192343|1.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[alienvault_reputation](#alienvault_reputation)|181161|181161|15220|8.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|8958|2.6%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|91335|91335|6141|6.7%|0.0%|
[blocklist_de](#blocklist_de)|24092|24092|2861|11.8%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29881|29881|2035|6.8%|0.0%|
[nixspam](#nixspam)|25443|25443|1800|7.0%|0.0%|
[voipbl](#voipbl)|10277|10748|1584|14.7%|0.0%|
[dshield](#dshield)|20|5120|1280|25.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1172|2.4%|0.0%|
[openbl_90d](#openbl_90d)|9910|9910|959|9.6%|0.0%|
[openbl](#openbl)|9910|9910|959|9.6%|0.0%|
[openbl_60d](#openbl_60d)|7835|7835|715|9.1%|0.0%|
[infiltrated](#infiltrated)|10520|10520|655|6.2%|0.0%|
[dm_tor](#dm_tor)|6579|6579|604|9.1%|0.0%|
[et_tor](#et_tor)|6340|6340|602|9.4%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7504|7504|532|7.0%|0.0%|
[openbl_30d](#openbl_30d)|4467|4467|439|9.8%|0.0%|
[et_compromised](#et_compromised)|2436|2436|243|9.9%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2302|2302|221|9.6%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6978|6978|209|2.9%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|146|11.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|3850|3850|123|3.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|110|7.5%|0.0%|
[openbl_7d](#openbl_7d)|1038|1038|89|8.5%|0.0%|
[malc0de](#malc0de)|418|418|77|18.4%|0.0%|
[et_botnet](#et_botnet)|515|515|76|14.7%|0.0%|
[ciarmy](#ciarmy)|420|420|75|17.8%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|51|7.5%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1530|1530|31|2.0%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|174|174|25|14.3%|0.0%|
[zeus](#zeus)|264|264|20|7.5%|0.0%|
[php_spammers](#php_spammers)|339|339|20|5.8%|0.0%|
[openbl_1d](#openbl_1d)|357|357|20|5.6%|0.0%|
[php_dictionary](#php_dictionary)|357|357|19|5.3%|0.0%|
[sslbl](#sslbl)|328|328|17|5.1%|0.0%|
[zeus_badips](#zeus_badips)|228|228|14|6.1%|0.0%|
[php_harvesters](#php_harvesters)|216|216|14|6.4%|0.0%|
[php_commenters](#php_commenters)|222|222|11|4.9%|0.0%|
[php_bad](#php_bad)|222|222|11|4.9%|0.0%|
[shunlist](#shunlist)|51|51|6|11.7%|0.0%|
[feodo](#feodo)|61|61|3|4.9%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|

## ib_bluetack_proxies

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Open Proxies IPs list (without TOR)

Source is downloaded from [this link](http://list.iblocklist.com/?list=xoebmbyexwuiogmbyprb&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Tue May 26 03:30:06 UTC 2015.

The ipset `ib_bluetack_proxies` has **673** entries, **673** unique IPs.

The following table shows the overlaps of `ib_bluetack_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_proxies`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|51|0.0%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|28|0.0%|4.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|91335|91335|24|0.0%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|18|0.0%|2.6%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29881|29881|14|0.0%|2.0%|
[infiltrated](#infiltrated)|10520|10520|13|0.1%|1.9%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|11|0.0%|1.6%|
[ri_web_proxies](#ri_web_proxies)|3850|3850|10|0.2%|1.4%|
[ri_connect_proxies](#ri_connect_proxies)|1530|1530|6|0.3%|0.8%|
[blocklist_de](#blocklist_de)|24092|24092|3|0.0%|0.4%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7504|7504|2|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.2%|
[nixspam](#nixspam)|25443|25443|2|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.2%|
[et_block](#et_block)|965|18065466|2|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|6978|6978|1|0.0%|0.1%|
[php_dictionary](#php_dictionary)|357|357|1|0.2%|0.1%|
[alienvault_reputation](#alienvault_reputation)|181161|181161|1|0.0%|0.1%|

## ib_bluetack_spyware

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) known malicious SPYWARE and ADWARE IP Address ranges

Source is downloaded from [this link](http://list.iblocklist.com/?list=llvtlsjyoyiczbkjsxpf&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Tue May 26 03:00:04 UTC 2015.

The ipset `ib_bluetack_spyware` has **898** entries, **336971** unique IPs.

The following table shows the overlaps of `ib_bluetack_spyware` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_spyware`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_spyware`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_spyware`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|12921|0.0%|3.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|8958|0.0%|2.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|7629|0.0%|2.2%|
[et_block](#et_block)|965|18065466|1029|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|1024|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1024|0.0%|0.3%|
[fullbogons](#fullbogons)|3669|670926040|871|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|181161|181161|282|0.1%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|91335|91335|42|0.0%|0.0%|
[infiltrated](#infiltrated)|10520|10520|26|0.2%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29881|29881|24|0.0%|0.0%|
[et_tor](#et_tor)|6340|6340|20|0.3%|0.0%|
[dm_tor](#dm_tor)|6579|6579|20|0.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|14|1.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6978|6978|11|0.1%|0.0%|
[nixspam](#nixspam)|25443|25443|10|0.0%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7504|7504|9|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[openbl_90d](#openbl_90d)|9910|9910|5|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7835|7835|5|0.0%|0.0%|
[openbl](#openbl)|9910|9910|5|0.0%|0.0%|
[blocklist_de](#blocklist_de)|24092|24092|5|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|3850|3850|4|0.1%|0.0%|
[openbl_30d](#openbl_30d)|4467|4467|4|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[dshield](#dshield)|20|5120|4|0.0%|0.0%|
[voipbl](#voipbl)|10277|10748|3|0.0%|0.0%|
[malc0de](#malc0de)|418|418|3|0.7%|0.0%|
[sslbl](#sslbl)|328|328|1|0.3%|0.0%|
[php_harvesters](#php_harvesters)|216|216|1|0.4%|0.0%|
[php_dictionary](#php_dictionary)|357|357|1|0.2%|0.0%|
[openbl_7d](#openbl_7d)|1038|1038|1|0.0%|0.0%|
[feodo](#feodo)|61|61|1|1.6%|0.0%|
[et_compromised](#et_compromised)|2436|2436|1|0.0%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|174|174|1|0.5%|0.0%|

## ib_bluetack_webexploit

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) web server hack and exploit attempts

Source is downloaded from [this link](http://list.iblocklist.com/?list=ghlzqtqxnzctvvajwwag&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Tue May 26 03:00:03 UTC 2015.

The ipset `ib_bluetack_webexploit` has **1460** entries, **1460** unique IPs.

The following table shows the overlaps of `ib_bluetack_webexploit` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_webexploit`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_webexploit`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_webexploit`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|110|0.0%|7.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|90|0.0%|6.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|43|0.0%|2.9%|
[fullbogons](#fullbogons)|3669|670926040|33|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|7|0.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[alienvault_reputation](#alienvault_reputation)|181161|181161|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|6|0.0%|0.4%|
[et_block](#et_block)|965|18065466|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|3|0.2%|0.2%|
[infiltrated](#infiltrated)|10520|10520|3|0.0%|0.2%|
[blocklist_de](#blocklist_de)|24092|24092|3|0.0%|0.2%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29881|29881|2|0.0%|0.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|91335|91335|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|6978|6978|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.1%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7504|7504|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|3850|3850|1|0.0%|0.0%|
[openbl_90d](#openbl_90d)|9910|9910|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|1038|1038|1|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7835|7835|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4467|4467|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|357|357|1|0.2%|0.0%|
[openbl](#openbl)|9910|9910|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_tor](#et_tor)|6340|6340|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2436|2436|1|0.0%|0.0%|
[et_botnet](#et_botnet)|515|515|1|0.1%|0.0%|
[dm_tor](#dm_tor)|6579|6579|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2302|2302|1|0.0%|0.0%|

## infiltrated

[infiltrated.net](http://www.infiltrated.net) (this list seems to be updated frequently, but we found no information about it)

Source is downloaded from [this link](http://www.infiltrated.net/blacklisted).

The last time downloaded was found to be dated: Tue May 26 17:00:21 UTC 2015.

The ipset `infiltrated` has **10520** entries, **10520** unique IPs.

The following table shows the overlaps of `infiltrated` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `infiltrated`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `infiltrated`.
- ` this % ` is the percentage **of this ipset (`infiltrated`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|655|0.0%|6.2%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|91335|91335|603|0.6%|5.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|412|0.0%|3.9%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29881|29881|327|1.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|318|0.0%|3.0%|
[blocklist_de](#blocklist_de)|24092|24092|258|1.0%|2.4%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7504|7504|187|2.4%|1.7%|
[nixspam](#nixspam)|25443|25443|161|0.6%|1.5%|
[alienvault_reputation](#alienvault_reputation)|181161|181161|146|0.0%|1.3%|
[snort_ipfilter](#snort_ipfilter)|6978|6978|140|2.0%|1.3%|
[php_dictionary](#php_dictionary)|357|357|106|29.6%|1.0%|
[php_spammers](#php_spammers)|339|339|100|29.4%|0.9%|
[php_harvesters](#php_harvesters)|216|216|80|37.0%|0.7%|
[et_tor](#et_tor)|6340|6340|69|1.0%|0.6%|
[dm_tor](#dm_tor)|6579|6579|67|1.0%|0.6%|
[et_block](#et_block)|965|18065466|65|0.0%|0.6%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|64|0.0%|0.6%|
[ri_web_proxies](#ri_web_proxies)|3850|3850|59|1.5%|0.5%|
[php_commenters](#php_commenters)|222|222|38|17.1%|0.3%|
[php_bad](#php_bad)|222|222|38|17.1%|0.3%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|37|0.0%|0.3%|
[openbl_90d](#openbl_90d)|9910|9910|29|0.2%|0.2%|
[openbl](#openbl)|9910|9910|29|0.2%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|26|0.0%|0.2%|
[openbl_60d](#openbl_60d)|7835|7835|25|0.3%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|13|1.9%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|10|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1530|1530|8|0.5%|0.0%|
[voipbl](#voipbl)|10277|10748|6|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6|0.0%|0.0%|
[dshield](#dshield)|20|5120|6|0.1%|0.0%|
[openbl_30d](#openbl_30d)|4467|4467|5|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.0%|
[openbl_7d](#openbl_7d)|1038|1038|2|0.1%|0.0%|
[et_compromised](#et_compromised)|2436|2436|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2302|2302|2|0.0%|0.0%|
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
[clean_mx_viruses](#clean_mx_viruses)|174|174|13|7.4%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|11|0.0%|2.6%|
[alienvault_reputation](#alienvault_reputation)|181161|181161|11|0.0%|2.6%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|4|0.3%|0.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|3|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.4%|
[et_block](#et_block)|965|18065466|2|0.0%|0.4%|
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
[et_block](#et_block)|965|18065466|28|0.0%|2.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|26|0.0%|2.0%|
[snort_ipfilter](#snort_ipfilter)|6978|6978|24|0.3%|1.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|14|0.0%|1.0%|
[fullbogons](#fullbogons)|3669|670926040|9|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|181161|181161|6|0.0%|0.4%|
[malc0de](#malc0de)|418|418|4|0.9%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.2%|
[clean_mx_viruses](#clean_mx_viruses)|174|174|3|1.7%|0.2%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|91335|91335|2|0.0%|0.1%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29881|29881|1|0.0%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7504|7504|1|0.0%|0.0%|
[nixspam](#nixspam)|25443|25443|1|0.0%|0.0%|
[infiltrated](#infiltrated)|10520|10520|1|0.0%|0.0%|
[et_botnet](#et_botnet)|515|515|1|0.1%|0.0%|
[blocklist_de](#blocklist_de)|24092|24092|1|0.0%|0.0%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Tue May 26 19:15:02 UTC 2015.

The ipset `nixspam` has **25443** entries, **25443** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|1800|0.0%|7.0%|
[blocklist_de](#blocklist_de)|24092|24092|1082|4.4%|4.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|731|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|424|0.0%|1.6%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|353|0.0%|1.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|299|0.0%|1.1%|
[et_block](#et_block)|965|18065466|299|0.0%|1.1%|
[snort_ipfilter](#snort_ipfilter)|6978|6978|237|3.3%|0.9%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|91335|91335|218|0.2%|0.8%|
[infiltrated](#infiltrated)|10520|10520|161|1.5%|0.6%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29881|29881|125|0.4%|0.4%|
[php_dictionary](#php_dictionary)|357|357|123|34.4%|0.4%|
[php_spammers](#php_spammers)|339|339|80|23.5%|0.3%|
[ri_web_proxies](#ri_web_proxies)|3850|3850|73|1.8%|0.2%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7504|7504|47|0.6%|0.1%|
[alienvault_reputation](#alienvault_reputation)|181161|181161|47|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|10|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|10|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1530|1530|9|0.5%|0.0%|
[php_commenters](#php_commenters)|222|222|9|4.0%|0.0%|
[php_bad](#php_bad)|222|222|9|4.0%|0.0%|
[php_harvesters](#php_harvesters)|216|216|8|3.7%|0.0%|
[openbl_90d](#openbl_90d)|9910|9910|6|0.0%|0.0%|
[openbl](#openbl)|9910|9910|6|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7835|7835|5|0.0%|0.0%|
[dm_tor](#dm_tor)|6579|6579|5|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4467|4467|4|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6340|6340|2|0.0%|0.0%|
[voipbl](#voipbl)|10277|10748|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2436|2436|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|420|420|1|0.2%|0.0%|

## openbl

[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**

Source is downloaded from [this link](http://www.openbl.org/lists/base.txt.gz).

The last time downloaded was found to be dated: Tue May 26 18:57:00 UTC 2015.

The ipset `openbl` has **9910** entries, **9910** unique IPs.

The following table shows the overlaps of `openbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl`.
- ` this % ` is the percentage **of this ipset (`openbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9910|9910|9910|100.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|181161|181161|9883|5.4%|99.7%|
[openbl_60d](#openbl_60d)|7835|7835|7835|100.0%|79.0%|
[openbl_30d](#openbl_30d)|4467|4467|4467|100.0%|45.0%|
[et_compromised](#et_compromised)|2436|2436|1482|60.8%|14.9%|
[bruteforceblocker](#bruteforceblocker)|2302|2302|1362|59.1%|13.7%|
[blocklist_de](#blocklist_de)|24092|24092|1049|4.3%|10.5%|
[openbl_7d](#openbl_7d)|1038|1038|1038|100.0%|10.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|959|0.0%|9.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|516|0.0%|5.2%|
[et_block](#et_block)|965|18065466|452|0.0%|4.5%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|447|0.0%|4.5%|
[openbl_1d](#openbl_1d)|357|357|357|100.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|216|0.0%|2.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|91335|91335|70|0.0%|0.7%|
[dshield](#dshield)|20|5120|58|1.1%|0.5%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29881|29881|39|0.1%|0.3%|
[infiltrated](#infiltrated)|10520|10520|29|0.2%|0.2%|
[snort_ipfilter](#snort_ipfilter)|6978|6978|24|0.3%|0.2%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7504|7504|22|0.2%|0.2%|
[dm_tor](#dm_tor)|6579|6579|21|0.3%|0.2%|
[et_tor](#et_tor)|6340|6340|20|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|19|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|14|0.0%|0.1%|
[shunlist](#shunlist)|51|51|13|25.4%|0.1%|
[voipbl](#voipbl)|10277|10748|10|0.0%|0.1%|
[php_commenters](#php_commenters)|222|222|7|3.1%|0.0%|
[php_bad](#php_bad)|222|222|7|3.1%|0.0%|
[nixspam](#nixspam)|25443|25443|6|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|5|0.0%|0.0%|
[php_harvesters](#php_harvesters)|216|216|4|1.8%|0.0%|
[zeus_badips](#zeus_badips)|228|228|1|0.4%|0.0%|
[zeus](#zeus)|264|264|1|0.3%|0.0%|
[sslbl](#sslbl)|328|328|1|0.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|3850|3850|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ciarmy](#ciarmy)|420|420|1|0.2%|0.0%|

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
[openbl_90d](#openbl_90d)|9910|9910|357|3.6%|100.0%|
[openbl_7d](#openbl_7d)|1038|1038|357|34.3%|100.0%|
[openbl_60d](#openbl_60d)|7835|7835|357|4.5%|100.0%|
[openbl_30d](#openbl_30d)|4467|4467|357|7.9%|100.0%|
[openbl](#openbl)|9910|9910|357|3.6%|100.0%|
[alienvault_reputation](#alienvault_reputation)|181161|181161|355|0.1%|99.4%|
[blocklist_de](#blocklist_de)|24092|24092|220|0.9%|61.6%|
[bruteforceblocker](#bruteforceblocker)|2302|2302|206|8.9%|57.7%|
[et_compromised](#et_compromised)|2436|2436|198|8.1%|55.4%|
[et_block](#et_block)|965|18065466|27|0.0%|7.5%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|26|0.0%|7.2%|
[dshield](#dshield)|20|5120|22|0.4%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|20|0.0%|5.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|17|0.0%|4.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|7|0.0%|1.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|1.4%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|91335|91335|1|0.0%|0.2%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.2%|
[shunlist](#shunlist)|51|51|1|1.9%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.2%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt.gz).

The last time downloaded was found to be dated: Tue May 26 18:57:00 UTC 2015.

The ipset `openbl_30d` has **4467** entries, **4467** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9910|9910|4467|45.0%|100.0%|
[openbl_60d](#openbl_60d)|7835|7835|4467|57.0%|100.0%|
[openbl](#openbl)|9910|9910|4467|45.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|181161|181161|4453|2.4%|99.6%|
[et_compromised](#et_compromised)|2436|2436|1328|54.5%|29.7%|
[bruteforceblocker](#bruteforceblocker)|2302|2302|1297|56.3%|29.0%|
[openbl_7d](#openbl_7d)|1038|1038|1038|100.0%|23.2%|
[blocklist_de](#blocklist_de)|24092|24092|932|3.8%|20.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|439|0.0%|9.8%|
[openbl_1d](#openbl_1d)|357|357|357|100.0%|7.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|227|0.0%|5.0%|
[et_block](#et_block)|965|18065466|215|0.0%|4.8%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|212|0.0%|4.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|99|0.0%|2.2%|
[dshield](#dshield)|20|5120|44|0.8%|0.9%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|91335|91335|23|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|13|0.0%|0.2%|
[shunlist](#shunlist)|51|51|11|21.5%|0.2%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29881|29881|8|0.0%|0.1%|
[infiltrated](#infiltrated)|10520|10520|5|0.0%|0.1%|
[nixspam](#nixspam)|25443|25443|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|4|0.0%|0.0%|
[voipbl](#voipbl)|10277|10748|2|0.0%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7504|7504|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|228|228|1|0.4%|0.0%|
[zeus](#zeus)|264|264|1|0.3%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6978|6978|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ciarmy](#ciarmy)|420|420|1|0.2%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt.gz).

The last time downloaded was found to be dated: Tue May 26 18:57:00 UTC 2015.

The ipset `openbl_60d` has **7835** entries, **7835** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9910|9910|7835|79.0%|100.0%|
[openbl](#openbl)|9910|9910|7835|79.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|181161|181161|7813|4.3%|99.7%|
[openbl_30d](#openbl_30d)|4467|4467|4467|100.0%|57.0%|
[et_compromised](#et_compromised)|2436|2436|1471|60.3%|18.7%|
[bruteforceblocker](#bruteforceblocker)|2302|2302|1352|58.7%|17.2%|
[openbl_7d](#openbl_7d)|1038|1038|1038|100.0%|13.2%|
[blocklist_de](#blocklist_de)|24092|24092|1018|4.2%|12.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|715|0.0%|9.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|368|0.0%|4.6%|
[openbl_1d](#openbl_1d)|357|357|357|100.0%|4.5%|
[et_block](#et_block)|965|18065466|312|0.0%|3.9%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|309|0.0%|3.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|178|0.0%|2.2%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|91335|91335|63|0.0%|0.8%|
[dshield](#dshield)|20|5120|46|0.8%|0.5%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29881|29881|35|0.1%|0.4%|
[infiltrated](#infiltrated)|10520|10520|25|0.2%|0.3%|
[snort_ipfilter](#snort_ipfilter)|6978|6978|24|0.3%|0.3%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7504|7504|21|0.2%|0.2%|
[dm_tor](#dm_tor)|6579|6579|21|0.3%|0.2%|
[et_tor](#et_tor)|6340|6340|20|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|18|0.0%|0.2%|
[shunlist](#shunlist)|51|51|13|25.4%|0.1%|
[voipbl](#voipbl)|10277|10748|8|0.0%|0.1%|
[php_commenters](#php_commenters)|222|222|7|3.1%|0.0%|
[php_bad](#php_bad)|222|222|7|3.1%|0.0%|
[nixspam](#nixspam)|25443|25443|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|5|0.0%|0.0%|
[php_harvesters](#php_harvesters)|216|216|4|1.8%|0.0%|
[zeus_badips](#zeus_badips)|228|228|1|0.4%|0.0%|
[zeus](#zeus)|264|264|1|0.3%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ciarmy](#ciarmy)|420|420|1|0.2%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt.gz).

The last time downloaded was found to be dated: Tue May 26 18:57:00 UTC 2015.

The ipset `openbl_7d` has **1038** entries, **1038** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9910|9910|1038|10.4%|100.0%|
[openbl_60d](#openbl_60d)|7835|7835|1038|13.2%|100.0%|
[openbl_30d](#openbl_30d)|4467|4467|1038|23.2%|100.0%|
[openbl](#openbl)|9910|9910|1038|10.4%|100.0%|
[alienvault_reputation](#alienvault_reputation)|181161|181161|1029|0.5%|99.1%|
[blocklist_de](#blocklist_de)|24092|24092|612|2.5%|58.9%|
[bruteforceblocker](#bruteforceblocker)|2302|2302|519|22.5%|50.0%|
[et_compromised](#et_compromised)|2436|2436|475|19.4%|45.7%|
[openbl_1d](#openbl_1d)|357|357|357|100.0%|34.3%|
[et_block](#et_block)|965|18065466|95|0.0%|9.1%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|93|0.0%|8.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|89|0.0%|8.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|47|0.0%|4.5%|
[dshield](#dshield)|20|5120|38|0.7%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|20|0.0%|1.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|9|0.0%|0.8%|
[shunlist](#shunlist)|51|51|3|5.8%|0.2%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|91335|91335|2|0.0%|0.1%|
[infiltrated](#infiltrated)|10520|10520|2|0.0%|0.1%|
[voipbl](#voipbl)|10277|10748|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|1|0.0%|0.0%|
[ciarmy](#ciarmy)|420|420|1|0.2%|0.0%|

## openbl_90d

[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_90days.txt.gz).

The last time downloaded was found to be dated: Tue May 26 18:57:00 UTC 2015.

The ipset `openbl_90d` has **9910** entries, **9910** unique IPs.

The following table shows the overlaps of `openbl_90d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_90d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_90d`.
- ` this % ` is the percentage **of this ipset (`openbl_90d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl](#openbl)|9910|9910|9910|100.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|181161|181161|9883|5.4%|99.7%|
[openbl_60d](#openbl_60d)|7835|7835|7835|100.0%|79.0%|
[openbl_30d](#openbl_30d)|4467|4467|4467|100.0%|45.0%|
[et_compromised](#et_compromised)|2436|2436|1482|60.8%|14.9%|
[bruteforceblocker](#bruteforceblocker)|2302|2302|1362|59.1%|13.7%|
[blocklist_de](#blocklist_de)|24092|24092|1049|4.3%|10.5%|
[openbl_7d](#openbl_7d)|1038|1038|1038|100.0%|10.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|959|0.0%|9.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|516|0.0%|5.2%|
[et_block](#et_block)|965|18065466|452|0.0%|4.5%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|447|0.0%|4.5%|
[openbl_1d](#openbl_1d)|357|357|357|100.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|216|0.0%|2.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|91335|91335|70|0.0%|0.7%|
[dshield](#dshield)|20|5120|58|1.1%|0.5%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29881|29881|39|0.1%|0.3%|
[infiltrated](#infiltrated)|10520|10520|29|0.2%|0.2%|
[snort_ipfilter](#snort_ipfilter)|6978|6978|24|0.3%|0.2%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7504|7504|22|0.2%|0.2%|
[dm_tor](#dm_tor)|6579|6579|21|0.3%|0.2%|
[et_tor](#et_tor)|6340|6340|20|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|19|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|14|0.0%|0.1%|
[shunlist](#shunlist)|51|51|13|25.4%|0.1%|
[voipbl](#voipbl)|10277|10748|10|0.0%|0.1%|
[php_commenters](#php_commenters)|222|222|7|3.1%|0.0%|
[php_bad](#php_bad)|222|222|7|3.1%|0.0%|
[nixspam](#nixspam)|25443|25443|6|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|5|0.0%|0.0%|
[php_harvesters](#php_harvesters)|216|216|4|1.8%|0.0%|
[zeus_badips](#zeus_badips)|228|228|1|0.4%|0.0%|
[zeus](#zeus)|264|264|1|0.3%|0.0%|
[sslbl](#sslbl)|328|328|1|0.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|3850|3850|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ciarmy](#ciarmy)|420|420|1|0.2%|0.0%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Tue May 26 18:53:27 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|965|18065466|13|0.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|6978|6978|11|0.1%|84.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|2|0.0%|15.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|1|0.0%|7.6%|

## php_bad

[projecthoneypot.org](http://www.projecthoneypot.org/) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1).

The last time downloaded was found to be dated: Tue May 26 18:53:38 UTC 2015.

The ipset `php_bad` has **222** entries, **222** unique IPs.

The following table shows the overlaps of `php_bad` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_bad`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_bad`.
- ` this % ` is the percentage **of this ipset (`php_bad`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[php_commenters](#php_commenters)|222|222|222|100.0%|100.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|91335|91335|170|0.1%|76.5%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29881|29881|161|0.5%|72.5%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7504|7504|118|1.5%|53.1%|
[blocklist_de](#blocklist_de)|24092|24092|73|0.3%|32.8%|
[infiltrated](#infiltrated)|10520|10520|38|0.3%|17.1%|
[snort_ipfilter](#snort_ipfilter)|6978|6978|31|0.4%|13.9%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|25|0.0%|11.2%|
[dm_tor](#dm_tor)|6579|6579|25|0.3%|11.2%|
[et_tor](#et_tor)|6340|6340|24|0.3%|10.8%|
[et_block](#et_block)|965|18065466|24|0.0%|10.8%|
[php_spammers](#php_spammers)|339|339|19|5.6%|8.5%|
[php_dictionary](#php_dictionary)|357|357|12|3.3%|5.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|11|0.0%|4.9%|
[alienvault_reputation](#alienvault_reputation)|181161|181161|11|0.0%|4.9%|
[nixspam](#nixspam)|25443|25443|9|0.0%|4.0%|
[php_harvesters](#php_harvesters)|216|216|8|3.7%|3.6%|
[ri_web_proxies](#ri_web_proxies)|3850|3850|7|0.1%|3.1%|
[openbl_90d](#openbl_90d)|9910|9910|7|0.0%|3.1%|
[openbl_60d](#openbl_60d)|7835|7835|7|0.0%|3.1%|
[openbl](#openbl)|9910|9910|7|0.0%|3.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|6|0.0%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|6|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|3|0.0%|1.3%|
[zeus_badips](#zeus_badips)|228|228|1|0.4%|0.4%|
[zeus](#zeus)|264|264|1|0.3%|0.4%|

## php_commenters

[projecthoneypot.org](http://www.projecthoneypot.org/) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1).

The last time downloaded was found to be dated: Tue May 26 18:53:39 UTC 2015.

The ipset `php_commenters` has **222** entries, **222** unique IPs.

The following table shows the overlaps of `php_commenters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_commenters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_commenters`.
- ` this % ` is the percentage **of this ipset (`php_commenters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[php_bad](#php_bad)|222|222|222|100.0%|100.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|91335|91335|170|0.1%|76.5%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29881|29881|161|0.5%|72.5%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7504|7504|118|1.5%|53.1%|
[blocklist_de](#blocklist_de)|24092|24092|73|0.3%|32.8%|
[infiltrated](#infiltrated)|10520|10520|38|0.3%|17.1%|
[snort_ipfilter](#snort_ipfilter)|6978|6978|31|0.4%|13.9%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|25|0.0%|11.2%|
[dm_tor](#dm_tor)|6579|6579|25|0.3%|11.2%|
[et_tor](#et_tor)|6340|6340|24|0.3%|10.8%|
[et_block](#et_block)|965|18065466|24|0.0%|10.8%|
[php_spammers](#php_spammers)|339|339|19|5.6%|8.5%|
[php_dictionary](#php_dictionary)|357|357|12|3.3%|5.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|11|0.0%|4.9%|
[alienvault_reputation](#alienvault_reputation)|181161|181161|11|0.0%|4.9%|
[nixspam](#nixspam)|25443|25443|9|0.0%|4.0%|
[php_harvesters](#php_harvesters)|216|216|8|3.7%|3.6%|
[ri_web_proxies](#ri_web_proxies)|3850|3850|7|0.1%|3.1%|
[openbl_90d](#openbl_90d)|9910|9910|7|0.0%|3.1%|
[openbl_60d](#openbl_60d)|7835|7835|7|0.0%|3.1%|
[openbl](#openbl)|9910|9910|7|0.0%|3.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|6|0.0%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|6|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|3|0.0%|1.3%|
[zeus_badips](#zeus_badips)|228|228|1|0.4%|0.4%|
[zeus](#zeus)|264|264|1|0.3%|0.4%|

## php_dictionary

[projecthoneypot.org](http://www.projecthoneypot.org/) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1).

The last time downloaded was found to be dated: Tue May 26 18:53:41 UTC 2015.

The ipset `php_dictionary` has **357** entries, **357** unique IPs.

The following table shows the overlaps of `php_dictionary` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_dictionary`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_dictionary`.
- ` this % ` is the percentage **of this ipset (`php_dictionary`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[nixspam](#nixspam)|25443|25443|123|0.4%|34.4%|
[infiltrated](#infiltrated)|10520|10520|106|1.0%|29.6%|
[blocklist_de](#blocklist_de)|24092|24092|95|0.3%|26.6%|
[snort_ipfilter](#snort_ipfilter)|6978|6978|86|1.2%|24.0%|
[php_spammers](#php_spammers)|339|339|66|19.4%|18.4%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|91335|91335|55|0.0%|15.4%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29881|29881|38|0.1%|10.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|19|0.0%|5.3%|
[ri_web_proxies](#ri_web_proxies)|3850|3850|17|0.4%|4.7%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7504|7504|16|0.2%|4.4%|
[php_commenters](#php_commenters)|222|222|12|5.4%|3.3%|
[php_bad](#php_bad)|222|222|12|5.4%|3.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|9|0.0%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|8|0.0%|2.2%|
[alienvault_reputation](#alienvault_reputation)|181161|181161|6|0.0%|1.6%|
[et_tor](#et_tor)|6340|6340|4|0.0%|1.1%|
[dm_tor](#dm_tor)|6579|6579|3|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.5%|
[ri_connect_proxies](#ri_connect_proxies)|1530|1530|2|0.1%|0.5%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.5%|
[et_block](#et_block)|965|18065466|2|0.0%|0.5%|
[php_harvesters](#php_harvesters)|216|216|1|0.4%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|1|0.0%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.2%|

## php_harvesters

[projecthoneypot.org](http://www.projecthoneypot.org/) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1).

The last time downloaded was found to be dated: Tue May 26 18:53:35 UTC 2015.

The ipset `php_harvesters` has **216** entries, **216** unique IPs.

The following table shows the overlaps of `php_harvesters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_harvesters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_harvesters`.
- ` this % ` is the percentage **of this ipset (`php_harvesters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[infiltrated](#infiltrated)|10520|10520|80|0.7%|37.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|91335|91335|55|0.0%|25.4%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29881|29881|47|0.1%|21.7%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7504|7504|34|0.4%|15.7%|
[blocklist_de](#blocklist_de)|24092|24092|28|0.1%|12.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|14|0.0%|6.4%|
[snort_ipfilter](#snort_ipfilter)|6978|6978|9|0.1%|4.1%|
[alienvault_reputation](#alienvault_reputation)|181161|181161|9|0.0%|4.1%|
[php_commenters](#php_commenters)|222|222|8|3.6%|3.7%|
[php_bad](#php_bad)|222|222|8|3.6%|3.7%|
[nixspam](#nixspam)|25443|25443|8|0.0%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|7|0.0%|3.2%|
[et_tor](#et_tor)|6340|6340|7|0.1%|3.2%|
[dm_tor](#dm_tor)|6579|6579|7|0.1%|3.2%|
[openbl_90d](#openbl_90d)|9910|9910|4|0.0%|1.8%|
[openbl_60d](#openbl_60d)|7835|7835|4|0.0%|1.8%|
[openbl](#openbl)|9910|9910|4|0.0%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|3|0.0%|1.3%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.9%|
[et_block](#et_block)|965|18065466|2|0.0%|0.9%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|1|0.0%|0.4%|
[ri_web_proxies](#ri_web_proxies)|3850|3850|1|0.0%|0.4%|
[php_spammers](#php_spammers)|339|339|1|0.2%|0.4%|
[php_dictionary](#php_dictionary)|357|357|1|0.2%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|1|0.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.4%|
[fullbogons](#fullbogons)|3669|670926040|1|0.0%|0.4%|
[bogons](#bogons)|13|592708608|1|0.0%|0.4%|

## php_spammers

[projecthoneypot.org](http://www.projecthoneypot.org/) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1).

The last time downloaded was found to be dated: Tue May 26 18:53:36 UTC 2015.

The ipset `php_spammers` has **339** entries, **339** unique IPs.

The following table shows the overlaps of `php_spammers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_spammers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_spammers`.
- ` this % ` is the percentage **of this ipset (`php_spammers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[infiltrated](#infiltrated)|10520|10520|100|0.9%|29.4%|
[blocklist_de](#blocklist_de)|24092|24092|83|0.3%|24.4%|
[nixspam](#nixspam)|25443|25443|80|0.3%|23.5%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|91335|91335|75|0.0%|22.1%|
[snort_ipfilter](#snort_ipfilter)|6978|6978|70|1.0%|20.6%|
[php_dictionary](#php_dictionary)|357|357|66|18.4%|19.4%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29881|29881|53|0.1%|15.6%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7504|7504|26|0.3%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|25|0.0%|7.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|20|0.0%|5.8%|
[php_commenters](#php_commenters)|222|222|19|8.5%|5.6%|
[php_bad](#php_bad)|222|222|19|8.5%|5.6%|
[ri_web_proxies](#ri_web_proxies)|3850|3850|14|0.3%|4.1%|
[et_tor](#et_tor)|6340|6340|5|0.0%|1.4%|
[dm_tor](#dm_tor)|6579|6579|5|0.0%|1.4%|
[alienvault_reputation](#alienvault_reputation)|181161|181161|3|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|2|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.5%|
[et_block](#et_block)|965|18065466|2|0.0%|0.5%|
[ri_connect_proxies](#ri_connect_proxies)|1530|1530|1|0.0%|0.2%|
[php_harvesters](#php_harvesters)|216|216|1|0.4%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.2%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Tue May 26 13:55:38 UTC 2015.

The ipset `ri_connect_proxies` has **1530** entries, **1530** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stop_forum_spam_30d](#stop_forum_spam_30d)|91335|91335|902|0.9%|58.9%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29881|29881|697|2.3%|45.5%|
[ri_web_proxies](#ri_web_proxies)|3850|3850|620|16.1%|40.5%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7504|7504|134|1.7%|8.7%|
[blocklist_de](#blocklist_de)|24092|24092|95|0.3%|6.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|72|0.0%|4.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|31|0.0%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|23|0.0%|1.5%|
[nixspam](#nixspam)|25443|25443|9|0.0%|0.5%|
[infiltrated](#infiltrated)|10520|10520|8|0.0%|0.5%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.3%|
[snort_ipfilter](#snort_ipfilter)|6978|6978|4|0.0%|0.2%|
[php_dictionary](#php_dictionary)|357|357|2|0.5%|0.1%|
[dm_tor](#dm_tor)|6579|6579|2|0.0%|0.1%|
[php_spammers](#php_spammers)|339|339|1|0.2%|0.0%|
[et_tor](#et_tor)|6340|6340|1|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|181161|181161|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Tue May 26 17:26:01 UTC 2015.

The ipset `ri_web_proxies` has **3850** entries, **3850** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stop_forum_spam_30d](#stop_forum_spam_30d)|91335|91335|1878|2.0%|48.7%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29881|29881|1543|5.1%|40.0%|
[ri_connect_proxies](#ri_connect_proxies)|1530|1530|620|40.5%|16.1%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7504|7504|454|6.0%|11.7%|
[blocklist_de](#blocklist_de)|24092|24092|395|1.6%|10.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|141|0.0%|3.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|123|0.0%|3.1%|
[nixspam](#nixspam)|25443|25443|73|0.2%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|61|0.0%|1.5%|
[infiltrated](#infiltrated)|10520|10520|59|0.5%|1.5%|
[snort_ipfilter](#snort_ipfilter)|6978|6978|41|0.5%|1.0%|
[php_dictionary](#php_dictionary)|357|357|17|4.7%|0.4%|
[php_spammers](#php_spammers)|339|339|14|4.1%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|10|1.4%|0.2%|
[php_commenters](#php_commenters)|222|222|7|3.1%|0.1%|
[php_bad](#php_bad)|222|222|7|3.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|4|0.0%|0.1%|
[et_tor](#et_tor)|6340|6340|4|0.0%|0.1%|
[dm_tor](#dm_tor)|6579|6579|3|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|181161|181161|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|216|216|1|0.4%|0.0%|
[openbl_90d](#openbl_90d)|9910|9910|1|0.0%|0.0%|
[openbl](#openbl)|9910|9910|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Tue May 26 18:30:03 UTC 2015.

The ipset `shunlist` has **51** entries, **51** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|181161|181161|50|0.0%|98.0%|
[openbl_90d](#openbl_90d)|9910|9910|13|0.1%|25.4%|
[openbl_60d](#openbl_60d)|7835|7835|13|0.1%|25.4%|
[openbl](#openbl)|9910|9910|13|0.1%|25.4%|
[openbl_30d](#openbl_30d)|4467|4467|11|0.2%|21.5%|
[blocklist_de](#blocklist_de)|24092|24092|11|0.0%|21.5%|
[bruteforceblocker](#bruteforceblocker)|2302|2302|10|0.4%|19.6%|
[et_compromised](#et_compromised)|2436|2436|9|0.3%|17.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|6|0.0%|11.7%|
[voipbl](#voipbl)|10277|10748|3|0.0%|5.8%|
[openbl_7d](#openbl_7d)|1038|1038|3|0.2%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|3|0.0%|5.8%|
[openbl_1d](#openbl_1d)|357|357|1|0.2%|1.9%|

## snort_ipfilter

[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)

Source is downloaded from [this link](http://labs.snort.org/feeds/ip-filter.blf).

The last time downloaded was found to be dated: Tue May 26 12:30:00 UTC 2015.

The ipset `snort_ipfilter` has **6978** entries, **6978** unique IPs.

The following table shows the overlaps of `snort_ipfilter` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `snort_ipfilter`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `snort_ipfilter`.
- ` this % ` is the percentage **of this ipset (`snort_ipfilter`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[dm_tor](#dm_tor)|6579|6579|1051|15.9%|15.0%|
[et_tor](#et_tor)|6340|6340|991|15.6%|14.2%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|91335|91335|690|0.7%|9.8%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29881|29881|508|1.7%|7.2%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7504|7504|292|3.8%|4.1%|
[et_block](#et_block)|965|18065466|282|0.0%|4.0%|
[blocklist_de](#blocklist_de)|24092|24092|245|1.0%|3.5%|
[nixspam](#nixspam)|25443|25443|237|0.9%|3.3%|
[zeus](#zeus)|264|264|223|84.4%|3.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|209|0.0%|2.9%|
[zeus_badips](#zeus_badips)|228|228|199|87.2%|2.8%|
[infiltrated](#infiltrated)|10520|10520|140|1.3%|2.0%|
[alienvault_reputation](#alienvault_reputation)|181161|181161|118|0.0%|1.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|104|0.0%|1.4%|
[php_dictionary](#php_dictionary)|357|357|86|24.0%|1.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|77|0.0%|1.1%|
[php_spammers](#php_spammers)|339|339|70|20.6%|1.0%|
[feodo](#feodo)|61|61|47|77.0%|0.6%|
[ri_web_proxies](#ri_web_proxies)|3850|3850|41|1.0%|0.5%|
[php_commenters](#php_commenters)|222|222|31|13.9%|0.4%|
[php_bad](#php_bad)|222|222|31|13.9%|0.4%|
[openbl_90d](#openbl_90d)|9910|9910|24|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7835|7835|24|0.3%|0.3%|
[openbl](#openbl)|9910|9910|24|0.2%|0.3%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|24|1.8%|0.3%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|20|0.0%|0.2%|
[sslbl](#sslbl)|328|328|17|5.1%|0.2%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|11|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.1%|
[php_harvesters](#php_harvesters)|216|216|9|4.1%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|6|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1530|1530|4|0.2%|0.0%|
[dshield](#dshield)|20|5120|3|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[voipbl](#voipbl)|10277|10748|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4467|4467|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2436|2436|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2302|2302|1|0.0%|0.0%|

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
[et_block](#et_block)|965|18065466|17994240|99.6%|99.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|8401433|2.4%|46.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7211008|78.5%|39.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|2132981|0.2%|11.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|195904|0.1%|1.0%|
[fullbogons](#fullbogons)|3669|670926040|20480|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|181161|181161|1624|0.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|1024|0.3%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|91335|91335|777|0.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|512|0.1%|0.0%|
[openbl_90d](#openbl_90d)|9910|9910|447|4.5%|0.0%|
[openbl](#openbl)|9910|9910|447|4.5%|0.0%|
[nixspam](#nixspam)|25443|25443|353|1.3%|0.0%|
[openbl_60d](#openbl_60d)|7835|7835|309|3.9%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29881|29881|246|0.8%|0.0%|
[openbl_30d](#openbl_30d)|4467|4467|212|4.7%|0.0%|
[blocklist_de](#blocklist_de)|24092|24092|181|0.7%|0.0%|
[openbl_7d](#openbl_7d)|1038|1038|93|8.9%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2302|2302|92|3.9%|0.0%|
[et_compromised](#et_compromised)|2436|2436|76|3.1%|0.0%|
[infiltrated](#infiltrated)|10520|10520|64|0.6%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7504|7504|60|0.7%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|28|2.1%|0.0%|
[openbl_1d](#openbl_1d)|357|357|26|7.2%|0.0%|
[php_commenters](#php_commenters)|222|222|25|11.2%|0.0%|
[php_bad](#php_bad)|222|222|25|11.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6978|6978|20|0.2%|0.0%|
[zeus_badips](#zeus_badips)|228|228|16|7.0%|0.0%|
[zeus](#zeus)|264|264|16|6.0%|0.0%|
[voipbl](#voipbl)|10277|10748|14|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[sslbl](#sslbl)|328|328|2|0.6%|0.0%|
[php_spammers](#php_spammers)|339|339|2|0.5%|0.0%|
[php_dictionary](#php_dictionary)|357|357|2|0.5%|0.0%|
[malc0de](#malc0de)|418|418|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6340|6340|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6579|6579|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|216|216|1|0.4%|0.0%|
[et_botnet](#et_botnet)|515|515|1|0.1%|0.0%|

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
[et_block](#et_block)|965|18065466|517|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|512|0.0%|0.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|91335|91335|109|0.1%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29881|29881|40|0.1%|0.0%|
[blocklist_de](#blocklist_de)|24092|24092|40|0.1%|0.0%|
[infiltrated](#infiltrated)|10520|10520|37|0.3%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7504|7504|16|0.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|181161|181161|16|0.0%|0.0%|
[openbl_90d](#openbl_90d)|9910|9910|14|0.1%|0.0%|
[openbl](#openbl)|9910|9910|14|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6978|6978|6|0.0%|0.0%|
[php_commenters](#php_commenters)|222|222|6|2.7%|0.0%|
[php_bad](#php_bad)|222|222|6|2.7%|0.0%|
[zeus_badips](#zeus_badips)|228|228|5|2.1%|0.0%|
[zeus](#zeus)|264|264|5|1.8%|0.0%|
[php_harvesters](#php_harvesters)|216|216|1|0.4%|0.0%|
[openbl_7d](#openbl_7d)|1038|1038|1|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7835|7835|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4467|4467|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|357|357|1|0.2%|0.0%|
[nixspam](#nixspam)|25443|25443|1|0.0%|0.0%|
[malc0de](#malc0de)|418|418|1|0.2%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Tue May 26 19:15:07 UTC 2015.

The ipset `sslbl` has **328** entries, **328** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|965|18065466|22|0.0%|6.7%|
[feodo](#feodo)|61|61|20|32.7%|6.0%|
[snort_ipfilter](#snort_ipfilter)|6978|6978|17|0.2%|5.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|17|0.0%|5.1%|
[alienvault_reputation](#alienvault_reputation)|181161|181161|7|0.0%|2.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|5|0.0%|1.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|3|0.0%|0.9%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.6%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|91335|91335|1|0.0%|0.3%|
[openbl_90d](#openbl_90d)|9910|9910|1|0.0%|0.3%|
[openbl](#openbl)|9910|9910|1|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|1|0.0%|0.3%|

## stop_forum_spam_1h

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Tue May 26 18:40:14 UTC 2015.

The ipset `stop_forum_spam_1h` has **7504** entries, **7504** unique IPs.

The following table shows the overlaps of `stop_forum_spam_1h` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stop_forum_spam_1h`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stop_forum_spam_1h`.
- ` this % ` is the percentage **of this ipset (`stop_forum_spam_1h`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29881|29881|5345|17.8%|71.2%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|91335|91335|5305|5.8%|70.6%|
[blocklist_de](#blocklist_de)|24092|24092|1481|6.1%|19.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|532|0.0%|7.0%|
[ri_web_proxies](#ri_web_proxies)|3850|3850|454|11.7%|6.0%|
[snort_ipfilter](#snort_ipfilter)|6978|6978|292|4.1%|3.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|265|0.0%|3.5%|
[dm_tor](#dm_tor)|6579|6579|259|3.9%|3.4%|
[et_tor](#et_tor)|6340|6340|251|3.9%|3.3%|
[infiltrated](#infiltrated)|10520|10520|187|1.7%|2.4%|
[ri_connect_proxies](#ri_connect_proxies)|1530|1530|134|8.7%|1.7%|
[php_commenters](#php_commenters)|222|222|118|53.1%|1.5%|
[php_bad](#php_bad)|222|222|118|53.1%|1.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|112|0.0%|1.4%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|60|0.0%|0.7%|
[et_block](#et_block)|965|18065466|59|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|181161|181161|56|0.0%|0.7%|
[nixspam](#nixspam)|25443|25443|47|0.1%|0.6%|
[php_harvesters](#php_harvesters)|216|216|34|15.7%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|34|0.0%|0.4%|
[php_spammers](#php_spammers)|339|339|26|7.6%|0.3%|
[openbl_90d](#openbl_90d)|9910|9910|22|0.2%|0.2%|
[openbl](#openbl)|9910|9910|22|0.2%|0.2%|
[openbl_60d](#openbl_60d)|7835|7835|21|0.2%|0.2%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|16|0.0%|0.2%|
[php_dictionary](#php_dictionary)|357|357|16|4.4%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|9|0.0%|0.1%|
[voipbl](#voipbl)|10277|10748|5|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4467|4467|2|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2436|2436|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2302|2302|1|0.0%|0.0%|

## stop_forum_spam_30d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip).

The last time downloaded was found to be dated: Tue May 26 00:01:02 UTC 2015.

The ipset `stop_forum_spam_30d` has **91335** entries, **91335** unique IPs.

The following table shows the overlaps of `stop_forum_spam_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stop_forum_spam_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stop_forum_spam_30d`.
- ` this % ` is the percentage **of this ipset (`stop_forum_spam_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29881|29881|29518|98.7%|32.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|6141|0.0%|6.7%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7504|7504|5305|70.6%|5.8%|
[blocklist_de](#blocklist_de)|24092|24092|2699|11.2%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|2423|0.0%|2.6%|
[ri_web_proxies](#ri_web_proxies)|3850|3850|1878|48.7%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|1312|0.0%|1.4%|
[ri_connect_proxies](#ri_connect_proxies)|1530|1530|902|58.9%|0.9%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|777|0.0%|0.8%|
[et_block](#et_block)|965|18065466|758|0.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|725|0.0%|0.7%|
[snort_ipfilter](#snort_ipfilter)|6978|6978|690|9.8%|0.7%|
[infiltrated](#infiltrated)|10520|10520|603|5.7%|0.6%|
[et_tor](#et_tor)|6340|6340|570|8.9%|0.6%|
[dm_tor](#dm_tor)|6579|6579|565|8.5%|0.6%|
[alienvault_reputation](#alienvault_reputation)|181161|181161|236|0.1%|0.2%|
[nixspam](#nixspam)|25443|25443|218|0.8%|0.2%|
[php_commenters](#php_commenters)|222|222|170|76.5%|0.1%|
[php_bad](#php_bad)|222|222|170|76.5%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|109|0.0%|0.1%|
[php_spammers](#php_spammers)|339|339|75|22.1%|0.0%|
[openbl_90d](#openbl_90d)|9910|9910|70|0.7%|0.0%|
[openbl](#openbl)|9910|9910|70|0.7%|0.0%|
[openbl_60d](#openbl_60d)|7835|7835|63|0.8%|0.0%|
[php_harvesters](#php_harvesters)|216|216|55|25.4%|0.0%|
[php_dictionary](#php_dictionary)|357|357|55|15.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|42|0.0%|0.0%|
[voipbl](#voipbl)|10277|10748|39|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|24|3.5%|0.0%|
[openbl_30d](#openbl_30d)|4467|4467|23|0.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[dshield](#dshield)|20|5120|6|0.1%|0.0%|
[et_compromised](#et_compromised)|2436|2436|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2302|2302|5|0.2%|0.0%|
[zeus](#zeus)|264|264|4|1.5%|0.0%|
[zeus_badips](#zeus_badips)|228|228|3|1.3%|0.0%|
[fullbogons](#fullbogons)|3669|670926040|3|0.0%|0.0%|
[openbl_7d](#openbl_7d)|1038|1038|2|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|2|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[sslbl](#sslbl)|328|328|1|0.3%|0.0%|
[openbl_1d](#openbl_1d)|357|357|1|0.2%|0.0%|
[ciarmy](#ciarmy)|420|420|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|

## stop_forum_spam_7d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip).

The last time downloaded was found to be dated: Tue May 26 03:00:08 UTC 2015.

The ipset `stop_forum_spam_7d` has **29881** entries, **29881** unique IPs.

The following table shows the overlaps of `stop_forum_spam_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stop_forum_spam_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stop_forum_spam_7d`.
- ` this % ` is the percentage **of this ipset (`stop_forum_spam_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stop_forum_spam_30d](#stop_forum_spam_30d)|91335|91335|29518|32.3%|98.7%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7504|7504|5345|71.2%|17.8%|
[blocklist_de](#blocklist_de)|24092|24092|2309|9.5%|7.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|2035|0.0%|6.8%|
[ri_web_proxies](#ri_web_proxies)|3850|3850|1543|40.0%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|864|0.0%|2.8%|
[ri_connect_proxies](#ri_connect_proxies)|1530|1530|697|45.5%|2.3%|
[snort_ipfilter](#snort_ipfilter)|6978|6978|508|7.2%|1.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|493|0.0%|1.6%|
[et_tor](#et_tor)|6340|6340|427|6.7%|1.4%|
[dm_tor](#dm_tor)|6579|6579|423|6.4%|1.4%|
[infiltrated](#infiltrated)|10520|10520|327|3.1%|1.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|246|0.0%|0.8%|
[et_block](#et_block)|965|18065466|227|0.0%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|207|0.0%|0.6%|
[php_commenters](#php_commenters)|222|222|161|72.5%|0.5%|
[php_bad](#php_bad)|222|222|161|72.5%|0.5%|
[nixspam](#nixspam)|25443|25443|125|0.4%|0.4%|
[alienvault_reputation](#alienvault_reputation)|181161|181161|115|0.0%|0.3%|
[php_spammers](#php_spammers)|339|339|53|15.6%|0.1%|
[php_harvesters](#php_harvesters)|216|216|47|21.7%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|40|0.0%|0.1%|
[openbl_90d](#openbl_90d)|9910|9910|39|0.3%|0.1%|
[openbl](#openbl)|9910|9910|39|0.3%|0.1%|
[php_dictionary](#php_dictionary)|357|357|38|10.6%|0.1%|
[openbl_60d](#openbl_60d)|7835|7835|35|0.4%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|24|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|14|2.0%|0.0%|
[voipbl](#voipbl)|10277|10748|13|0.1%|0.0%|
[openbl_30d](#openbl_30d)|4467|4467|8|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[et_compromised](#et_compromised)|2436|2436|3|0.1%|0.0%|
[dshield](#dshield)|20|5120|3|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2302|2302|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|228|228|1|0.4%|0.0%|
[zeus](#zeus)|264|264|1|0.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3669|670926040|1|0.0%|0.0%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Tue May 26 15:40:38 UTC 2015.

The ipset `voipbl` has **10277** entries, **10748** unique IPs.

The following table shows the overlaps of `voipbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `voipbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `voipbl`.
- ` this % ` is the percentage **of this ipset (`voipbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|1584|0.0%|14.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|428|0.0%|3.9%|
[fullbogons](#fullbogons)|3669|670926040|351|0.0%|3.2%|
[bogons](#bogons)|13|592708608|351|0.0%|3.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|283|0.0%|2.6%|
[alienvault_reputation](#alienvault_reputation)|181161|181161|200|0.1%|1.8%|
[blocklist_de](#blocklist_de)|24092|24092|46|0.1%|0.4%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|91335|91335|39|0.0%|0.3%|
[et_block](#et_block)|965|18065466|18|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|14|0.0%|0.1%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29881|29881|13|0.0%|0.1%|
[openbl_90d](#openbl_90d)|9910|9910|10|0.1%|0.0%|
[openbl](#openbl)|9910|9910|10|0.1%|0.0%|
[openbl_60d](#openbl_60d)|7835|7835|8|0.1%|0.0%|
[infiltrated](#infiltrated)|10520|10520|6|0.0%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7504|7504|5|0.0%|0.0%|
[dshield](#dshield)|20|5120|4|0.0%|0.0%|
[shunlist](#shunlist)|51|51|3|5.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|898|336971|3|0.0%|0.0%|
[ciarmy](#ciarmy)|420|420|3|0.7%|0.0%|
[openbl_30d](#openbl_30d)|4467|4467|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6978|6978|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|1038|1038|1|0.0%|0.0%|
[nixspam](#nixspam)|25443|25443|1|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[et_tor](#et_tor)|6340|6340|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2436|2436|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6579|6579|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2302|2302|1|0.0%|0.0%|

## zeus

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) default blocklist including hijacked sites and web hosting providers - **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist).

The last time downloaded was found to be dated: Tue May 26 18:50:13 UTC 2015.

The ipset `zeus` has **264** entries, **264** unique IPs.

The following table shows the overlaps of `zeus` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus`.
- ` this % ` is the percentage **of this ipset (`zeus`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|965|18065466|256|0.0%|96.9%|
[zeus_badips](#zeus_badips)|228|228|228|100.0%|86.3%|
[snort_ipfilter](#snort_ipfilter)|6978|6978|223|3.1%|84.4%|
[alienvault_reputation](#alienvault_reputation)|181161|181161|65|0.0%|24.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|20|0.0%|7.5%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|16|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|9|0.0%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|7|0.0%|2.6%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|5|0.0%|1.8%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|91335|91335|4|0.0%|1.5%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29881|29881|1|0.0%|0.3%|
[php_commenters](#php_commenters)|222|222|1|0.4%|0.3%|
[php_bad](#php_bad)|222|222|1|0.4%|0.3%|
[openbl_90d](#openbl_90d)|9910|9910|1|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7835|7835|1|0.0%|0.3%|
[openbl_30d](#openbl_30d)|4467|4467|1|0.0%|0.3%|
[openbl](#openbl)|9910|9910|1|0.0%|0.3%|
[et_compromised](#et_compromised)|2436|2436|1|0.0%|0.3%|
[dshield](#dshield)|20|5120|1|0.0%|0.3%|
[bruteforceblocker](#bruteforceblocker)|2302|2302|1|0.0%|0.3%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) includes IPv4 addresses that are used by the ZeuS trojan

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Tue May 26 18:53:22 UTC 2015.

The ipset `zeus_badips` has **228** entries, **228** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|264|264|228|86.3%|100.0%|
[et_block](#et_block)|965|18065466|224|0.0%|98.2%|
[snort_ipfilter](#snort_ipfilter)|6978|6978|199|2.8%|87.2%|
[alienvault_reputation](#alienvault_reputation)|181161|181161|36|0.0%|15.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|16|0.0%|7.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18550|139108857|14|0.0%|6.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|75927|348729520|8|0.0%|3.5%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|5|0.0%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|215693|765044590|4|0.0%|1.7%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|91335|91335|3|0.0%|1.3%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|29881|29881|1|0.0%|0.4%|
[php_commenters](#php_commenters)|222|222|1|0.4%|0.4%|
[php_bad](#php_bad)|222|222|1|0.4%|0.4%|
[openbl_90d](#openbl_90d)|9910|9910|1|0.0%|0.4%|
[openbl_60d](#openbl_60d)|7835|7835|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|4467|4467|1|0.0%|0.4%|
[openbl](#openbl)|9910|9910|1|0.0%|0.4%|
[et_compromised](#et_compromised)|2436|2436|1|0.0%|0.4%|
[bruteforceblocker](#bruteforceblocker)|2302|2302|1|0.0%|0.4%|
