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

The following list was automatically generated on Wed May 27 17:45:32 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|179777 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|23463 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6505 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD)|ipv4 hash:ip|2383 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|409 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[clean_mx_viruses](#clean_mx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|299 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6499 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|19 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
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
[malc0de](#malc0de)|[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days|ipv4 hash:ip|414 unique IPs|updated every 1 day  from [this link](http://malc0de.com/bl/IP_Blacklist.txt)
[malwaredomainlist](#malwaredomainlist)|[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses|ipv4 hash:ip|1283 unique IPs|updated every 12 hours  from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt)
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|28307 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
[openbl](#openbl)|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|9900 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt.gz)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|357 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_1days.txt.gz)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|4444 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt.gz)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7827 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt.gz)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|982 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt.gz)
[openbl_90d](#openbl_90d)|[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|9900 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt.gz)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
[php_bad](#php_bad)|[projecthoneypot.org](http://www.projecthoneypot.org/) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|246 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|246 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|398 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|235 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|378 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1622 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|4104 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|51 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|7341 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|641 subnets, 18117120 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|55 subnets, 421120 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|335 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
[stop_forum_spam_1h](#stop_forum_spam_1h)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|7897 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stop_forum_spam_30d](#stop_forum_spam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|92800 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
[stop_forum_spam_7d](#stop_forum_spam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|30172 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10286 subnets, 10757 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) default blocklist including hijacked sites and web hosting providers - **excellent list**|ipv4 hash:ip|266 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
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
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|5.8%|
[openbl_90d](#openbl_90d)|9900|9900|9879|99.7%|5.4%|
[openbl](#openbl)|9900|9900|9879|99.7%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|8413|0.0%|4.6%|
[openbl_60d](#openbl_60d)|7827|7827|7809|99.7%|4.3%|
[et_block](#et_block)|974|18056767|5529|0.0%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|5212|0.0%|2.8%|
[openbl_30d](#openbl_30d)|4444|4444|4434|99.7%|2.4%|
[dshield](#dshield)|19|5120|4352|85.0%|2.4%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|1624|0.0%|0.9%|
[blocklist_de](#blocklist_de)|23463|23463|1613|6.8%|0.8%|
[bruteforceblocker](#bruteforceblocker)|2383|2383|1474|61.8%|0.8%|
[et_compromised](#et_compromised)|2292|2292|1454|63.4%|0.8%|
[openbl_7d](#openbl_7d)|982|982|977|99.4%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|519|0.0%|0.2%|
[ciarmy](#ciarmy)|409|409|402|98.2%|0.2%|
[openbl_1d](#openbl_1d)|357|357|355|99.4%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|293|0.0%|0.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|240|0.2%|0.1%|
[voipbl](#voipbl)|10286|10757|202|1.8%|0.1%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|122|1.6%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|117|0.3%|0.0%|
[zeus](#zeus)|266|266|67|25.1%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|57|0.7%|0.0%|
[shunlist](#shunlist)|51|51|51|100.0%|0.0%|
[dm_tor](#dm_tor)|6499|6499|45|0.6%|0.0%|
[bm_tor](#bm_tor)|6505|6505|45|0.6%|0.0%|
[et_tor](#et_tor)|6400|6400|44|0.6%|0.0%|
[nixspam](#nixspam)|28307|28307|43|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|36|15.7%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|15|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|13|0.0%|0.0%|
[php_commenters](#php_commenters)|246|246|12|4.8%|0.0%|
[php_bad](#php_bad)|246|246|12|4.8%|0.0%|
[malc0de](#malc0de)|414|414|11|2.6%|0.0%|
[php_harvesters](#php_harvesters)|235|235|9|3.8%|0.0%|
[sslbl](#sslbl)|335|335|7|2.0%|0.0%|
[php_dictionary](#php_dictionary)|398|398|7|1.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|6|0.4%|0.0%|
[php_spammers](#php_spammers)|378|378|4|1.0%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|299|299|4|1.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4104|4104|3|0.0%|0.0%|
[et_botnet](#et_botnet)|505|505|3|0.5%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1622|1622|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[feodo](#feodo)|62|62|1|1.6%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Wed May 27 17:28:04 UTC 2015.

The ipset `blocklist_de` has **23463** entries, **23463** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|44.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|2861|0.0%|12.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|2417|2.6%|10.3%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|2196|7.2%|9.3%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|1613|0.8%|6.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|1494|0.0%|6.3%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|1471|18.6%|6.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|1447|0.0%|6.1%|
[openbl_90d](#openbl_90d)|9900|9900|1346|13.5%|5.7%|
[openbl](#openbl)|9900|9900|1346|13.5%|5.7%|
[openbl_60d](#openbl_60d)|7827|7827|1293|16.5%|5.5%|
[openbl_30d](#openbl_30d)|4444|4444|1182|26.5%|5.0%|
[bruteforceblocker](#bruteforceblocker)|2383|2383|1126|47.2%|4.7%|
[et_compromised](#et_compromised)|2292|2292|1024|44.6%|4.3%|
[nixspam](#nixspam)|28307|28307|1023|3.6%|4.3%|
[openbl_7d](#openbl_7d)|982|982|657|66.9%|2.8%|
[ri_web_proxies](#ri_web_proxies)|4104|4104|373|9.0%|1.5%|
[openbl_1d](#openbl_1d)|357|357|252|70.5%|1.0%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|195|2.6%|0.8%|
[et_block](#et_block)|974|18056767|191|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|188|0.0%|0.8%|
[dshield](#dshield)|19|5120|174|3.3%|0.7%|
[php_dictionary](#php_dictionary)|398|398|82|20.6%|0.3%|
[php_commenters](#php_commenters)|246|246|75|30.4%|0.3%|
[php_bad](#php_bad)|246|246|75|30.4%|0.3%|
[ri_connect_proxies](#ri_connect_proxies)|1622|1622|74|4.5%|0.3%|
[php_spammers](#php_spammers)|378|378|66|17.4%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|66|0.0%|0.2%|
[voipbl](#voipbl)|10286|10757|43|0.3%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|41|0.0%|0.1%|
[ciarmy](#ciarmy)|409|409|41|10.0%|0.1%|
[et_tor](#et_tor)|6400|6400|29|0.4%|0.1%|
[php_harvesters](#php_harvesters)|235|235|25|10.6%|0.1%|
[dm_tor](#dm_tor)|6499|6499|25|0.3%|0.1%|
[bm_tor](#bm_tor)|6505|6505|25|0.3%|0.1%|
[shunlist](#shunlist)|51|51|11|21.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|6|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|3|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Wed May 27 17:40:07 UTC 2015.

The ipset `bm_tor` has **6505** entries, **6505** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|161.7%|
[dm_tor](#dm_tor)|6499|6499|6412|98.6%|98.5%|
[et_tor](#et_tor)|6400|6400|5680|88.7%|87.3%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|1040|14.1%|15.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|609|0.0%|9.3%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|566|0.6%|8.7%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|425|1.4%|6.5%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|229|2.8%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|183|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|166|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|45|0.0%|0.6%|
[php_commenters](#php_commenters)|246|246|28|11.3%|0.4%|
[php_bad](#php_bad)|246|246|28|11.3%|0.4%|
[blocklist_de](#blocklist_de)|23463|23463|25|0.1%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|21|0.0%|0.3%|
[openbl_90d](#openbl_90d)|9900|9900|20|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7827|7827|20|0.2%|0.3%|
[openbl](#openbl)|9900|9900|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|235|235|7|2.9%|0.1%|
[php_spammers](#php_spammers)|378|378|5|1.3%|0.0%|
[nixspam](#nixspam)|28307|28307|5|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4104|4104|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|398|398|3|0.7%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|974|18056767|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1622|1622|2|0.1%|0.0%|
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
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|0.0%|
[voipbl](#voipbl)|10286|10757|351|3.2%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|5|0.0%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|235|235|1|0.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2383|2383|1|0.0%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD)

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Wed May 27 15:01:33 UTC 2015.

The ipset `bruteforceblocker` has **2383** entries, **2383** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|441.4%|
[et_compromised](#et_compromised)|2292|2292|2253|98.2%|94.5%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|1474|0.8%|61.8%|
[openbl_90d](#openbl_90d)|9900|9900|1397|14.1%|58.6%|
[openbl](#openbl)|9900|9900|1397|14.1%|58.6%|
[openbl_60d](#openbl_60d)|7827|7827|1386|17.7%|58.1%|
[openbl_30d](#openbl_30d)|4444|4444|1327|29.8%|55.6%|
[blocklist_de](#blocklist_de)|23463|23463|1126|4.7%|47.2%|
[openbl_7d](#openbl_7d)|982|982|493|50.2%|20.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|230|0.0%|9.6%|
[openbl_1d](#openbl_1d)|357|357|207|57.9%|8.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|148|0.0%|6.2%|
[dshield](#dshield)|19|5120|125|2.4%|5.2%|
[et_block](#et_block)|974|18056767|97|0.0%|4.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|96|0.0%|4.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|74|0.0%|3.1%|
[shunlist](#shunlist)|51|51|9|17.6%|0.3%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|6|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|3|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[voipbl](#voipbl)|10286|10757|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|1|0.0%|0.0%|
[nixspam](#nixspam)|28307|28307|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3666|670786520|1|0.0%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Wed May 27 15:15:07 UTC 2015.

The ipset `ciarmy` has **409** entries, **409** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|2572.1%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|402|0.2%|98.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|68|0.0%|16.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|47|0.0%|11.4%|
[blocklist_de](#blocklist_de)|23463|23463|41|0.1%|10.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|26|0.0%|6.3%|
[voipbl](#voipbl)|10286|10757|3|0.0%|0.7%|
[nixspam](#nixspam)|28307|28307|2|0.0%|0.4%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|1|0.0%|0.2%|
[shunlist](#shunlist)|51|51|1|1.9%|0.2%|
[openbl_90d](#openbl_90d)|9900|9900|1|0.0%|0.2%|
[openbl_7d](#openbl_7d)|982|982|1|0.1%|0.2%|
[openbl_60d](#openbl_60d)|7827|7827|1|0.0%|0.2%|
[openbl_30d](#openbl_30d)|4444|4444|1|0.0%|0.2%|
[openbl](#openbl)|9900|9900|1|0.0%|0.2%|
[et_block](#et_block)|974|18056767|1|0.0%|0.2%|
[dshield](#dshield)|19|5120|1|0.0%|0.2%|

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
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|3518.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|40|0.0%|13.3%|
[malc0de](#malc0de)|414|414|21|5.0%|7.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|10|0.0%|3.3%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|9|0.1%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|9|0.0%|3.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|4|0.3%|1.3%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|4|0.0%|1.3%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|3|0.0%|1.0%|
[zeus](#zeus)|266|266|1|0.3%|0.3%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|1|0.0%|0.3%|
[ri_web_proxies](#ri_web_proxies)|4104|4104|1|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.3%|
[et_block](#et_block)|974|18056767|1|0.0%|0.3%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Wed May 27 17:40:04 UTC 2015.

The ipset `dm_tor` has **6499** entries, **6499** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|161.8%|
[bm_tor](#bm_tor)|6505|6505|6412|98.5%|98.6%|
[et_tor](#et_tor)|6400|6400|5678|88.7%|87.3%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|1040|14.1%|16.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|608|0.0%|9.3%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|567|0.6%|8.7%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|424|1.4%|6.5%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|229|2.8%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|184|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|166|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|45|0.0%|0.6%|
[php_commenters](#php_commenters)|246|246|28|11.3%|0.4%|
[php_bad](#php_bad)|246|246|28|11.3%|0.4%|
[blocklist_de](#blocklist_de)|23463|23463|25|0.1%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|21|0.0%|0.3%|
[openbl_90d](#openbl_90d)|9900|9900|20|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7827|7827|20|0.2%|0.3%|
[openbl](#openbl)|9900|9900|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|235|235|7|2.9%|0.1%|
[ri_web_proxies](#ri_web_proxies)|4104|4104|5|0.1%|0.0%|
[php_spammers](#php_spammers)|378|378|5|1.3%|0.0%|
[nixspam](#nixspam)|28307|28307|5|0.0%|0.0%|
[php_dictionary](#php_dictionary)|398|398|3|0.7%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|974|18056767|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1622|1622|2|0.1%|0.0%|
[voipbl](#voipbl)|10286|10757|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Wed May 27 14:56:03 UTC 2015.

The ipset `dshield` has **19** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|205.4%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|4352|2.4%|85.0%|
[et_block](#et_block)|974|18056767|1280|0.0%|25.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|512|0.0%|10.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|256|0.0%|5.0%|
[openbl_90d](#openbl_90d)|9900|9900|209|2.1%|4.0%|
[openbl](#openbl)|9900|9900|209|2.1%|4.0%|
[openbl_60d](#openbl_60d)|7827|7827|206|2.6%|4.0%|
[openbl_30d](#openbl_30d)|4444|4444|186|4.1%|3.6%|
[blocklist_de](#blocklist_de)|23463|23463|174|0.7%|3.3%|
[openbl_7d](#openbl_7d)|982|982|154|15.6%|3.0%|
[bruteforceblocker](#bruteforceblocker)|2383|2383|125|5.2%|2.4%|
[et_compromised](#et_compromised)|2292|2292|120|5.2%|2.3%|
[openbl_1d](#openbl_1d)|357|357|79|22.1%|1.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|5|0.0%|0.0%|
[malc0de](#malc0de)|414|414|4|0.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|4|0.0%|0.0%|
[nixspam](#nixspam)|28307|28307|1|0.0%|0.0%|
[ciarmy](#ciarmy)|409|409|1|0.2%|0.0%|

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
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|5529|3.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1301|0.3%|0.0%|
[dshield](#dshield)|19|5120|1280|25.0%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|771|0.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|517|0.1%|0.0%|
[openbl_90d](#openbl_90d)|9900|9900|452|4.5%|0.0%|
[openbl](#openbl)|9900|9900|452|4.5%|0.0%|
[openbl_60d](#openbl_60d)|7827|7827|305|3.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|286|3.8%|0.0%|
[zeus](#zeus)|266|266|261|98.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|227|99.1%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|225|0.7%|0.0%|
[openbl_30d](#openbl_30d)|4444|4444|213|4.7%|0.0%|
[blocklist_de](#blocklist_de)|23463|23463|191|0.8%|0.0%|
[nixspam](#nixspam)|28307|28307|187|0.6%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2383|2383|97|4.0%|0.0%|
[openbl_7d](#openbl_7d)|982|982|96|9.7%|0.0%|
[et_compromised](#et_compromised)|2292|2292|91|3.9%|0.0%|
[feodo](#feodo)|62|62|59|95.1%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|54|0.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|28|2.1%|0.0%|
[openbl_1d](#openbl_1d)|357|357|26|7.2%|0.0%|
[php_commenters](#php_commenters)|246|246|24|9.7%|0.0%|
[php_bad](#php_bad)|246|246|24|9.7%|0.0%|
[sslbl](#sslbl)|335|335|22|6.5%|0.0%|
[voipbl](#voipbl)|10286|10757|18|0.1%|0.0%|
[palevo](#palevo)|13|13|13|100.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[php_dictionary](#php_dictionary)|398|398|3|0.7%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6499|6499|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6505|6505|3|0.0%|0.0%|
[php_spammers](#php_spammers)|378|378|2|0.5%|0.0%|
[malc0de](#malc0de)|414|414|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[php_harvesters](#php_harvesters)|235|235|1|0.4%|0.0%|
[et_botnet](#et_botnet)|505|505|1|0.1%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|299|299|1|0.3%|0.0%|
[ciarmy](#ciarmy)|409|409|1|0.2%|0.0%|

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
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|2083.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|73|0.0%|14.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|42|0.0%|8.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|21|0.0%|4.1%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|3|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|1|0.0%|0.1%|
[nixspam](#nixspam)|28307|28307|1|0.0%|0.1%|
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
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|458.9%|
[bruteforceblocker](#bruteforceblocker)|2383|2383|2253|94.5%|98.2%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|1454|0.8%|63.4%|
[openbl_90d](#openbl_90d)|9900|9900|1375|13.8%|59.9%|
[openbl](#openbl)|9900|9900|1375|13.8%|59.9%|
[openbl_60d](#openbl_60d)|7827|7827|1365|17.4%|59.5%|
[openbl_30d](#openbl_30d)|4444|4444|1304|29.3%|56.8%|
[blocklist_de](#blocklist_de)|23463|23463|1024|4.3%|44.6%|
[openbl_7d](#openbl_7d)|982|982|483|49.1%|21.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|222|0.0%|9.6%|
[openbl_1d](#openbl_1d)|357|357|204|57.1%|8.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|144|0.0%|6.2%|
[dshield](#dshield)|19|5120|120|2.3%|5.2%|
[et_block](#et_block)|974|18056767|91|0.0%|3.9%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|90|0.0%|3.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|70|0.0%|3.0%|
[shunlist](#shunlist)|51|51|9|17.6%|0.3%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|5|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.1%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[voipbl](#voipbl)|10286|10757|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|1|0.0%|0.0%|
[nixspam](#nixspam)|28307|28307|1|0.0%|0.0%|
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
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|164.3%|
[bm_tor](#bm_tor)|6505|6505|5680|87.3%|88.7%|
[dm_tor](#dm_tor)|6499|6499|5678|87.3%|88.7%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|1085|14.7%|16.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|609|0.0%|9.5%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|580|0.6%|9.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|440|1.4%|6.8%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|231|2.9%|3.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|185|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|164|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|44|0.0%|0.6%|
[blocklist_de](#blocklist_de)|23463|23463|29|0.1%|0.4%|
[php_commenters](#php_commenters)|246|246|28|11.3%|0.4%|
[php_bad](#php_bad)|246|246|28|11.3%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|21|0.0%|0.3%|
[openbl_90d](#openbl_90d)|9900|9900|20|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7827|7827|20|0.2%|0.3%|
[openbl](#openbl)|9900|9900|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|235|235|7|2.9%|0.1%|
[php_spammers](#php_spammers)|378|378|6|1.5%|0.0%|
[nixspam](#nixspam)|28307|28307|6|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4104|4104|5|0.1%|0.0%|
[php_dictionary](#php_dictionary)|398|398|3|0.7%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|974|18056767|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1622|1622|2|0.1%|0.0%|
[voipbl](#voipbl)|10286|10757|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Wed May 27 17:40:19 UTC 2015.

The ipset `feodo` has **62** entries, **62** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|16967.7%|
[et_block](#et_block)|974|18056767|59|0.0%|95.1%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|48|0.6%|77.4%|
[sslbl](#sslbl)|335|335|20|5.9%|32.2%|
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
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|894|0.2%|0.0%|
[voipbl](#voipbl)|10286|10757|351|3.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|33|2.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|9|0.7%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|235|235|1|0.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2383|2383|1|0.0%|0.0%|

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
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|21.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|1172|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|432|0.0%|0.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|233|0.0%|0.4%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|14|0.0%|0.0%|
[nixspam](#nixspam)|28307|28307|14|0.0%|0.0%|
[fullbogons](#fullbogons)|3666|670786520|14|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|13|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|6|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|6|0.0%|0.0%|
[et_block](#et_block)|974|18056767|6|0.0%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|23463|23463|3|0.0%|0.0%|
[voipbl](#voipbl)|10286|10757|2|0.0%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|235|235|2|0.8%|0.0%|
[php_dictionary](#php_dictionary)|398|398|2|0.5%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4104|4104|1|0.0%|0.0%|
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
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|2526625|0.7%|27.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|904796|0.1%|9.8%|
[fullbogons](#fullbogons)|3666|670786520|565248|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|145472|0.1%|1.5%|
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1036|0.3%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|737|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|519|0.2%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|209|0.6%|0.0%|
[nixspam](#nixspam)|28307|28307|189|0.6%|0.0%|
[blocklist_de](#blocklist_de)|23463|23463|66|0.2%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|35|0.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|27|2.1%|0.0%|
[openbl_90d](#openbl_90d)|9900|9900|19|0.1%|0.0%|
[openbl](#openbl)|9900|9900|19|0.1%|0.0%|
[openbl_60d](#openbl_60d)|7827|7827|18|0.2%|0.0%|
[openbl_30d](#openbl_30d)|4444|4444|13|0.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|11|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|10|4.3%|0.0%|
[zeus](#zeus)|266|266|10|3.7%|0.0%|
[openbl_7d](#openbl_7d)|982|982|9|0.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[openbl_1d](#openbl_1d)|357|357|5|1.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2383|2383|5|0.2%|0.0%|
[et_compromised](#et_compromised)|2292|2292|4|0.1%|0.0%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6499|6499|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6505|6505|3|0.0%|0.0%|
[php_spammers](#php_spammers)|378|378|2|0.5%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
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
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|5212|2.8%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|1498|1.6%|0.0%|
[blocklist_de](#blocklist_de)|23463|23463|1494|6.3%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|578|1.9%|0.0%|
[nixspam](#nixspam)|28307|28307|536|1.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|432|0.8%|0.0%|
[voipbl](#voipbl)|10286|10757|301|2.7%|0.0%|
[openbl_90d](#openbl_90d)|9900|9900|220|2.2%|0.0%|
[openbl](#openbl)|9900|9900|220|2.2%|0.0%|
[openbl_60d](#openbl_60d)|7827|7827|181|2.3%|0.0%|
[dm_tor](#dm_tor)|6499|6499|166|2.5%|0.0%|
[bm_tor](#bm_tor)|6505|6505|166|2.5%|0.0%|
[et_tor](#et_tor)|6400|6400|164|2.5%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|155|1.9%|0.0%|
[openbl_30d](#openbl_30d)|4444|4444|100|2.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|98|6.7%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4104|4104|95|2.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|91|1.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2383|2383|74|3.1%|0.0%|
[et_compromised](#et_compromised)|2292|2292|70|3.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|66|5.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1622|1622|59|3.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|58|8.6%|0.0%|
[et_botnet](#et_botnet)|505|505|42|8.3%|0.0%|
[ciarmy](#ciarmy)|409|409|26|6.3%|0.0%|
[openbl_7d](#openbl_7d)|982|982|19|1.9%|0.0%|
[malc0de](#malc0de)|414|414|12|2.8%|0.0%|
[php_dictionary](#php_dictionary)|398|398|9|2.2%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|299|299|9|3.0%|0.0%|
[zeus](#zeus)|266|266|7|2.6%|0.0%|
[php_harvesters](#php_harvesters)|235|235|7|2.9%|0.0%|
[openbl_1d](#openbl_1d)|357|357|7|1.9%|0.0%|
[php_spammers](#php_spammers)|378|378|5|1.3%|0.0%|
[php_commenters](#php_commenters)|246|246|5|2.0%|0.0%|
[php_bad](#php_bad)|246|246|5|2.0%|0.0%|
[dshield](#dshield)|19|5120|5|0.0%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[zeus_badips](#zeus_badips)|229|229|4|1.7%|0.0%|
[sslbl](#sslbl)|335|335|3|0.8%|0.0%|
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
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|8413|4.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|7752|2.2%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|2453|2.6%|0.0%|
[blocklist_de](#blocklist_de)|23463|23463|1447|6.1%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|894|2.9%|0.0%|
[nixspam](#nixspam)|28307|28307|775|2.7%|0.0%|
[openbl_90d](#openbl_90d)|9900|9900|516|5.2%|0.0%|
[openbl](#openbl)|9900|9900|516|5.2%|0.0%|
[voipbl](#voipbl)|10286|10757|428|3.9%|0.0%|
[openbl_60d](#openbl_60d)|7827|7827|367|4.6%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|270|3.4%|0.0%|
[dshield](#dshield)|19|5120|256|5.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|233|0.4%|0.0%|
[openbl_30d](#openbl_30d)|4444|4444|230|5.1%|0.0%|
[et_tor](#et_tor)|6400|6400|185|2.8%|0.0%|
[dm_tor](#dm_tor)|6499|6499|184|2.8%|0.0%|
[bm_tor](#bm_tor)|6505|6505|183|2.8%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4104|4104|148|3.6%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2383|2383|148|6.2%|0.0%|
[et_compromised](#et_compromised)|2292|2292|144|6.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|105|1.4%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1622|1622|73|4.5%|0.0%|
[openbl_7d](#openbl_7d)|982|982|48|4.8%|0.0%|
[ciarmy](#ciarmy)|409|409|47|11.4%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|45|3.0%|0.0%|
[php_spammers](#php_spammers)|378|378|29|7.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|28|4.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|26|2.0%|0.0%|
[malc0de](#malc0de)|414|414|26|6.2%|0.0%|
[et_botnet](#et_botnet)|505|505|21|4.1%|0.0%|
[openbl_1d](#openbl_1d)|357|357|17|4.7%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|299|299|10|3.3%|0.0%|
[zeus](#zeus)|266|266|9|3.3%|0.0%|
[php_dictionary](#php_dictionary)|398|398|9|2.2%|0.0%|
[zeus_badips](#zeus_badips)|229|229|8|3.4%|0.0%|
[php_commenters](#php_commenters)|246|246|8|3.2%|0.0%|
[php_bad](#php_bad)|246|246|8|3.2%|0.0%|
[php_harvesters](#php_harvesters)|235|235|7|2.9%|0.0%|
[sslbl](#sslbl)|335|335|5|1.4%|0.0%|
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
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|9278|2.7%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|6226|6.7%|0.0%|
[blocklist_de](#blocklist_de)|23463|23463|2861|12.1%|0.0%|
[nixspam](#nixspam)|28307|28307|2068|7.3%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|2067|6.8%|0.0%|
[voipbl](#voipbl)|10286|10757|1587|14.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1172|2.4%|0.0%|
[openbl_90d](#openbl_90d)|9900|9900|960|9.6%|0.0%|
[openbl](#openbl)|9900|9900|960|9.6%|0.0%|
[openbl_60d](#openbl_60d)|7827|7827|718|9.1%|0.0%|
[et_tor](#et_tor)|6400|6400|609|9.5%|0.0%|
[bm_tor](#bm_tor)|6505|6505|609|9.3%|0.0%|
[dm_tor](#dm_tor)|6499|6499|608|9.3%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|564|7.1%|0.0%|
[openbl_30d](#openbl_30d)|4444|4444|444|9.9%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2383|2383|230|9.6%|0.0%|
[et_compromised](#et_compromised)|2292|2292|222|9.6%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|219|2.9%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|146|11.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4104|4104|133|3.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|110|7.5%|0.0%|
[openbl_7d](#openbl_7d)|982|982|92|9.3%|0.0%|
[malc0de](#malc0de)|414|414|76|18.3%|0.0%|
[et_botnet](#et_botnet)|505|505|73|14.4%|0.0%|
[ciarmy](#ciarmy)|409|409|68|16.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|51|7.5%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|299|299|40|13.3%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1622|1622|39|2.4%|0.0%|
[php_spammers](#php_spammers)|378|378|24|6.3%|0.0%|
[php_dictionary](#php_dictionary)|398|398|23|5.7%|0.0%|
[zeus](#zeus)|266|266|20|7.5%|0.0%|
[openbl_1d](#openbl_1d)|357|357|20|5.6%|0.0%|
[sslbl](#sslbl)|335|335|19|5.6%|0.0%|
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
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|1563.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|58|0.0%|8.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|51|0.0%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|28|0.0%|4.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|24|0.0%|3.5%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|12|0.0%|1.7%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|11|0.0%|1.6%|
[ri_web_proxies](#ri_web_proxies)|4104|4104|10|0.2%|1.4%|
[ri_connect_proxies](#ri_connect_proxies)|1622|1622|6|0.3%|0.8%|
[nixspam](#nixspam)|28307|28307|3|0.0%|0.4%|
[blocklist_de](#blocklist_de)|23463|23463|3|0.0%|0.4%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|2|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.2%|
[et_block](#et_block)|974|18056767|2|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|1|0.0%|0.1%|
[php_dictionary](#php_dictionary)|398|398|1|0.2%|0.1%|
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
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|3.0%|
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
[dm_tor](#dm_tor)|6499|6499|21|0.3%|0.0%|
[bm_tor](#bm_tor)|6505|6505|21|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|19|1.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|15|0.2%|0.0%|
[nixspam](#nixspam)|28307|28307|9|0.0%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|8|0.1%|0.0%|
[openbl_90d](#openbl_90d)|9900|9900|6|0.0%|0.0%|
[openbl](#openbl)|9900|9900|6|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[blocklist_de](#blocklist_de)|23463|23463|6|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7827|7827|5|0.0%|0.0%|
[voipbl](#voipbl)|10286|10757|4|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4104|4104|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4444|4444|4|0.0%|0.0%|
[dshield](#dshield)|19|5120|4|0.0%|0.0%|
[malc0de](#malc0de)|414|414|3|0.7%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[sslbl](#sslbl)|335|335|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|235|235|1|0.4%|0.0%|
[php_dictionary](#php_dictionary)|398|398|1|0.2%|0.0%|
[openbl_7d](#openbl_7d)|982|982|1|0.1%|0.0%|
[feodo](#feodo)|62|62|1|1.6%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|299|299|1|0.3%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|

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
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|720.5%|
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
[blocklist_de](#blocklist_de)|23463|23463|3|0.0%|0.2%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|2|0.0%|0.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|2|0.0%|0.1%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.1%|
[bruteforceblocker](#bruteforceblocker)|2383|2383|2|0.0%|0.1%|
[ri_web_proxies](#ri_web_proxies)|4104|4104|1|0.0%|0.0%|
[openbl_90d](#openbl_90d)|9900|9900|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|982|982|1|0.1%|0.0%|
[openbl_60d](#openbl_60d)|7827|7827|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4444|4444|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|357|357|1|0.2%|0.0%|
[openbl](#openbl)|9900|9900|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2292|2292|1|0.0%|0.0%|
[et_botnet](#et_botnet)|505|505|1|0.1%|0.0%|
[dm_tor](#dm_tor)|6499|6499|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6505|6505|1|0.0%|0.0%|

## infiltrated

[infiltrated.net](http://www.infiltrated.net) (this list seems to be updated frequently, but we found no information about it)

Source is downloaded from [this link](http://www.infiltrated.net/blacklisted).

The last time downloaded was found to be dated: Wed May 27 17:40:20 UTC 2015.

The ipset `infiltrated` has **10520** entries, **10520** unique IPs.

The following table shows the overlaps of `infiltrated` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `infiltrated`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `infiltrated`.
- ` this % ` is the percentage **of this ipset (`infiltrated`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus_badips](#zeus_badips)|229|229|10520|4593.8%|100.0%|
[zeus](#zeus)|266|266|10520|3954.8%|100.0%|
[voipbl](#voipbl)|10286|10757|10520|97.7%|100.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|10520|34.8%|100.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|10520|11.3%|100.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|10520|133.2%|100.0%|
[sslbl](#sslbl)|335|335|10520|3140.2%|100.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|10520|2.4%|100.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|10520|0.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|10520|143.3%|100.0%|
[shunlist](#shunlist)|51|51|10520|20627.4%|100.0%|
[ri_web_proxies](#ri_web_proxies)|4104|4104|10520|256.3%|100.0%|
[ri_connect_proxies](#ri_connect_proxies)|1622|1622|10520|648.5%|100.0%|
[php_spammers](#php_spammers)|378|378|10520|2783.0%|100.0%|
[php_harvesters](#php_harvesters)|235|235|10520|4476.5%|100.0%|
[php_dictionary](#php_dictionary)|398|398|10520|2643.2%|100.0%|
[php_commenters](#php_commenters)|246|246|10520|4276.4%|100.0%|
[php_bad](#php_bad)|246|246|10520|4276.4%|100.0%|
[palevo](#palevo)|13|13|10520|80923.0%|100.0%|
[openbl_90d](#openbl_90d)|9900|9900|10520|106.2%|100.0%|
[openbl_7d](#openbl_7d)|982|982|10520|1071.2%|100.0%|
[openbl_60d](#openbl_60d)|7827|7827|10520|134.4%|100.0%|
[openbl_30d](#openbl_30d)|4444|4444|10520|236.7%|100.0%|
[openbl_1d](#openbl_1d)|357|357|10520|2946.7%|100.0%|
[openbl](#openbl)|9900|9900|10520|106.2%|100.0%|
[nixspam](#nixspam)|28307|28307|10520|37.1%|100.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|10520|819.9%|100.0%|
[malc0de](#malc0de)|414|414|10520|2541.0%|100.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|10520|720.5%|100.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|10520|3.0%|100.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|10520|1563.1%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|10520|0.0%|100.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|10520|0.0%|100.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|10520|0.0%|100.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10520|0.1%|100.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|10520|21.8%|100.0%|
[fullbogons](#fullbogons)|3666|670786520|10520|0.0%|100.0%|
[feodo](#feodo)|62|62|10520|16967.7%|100.0%|
[et_tor](#et_tor)|6400|6400|10520|164.3%|100.0%|
[et_compromised](#et_compromised)|2292|2292|10520|458.9%|100.0%|
[et_botnet](#et_botnet)|505|505|10520|2083.1%|100.0%|
[et_block](#et_block)|974|18056767|10520|0.0%|100.0%|
[dshield](#dshield)|19|5120|10520|205.4%|100.0%|
[dm_tor](#dm_tor)|6499|6499|10520|161.8%|100.0%|
[clean_mx_viruses](#clean_mx_viruses)|299|299|10520|3518.3%|100.0%|
[ciarmy](#ciarmy)|409|409|10520|2572.1%|100.0%|
[bruteforceblocker](#bruteforceblocker)|2383|2383|10520|441.4%|100.0%|
[bogons](#bogons)|13|592708608|10520|0.0%|100.0%|
[bm_tor](#bm_tor)|6505|6505|10520|161.7%|100.0%|
[blocklist_de](#blocklist_de)|23463|23463|10520|44.8%|100.0%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|10520|5.8%|100.0%|

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
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|2541.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|76|0.0%|18.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|26|0.0%|6.2%|
[clean_mx_viruses](#clean_mx_viruses)|299|299|21|7.0%|5.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|12|0.0%|2.8%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|11|0.0%|2.6%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|4|0.3%|0.9%|
[dshield](#dshield)|19|5120|4|0.0%|0.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|3|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.4%|
[et_block](#et_block)|974|18056767|2|0.0%|0.4%|
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
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|819.9%|
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
[nixspam](#nixspam)|28307|28307|2|0.0%|0.1%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|1|0.0%|0.0%|
[et_botnet](#et_botnet)|505|505|1|0.1%|0.0%|
[blocklist_de](#blocklist_de)|23463|23463|1|0.0%|0.0%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Wed May 27 17:30:02 UTC 2015.

The ipset `nixspam` has **28307** entries, **28307** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|37.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|2068|0.0%|7.3%|
[blocklist_de](#blocklist_de)|23463|23463|1023|4.3%|3.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|775|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|536|0.0%|1.8%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|245|0.2%|0.8%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|216|2.9%|0.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|189|0.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|189|0.0%|0.6%|
[et_block](#et_block)|974|18056767|187|0.0%|0.6%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|148|0.4%|0.5%|
[php_dictionary](#php_dictionary)|398|398|111|27.8%|0.3%|
[ri_web_proxies](#ri_web_proxies)|4104|4104|82|1.9%|0.2%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|81|1.0%|0.2%|
[php_spammers](#php_spammers)|378|378|74|19.5%|0.2%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|43|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[php_bad](#php_bad)|246|246|12|4.8%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1622|1622|11|0.6%|0.0%|
[php_commenters](#php_commenters)|246|246|11|4.4%|0.0%|
[openbl_90d](#openbl_90d)|9900|9900|9|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7827|7827|9|0.1%|0.0%|
[openbl](#openbl)|9900|9900|9|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|9|0.0%|0.0%|
[voipbl](#voipbl)|10286|10757|6|0.0%|0.0%|
[php_harvesters](#php_harvesters)|235|235|6|2.5%|0.0%|
[et_tor](#et_tor)|6400|6400|6|0.0%|0.0%|
[dm_tor](#dm_tor)|6499|6499|5|0.0%|0.0%|
[bm_tor](#bm_tor)|6505|6505|5|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4444|4444|4|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|3|0.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|2|0.1%|0.0%|
[ciarmy](#ciarmy)|409|409|2|0.4%|0.0%|
[et_compromised](#et_compromised)|2292|2292|1|0.0%|0.0%|
[et_botnet](#et_botnet)|505|505|1|0.1%|0.0%|
[dshield](#dshield)|19|5120|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2383|2383|1|0.0%|0.0%|

## openbl

[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**

Source is downloaded from [this link](http://www.openbl.org/lists/base.txt.gz).

The last time downloaded was found to be dated: Wed May 27 15:17:01 UTC 2015.

The ipset `openbl` has **9900** entries, **9900** unique IPs.

The following table shows the overlaps of `openbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl`.
- ` this % ` is the percentage **of this ipset (`openbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|106.2%|
[openbl_90d](#openbl_90d)|9900|9900|9900|100.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|9879|5.4%|99.7%|
[openbl_60d](#openbl_60d)|7827|7827|7827|100.0%|79.0%|
[openbl_30d](#openbl_30d)|4444|4444|4444|100.0%|44.8%|
[bruteforceblocker](#bruteforceblocker)|2383|2383|1397|58.6%|14.1%|
[et_compromised](#et_compromised)|2292|2292|1375|59.9%|13.8%|
[blocklist_de](#blocklist_de)|23463|23463|1346|5.7%|13.5%|
[openbl_7d](#openbl_7d)|982|982|982|100.0%|9.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|960|0.0%|9.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|516|0.0%|5.2%|
[et_block](#et_block)|974|18056767|452|0.0%|4.5%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|447|0.0%|4.5%|
[openbl_1d](#openbl_1d)|357|357|357|100.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|220|0.0%|2.2%|
[dshield](#dshield)|19|5120|209|4.0%|2.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|70|0.0%|0.7%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|38|0.1%|0.3%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|24|0.3%|0.2%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|22|0.2%|0.2%|
[et_tor](#et_tor)|6400|6400|20|0.3%|0.2%|
[dm_tor](#dm_tor)|6499|6499|20|0.3%|0.2%|
[bm_tor](#bm_tor)|6505|6505|20|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|19|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|14|0.0%|0.1%|
[voipbl](#voipbl)|10286|10757|11|0.1%|0.1%|
[shunlist](#shunlist)|51|51|11|21.5%|0.1%|
[nixspam](#nixspam)|28307|28307|9|0.0%|0.0%|
[php_commenters](#php_commenters)|246|246|8|3.2%|0.0%|
[php_bad](#php_bad)|246|246|8|3.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|6|0.0%|0.0%|
[php_harvesters](#php_harvesters)|235|235|4|1.7%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[sslbl](#sslbl)|335|335|1|0.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4104|4104|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ciarmy](#ciarmy)|409|409|1|0.2%|0.0%|

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
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|2946.7%|
[openbl_90d](#openbl_90d)|9900|9900|357|3.6%|100.0%|
[openbl_60d](#openbl_60d)|7827|7827|357|4.5%|100.0%|
[openbl_30d](#openbl_30d)|4444|4444|357|8.0%|100.0%|
[openbl](#openbl)|9900|9900|357|3.6%|100.0%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|355|0.1%|99.4%|
[blocklist_de](#blocklist_de)|23463|23463|252|1.0%|70.5%|
[openbl_7d](#openbl_7d)|982|982|211|21.4%|59.1%|
[bruteforceblocker](#bruteforceblocker)|2383|2383|207|8.6%|57.9%|
[et_compromised](#et_compromised)|2292|2292|204|8.9%|57.1%|
[dshield](#dshield)|19|5120|79|1.5%|22.1%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|26|0.0%|7.2%|
[et_block](#et_block)|974|18056767|26|0.0%|7.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|20|0.0%|5.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|17|0.0%|4.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|7|0.0%|1.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|1.4%|
[shunlist](#shunlist)|51|51|2|3.9%|0.5%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|1|0.0%|0.2%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.2%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt.gz).

The last time downloaded was found to be dated: Wed May 27 15:17:00 UTC 2015.

The ipset `openbl_30d` has **4444** entries, **4444** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|236.7%|
[openbl_90d](#openbl_90d)|9900|9900|4444|44.8%|100.0%|
[openbl_60d](#openbl_60d)|7827|7827|4444|56.7%|100.0%|
[openbl](#openbl)|9900|9900|4444|44.8%|100.0%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|4434|2.4%|99.7%|
[bruteforceblocker](#bruteforceblocker)|2383|2383|1327|55.6%|29.8%|
[et_compromised](#et_compromised)|2292|2292|1304|56.8%|29.3%|
[blocklist_de](#blocklist_de)|23463|23463|1182|5.0%|26.5%|
[openbl_7d](#openbl_7d)|982|982|982|100.0%|22.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|444|0.0%|9.9%|
[openbl_1d](#openbl_1d)|357|357|357|100.0%|8.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|230|0.0%|5.1%|
[et_block](#et_block)|974|18056767|213|0.0%|4.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|211|0.0%|4.7%|
[dshield](#dshield)|19|5120|186|3.6%|4.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|100|0.0%|2.2%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|21|0.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|13|0.0%|0.2%|
[shunlist](#shunlist)|51|51|10|19.6%|0.2%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|7|0.0%|0.1%|
[nixspam](#nixspam)|28307|28307|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|4|0.0%|0.0%|
[voipbl](#voipbl)|10286|10757|3|0.0%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ciarmy](#ciarmy)|409|409|1|0.2%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt.gz).

The last time downloaded was found to be dated: Wed May 27 15:17:00 UTC 2015.

The ipset `openbl_60d` has **7827** entries, **7827** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|134.4%|
[openbl_90d](#openbl_90d)|9900|9900|7827|79.0%|100.0%|
[openbl](#openbl)|9900|9900|7827|79.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|7809|4.3%|99.7%|
[openbl_30d](#openbl_30d)|4444|4444|4444|100.0%|56.7%|
[bruteforceblocker](#bruteforceblocker)|2383|2383|1386|58.1%|17.7%|
[et_compromised](#et_compromised)|2292|2292|1365|59.5%|17.4%|
[blocklist_de](#blocklist_de)|23463|23463|1293|5.5%|16.5%|
[openbl_7d](#openbl_7d)|982|982|982|100.0%|12.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|718|0.0%|9.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|367|0.0%|4.6%|
[openbl_1d](#openbl_1d)|357|357|357|100.0%|4.5%|
[et_block](#et_block)|974|18056767|305|0.0%|3.8%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|303|0.0%|3.8%|
[dshield](#dshield)|19|5120|206|4.0%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|181|0.0%|2.3%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|63|0.0%|0.8%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|35|0.1%|0.4%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|24|0.3%|0.3%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|20|0.2%|0.2%|
[et_tor](#et_tor)|6400|6400|20|0.3%|0.2%|
[dm_tor](#dm_tor)|6499|6499|20|0.3%|0.2%|
[bm_tor](#bm_tor)|6505|6505|20|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|18|0.0%|0.2%|
[shunlist](#shunlist)|51|51|11|21.5%|0.1%|
[voipbl](#voipbl)|10286|10757|9|0.0%|0.1%|
[nixspam](#nixspam)|28307|28307|9|0.0%|0.1%|
[php_commenters](#php_commenters)|246|246|8|3.2%|0.1%|
[php_bad](#php_bad)|246|246|8|3.2%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|5|0.0%|0.0%|
[php_harvesters](#php_harvesters)|235|235|4|1.7%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ciarmy](#ciarmy)|409|409|1|0.2%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt.gz).

The last time downloaded was found to be dated: Wed May 27 15:17:00 UTC 2015.

The ipset `openbl_7d` has **982** entries, **982** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|1071.2%|
[openbl_90d](#openbl_90d)|9900|9900|982|9.9%|100.0%|
[openbl_60d](#openbl_60d)|7827|7827|982|12.5%|100.0%|
[openbl_30d](#openbl_30d)|4444|4444|982|22.0%|100.0%|
[openbl](#openbl)|9900|9900|982|9.9%|100.0%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|977|0.5%|99.4%|
[blocklist_de](#blocklist_de)|23463|23463|657|2.8%|66.9%|
[bruteforceblocker](#bruteforceblocker)|2383|2383|493|20.6%|50.2%|
[et_compromised](#et_compromised)|2292|2292|483|21.0%|49.1%|
[openbl_1d](#openbl_1d)|357|357|211|59.1%|21.4%|
[dshield](#dshield)|19|5120|154|3.0%|15.6%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|96|0.0%|9.7%|
[et_block](#et_block)|974|18056767|96|0.0%|9.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|92|0.0%|9.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|48|0.0%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|19|0.0%|1.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|9|0.0%|0.9%|
[shunlist](#shunlist)|51|51|4|7.8%|0.4%|
[voipbl](#voipbl)|10286|10757|2|0.0%|0.2%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.1%|
[ciarmy](#ciarmy)|409|409|1|0.2%|0.1%|

## openbl_90d

[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_90days.txt.gz).

The last time downloaded was found to be dated: Wed May 27 15:17:01 UTC 2015.

The ipset `openbl_90d` has **9900** entries, **9900** unique IPs.

The following table shows the overlaps of `openbl_90d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_90d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_90d`.
- ` this % ` is the percentage **of this ipset (`openbl_90d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|106.2%|
[openbl](#openbl)|9900|9900|9900|100.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|9879|5.4%|99.7%|
[openbl_60d](#openbl_60d)|7827|7827|7827|100.0%|79.0%|
[openbl_30d](#openbl_30d)|4444|4444|4444|100.0%|44.8%|
[bruteforceblocker](#bruteforceblocker)|2383|2383|1397|58.6%|14.1%|
[et_compromised](#et_compromised)|2292|2292|1375|59.9%|13.8%|
[blocklist_de](#blocklist_de)|23463|23463|1346|5.7%|13.5%|
[openbl_7d](#openbl_7d)|982|982|982|100.0%|9.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|960|0.0%|9.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|516|0.0%|5.2%|
[et_block](#et_block)|974|18056767|452|0.0%|4.5%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|447|0.0%|4.5%|
[openbl_1d](#openbl_1d)|357|357|357|100.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|220|0.0%|2.2%|
[dshield](#dshield)|19|5120|209|4.0%|2.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|70|0.0%|0.7%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|38|0.1%|0.3%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|24|0.3%|0.2%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|22|0.2%|0.2%|
[et_tor](#et_tor)|6400|6400|20|0.3%|0.2%|
[dm_tor](#dm_tor)|6499|6499|20|0.3%|0.2%|
[bm_tor](#bm_tor)|6505|6505|20|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|19|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|14|0.0%|0.1%|
[voipbl](#voipbl)|10286|10757|11|0.1%|0.1%|
[shunlist](#shunlist)|51|51|11|21.5%|0.1%|
[nixspam](#nixspam)|28307|28307|9|0.0%|0.0%|
[php_commenters](#php_commenters)|246|246|8|3.2%|0.0%|
[php_bad](#php_bad)|246|246|8|3.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|6|0.0%|0.0%|
[php_harvesters](#php_harvesters)|235|235|4|1.7%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[sslbl](#sslbl)|335|335|1|0.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4104|4104|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ciarmy](#ciarmy)|409|409|1|0.2%|0.0%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Wed May 27 17:40:16 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|80923.0%|
[et_block](#et_block)|974|18056767|13|0.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|11|0.1%|84.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|3|0.0%|23.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|2|0.0%|15.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|1|0.0%|7.6%|

## php_bad

[projecthoneypot.org](http://www.projecthoneypot.org/) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1).

The last time downloaded was found to be dated: Wed May 27 17:40:30 UTC 2015.

The ipset `php_bad` has **246** entries, **246** unique IPs.

The following table shows the overlaps of `php_bad` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_bad`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_bad`.
- ` this % ` is the percentage **of this ipset (`php_bad`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|4276.4%|
[php_commenters](#php_commenters)|246|246|245|99.5%|99.5%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|180|0.1%|73.1%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|175|0.5%|71.1%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|111|1.4%|45.1%|
[blocklist_de](#blocklist_de)|23463|23463|75|0.3%|30.4%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|37|0.5%|15.0%|
[et_tor](#et_tor)|6400|6400|28|0.4%|11.3%|
[dm_tor](#dm_tor)|6499|6499|28|0.4%|11.3%|
[bm_tor](#bm_tor)|6505|6505|28|0.4%|11.3%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|25|0.0%|10.1%|
[php_spammers](#php_spammers)|378|378|25|6.6%|10.1%|
[et_block](#et_block)|974|18056767|24|0.0%|9.7%|
[php_dictionary](#php_dictionary)|398|398|15|3.7%|6.0%|
[nixspam](#nixspam)|28307|28307|12|0.0%|4.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|12|0.0%|4.8%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|12|0.0%|4.8%|
[php_harvesters](#php_harvesters)|235|235|9|3.8%|3.6%|
[openbl_90d](#openbl_90d)|9900|9900|8|0.0%|3.2%|
[openbl_60d](#openbl_60d)|7827|7827|8|0.1%|3.2%|
[openbl](#openbl)|9900|9900|8|0.0%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|8|0.0%|3.2%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|7|0.0%|2.8%|
[ri_web_proxies](#ri_web_proxies)|4104|4104|7|0.1%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|5|0.0%|2.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.4%|
[zeus](#zeus)|266|266|1|0.3%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.4%|

## php_commenters

[projecthoneypot.org](http://www.projecthoneypot.org/) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1).

The last time downloaded was found to be dated: Wed May 27 17:40:32 UTC 2015.

The ipset `php_commenters` has **246** entries, **246** unique IPs.

The following table shows the overlaps of `php_commenters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_commenters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_commenters`.
- ` this % ` is the percentage **of this ipset (`php_commenters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|4276.4%|
[php_bad](#php_bad)|246|246|245|99.5%|99.5%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|181|0.1%|73.5%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|176|0.5%|71.5%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|112|1.4%|45.5%|
[blocklist_de](#blocklist_de)|23463|23463|75|0.3%|30.4%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|36|0.4%|14.6%|
[et_tor](#et_tor)|6400|6400|28|0.4%|11.3%|
[dm_tor](#dm_tor)|6499|6499|28|0.4%|11.3%|
[bm_tor](#bm_tor)|6505|6505|28|0.4%|11.3%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|25|0.0%|10.1%|
[php_spammers](#php_spammers)|378|378|24|6.3%|9.7%|
[et_block](#et_block)|974|18056767|24|0.0%|9.7%|
[php_dictionary](#php_dictionary)|398|398|14|3.5%|5.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|12|0.0%|4.8%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|12|0.0%|4.8%|
[nixspam](#nixspam)|28307|28307|11|0.0%|4.4%|
[php_harvesters](#php_harvesters)|235|235|9|3.8%|3.6%|
[openbl_90d](#openbl_90d)|9900|9900|8|0.0%|3.2%|
[openbl_60d](#openbl_60d)|7827|7827|8|0.1%|3.2%|
[openbl](#openbl)|9900|9900|8|0.0%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|8|0.0%|3.2%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|7|0.0%|2.8%|
[ri_web_proxies](#ri_web_proxies)|4104|4104|7|0.1%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|5|0.0%|2.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.4%|
[zeus](#zeus)|266|266|1|0.3%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.4%|

## php_dictionary

[projecthoneypot.org](http://www.projecthoneypot.org/) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1).

The last time downloaded was found to be dated: Wed May 27 17:40:36 UTC 2015.

The ipset `php_dictionary` has **398** entries, **398** unique IPs.

The following table shows the overlaps of `php_dictionary` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_dictionary`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_dictionary`.
- ` this % ` is the percentage **of this ipset (`php_dictionary`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|2643.2%|
[nixspam](#nixspam)|28307|28307|111|0.3%|27.8%|
[blocklist_de](#blocklist_de)|23463|23463|82|0.3%|20.6%|
[php_spammers](#php_spammers)|378|378|74|19.5%|18.5%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|70|0.9%|17.5%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|61|0.0%|15.3%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|48|0.1%|12.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|34|0.4%|8.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|23|0.0%|5.7%|
[ri_web_proxies](#ri_web_proxies)|4104|4104|19|0.4%|4.7%|
[php_bad](#php_bad)|246|246|15|6.0%|3.7%|
[php_commenters](#php_commenters)|246|246|14|5.6%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|9|0.0%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|9|0.0%|2.2%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|7|0.0%|1.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|3|0.0%|0.7%|
[et_tor](#et_tor)|6400|6400|3|0.0%|0.7%|
[et_block](#et_block)|974|18056767|3|0.0%|0.7%|
[dm_tor](#dm_tor)|6499|6499|3|0.0%|0.7%|
[bm_tor](#bm_tor)|6505|6505|3|0.0%|0.7%|
[ri_connect_proxies](#ri_connect_proxies)|1622|1622|2|0.1%|0.5%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.5%|
[php_harvesters](#php_harvesters)|235|235|1|0.4%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.2%|

## php_harvesters

[projecthoneypot.org](http://www.projecthoneypot.org/) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1).

The last time downloaded was found to be dated: Wed May 27 17:40:25 UTC 2015.

The ipset `php_harvesters` has **235** entries, **235** unique IPs.

The following table shows the overlaps of `php_harvesters` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_harvesters`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_harvesters`.
- ` this % ` is the percentage **of this ipset (`php_harvesters`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|4476.5%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|59|0.0%|25.1%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|48|0.1%|20.4%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|30|0.3%|12.7%|
[blocklist_de](#blocklist_de)|23463|23463|25|0.1%|10.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|14|0.0%|5.9%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|9|0.1%|3.8%|
[php_commenters](#php_commenters)|246|246|9|3.6%|3.8%|
[php_bad](#php_bad)|246|246|9|3.6%|3.8%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|9|0.0%|3.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|7|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|7|0.0%|2.9%|
[et_tor](#et_tor)|6400|6400|7|0.1%|2.9%|
[dm_tor](#dm_tor)|6499|6499|7|0.1%|2.9%|
[bm_tor](#bm_tor)|6505|6505|7|0.1%|2.9%|
[nixspam](#nixspam)|28307|28307|6|0.0%|2.5%|
[openbl_90d](#openbl_90d)|9900|9900|4|0.0%|1.7%|
[openbl_60d](#openbl_60d)|7827|7827|4|0.0%|1.7%|
[openbl](#openbl)|9900|9900|4|0.0%|1.7%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.8%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|1|0.0%|0.4%|
[ri_web_proxies](#ri_web_proxies)|4104|4104|1|0.0%|0.4%|
[php_spammers](#php_spammers)|378|378|1|0.2%|0.4%|
[php_dictionary](#php_dictionary)|398|398|1|0.2%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.4%|
[fullbogons](#fullbogons)|3666|670786520|1|0.0%|0.4%|
[et_block](#et_block)|974|18056767|1|0.0%|0.4%|
[bogons](#bogons)|13|592708608|1|0.0%|0.4%|

## php_spammers

[projecthoneypot.org](http://www.projecthoneypot.org/) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1).

The last time downloaded was found to be dated: Wed May 27 17:40:28 UTC 2015.

The ipset `php_spammers` has **378** entries, **378** unique IPs.

The following table shows the overlaps of `php_spammers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `php_spammers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `php_spammers`.
- ` this % ` is the percentage **of this ipset (`php_spammers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|2783.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|81|0.0%|21.4%|
[php_dictionary](#php_dictionary)|398|398|74|18.5%|19.5%|
[nixspam](#nixspam)|28307|28307|74|0.2%|19.5%|
[blocklist_de](#blocklist_de)|23463|23463|66|0.2%|17.4%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|63|0.8%|16.6%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|57|0.1%|15.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|29|0.0%|7.6%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|28|0.3%|7.4%|
[php_bad](#php_bad)|246|246|25|10.1%|6.6%|
[php_commenters](#php_commenters)|246|246|24|9.7%|6.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|24|0.0%|6.3%|
[ri_web_proxies](#ri_web_proxies)|4104|4104|16|0.3%|4.2%|
[et_tor](#et_tor)|6400|6400|6|0.0%|1.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|5|0.0%|1.3%|
[dm_tor](#dm_tor)|6499|6499|5|0.0%|1.3%|
[bm_tor](#bm_tor)|6505|6505|5|0.0%|1.3%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|4|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.5%|
[ri_connect_proxies](#ri_connect_proxies)|1622|1622|2|0.1%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.5%|
[et_block](#et_block)|974|18056767|2|0.0%|0.5%|
[php_harvesters](#php_harvesters)|235|235|1|0.4%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.2%|

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
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|648.5%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|938|1.0%|57.8%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|699|2.3%|43.0%|
[ri_web_proxies](#ri_web_proxies)|4104|4104|656|15.9%|40.4%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|186|2.3%|11.4%|
[blocklist_de](#blocklist_de)|23463|23463|74|0.3%|4.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|73|0.0%|4.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|59|0.0%|3.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|39|0.0%|2.4%|
[nixspam](#nixspam)|28307|28307|11|0.0%|0.6%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.3%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|4|0.0%|0.2%|
[php_spammers](#php_spammers)|378|378|2|0.5%|0.1%|
[php_dictionary](#php_dictionary)|398|398|2|0.5%|0.1%|
[et_tor](#et_tor)|6400|6400|2|0.0%|0.1%|
[dm_tor](#dm_tor)|6499|6499|2|0.0%|0.1%|
[bm_tor](#bm_tor)|6505|6505|2|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Wed May 27 14:08:41 UTC 2015.

The ipset `ri_web_proxies` has **4104** entries, **4104** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|256.3%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|1986|2.1%|48.3%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|1573|5.2%|38.3%|
[ri_connect_proxies](#ri_connect_proxies)|1622|1622|656|40.4%|15.9%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|549|6.9%|13.3%|
[blocklist_de](#blocklist_de)|23463|23463|373|1.5%|9.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|148|0.0%|3.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|133|0.0%|3.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|95|0.0%|2.3%|
[nixspam](#nixspam)|28307|28307|82|0.2%|1.9%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|30|0.4%|0.7%|
[php_dictionary](#php_dictionary)|398|398|19|4.7%|0.4%|
[php_spammers](#php_spammers)|378|378|16|4.2%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|10|1.4%|0.2%|
[php_commenters](#php_commenters)|246|246|7|2.8%|0.1%|
[php_bad](#php_bad)|246|246|7|2.8%|0.1%|
[et_tor](#et_tor)|6400|6400|5|0.0%|0.1%|
[dm_tor](#dm_tor)|6499|6499|5|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6505|6505|4|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|235|235|1|0.4%|0.0%|
[openbl_90d](#openbl_90d)|9900|9900|1|0.0%|0.0%|
[openbl](#openbl)|9900|9900|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|299|299|1|0.3%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Wed May 27 14:30:05 UTC 2015.

The ipset `shunlist` has **51** entries, **51** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|20627.4%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|51|0.0%|100.0%|
[openbl_90d](#openbl_90d)|9900|9900|11|0.1%|21.5%|
[openbl_60d](#openbl_60d)|7827|7827|11|0.1%|21.5%|
[openbl](#openbl)|9900|9900|11|0.1%|21.5%|
[blocklist_de](#blocklist_de)|23463|23463|11|0.0%|21.5%|
[openbl_30d](#openbl_30d)|4444|4444|10|0.2%|19.6%|
[et_compromised](#et_compromised)|2292|2292|9|0.3%|17.6%|
[bruteforceblocker](#bruteforceblocker)|2383|2383|9|0.3%|17.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|6|0.0%|11.7%|
[openbl_7d](#openbl_7d)|982|982|4|0.4%|7.8%|
[voipbl](#voipbl)|10286|10757|3|0.0%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|3|0.0%|5.8%|
[openbl_1d](#openbl_1d)|357|357|2|0.5%|3.9%|
[ciarmy](#ciarmy)|409|409|1|0.2%|1.9%|

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
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|143.3%|
[et_tor](#et_tor)|6400|6400|1085|16.9%|14.7%|
[dm_tor](#dm_tor)|6499|6499|1040|16.0%|14.1%|
[bm_tor](#bm_tor)|6505|6505|1040|15.9%|14.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|695|0.7%|9.4%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|526|1.7%|7.1%|
[et_block](#et_block)|974|18056767|286|0.0%|3.8%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|275|3.4%|3.7%|
[zeus](#zeus)|266|266|226|84.9%|3.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|219|0.0%|2.9%|
[nixspam](#nixspam)|28307|28307|216|0.7%|2.9%|
[zeus_badips](#zeus_badips)|229|229|200|87.3%|2.7%|
[blocklist_de](#blocklist_de)|23463|23463|195|0.8%|2.6%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|122|0.0%|1.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|105|0.0%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|91|0.0%|1.2%|
[php_dictionary](#php_dictionary)|398|398|70|17.5%|0.9%|
[php_spammers](#php_spammers)|378|378|63|16.6%|0.8%|
[feodo](#feodo)|62|62|48|77.4%|0.6%|
[php_bad](#php_bad)|246|246|37|15.0%|0.5%|
[php_commenters](#php_commenters)|246|246|36|14.6%|0.4%|
[ri_web_proxies](#ri_web_proxies)|4104|4104|30|0.7%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|25|1.9%|0.3%|
[openbl_90d](#openbl_90d)|9900|9900|24|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7827|7827|24|0.3%|0.3%|
[openbl](#openbl)|9900|9900|24|0.2%|0.3%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|20|0.0%|0.2%|
[sslbl](#sslbl)|335|335|17|5.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|15|0.0%|0.2%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.1%|
[php_harvesters](#php_harvesters)|235|235|9|3.8%|0.1%|
[clean_mx_viruses](#clean_mx_viruses)|299|299|9|3.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|6|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1622|1622|4|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[voipbl](#voipbl)|10286|10757|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4444|4444|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2292|2292|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2383|2383|1|0.0%|0.0%|

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
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|1624|0.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1037|0.3%|0.0%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|788|0.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|512|0.1%|0.0%|
[dshield](#dshield)|19|5120|512|10.0%|0.0%|
[openbl_90d](#openbl_90d)|9900|9900|447|4.5%|0.0%|
[openbl](#openbl)|9900|9900|447|4.5%|0.0%|
[openbl_60d](#openbl_60d)|7827|7827|303|3.8%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|246|0.8%|0.0%|
[openbl_30d](#openbl_30d)|4444|4444|211|4.7%|0.0%|
[nixspam](#nixspam)|28307|28307|189|0.6%|0.0%|
[blocklist_de](#blocklist_de)|23463|23463|188|0.8%|0.0%|
[openbl_7d](#openbl_7d)|982|982|96|9.7%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2383|2383|96|4.0%|0.0%|
[et_compromised](#et_compromised)|2292|2292|90|3.9%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|56|0.7%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|28|2.1%|0.0%|
[openbl_1d](#openbl_1d)|357|357|26|7.2%|0.0%|
[php_commenters](#php_commenters)|246|246|25|10.1%|0.0%|
[php_bad](#php_bad)|246|246|25|10.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|20|0.2%|0.0%|
[zeus_badips](#zeus_badips)|229|229|16|6.9%|0.0%|
[zeus](#zeus)|266|266|16|6.0%|0.0%|
[voipbl](#voipbl)|10286|10757|14|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[php_dictionary](#php_dictionary)|398|398|3|0.7%|0.0%|
[sslbl](#sslbl)|335|335|2|0.5%|0.0%|
[php_spammers](#php_spammers)|378|378|2|0.5%|0.0%|
[malc0de](#malc0de)|414|414|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6400|6400|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6499|6499|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6505|6505|2|0.0%|0.0%|
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
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|270785|0.1%|64.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|33368|0.0%|7.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|33155|0.0%|7.8%|
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|2.4%|
[et_block](#et_block)|974|18056767|517|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|512|0.0%|0.1%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|109|0.1%|0.0%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|41|0.1%|0.0%|
[blocklist_de](#blocklist_de)|23463|23463|41|0.1%|0.0%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|15|0.0%|0.0%|
[openbl_90d](#openbl_90d)|9900|9900|14|0.1%|0.0%|
[openbl](#openbl)|9900|9900|14|0.1%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|10|0.1%|0.0%|
[php_commenters](#php_commenters)|246|246|7|2.8%|0.0%|
[php_bad](#php_bad)|246|246|7|2.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|6|0.0%|0.0%|
[zeus_badips](#zeus_badips)|229|229|5|2.1%|0.0%|
[zeus](#zeus)|266|266|5|1.8%|0.0%|
[php_harvesters](#php_harvesters)|235|235|1|0.4%|0.0%|
[openbl_60d](#openbl_60d)|7827|7827|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4444|4444|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|357|357|1|0.2%|0.0%|
[malc0de](#malc0de)|414|414|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Wed May 27 17:30:05 UTC 2015.

The ipset `sslbl` has **335** entries, **335** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|3140.2%|
[et_block](#et_block)|974|18056767|22|0.0%|6.5%|
[feodo](#feodo)|62|62|20|32.2%|5.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|19|0.0%|5.6%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|17|0.2%|5.0%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|7|0.0%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|5|0.0%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|3|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|2|0.0%|0.5%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|1|0.0%|0.2%|
[openbl_90d](#openbl_90d)|9900|9900|1|0.0%|0.2%|
[openbl](#openbl)|9900|9900|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.2%|

## stop_forum_spam_1h

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Wed May 27 17:00:02 UTC 2015.

The ipset `stop_forum_spam_1h` has **7897** entries, **7897** unique IPs.

The following table shows the overlaps of `stop_forum_spam_1h` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stop_forum_spam_1h`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stop_forum_spam_1h`.
- ` this % ` is the percentage **of this ipset (`stop_forum_spam_1h`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|133.2%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|5334|17.6%|67.5%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|4498|4.8%|56.9%|
[blocklist_de](#blocklist_de)|23463|23463|1471|6.2%|18.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|564|0.0%|7.1%|
[ri_web_proxies](#ri_web_proxies)|4104|4104|549|13.3%|6.9%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|275|3.7%|3.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|270|0.0%|3.4%|
[et_tor](#et_tor)|6400|6400|231|3.6%|2.9%|
[dm_tor](#dm_tor)|6499|6499|229|3.5%|2.8%|
[bm_tor](#bm_tor)|6505|6505|229|3.5%|2.8%|
[ri_connect_proxies](#ri_connect_proxies)|1622|1622|186|11.4%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|155|0.0%|1.9%|
[php_commenters](#php_commenters)|246|246|112|45.5%|1.4%|
[php_bad](#php_bad)|246|246|111|45.1%|1.4%|
[nixspam](#nixspam)|28307|28307|81|0.2%|1.0%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|57|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|56|0.0%|0.7%|
[et_block](#et_block)|974|18056767|54|0.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|35|0.0%|0.4%|
[php_dictionary](#php_dictionary)|398|398|34|8.5%|0.4%|
[php_harvesters](#php_harvesters)|235|235|30|12.7%|0.3%|
[php_spammers](#php_spammers)|378|378|28|7.4%|0.3%|
[openbl_90d](#openbl_90d)|9900|9900|22|0.2%|0.2%|
[openbl](#openbl)|9900|9900|22|0.2%|0.2%|
[openbl_60d](#openbl_60d)|7827|7827|20|0.2%|0.2%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|10|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|8|0.0%|0.1%|
[voipbl](#voipbl)|10286|10757|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4444|4444|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|

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
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|11.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|6226|0.0%|6.7%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|4498|56.9%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|2453|0.0%|2.6%|
[blocklist_de](#blocklist_de)|23463|23463|2417|10.3%|2.6%|
[ri_web_proxies](#ri_web_proxies)|4104|4104|1986|48.3%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|1498|0.0%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|1622|1622|938|57.8%|1.0%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|788|0.0%|0.8%|
[et_block](#et_block)|974|18056767|771|0.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|737|0.0%|0.7%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|695|9.4%|0.7%|
[et_tor](#et_tor)|6400|6400|580|9.0%|0.6%|
[dm_tor](#dm_tor)|6499|6499|567|8.7%|0.6%|
[bm_tor](#bm_tor)|6505|6505|566|8.7%|0.6%|
[nixspam](#nixspam)|28307|28307|245|0.8%|0.2%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|240|0.1%|0.2%|
[php_commenters](#php_commenters)|246|246|181|73.5%|0.1%|
[php_bad](#php_bad)|246|246|180|73.1%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|109|0.0%|0.1%|
[php_spammers](#php_spammers)|378|378|81|21.4%|0.0%|
[openbl_90d](#openbl_90d)|9900|9900|70|0.7%|0.0%|
[openbl](#openbl)|9900|9900|70|0.7%|0.0%|
[openbl_60d](#openbl_60d)|7827|7827|63|0.8%|0.0%|
[php_dictionary](#php_dictionary)|398|398|61|15.3%|0.0%|
[php_harvesters](#php_harvesters)|235|235|59|25.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|46|0.0%|0.0%|
[voipbl](#voipbl)|10286|10757|39|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|24|3.5%|0.0%|
[openbl_30d](#openbl_30d)|4444|4444|21|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2383|2383|6|0.2%|0.0%|
[et_compromised](#et_compromised)|2292|2292|5|0.2%|0.0%|
[zeus](#zeus)|266|266|4|1.5%|0.0%|
[zeus_badips](#zeus_badips)|229|229|3|1.3%|0.0%|
[fullbogons](#fullbogons)|3666|670786520|3|0.0%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|299|299|3|1.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|2|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[sslbl](#sslbl)|335|335|1|0.2%|0.0%|
[openbl_7d](#openbl_7d)|982|982|1|0.1%|0.0%|
[openbl_1d](#openbl_1d)|357|357|1|0.2%|0.0%|
[ciarmy](#ciarmy)|409|409|1|0.2%|0.0%|
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
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|34.8%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|5334|67.5%|17.6%|
[blocklist_de](#blocklist_de)|23463|23463|2196|9.3%|7.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|2067|0.0%|6.8%|
[ri_web_proxies](#ri_web_proxies)|4104|4104|1573|38.3%|5.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|894|0.0%|2.9%|
[ri_connect_proxies](#ri_connect_proxies)|1622|1622|699|43.0%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|578|0.0%|1.9%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|526|7.1%|1.7%|
[et_tor](#et_tor)|6400|6400|440|6.8%|1.4%|
[bm_tor](#bm_tor)|6505|6505|425|6.5%|1.4%|
[dm_tor](#dm_tor)|6499|6499|424|6.5%|1.4%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|246|0.0%|0.8%|
[et_block](#et_block)|974|18056767|225|0.0%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|209|0.0%|0.6%|
[php_commenters](#php_commenters)|246|246|176|71.5%|0.5%|
[php_bad](#php_bad)|246|246|175|71.1%|0.5%|
[nixspam](#nixspam)|28307|28307|148|0.5%|0.4%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|117|0.0%|0.3%|
[php_spammers](#php_spammers)|378|378|57|15.0%|0.1%|
[php_harvesters](#php_harvesters)|235|235|48|20.4%|0.1%|
[php_dictionary](#php_dictionary)|398|398|48|12.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|41|0.0%|0.1%|
[openbl_90d](#openbl_90d)|9900|9900|38|0.3%|0.1%|
[openbl](#openbl)|9900|9900|38|0.3%|0.1%|
[openbl_60d](#openbl_60d)|7827|7827|35|0.4%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|21|0.0%|0.0%|
[voipbl](#voipbl)|10286|10757|12|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|12|1.7%|0.0%|
[openbl_30d](#openbl_30d)|4444|4444|7|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2383|2383|3|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[et_compromised](#et_compromised)|2292|2292|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|
[clean_mx_viruses](#clean_mx_viruses)|299|299|1|0.3%|0.0%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Wed May 27 16:40:53 UTC 2015.

The ipset `voipbl` has **10286** entries, **10757** unique IPs.

The following table shows the overlaps of `voipbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `voipbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `voipbl`.
- ` this % ` is the percentage **of this ipset (`voipbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|97.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|1587|0.0%|14.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|428|0.0%|3.9%|
[fullbogons](#fullbogons)|3666|670786520|351|0.0%|3.2%|
[bogons](#bogons)|13|592708608|351|0.0%|3.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|301|0.0%|2.7%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|202|0.1%|1.8%|
[blocklist_de](#blocklist_de)|23463|23463|43|0.1%|0.3%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|39|0.0%|0.3%|
[et_block](#et_block)|974|18056767|18|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|14|0.0%|0.1%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|12|0.0%|0.1%|
[openbl_90d](#openbl_90d)|9900|9900|11|0.1%|0.1%|
[openbl](#openbl)|9900|9900|11|0.1%|0.1%|
[openbl_60d](#openbl_60d)|7827|7827|9|0.1%|0.0%|
[nixspam](#nixspam)|28307|28307|6|0.0%|0.0%|
[stop_forum_spam_1h](#stop_forum_spam_1h)|7897|7897|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|4|0.0%|0.0%|
[shunlist](#shunlist)|51|51|3|5.8%|0.0%|
[openbl_30d](#openbl_30d)|4444|4444|3|0.0%|0.0%|
[ciarmy](#ciarmy)|409|409|3|0.7%|0.0%|
[openbl_7d](#openbl_7d)|982|982|2|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|1|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[et_tor](#et_tor)|6400|6400|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2292|2292|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6499|6499|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2383|2383|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6505|6505|1|0.0%|0.0%|

## zeus

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) default blocklist including hijacked sites and web hosting providers - **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist).

The last time downloaded was found to be dated: Wed May 27 17:15:13 UTC 2015.

The ipset `zeus` has **266** entries, **266** unique IPs.

The following table shows the overlaps of `zeus` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus`.
- ` this % ` is the percentage **of this ipset (`zeus`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|3954.8%|
[et_block](#et_block)|974|18056767|261|0.0%|98.1%|
[zeus_badips](#zeus_badips)|229|229|229|100.0%|86.0%|
[snort_ipfilter](#snort_ipfilter)|7341|7341|226|3.0%|84.9%|
[alienvault_reputation](#alienvault_reputation)|179777|179777|67|0.0%|25.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|20|0.0%|7.5%|
[spamhaus_drop](#spamhaus_drop)|641|18117120|16|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|9|0.0%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|7|0.0%|2.6%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|5|0.0%|1.8%|
[stop_forum_spam_30d](#stop_forum_spam_30d)|92800|92800|4|0.0%|1.5%|
[stop_forum_spam_7d](#stop_forum_spam_7d)|30172|30172|1|0.0%|0.3%|
[php_commenters](#php_commenters)|246|246|1|0.4%|0.3%|
[php_bad](#php_bad)|246|246|1|0.4%|0.3%|
[openbl_90d](#openbl_90d)|9900|9900|1|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7827|7827|1|0.0%|0.3%|
[openbl_30d](#openbl_30d)|4444|4444|1|0.0%|0.3%|
[openbl](#openbl)|9900|9900|1|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.3%|
[et_compromised](#et_compromised)|2292|2292|1|0.0%|0.3%|
[clean_mx_viruses](#clean_mx_viruses)|299|299|1|0.3%|0.3%|
[bruteforceblocker](#bruteforceblocker)|2383|2383|1|0.0%|0.3%|
[blocklist_de](#blocklist_de)|23463|23463|1|0.0%|0.3%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) includes IPv4 addresses that are used by the ZeuS trojan

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Wed May 27 17:40:13 UTC 2015.

The ipset `zeus_badips` has **229** entries, **229** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[infiltrated](#infiltrated)|10520|10520|10520|100.0%|4593.8%|
[zeus](#zeus)|266|266|229|86.0%|100.0%|
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
[openbl_90d](#openbl_90d)|9900|9900|1|0.0%|0.4%|
[openbl_60d](#openbl_60d)|7827|7827|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|4444|4444|1|0.0%|0.4%|
[openbl](#openbl)|9900|9900|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.4%|
[et_compromised](#et_compromised)|2292|2292|1|0.0%|0.4%|
[bruteforceblocker](#bruteforceblocker)|2383|2383|1|0.0%|0.4%|
