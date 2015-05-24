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

---

# About this repo

This repository includes a list of ipsets dynamically updated with
firehol's (https://github.com/ktsaou/firehol) `update-ipsets.sh`
script found [here](https://github.com/ktsaou/firehol/blob/master/contrib/update-ipsets.sh).

This repo is self maintained. It it updated automatically from the script via a cron job.

## Why do we need blocklists?

As time passes and the internet matures in our life, cyber crime is becoming increasingly sophisticated.
Although there many tools (detection of malware, viruses, intrusion detection and prevension systems, etc)
to help us isolate the budguys, at the end of day they always manage to bypass all that.

What is more interesting is that the fraudsters or attackers in many cases are not going to do a
direct damage to you or your systems. They will use you and your systems to gain something else,
possibly not related or indirectly related to your business. Nowdays the attacks cannot be identified easily. They are
distributed and come to our systems from a vast amount of IPs around the world.

To get an idea, check for example the [XRumer](http://en.wikipedia.org/wiki/XRumer) software.

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

The following list was automatically generated on Sun May 24 19:34:45 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
alienvault_reputation|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|188000 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
autoshun|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|51 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
blocklist_de|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|26479 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
bogons|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
botnet|[EmergingThreats.net](http://www.emergingthreats.net/) botnet IPs (at the time of writing includes any abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:ip|515 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
bruteforceblocker|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD)|ipv4 hash:ip|2287 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
ciarmy|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|400 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
clean_mx_viruses|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|318 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
compromised|[EmergingThreats.net](http://www.emergingthreats.net/) distribution of IPs that have beed compromised (at the time of writing includes openbl, bruteforceblocker and sidreporter)|ipv4 hash:ip|2436 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
danmetor|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6555 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
dshield|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
emerging_block|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|965 subnets, 18065466 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
feodo|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|58 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
fullbogons|[Team-Cymru.org](http://www.team-cymru.org) IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user - **excellent list - use it only your internet interface**|ipv4 hash:net|3646 subnets, 670922200 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt)
geolite2_country|[MaxMind GeoLite2](http://dev.maxmind.com/geoip/geoip2/geolite2/) databases are free IP geolocation databases comparable to, but less accurate than, MaxMind’s GeoIP2 databases. They include IPs per country, IPs per continent, IPs used by anonymous services (VPNs, Proxies, etc) and Satellite Providers.|ipv4 hash:net|All the world|updated every 7 days  from [this link](http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country-CSV.zip)
ib_bluetack_badpeers|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) IPs that have been reported for bad deeds in p2p|ipv4 hash:ip|48134 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=cwworuawihqvocglcoss&fileformat=p2p&archiveformat=gz)
ib_bluetack_hijacked|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) hijacked IP-Blocks Hijacked IP space are IP blocks that are being used without permission|ipv4 hash:net|535 subnets, 9177856 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=usrcshglbiilevmyfhse&fileformat=p2p&archiveformat=gz)
ib_bluetack_level1|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Level 1 (for use in p2p): Companies or organizations who are clearly involved with trying to stop filesharing (e.g. Baytsp, MediaDefender, Mediasentry a.o.). Companies which anti-p2p activity has been seen from. Companies that produce or have a strong financial interest in copyrighted material (e.g. music, movie, software industries a.o.). Government ranges or companies that have a strong financial interest in doing work for governments. Legal industry ranges. IPs or ranges of ISPs from which anti-p2p activity has been observed. Basically this list will block all kinds of internet connections that most people would rather not have during their internet travels.|ipv4 hash:net|215693 subnets, 765044590 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz)
ib_bluetack_level2|[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 2 (for use in p2p). General corporate ranges. Ranges used by labs or researchers. Proxies.|ipv4 hash:net|75927 subnets, 348729520 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw&fileformat=p2p&archiveformat=gz)
ib_bluetack_level3|[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 3 (for use in p2p). Many portal-type websites. ISP ranges that may be dodgy for some reason. Ranges that belong to an individual, but which have not been determined to be used by a particular company. Ranges for things that are unusual in some way. The L3 list is aka the paranoid list.|ipv4 hash:net|18550 subnets, 139108857 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh&fileformat=p2p&archiveformat=gz)
ib_bluetack_proxies|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Open Proxies IPs list (without TOR)|ipv4 hash:ip|673 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=xoebmbyexwuiogmbyprb&fileformat=p2p&archiveformat=gz)
ib_bluetack_spyware|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) known malicious SPYWARE and ADWARE IP Address ranges|ipv4 hash:net|898 subnets, 336971 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=llvtlsjyoyiczbkjsxpf&fileformat=p2p&archiveformat=gz)
ib_bluetack_webexploit|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) web server hack and exploit attempts|ipv4 hash:ip|1460 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=ghlzqtqxnzctvvajwwag&fileformat=p2p&archiveformat=gz)
infiltrated|[infiltrated.net](http://www.infiltrated.net) (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|10520 unique IPs|updated every 12 hours  from [this link](http://www.infiltrated.net/blacklisted)
malc0de|[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days|ipv4 hash:ip|426 unique IPs|updated every 1 day  from [this link](http://malc0de.com/bl/IP_Blacklist.txt)
malwaredomainlist|[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses|ipv4 hash:ip|1283 unique IPs|updated every 12 hours  from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt)
nixspam|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|18589 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
openbl|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|9986 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt.gz)
openbl_1d|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|357 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_1days.txt.gz)
openbl_30d|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|4722 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt.gz)
openbl_60d|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7904 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt.gz)
openbl_7d|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|1427 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt.gz)
openbl_90d|[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|9986 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt.gz)
palevo|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|12 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
php_bad|[projecthoneypot.org](http://www.projecthoneypot.org/) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|184 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
php_commenters|[projecthoneypot.org](http://www.projecthoneypot.org/) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|184 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
php_dictionary|[projecthoneypot.org](http://www.projecthoneypot.org/) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|275 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
php_harvesters|[projecthoneypot.org](http://www.projecthoneypot.org/) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|178 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
php_spammers|[projecthoneypot.org](http://www.projecthoneypot.org/) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|261 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
rosi_connect_proxies|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1348 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
rosi_web_proxies|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|3230 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
snort_ipfilter|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|6580 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
spamhaus_drop|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|640 subnets, 18051584 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
spamhaus_edrop|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|55 subnets, 421120 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
sslbl|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|319 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
stop_forum_spam_1h|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|6751 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
stop_forum_spam_30d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|91499 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
stop_forum_spam_7d|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|28751 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
tor|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6340 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
tor_servers|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6539 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
zeus|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) default blocklist including hijacked sites and web hosting providers - **excellent list**|ipv4 hash:ip|262 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
zeus_badips|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) includes IPv4 addresses that are used by the ZeuS trojan|ipv4 hash:ip|228 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

The ipset `alienvault_reputation` has 188000 entries, 188000 unique IPs.

The following table shows the overlaps of \'alienvault_reputation\' with all the other ipsets supported.

- ` %  in ` is the percentage of each row found **in alienvault_reputation**.
- ` %  of ` is the percentage **of alienvault_reputation** found in each row.

ipset|entries|unique IPs|IPs found on both| % in| % of|
:---:|:-----:|:--------:|:---------------:|:---:|:---:|
ib_bluetack_level3|18550|139108857|15506|0.0%|8.2%|
openbl|9986|9986|9955|99.6%|5.2%|
openbl_90d|9986|9986|9955|99.6%|5.2%|
ib_bluetack_level2|75927|348729520|8665|0.0%|4.6%|
openbl_60d|7904|7904|7879|99.6%|4.1%|
emerging_block|965|18065466|5415|0.0%|2.8%|
ib_bluetack_level1|215693|765044590|5119|0.0%|2.7%|
openbl_30d|4722|4722|4705|99.6%|2.5%|
dshield|20|5120|3589|70.0%|1.9%|
spamhaus_drop|640|18051584|2274|0.0%|1.2%|
compromised|2436|2436|1591|65.3%|0.8%|
blocklist_de|26479|26479|1555|5.8%|0.8%|
bruteforceblocker|2287|2287|1442|63.0%|0.7%|
openbl_7d|1427|1427|1412|98.9%|0.7%|
ib_bluetack_hijacked|535|9177856|519|0.0%|0.2%|
ciarmy|400|400|389|97.2%|0.2%|
openbl_1d|357|357|355|99.4%|0.1%|
ib_bluetack_spyware|898|336971|280|0.0%|0.1%|
stop_forum_spam_30d|91499|91499|254|0.2%|0.1%|
stop_forum_spam_7d|28751|28751|120|0.4%|0.0%|
snort_ipfilter|6580|6580|115|1.7%|0.0%|
zeus|262|262|64|24.4%|0.0%|
stop_forum_spam_1h|6751|6751|55|0.8%|0.0%|
autoshun|51|51|49|96.0%|0.0%|
danmetor|6555|6555|45|0.6%|0.0%|
tor|6340|6340|44|0.6%|0.0%|
tor_servers|6539|6539|44|0.6%|0.0%|
zeus_badips|228|228|37|16.2%|0.0%|
nixspam|18589|18589|32|0.1%|0.0%|
spamhaus_edrop|55|421120|16|0.0%|0.0%|
ib_bluetack_badpeers|48134|48134|15|0.0%|0.0%|
malc0de|426|426|11|2.5%|0.0%|
php_commenters|184|184|10|5.4%|0.0%|
php_bad|184|184|10|5.4%|0.0%|
sslbl|319|319|7|2.1%|0.0%|
php_harvesters|178|178|7|3.9%|0.0%|
ib_bluetack_webexploit|1460|1460|7|0.4%|0.0%|
malwaredomainlist|1283|1283|6|0.4%|0.0%|
clean_mx_viruses|318|318|6|1.8%|0.0%|
php_spammers|261|261|3|1.1%|0.0%|
botnet|515|515|3|0.5%|0.0%|
rosi_web_proxies|3230|3230|2|0.0%|0.0%|
php_dictionary|275|275|2|0.7%|0.0%|
rosi_connect_proxies|1348|1348|1|0.0%|0.0%|
ib_bluetack_proxies|673|673|1|0.1%|0.0%|
feodo|58|58|1|1.7%|0.0%|

# autoshun

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

The ipset `autoshun` has 51 entries, 51 unique IPs.

The following table shows the overlaps of \'autoshun\' with all the other ipsets supported.

- ` %  in ` is the percentage of each row found **in autoshun**.
- ` %  of ` is the percentage **of autoshun** found in each row.

ipset|entries|unique IPs|IPs found on both| % in| % of|
:---:|:-----:|:--------:|:---------------:|:---:|:---:|
alienvault_reputation|188000|188000|49|0.0%|96.0%|
openbl|9986|9986|12|0.1%|23.5%|
openbl_90d|9986|9986|12|0.1%|23.5%|
openbl_60d|7904|7904|12|0.1%|23.5%|
openbl_30d|4722|4722|11|0.2%|21.5%|
bruteforceblocker|2287|2287|11|0.4%|21.5%|
blocklist_de|26479|26479|11|0.0%|21.5%|
compromised|2436|2436|10|0.4%|19.6%|
openbl_7d|1427|1427|9|0.6%|17.6%|
ib_bluetack_level3|18550|139108857|6|0.0%|11.7%|
ib_bluetack_level2|75927|348729520|3|0.0%|5.8%|
openbl_1d|357|357|2|0.5%|3.9%|
ciarmy|400|400|2|0.5%|3.9%|

# blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

The ipset `blocklist_de` has 26479 entries, 26479 unique IPs.

The following table shows the overlaps of \'blocklist_de\' with all the other ipsets supported.

- ` %  in ` is the percentage of each row found **in blocklist_de**.
- ` %  of ` is the percentage **of blocklist_de** found in each row.

ipset|entries|unique IPs|IPs found on both| % in| % of|
:---:|:-----:|:--------:|:---------------:|:---:|:---:|
ib_bluetack_level3|18550|139108857|3262|0.0%|12.3%|
stop_forum_spam_30d|91499|91499|2503|2.7%|9.4%|
stop_forum_spam_7d|28751|28751|2041|7.0%|7.7%|
alienvault_reputation|188000|188000|1555|0.8%|5.8%|
ib_bluetack_level1|215693|765044590|1521|0.0%|5.7%|
ib_bluetack_level2|75927|348729520|1431|0.0%|5.4%|
stop_forum_spam_1h|6751|6751|1318|19.5%|4.9%|
openbl|9986|9986|1292|12.9%|4.8%|
openbl_90d|9986|9986|1292|12.9%|4.8%|
openbl_60d|7904|7904|1242|15.7%|4.6%|
openbl_30d|4722|4722|1101|23.3%|4.1%|
bruteforceblocker|2287|2287|879|38.4%|3.3%|
compromised|2436|2436|814|33.4%|3.0%|
openbl_7d|1427|1427|796|55.7%|3.0%|
nixspam|18589|18589|682|3.6%|2.5%|
rosi_web_proxies|3230|3230|351|10.8%|1.3%|
openbl_1d|357|357|252|70.5%|0.9%|
snort_ipfilter|6580|6580|208|3.1%|0.7%|
emerging_block|965|18065466|201|0.0%|0.7%|
spamhaus_drop|640|18051584|194|0.0%|0.7%|
php_dictionary|275|275|81|29.4%|0.3%|
rosi_connect_proxies|1348|1348|80|5.9%|0.3%|
php_spammers|261|261|65|24.9%|0.2%|
ib_bluetack_hijacked|535|9177856|65|0.0%|0.2%|
php_commenters|184|184|61|33.1%|0.2%|
php_bad|184|184|61|33.1%|0.2%|
dshield|20|5120|45|0.8%|0.1%|
ciarmy|400|400|40|10.0%|0.1%|
spamhaus_edrop|55|421120|38|0.0%|0.1%|
php_harvesters|178|178|22|12.3%|0.0%|
ib_bluetack_spyware|898|336971|11|0.0%|0.0%|
autoshun|51|51|11|21.5%|0.0%|
tor_servers|6539|6539|6|0.0%|0.0%|
danmetor|6555|6555|6|0.0%|0.0%|
ib_bluetack_badpeers|48134|48134|4|0.0%|0.0%|
tor|6340|6340|3|0.0%|0.0%|
malwaredomainlist|1283|1283|3|0.2%|0.0%|
ib_bluetack_proxies|673|673|3|0.4%|0.0%|
clean_mx_viruses|318|318|2|0.6%|0.0%|
zeus|262|262|1|0.3%|0.0%|
zeus_badips|228|228|1|0.4%|0.0%|
ib_bluetack_webexploit|1460|1460|1|0.0%|0.0%|

# bogons

[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**

The ipset `bogons` has 13 entries, 592708608 unique IPs.

The following table shows the overlaps of \'bogons\' with all the other ipsets supported.

- ` %  in ` is the percentage of each row found **in bogons**.
- ` %  of ` is the percentage **of bogons** found in each row.

ipset|entries|unique IPs|IPs found on both| % in| % of|
:---:|:-----:|:--------:|:---------------:|:---:|:---:|
fullbogons|3646|670922200|592708608|88.3%|100.0%|
ib_bluetack_level3|18550|139108857|4194304|3.0%|0.7%|
stop_forum_spam_30d|91499|91499|1|0.0%|0.0%|
php_harvesters|178|178|1|0.5%|0.0%|
bruteforceblocker|2287|2287|1|0.0%|0.0%|

# botnet

[EmergingThreats.net](http://www.emergingthreats.net/) botnet IPs (at the time of writing includes any abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)

The ipset `botnet` has 515 entries, 515 unique IPs.

The following table shows the overlaps of \'botnet\' with all the other ipsets supported.

- ` %  in ` is the percentage of each row found **in botnet**.
- ` %  of ` is the percentage **of botnet** found in each row.

ipset|entries|unique IPs|IPs found on both| % in| % of|
:---:|:-----:|:--------:|:---------------:|:---:|:---:|
ib_bluetack_level3|18550|139108857|76|0.0%|14.7%|
ib_bluetack_level1|215693|765044590|42|0.0%|8.1%|
ib_bluetack_level2|75927|348729520|24|0.0%|4.6%|
alienvault_reputation|188000|188000|3|0.0%|0.5%|
spamhaus_drop|640|18051584|1|0.0%|0.1%|
malwaredomainlist|1283|1283|1|0.0%|0.1%|
ib_bluetack_webexploit|1460|1460|1|0.0%|0.1%|
ib_bluetack_hijacked|535|9177856|1|0.0%|0.1%|
emerging_block|965|18065466|1|0.0%|0.1%|
dshield|20|5120|1|0.0%|0.1%|

# bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD)

The ipset `bruteforceblocker` has 2287 entries, 2287 unique IPs.

The following table shows the overlaps of \'bruteforceblocker\' with all the other ipsets supported.

- ` %  in ` is the percentage of each row found **in bruteforceblocker**.
- ` %  of ` is the percentage **of bruteforceblocker** found in each row.

ipset|entries|unique IPs|IPs found on both| % in| % of|
:---:|:-----:|:--------:|:---------------:|:---:|:---:|
compromised|2436|2436|2148|88.1%|93.9%|
alienvault_reputation|188000|188000|1442|0.7%|63.0%|
openbl|9986|9986|1353|13.5%|59.1%|
openbl_90d|9986|9986|1353|13.5%|59.1%|
openbl_60d|7904|7904|1342|16.9%|58.6%|
openbl_30d|4722|4722|1288|27.2%|56.3%|
blocklist_de|26479|26479|879|3.3%|38.4%|
openbl_7d|1427|1427|722|50.5%|31.5%|
ib_bluetack_level3|18550|139108857|221|0.0%|9.6%|
openbl_1d|357|357|201|56.3%|8.7%|
ib_bluetack_level2|75927|348729520|143|0.0%|6.2%|
emerging_block|965|18065466|91|0.0%|3.9%|
spamhaus_drop|640|18051584|89|0.0%|3.8%|
ib_bluetack_level1|215693|765044590|66|0.0%|2.8%|
dshield|20|5120|33|0.6%|1.4%|
autoshun|51|51|11|21.5%|0.4%|
stop_forum_spam_30d|91499|91499|4|0.0%|0.1%|
ib_bluetack_hijacked|535|9177856|4|0.0%|0.1%|
nixspam|18589|18589|2|0.0%|0.0%|
zeus|262|262|1|0.3%|0.0%|
zeus_badips|228|228|1|0.4%|0.0%|
stop_forum_spam_7d|28751|28751|1|0.0%|0.0%|
snort_ipfilter|6580|6580|1|0.0%|0.0%|
ib_bluetack_webexploit|1460|1460|1|0.0%|0.0%|
fullbogons|3646|670922200|1|0.0%|0.0%|
bogons|13|592708608|1|0.0%|0.0%|

# ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

The ipset `ciarmy` has 400 entries, 400 unique IPs.

The following table shows the overlaps of \'ciarmy\' with all the other ipsets supported.

- ` %  in ` is the percentage of each row found **in ciarmy**.
- ` %  of ` is the percentage **of ciarmy** found in each row.

ipset|entries|unique IPs|IPs found on both| % in| % of|
:---:|:-----:|:--------:|:---------------:|:---:|:---:|
alienvault_reputation|188000|188000|389|0.2%|97.2%|
ib_bluetack_level3|18550|139108857|69|0.0%|17.2%|
ib_bluetack_level2|75927|348729520|49|0.0%|12.2%|
blocklist_de|26479|26479|40|0.1%|10.0%|
ib_bluetack_level1|215693|765044590|33|0.0%|8.2%|
dshield|20|5120|4|0.0%|1.0%|
emerging_block|965|18065466|3|0.0%|0.7%|
autoshun|51|51|2|3.9%|0.5%|

# clean_mx_viruses

[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses

The ipset `clean_mx_viruses` has 318 entries, 318 unique IPs.

The following table shows the overlaps of \'clean_mx_viruses\' with all the other ipsets supported.

- ` %  in ` is the percentage of each row found **in clean_mx_viruses**.
- ` %  of ` is the percentage **of clean_mx_viruses** found in each row.

ipset|entries|unique IPs|IPs found on both| % in| % of|
:---:|:-----:|:--------:|:---------------:|:---:|:---:|
ib_bluetack_level3|18550|139108857|52|0.0%|16.3%|
malc0de|426|426|23|5.3%|7.2%|
ib_bluetack_level2|75927|348729520|12|0.0%|3.7%|
ib_bluetack_level1|215693|765044590|10|0.0%|3.1%|
alienvault_reputation|188000|188000|6|0.0%|1.8%|
snort_ipfilter|6580|6580|3|0.0%|0.9%|
ib_bluetack_spyware|898|336971|3|0.0%|0.9%|
blocklist_de|26479|26479|2|0.0%|0.6%|
stop_forum_spam_7d|28751|28751|1|0.0%|0.3%|
stop_forum_spam_30d|91499|91499|1|0.0%|0.3%|
nixspam|18589|18589|1|0.0%|0.3%|

# compromised

[EmergingThreats.net](http://www.emergingthreats.net/) distribution of IPs that have beed compromised (at the time of writing includes openbl, bruteforceblocker and sidreporter)

The ipset `compromised` has 2436 entries, 2436 unique IPs.

The following table shows the overlaps of \'compromised\' with all the other ipsets supported.

- ` %  in ` is the percentage of each row found **in compromised**.
- ` %  of ` is the percentage **of compromised** found in each row.

ipset|entries|unique IPs|IPs found on both| % in| % of|
:---:|:-----:|:--------:|:---------------:|:---:|:---:|
bruteforceblocker|2287|2287|2148|93.9%|88.1%|
alienvault_reputation|188000|188000|1591|0.8%|65.3%|
openbl|9986|9986|1473|14.7%|60.4%|
openbl_90d|9986|9986|1473|14.7%|60.4%|
openbl_60d|7904|7904|1461|18.4%|59.9%|
openbl_30d|4722|4722|1337|28.3%|54.8%|
blocklist_de|26479|26479|814|3.0%|33.4%|
openbl_7d|1427|1427|706|49.4%|28.9%|
ib_bluetack_level3|18550|139108857|243|0.0%|9.9%|
openbl_1d|357|357|198|55.4%|8.1%|
ib_bluetack_level2|75927|348729520|153|0.0%|6.2%|
emerging_block|965|18065466|77|0.0%|3.1%|
spamhaus_drop|640|18051584|76|0.0%|3.1%|
ib_bluetack_level1|215693|765044590|75|0.0%|3.0%|
dshield|20|5120|24|0.4%|0.9%|
autoshun|51|51|10|19.6%|0.4%|
stop_forum_spam_30d|91499|91499|4|0.0%|0.1%|
ib_bluetack_hijacked|535|9177856|4|0.0%|0.1%|
stop_forum_spam_7d|28751|28751|2|0.0%|0.0%|
nixspam|18589|18589|2|0.0%|0.0%|
zeus|262|262|1|0.3%|0.0%|
zeus_badips|228|228|1|0.4%|0.0%|
snort_ipfilter|6580|6580|1|0.0%|0.0%|
ib_bluetack_webexploit|1460|1460|1|0.0%|0.0%|
ib_bluetack_spyware|898|336971|1|0.0%|0.0%|

# danmetor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

The ipset `danmetor` has 6555 entries, 6555 unique IPs.

The following table shows the overlaps of \'danmetor\' with all the other ipsets supported.

- ` %  in ` is the percentage of each row found **in danmetor**.
- ` %  of ` is the percentage **of danmetor** found in each row.

ipset|entries|unique IPs|IPs found on both| % in| % of|
:---:|:-----:|:--------:|:---------------:|:---:|:---:|
tor_servers|6539|6539|6473|98.9%|98.7%|
tor|6340|6340|5584|88.0%|85.1%|
snort_ipfilter|6580|6580|1063|16.1%|16.2%|
ib_bluetack_level3|18550|139108857|603|0.0%|9.1%|
stop_forum_spam_30d|91499|91499|566|0.6%|8.6%|
stop_forum_spam_7d|28751|28751|417|1.4%|6.3%|
stop_forum_spam_1h|6751|6751|249|3.6%|3.7%|
ib_bluetack_level2|75927|348729520|170|0.0%|2.5%|
ib_bluetack_level1|215693|765044590|148|0.0%|2.2%|
alienvault_reputation|188000|188000|45|0.0%|0.6%|
openbl|9986|9986|21|0.2%|0.3%|
openbl_90d|9986|9986|21|0.2%|0.3%|
openbl_60d|7904|7904|21|0.2%|0.3%|
ib_bluetack_spyware|898|336971|20|0.0%|0.3%|
php_commenters|184|184|18|9.7%|0.2%|
php_bad|184|184|18|9.7%|0.2%|
php_harvesters|178|178|7|3.9%|0.1%|
blocklist_de|26479|26479|6|0.0%|0.0%|
php_spammers|261|261|5|1.9%|0.0%|
rosi_web_proxies|3230|3230|4|0.1%|0.0%|
php_dictionary|275|275|4|1.4%|0.0%|
emerging_block|965|18065466|4|0.0%|0.0%|
spamhaus_drop|640|18051584|2|0.0%|0.0%|
ib_bluetack_hijacked|535|9177856|2|0.0%|0.0%|
dshield|20|5120|2|0.0%|0.0%|
rosi_connect_proxies|1348|1348|1|0.0%|0.0%|
nixspam|18589|18589|1|0.0%|0.0%|
ib_bluetack_webexploit|1460|1460|1|0.0%|0.0%|

# dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

The ipset `dshield` has 20 entries, 5120 unique IPs.

The following table shows the overlaps of \'dshield\' with all the other ipsets supported.

- ` %  in ` is the percentage of each row found **in dshield**.
- ` %  of ` is the percentage **of dshield** found in each row.

ipset|entries|unique IPs|IPs found on both| % in| % of|
:---:|:-----:|:--------:|:---------------:|:---:|:---:|
alienvault_reputation|188000|188000|3589|1.9%|70.0%|
emerging_block|965|18065466|1536|0.0%|30.0%|
ib_bluetack_level1|215693|765044590|516|0.0%|10.0%|
spamhaus_drop|640|18051584|256|0.0%|5.0%|
ib_bluetack_level3|18550|139108857|256|0.0%|5.0%|
ib_bluetack_level2|75927|348729520|256|0.0%|5.0%|
blocklist_de|26479|26479|45|0.1%|0.8%|
openbl|9986|9986|38|0.3%|0.7%|
openbl_90d|9986|9986|38|0.3%|0.7%|
openbl_60d|7904|7904|38|0.4%|0.7%|
openbl_30d|4722|4722|37|0.7%|0.7%|
openbl_7d|1427|1427|36|2.5%|0.7%|
bruteforceblocker|2287|2287|33|1.4%|0.6%|
compromised|2436|2436|24|0.9%|0.4%|
openbl_1d|357|357|21|5.8%|0.4%|
stop_forum_spam_30d|91499|91499|6|0.0%|0.1%|
ib_bluetack_spyware|898|336971|4|0.0%|0.0%|
ciarmy|400|400|4|1.0%|0.0%|
stop_forum_spam_7d|28751|28751|3|0.0%|0.0%|
stop_forum_spam_1h|6751|6751|3|0.0%|0.0%|
tor|6340|6340|2|0.0%|0.0%|
tor_servers|6539|6539|2|0.0%|0.0%|
ib_bluetack_badpeers|48134|48134|2|0.0%|0.0%|
danmetor|6555|6555|2|0.0%|0.0%|
snort_ipfilter|6580|6580|1|0.0%|0.0%|
nixspam|18589|18589|1|0.0%|0.0%|
malc0de|426|426|1|0.2%|0.0%|
ib_bluetack_webexploit|1460|1460|1|0.0%|0.0%|
botnet|515|515|1|0.1%|0.0%|

# emerging_block

[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)

The ipset `emerging_block` has 965 entries, 18065466 unique IPs.

The following table shows the overlaps of \'emerging_block\' with all the other ipsets supported.

- ` %  in ` is the percentage of each row found **in emerging_block**.
- ` %  of ` is the percentage **of emerging_block** found in each row.

ipset|entries|unique IPs|IPs found on both| % in| % of|
:---:|:-----:|:--------:|:---------------:|:---:|:---:|
spamhaus_drop|640|18051584|17994240|99.6%|99.6%|
ib_bluetack_level2|75927|348729520|8401701|2.4%|46.5%|
ib_bluetack_hijacked|535|9177856|7277056|79.2%|40.2%|
ib_bluetack_level1|215693|765044590|2133264|0.2%|11.8%|
ib_bluetack_level3|18550|139108857|192343|0.1%|1.0%|
fullbogons|3646|670922200|20480|0.0%|0.1%|
alienvault_reputation|188000|188000|5415|2.8%|0.0%|
dshield|20|5120|1536|30.0%|0.0%|
ib_bluetack_spyware|898|336971|1029|0.3%|0.0%|
stop_forum_spam_30d|91499|91499|752|0.8%|0.0%|
spamhaus_edrop|55|421120|517|0.1%|0.0%|
openbl|9986|9986|452|4.5%|0.0%|
openbl_90d|9986|9986|452|4.5%|0.0%|
openbl_60d|7904|7904|324|4.0%|0.0%|
snort_ipfilter|6580|6580|282|4.2%|0.0%|
zeus|262|262|256|97.7%|0.0%|
zeus_badips|228|228|225|98.6%|0.0%|
stop_forum_spam_7d|28751|28751|221|0.7%|0.0%|
openbl_30d|4722|4722|216|4.5%|0.0%|
blocklist_de|26479|26479|201|0.7%|0.0%|
nixspam|18589|18589|174|0.9%|0.0%|
openbl_7d|1427|1427|103|7.2%|0.0%|
bruteforceblocker|2287|2287|91|3.9%|0.0%|
compromised|2436|2436|77|3.1%|0.0%|
stop_forum_spam_1h|6751|6751|58|0.8%|0.0%|
feodo|58|58|56|96.5%|0.0%|
malwaredomainlist|1283|1283|28|2.1%|0.0%|
openbl_1d|357|357|27|7.5%|0.0%|
php_commenters|184|184|24|13.0%|0.0%|
php_bad|184|184|24|13.0%|0.0%|
sslbl|319|319|23|7.2%|0.0%|
palevo|12|12|12|100.0%|0.0%|
ib_bluetack_badpeers|48134|48134|10|0.0%|0.0%|
ib_bluetack_webexploit|1460|1460|6|0.4%|0.0%|
tor|6340|6340|4|0.0%|0.0%|
tor_servers|6539|6539|4|0.0%|0.0%|
danmetor|6555|6555|4|0.0%|0.0%|
ciarmy|400|400|3|0.7%|0.0%|
php_spammers|261|261|2|0.7%|0.0%|
malc0de|426|426|2|0.4%|0.0%|
ib_bluetack_proxies|673|673|2|0.2%|0.0%|
php_harvesters|178|178|1|0.5%|0.0%|
php_dictionary|275|275|1|0.3%|0.0%|
botnet|515|515|1|0.1%|0.0%|

# feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

The ipset `feodo` has 58 entries, 58 unique IPs.

The following table shows the overlaps of \'feodo\' with all the other ipsets supported.

- ` %  in ` is the percentage of each row found **in feodo**.
- ` %  of ` is the percentage **of feodo** found in each row.

ipset|entries|unique IPs|IPs found on both| % in| % of|
:---:|:-----:|:--------:|:---------------:|:---:|:---:|
emerging_block|965|18065466|56|0.0%|96.5%|
snort_ipfilter|6580|6580|46|0.6%|79.3%|
sslbl|319|319|21|6.5%|36.2%|
ib_bluetack_level3|18550|139108857|3|0.0%|5.1%|
ib_bluetack_level2|75927|348729520|3|0.0%|5.1%|
ib_bluetack_level1|215693|765044590|3|0.0%|5.1%|
openbl|9986|9986|1|0.0%|1.7%|
openbl_90d|9986|9986|1|0.0%|1.7%|
ib_bluetack_spyware|898|336971|1|0.0%|1.7%|
alienvault_reputation|188000|188000|1|0.0%|1.7%|

# fullbogons

[Team-Cymru.org](http://www.team-cymru.org) IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user - **excellent list - use it only your internet interface**

The ipset `fullbogons` has 3646 entries, 670922200 unique IPs.

The following table shows the overlaps of \'fullbogons\' with all the other ipsets supported.

- ` %  in ` is the percentage of each row found **in fullbogons**.
- ` %  of ` is the percentage **of fullbogons** found in each row.

ipset|entries|unique IPs|IPs found on both| % in| % of|
:---:|:-----:|:--------:|:---------------:|:---:|:---:|
bogons|13|592708608|592708608|100.0%|88.3%|
ib_bluetack_level3|18550|139108857|4233774|3.0%|0.6%|
ib_bluetack_hijacked|535|9177856|565248|6.1%|0.0%|
ib_bluetack_level2|75927|348729520|247298|0.0%|0.0%|
ib_bluetack_level1|215693|765044590|232563|0.0%|0.0%|
spamhaus_drop|640|18051584|20480|0.1%|0.0%|
emerging_block|965|18065466|20480|0.1%|0.0%|
ib_bluetack_spyware|898|336971|871|0.2%|0.0%|
ib_bluetack_webexploit|1460|1460|33|2.2%|0.0%|
ib_bluetack_badpeers|48134|48134|14|0.0%|0.0%|
malwaredomainlist|1283|1283|9|0.7%|0.0%|
stop_forum_spam_30d|91499|91499|3|0.0%|0.0%|
stop_forum_spam_7d|28751|28751|1|0.0%|0.0%|
php_harvesters|178|178|1|0.5%|0.0%|
bruteforceblocker|2287|2287|1|0.0%|0.0%|

# ib_bluetack_badpeers

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) IPs that have been reported for bad deeds in p2p

The ipset `ib_bluetack_badpeers` has 48134 entries, 48134 unique IPs.

The following table shows the overlaps of \'ib_bluetack_badpeers\' with all the other ipsets supported.

- ` %  in ` is the percentage of each row found **in ib_bluetack_badpeers**.
- ` %  of ` is the percentage **of ib_bluetack_badpeers** found in each row.

ipset|entries|unique IPs|IPs found on both| % in| % of|
:---:|:-----:|:--------:|:---------------:|:---:|:---:|
ib_bluetack_level3|18550|139108857|1172|0.0%|2.4%|
ib_bluetack_level1|215693|765044590|366|0.0%|0.7%|
ib_bluetack_level2|75927|348729520|233|0.0%|0.4%|
alienvault_reputation|188000|188000|15|0.0%|0.0%|
stop_forum_spam_30d|91499|91499|14|0.0%|0.0%|
fullbogons|3646|670922200|14|0.0%|0.0%|
ib_bluetack_proxies|673|673|11|1.6%|0.0%|
emerging_block|965|18065466|10|0.0%|0.0%|
nixspam|18589|18589|7|0.0%|0.0%|
spamhaus_drop|640|18051584|6|0.0%|0.0%|
stop_forum_spam_7d|28751|28751|5|0.0%|0.0%|
ib_bluetack_spyware|898|336971|4|0.0%|0.0%|
blocklist_de|26479|26479|4|0.0%|0.0%|
php_harvesters|178|178|2|1.1%|0.0%|
php_dictionary|275|275|2|0.7%|0.0%|
dshield|20|5120|2|0.0%|0.0%|
stop_forum_spam_1h|6751|6751|1|0.0%|0.0%|
snort_ipfilter|6580|6580|1|0.0%|0.0%|
rosi_web_proxies|3230|3230|1|0.0%|0.0%|
php_spammers|261|261|1|0.3%|0.0%|
ib_bluetack_webexploit|1460|1460|1|0.0%|0.0%|

# ib_bluetack_hijacked

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) hijacked IP-Blocks Hijacked IP space are IP blocks that are being used without permission

The ipset `ib_bluetack_hijacked` has 535 entries, 9177856 unique IPs.

The following table shows the overlaps of \'ib_bluetack_hijacked\' with all the other ipsets supported.

- ` %  in ` is the percentage of each row found **in ib_bluetack_hijacked**.
- ` %  of ` is the percentage **of ib_bluetack_hijacked** found in each row.

ipset|entries|unique IPs|IPs found on both| % in| % of|
:---:|:-----:|:--------:|:---------------:|:---:|:---:|
emerging_block|965|18065466|7277056|40.2%|79.2%|
spamhaus_drop|640|18051584|7211008|39.9%|78.5%|
ib_bluetack_level2|75927|348729520|2526624|0.7%|27.5%|
ib_bluetack_level1|215693|765044590|904787|0.1%|9.8%|
fullbogons|3646|670922200|565248|0.0%|6.1%|
ib_bluetack_level3|18550|139108857|145472|0.1%|1.5%|
ib_bluetack_spyware|898|336971|1024|0.3%|0.0%|
stop_forum_spam_30d|91499|91499|708|0.7%|0.0%|
alienvault_reputation|188000|188000|519|0.2%|0.0%|
stop_forum_spam_7d|28751|28751|198|0.6%|0.0%|
nixspam|18589|18589|168|0.9%|0.0%|
blocklist_de|26479|26479|65|0.2%|0.0%|
stop_forum_spam_1h|6751|6751|36|0.5%|0.0%|
malwaredomainlist|1283|1283|27|2.1%|0.0%|
openbl|9986|9986|18|0.1%|0.0%|
openbl_90d|9986|9986|18|0.1%|0.0%|
openbl_60d|7904|7904|17|0.2%|0.0%|
openbl_30d|4722|4722|12|0.2%|0.0%|
snort_ipfilter|6580|6580|11|0.1%|0.0%|
zeus|262|262|10|3.8%|0.0%|
zeus_badips|228|228|10|4.3%|0.0%|
openbl_7d|1427|1427|10|0.7%|0.0%|
ib_bluetack_webexploit|1460|1460|7|0.4%|0.0%|
openbl_1d|357|357|5|1.4%|0.0%|
compromised|2436|2436|4|0.1%|0.0%|
bruteforceblocker|2287|2287|4|0.1%|0.0%|
tor|6340|6340|2|0.0%|0.0%|
tor_servers|6539|6539|2|0.0%|0.0%|
php_spammers|261|261|2|0.7%|0.0%|
ib_bluetack_proxies|673|673|2|0.2%|0.0%|
danmetor|6555|6555|2|0.0%|0.0%|
php_harvesters|178|178|1|0.5%|0.0%|
botnet|515|515|1|0.1%|0.0%|

# ib_bluetack_level1

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Level 1 (for use in p2p): Companies or organizations who are clearly involved with trying to stop filesharing (e.g. Baytsp, MediaDefender, Mediasentry a.o.). Companies which anti-p2p activity has been seen from. Companies that produce or have a strong financial interest in copyrighted material (e.g. music, movie, software industries a.o.). Government ranges or companies that have a strong financial interest in doing work for governments. Legal industry ranges. IPs or ranges of ISPs from which anti-p2p activity has been observed. Basically this list will block all kinds of internet connections that most people would rather not have during their internet travels.

The ipset `ib_bluetack_level1` has 215693 entries, 765044590 unique IPs.

The following table shows the overlaps of \'ib_bluetack_level1\' with all the other ipsets supported.

- ` %  in ` is the percentage of each row found **in ib_bluetack_level1**.
- ` %  of ` is the percentage **of ib_bluetack_level1** found in each row.

ipset|entries|unique IPs|IPs found on both| % in| % of|
:---:|:-----:|:--------:|:---------------:|:---:|:---:|
ib_bluetack_level2|75927|348729520|16309487|4.6%|2.1%|
emerging_block|965|18065466|2133264|11.8%|0.2%|
spamhaus_drop|640|18051584|2132981|11.8%|0.2%|
ib_bluetack_level3|18550|139108857|1357462|0.9%|0.1%|
ib_bluetack_hijacked|535|9177856|904787|9.8%|0.1%|
fullbogons|3646|670922200|232563|0.0%|0.0%|
spamhaus_edrop|55|421120|33152|7.8%|0.0%|
ib_bluetack_spyware|898|336971|12921|3.8%|0.0%|
alienvault_reputation|188000|188000|5119|2.7%|0.0%|
blocklist_de|26479|26479|1521|5.7%|0.0%|
stop_forum_spam_30d|91499|91499|1257|1.3%|0.0%|
dshield|20|5120|516|10.0%|0.0%|
stop_forum_spam_7d|28751|28751|451|1.5%|0.0%|
ib_bluetack_badpeers|48134|48134|366|0.7%|0.0%|
nixspam|18589|18589|328|1.7%|0.0%|
openbl|9986|9986|219|2.1%|0.0%|
openbl_90d|9986|9986|219|2.1%|0.0%|
openbl_60d|7904|7904|177|2.2%|0.0%|
tor|6340|6340|148|2.3%|0.0%|
tor_servers|6539|6539|148|2.2%|0.0%|
danmetor|6555|6555|148|2.2%|0.0%|
stop_forum_spam_1h|6751|6751|117|1.7%|0.0%|
openbl_30d|4722|4722|99|2.0%|0.0%|
ib_bluetack_webexploit|1460|1460|90|6.1%|0.0%|
compromised|2436|2436|75|3.0%|0.0%|
bruteforceblocker|2287|2287|66|2.8%|0.0%|
malwaredomainlist|1283|1283|60|4.6%|0.0%|
rosi_web_proxies|3230|3230|57|1.7%|0.0%|
snort_ipfilter|6580|6580|55|0.8%|0.0%|
botnet|515|515|42|8.1%|0.0%|
ciarmy|400|400|33|8.2%|0.0%|
openbl_7d|1427|1427|29|2.0%|0.0%|
rosi_connect_proxies|1348|1348|22|1.6%|0.0%|
ib_bluetack_proxies|673|673|18|2.6%|0.0%|
malc0de|426|426|11|2.5%|0.0%|
clean_mx_viruses|318|318|10|3.1%|0.0%|
zeus|262|262|7|2.6%|0.0%|
php_dictionary|275|275|7|2.5%|0.0%|
openbl_1d|357|357|7|1.9%|0.0%|
zeus_badips|228|228|4|1.7%|0.0%|
sslbl|319|319|3|0.9%|0.0%|
php_commenters|184|184|3|1.6%|0.0%|
php_bad|184|184|3|1.6%|0.0%|
feodo|58|58|3|5.1%|0.0%|
php_spammers|261|261|2|0.7%|0.0%|
php_harvesters|178|178|1|0.5%|0.0%|

# ib_bluetack_level2

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 2 (for use in p2p). General corporate ranges. Ranges used by labs or researchers. Proxies.

The ipset `ib_bluetack_level2` has 75927 entries, 348729520 unique IPs.

The following table shows the overlaps of \'ib_bluetack_level2\' with all the other ipsets supported.

- ` %  in ` is the percentage of each row found **in ib_bluetack_level2**.
- ` %  of ` is the percentage **of ib_bluetack_level2** found in each row.

ipset|entries|unique IPs|IPs found on both| % in| % of|
:---:|:-----:|:--------:|:---------------:|:---:|:---:|
ib_bluetack_level1|215693|765044590|16309487|2.1%|4.6%|
emerging_block|965|18065466|8401701|46.5%|2.4%|
spamhaus_drop|640|18051584|8401433|46.5%|2.4%|
ib_bluetack_level3|18550|139108857|2831962|2.0%|0.8%|
ib_bluetack_hijacked|535|9177856|2526624|27.5%|0.7%|
fullbogons|3646|670922200|247298|0.0%|0.0%|
spamhaus_edrop|55|421120|33368|7.9%|0.0%|
alienvault_reputation|188000|188000|8665|4.6%|0.0%|
ib_bluetack_spyware|898|336971|7629|2.2%|0.0%|
stop_forum_spam_30d|91499|91499|2388|2.6%|0.0%|
blocklist_de|26479|26479|1431|5.4%|0.0%|
stop_forum_spam_7d|28751|28751|819|2.8%|0.0%|
openbl|9986|9986|534|5.3%|0.0%|
openbl_90d|9986|9986|534|5.3%|0.0%|
nixspam|18589|18589|476|2.5%|0.0%|
openbl_60d|7904|7904|382|4.8%|0.0%|
dshield|20|5120|256|5.0%|0.0%|
ib_bluetack_badpeers|48134|48134|233|0.4%|0.0%|
openbl_30d|4722|4722|232|4.9%|0.0%|
stop_forum_spam_1h|6751|6751|216|3.1%|0.0%|
tor|6340|6340|171|2.6%|0.0%|
tor_servers|6539|6539|170|2.5%|0.0%|
danmetor|6555|6555|170|2.5%|0.0%|
compromised|2436|2436|153|6.2%|0.0%|
bruteforceblocker|2287|2287|143|6.2%|0.0%|
rosi_web_proxies|3230|3230|122|3.7%|0.0%|
snort_ipfilter|6580|6580|97|1.4%|0.0%|
openbl_7d|1427|1427|81|5.6%|0.0%|
rosi_connect_proxies|1348|1348|66|4.8%|0.0%|
ciarmy|400|400|49|12.2%|0.0%|
ib_bluetack_webexploit|1460|1460|43|2.9%|0.0%|
malc0de|426|426|28|6.5%|0.0%|
ib_bluetack_proxies|673|673|28|4.1%|0.0%|
malwaredomainlist|1283|1283|26|2.0%|0.0%|
botnet|515|515|24|4.6%|0.0%|
php_spammers|261|261|18|6.8%|0.0%|
openbl_1d|357|357|17|4.7%|0.0%|
clean_mx_viruses|318|318|12|3.7%|0.0%|
zeus|262|262|7|2.6%|0.0%|
zeus_badips|228|228|7|3.0%|0.0%|
php_dictionary|275|275|7|2.5%|0.0%|
sslbl|319|319|5|1.5%|0.0%|
php_harvesters|178|178|5|2.8%|0.0%|
php_commenters|184|184|4|2.1%|0.0%|
php_bad|184|184|4|2.1%|0.0%|
feodo|58|58|3|5.1%|0.0%|
autoshun|51|51|3|5.8%|0.0%|
palevo|12|12|1|8.3%|0.0%|

# ib_bluetack_level3

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 3 (for use in p2p). Many portal-type websites. ISP ranges that may be dodgy for some reason. Ranges that belong to an individual, but which have not been determined to be used by a particular company. Ranges for things that are unusual in some way. The L3 list is aka the paranoid list.

The ipset `ib_bluetack_level3` has 18550 entries, 139108857 unique IPs.

The following table shows the overlaps of \'ib_bluetack_level3\' with all the other ipsets supported.

- ` %  in ` is the percentage of each row found **in ib_bluetack_level3**.
- ` %  of ` is the percentage **of ib_bluetack_level3** found in each row.

ipset|entries|unique IPs|IPs found on both| % in| % of|
:---:|:-----:|:--------:|:---------------:|:---:|:---:|
fullbogons|3646|670922200|4233774|0.6%|3.0%|
bogons|13|592708608|4194304|0.7%|3.0%|
ib_bluetack_level2|75927|348729520|2831962|0.8%|2.0%|
ib_bluetack_level1|215693|765044590|1357462|0.1%|0.9%|
spamhaus_edrop|55|421120|270785|64.3%|0.1%|
spamhaus_drop|640|18051584|195904|1.0%|0.1%|
emerging_block|965|18065466|192343|1.0%|0.1%|
ib_bluetack_hijacked|535|9177856|145472|1.5%|0.1%|
alienvault_reputation|188000|188000|15506|8.2%|0.0%|
ib_bluetack_spyware|898|336971|8958|2.6%|0.0%|
stop_forum_spam_30d|91499|91499|6228|6.8%|0.0%|
blocklist_de|26479|26479|3262|12.3%|0.0%|
stop_forum_spam_7d|28751|28751|1914|6.6%|0.0%|
nixspam|18589|18589|1241|6.6%|0.0%|
ib_bluetack_badpeers|48134|48134|1172|2.4%|0.0%|
openbl|9986|9986|971|9.7%|0.0%|
openbl_90d|9986|9986|971|9.7%|0.0%|
openbl_60d|7904|7904|719|9.0%|0.0%|
tor_servers|6539|6539|605|9.2%|0.0%|
danmetor|6555|6555|603|9.1%|0.0%|
tor|6340|6340|602|9.4%|0.0%|
openbl_30d|4722|4722|488|10.3%|0.0%|
stop_forum_spam_1h|6751|6751|435|6.4%|0.0%|
dshield|20|5120|256|5.0%|0.0%|
compromised|2436|2436|243|9.9%|0.0%|
bruteforceblocker|2287|2287|221|9.6%|0.0%|
snort_ipfilter|6580|6580|211|3.2%|0.0%|
malwaredomainlist|1283|1283|146|11.3%|0.0%|
openbl_7d|1427|1427|117|8.1%|0.0%|
rosi_web_proxies|3230|3230|114|3.5%|0.0%|
ib_bluetack_webexploit|1460|1460|110|7.5%|0.0%|
malc0de|426|426|80|18.7%|0.0%|
botnet|515|515|76|14.7%|0.0%|
ciarmy|400|400|69|17.2%|0.0%|
clean_mx_viruses|318|318|52|16.3%|0.0%|
ib_bluetack_proxies|673|673|51|7.5%|0.0%|
rosi_connect_proxies|1348|1348|29|2.1%|0.0%|
openbl_1d|357|357|20|5.6%|0.0%|
zeus|262|262|19|7.2%|0.0%|
php_spammers|261|261|18|6.8%|0.0%|
sslbl|319|319|16|5.0%|0.0%|
zeus_badips|228|228|14|6.1%|0.0%|
php_dictionary|275|275|13|4.7%|0.0%|
php_harvesters|178|178|12|6.7%|0.0%|
php_commenters|184|184|8|4.3%|0.0%|
php_bad|184|184|8|4.3%|0.0%|
autoshun|51|51|6|11.7%|0.0%|
feodo|58|58|3|5.1%|0.0%|
palevo|12|12|1|8.3%|0.0%|

# ib_bluetack_proxies

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Open Proxies IPs list (without TOR)

The ipset `ib_bluetack_proxies` has 673 entries, 673 unique IPs.

The following table shows the overlaps of \'ib_bluetack_proxies\' with all the other ipsets supported.

- ` %  in ` is the percentage of each row found **in ib_bluetack_proxies**.
- ` %  of ` is the percentage **of ib_bluetack_proxies** found in each row.

ipset|entries|unique IPs|IPs found on both| % in| % of|
:---:|:-----:|:--------:|:---------------:|:---:|:---:|
ib_bluetack_level3|18550|139108857|51|0.0%|7.5%|
ib_bluetack_level2|75927|348729520|28|0.0%|4.1%|
stop_forum_spam_30d|91499|91499|24|0.0%|3.5%|
ib_bluetack_level1|215693|765044590|18|0.0%|2.6%|
stop_forum_spam_7d|28751|28751|15|0.0%|2.2%|
ib_bluetack_badpeers|48134|48134|11|0.0%|1.6%|
rosi_web_proxies|3230|3230|9|0.2%|1.3%|
stop_forum_spam_1h|6751|6751|6|0.0%|0.8%|
rosi_connect_proxies|1348|1348|5|0.3%|0.7%|
nixspam|18589|18589|3|0.0%|0.4%|
blocklist_de|26479|26479|3|0.0%|0.4%|
spamhaus_drop|640|18051584|2|0.0%|0.2%|
ib_bluetack_webexploit|1460|1460|2|0.1%|0.2%|
ib_bluetack_hijacked|535|9177856|2|0.0%|0.2%|
emerging_block|965|18065466|2|0.0%|0.2%|
snort_ipfilter|6580|6580|1|0.0%|0.1%|
php_dictionary|275|275|1|0.3%|0.1%|
alienvault_reputation|188000|188000|1|0.0%|0.1%|

# ib_bluetack_spyware

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) known malicious SPYWARE and ADWARE IP Address ranges

The ipset `ib_bluetack_spyware` has 898 entries, 336971 unique IPs.

The following table shows the overlaps of \'ib_bluetack_spyware\' with all the other ipsets supported.

- ` %  in ` is the percentage of each row found **in ib_bluetack_spyware**.
- ` %  of ` is the percentage **of ib_bluetack_spyware** found in each row.

ipset|entries|unique IPs|IPs found on both| % in| % of|
:---:|:-----:|:--------:|:---------------:|:---:|:---:|
ib_bluetack_level1|215693|765044590|12921|0.0%|3.8%|
ib_bluetack_level3|18550|139108857|8958|0.0%|2.6%|
ib_bluetack_level2|75927|348729520|7629|0.0%|2.2%|
emerging_block|965|18065466|1029|0.0%|0.3%|
spamhaus_drop|640|18051584|1024|0.0%|0.3%|
ib_bluetack_hijacked|535|9177856|1024|0.0%|0.3%|
fullbogons|3646|670922200|871|0.0%|0.2%|
alienvault_reputation|188000|188000|280|0.1%|0.0%|
stop_forum_spam_30d|91499|91499|41|0.0%|0.0%|
stop_forum_spam_7d|28751|28751|22|0.0%|0.0%|
tor|6340|6340|20|0.3%|0.0%|
tor_servers|6539|6539|20|0.3%|0.0%|
danmetor|6555|6555|20|0.3%|0.0%|
nixspam|18589|18589|18|0.0%|0.0%|
malwaredomainlist|1283|1283|14|1.0%|0.0%|
snort_ipfilter|6580|6580|12|0.1%|0.0%|
blocklist_de|26479|26479|11|0.0%|0.0%|
stop_forum_spam_1h|6751|6751|10|0.1%|0.0%|
ib_bluetack_webexploit|1460|1460|7|0.4%|0.0%|
openbl|9986|9986|5|0.0%|0.0%|
openbl_90d|9986|9986|5|0.0%|0.0%|
openbl_60d|7904|7904|4|0.0%|0.0%|
ib_bluetack_badpeers|48134|48134|4|0.0%|0.0%|
dshield|20|5120|4|0.0%|0.0%|
rosi_web_proxies|3230|3230|3|0.0%|0.0%|
openbl_30d|4722|4722|3|0.0%|0.0%|
malc0de|426|426|3|0.7%|0.0%|
clean_mx_viruses|318|318|3|0.9%|0.0%|
sslbl|319|319|1|0.3%|0.0%|
php_harvesters|178|178|1|0.5%|0.0%|
php_dictionary|275|275|1|0.3%|0.0%|
openbl_7d|1427|1427|1|0.0%|0.0%|
feodo|58|58|1|1.7%|0.0%|
compromised|2436|2436|1|0.0%|0.0%|

# ib_bluetack_webexploit

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) web server hack and exploit attempts

The ipset `ib_bluetack_webexploit` has 1460 entries, 1460 unique IPs.

The following table shows the overlaps of \'ib_bluetack_webexploit\' with all the other ipsets supported.

- ` %  in ` is the percentage of each row found **in ib_bluetack_webexploit**.
- ` %  of ` is the percentage **of ib_bluetack_webexploit** found in each row.

ipset|entries|unique IPs|IPs found on both| % in| % of|
:---:|:-----:|:--------:|:---------------:|:---:|:---:|
ib_bluetack_level3|18550|139108857|110|0.0%|7.5%|
ib_bluetack_level1|215693|765044590|90|0.0%|6.1%|
ib_bluetack_level2|75927|348729520|43|0.0%|2.9%|
fullbogons|3646|670922200|33|0.0%|2.2%|
ib_bluetack_spyware|898|336971|7|0.0%|0.4%|
ib_bluetack_hijacked|535|9177856|7|0.0%|0.4%|
alienvault_reputation|188000|188000|7|0.0%|0.4%|
spamhaus_drop|640|18051584|6|0.0%|0.4%|
emerging_block|965|18065466|6|0.0%|0.4%|
malwaredomainlist|1283|1283|3|0.2%|0.2%|
stop_forum_spam_7d|28751|28751|2|0.0%|0.1%|
stop_forum_spam_30d|91499|91499|2|0.0%|0.1%|
snort_ipfilter|6580|6580|2|0.0%|0.1%|
ib_bluetack_proxies|673|673|2|0.2%|0.1%|
tor|6340|6340|1|0.0%|0.0%|
tor_servers|6539|6539|1|0.0%|0.0%|
stop_forum_spam_1h|6751|6751|1|0.0%|0.0%|
rosi_web_proxies|3230|3230|1|0.0%|0.0%|
openbl|9986|9986|1|0.0%|0.0%|
openbl_90d|9986|9986|1|0.0%|0.0%|
openbl_7d|1427|1427|1|0.0%|0.0%|
openbl_60d|7904|7904|1|0.0%|0.0%|
openbl_30d|4722|4722|1|0.0%|0.0%|
openbl_1d|357|357|1|0.2%|0.0%|
ib_bluetack_badpeers|48134|48134|1|0.0%|0.0%|
dshield|20|5120|1|0.0%|0.0%|
danmetor|6555|6555|1|0.0%|0.0%|
compromised|2436|2436|1|0.0%|0.0%|
bruteforceblocker|2287|2287|1|0.0%|0.0%|
botnet|515|515|1|0.1%|0.0%|
blocklist_de|26479|26479|1|0.0%|0.0%|

# malc0de

[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days

The ipset `malc0de` has 426 entries, 426 unique IPs.

The following table shows the overlaps of \'malc0de\' with all the other ipsets supported.

- ` %  in ` is the percentage of each row found **in malc0de**.
- ` %  of ` is the percentage **of malc0de** found in each row.

ipset|entries|unique IPs|IPs found on both| % in| % of|
:---:|:-----:|:--------:|:---------------:|:---:|:---:|
ib_bluetack_level3|18550|139108857|80|0.0%|18.7%|
ib_bluetack_level2|75927|348729520|28|0.0%|6.5%|
clean_mx_viruses|318|318|23|7.2%|5.3%|
ib_bluetack_level1|215693|765044590|11|0.0%|2.5%|
alienvault_reputation|188000|188000|11|0.0%|2.5%|
malwaredomainlist|1283|1283|4|0.3%|0.9%|
ib_bluetack_spyware|898|336971|3|0.0%|0.7%|
spamhaus_drop|640|18051584|2|0.0%|0.4%|
emerging_block|965|18065466|2|0.0%|0.4%|
spamhaus_edrop|55|421120|1|0.0%|0.2%|
dshield|20|5120|1|0.0%|0.2%|

# malwaredomainlist

[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses

The ipset `malwaredomainlist` has 1283 entries, 1283 unique IPs.

The following table shows the overlaps of \'malwaredomainlist\' with all the other ipsets supported.

- ` %  in ` is the percentage of each row found **in malwaredomainlist**.
- ` %  of ` is the percentage **of malwaredomainlist** found in each row.

ipset|entries|unique IPs|IPs found on both| % in| % of|
:---:|:-----:|:--------:|:---------------:|:---:|:---:|
ib_bluetack_level3|18550|139108857|146|0.0%|11.3%|
ib_bluetack_level1|215693|765044590|60|0.0%|4.6%|
spamhaus_drop|640|18051584|28|0.0%|2.1%|
emerging_block|965|18065466|28|0.0%|2.1%|
ib_bluetack_hijacked|535|9177856|27|0.0%|2.1%|
ib_bluetack_level2|75927|348729520|26|0.0%|2.0%|
snort_ipfilter|6580|6580|24|0.3%|1.8%|
ib_bluetack_spyware|898|336971|14|0.0%|1.0%|
fullbogons|3646|670922200|9|0.0%|0.7%|
alienvault_reputation|188000|188000|6|0.0%|0.4%|
malc0de|426|426|4|0.9%|0.3%|
ib_bluetack_webexploit|1460|1460|3|0.2%|0.2%|
blocklist_de|26479|26479|3|0.0%|0.2%|
stop_forum_spam_30d|91499|91499|2|0.0%|0.1%|
nixspam|18589|18589|1|0.0%|0.0%|
botnet|515|515|1|0.1%|0.0%|

# nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

The ipset `nixspam` has 18589 entries, 18589 unique IPs.

The following table shows the overlaps of \'nixspam\' with all the other ipsets supported.

- ` %  in ` is the percentage of each row found **in nixspam**.
- ` %  of ` is the percentage **of nixspam** found in each row.

ipset|entries|unique IPs|IPs found on both| % in| % of|
:---:|:-----:|:--------:|:---------------:|:---:|:---:|
ib_bluetack_level3|18550|139108857|1241|0.0%|6.6%|
blocklist_de|26479|26479|682|2.5%|3.6%|
ib_bluetack_level2|75927|348729520|476|0.0%|2.5%|
ib_bluetack_level1|215693|765044590|328|0.0%|1.7%|
stop_forum_spam_30d|91499|91499|199|0.2%|1.0%|
snort_ipfilter|6580|6580|188|2.8%|1.0%|
emerging_block|965|18065466|174|0.0%|0.9%|
spamhaus_drop|640|18051584|173|0.0%|0.9%|
ib_bluetack_hijacked|535|9177856|168|0.0%|0.9%|
stop_forum_spam_7d|28751|28751|118|0.4%|0.6%|
php_dictionary|275|275|83|30.1%|0.4%|
rosi_web_proxies|3230|3230|76|2.3%|0.4%|
php_spammers|261|261|61|23.3%|0.3%|
stop_forum_spam_1h|6751|6751|57|0.8%|0.3%|
alienvault_reputation|188000|188000|32|0.0%|0.1%|
ib_bluetack_spyware|898|336971|18|0.0%|0.0%|
rosi_connect_proxies|1348|1348|14|1.0%|0.0%|
php_commenters|184|184|14|7.6%|0.0%|
php_bad|184|184|14|7.6%|0.0%|
ib_bluetack_badpeers|48134|48134|7|0.0%|0.0%|
php_harvesters|178|178|3|1.6%|0.0%|
openbl|9986|9986|3|0.0%|0.0%|
openbl_90d|9986|9986|3|0.0%|0.0%|
openbl_60d|7904|7904|3|0.0%|0.0%|
ib_bluetack_proxies|673|673|3|0.4%|0.0%|
tor|6340|6340|2|0.0%|0.0%|
openbl_30d|4722|4722|2|0.0%|0.0%|
compromised|2436|2436|2|0.0%|0.0%|
bruteforceblocker|2287|2287|2|0.0%|0.0%|
tor_servers|6539|6539|1|0.0%|0.0%|
spamhaus_edrop|55|421120|1|0.0%|0.0%|
openbl_7d|1427|1427|1|0.0%|0.0%|
malwaredomainlist|1283|1283|1|0.0%|0.0%|
dshield|20|5120|1|0.0%|0.0%|
danmetor|6555|6555|1|0.0%|0.0%|
clean_mx_viruses|318|318|1|0.3%|0.0%|

# openbl

[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**

The ipset `openbl` has 9986 entries, 9986 unique IPs.

The following table shows the overlaps of \'openbl\' with all the other ipsets supported.

- ` %  in ` is the percentage of each row found **in openbl**.
- ` %  of ` is the percentage **of openbl** found in each row.

ipset|entries|unique IPs|IPs found on both| % in| % of|
:---:|:-----:|:--------:|:---------------:|:---:|:---:|
openbl_90d|9986|9986|9986|100.0%|100.0%|
alienvault_reputation|188000|188000|9955|5.2%|99.6%|
openbl_60d|7904|7904|7904|100.0%|79.1%|
openbl_30d|4722|4722|4722|100.0%|47.2%|
compromised|2436|2436|1473|60.4%|14.7%|
openbl_7d|1427|1427|1427|100.0%|14.2%|
bruteforceblocker|2287|2287|1353|59.1%|13.5%|
blocklist_de|26479|26479|1292|4.8%|12.9%|
ib_bluetack_level3|18550|139108857|971|0.0%|9.7%|
ib_bluetack_level2|75927|348729520|534|0.0%|5.3%|
emerging_block|965|18065466|452|0.0%|4.5%|
spamhaus_drop|640|18051584|446|0.0%|4.4%|
openbl_1d|357|357|357|100.0%|3.5%|
ib_bluetack_level1|215693|765044590|219|0.0%|2.1%|
stop_forum_spam_30d|91499|91499|73|0.0%|0.7%|
dshield|20|5120|38|0.7%|0.3%|
stop_forum_spam_7d|28751|28751|37|0.1%|0.3%|
snort_ipfilter|6580|6580|25|0.3%|0.2%|
stop_forum_spam_1h|6751|6751|22|0.3%|0.2%|
danmetor|6555|6555|21|0.3%|0.2%|
tor|6340|6340|20|0.3%|0.2%|
tor_servers|6539|6539|20|0.3%|0.2%|
ib_bluetack_hijacked|535|9177856|18|0.0%|0.1%|
spamhaus_edrop|55|421120|14|0.0%|0.1%|
autoshun|51|51|12|23.5%|0.1%|
php_commenters|184|184|6|3.2%|0.0%|
php_bad|184|184|6|3.2%|0.0%|
ib_bluetack_spyware|898|336971|5|0.0%|0.0%|
php_harvesters|178|178|4|2.2%|0.0%|
nixspam|18589|18589|3|0.0%|0.0%|
zeus|262|262|1|0.3%|0.0%|
zeus_badips|228|228|1|0.4%|0.0%|
sslbl|319|319|1|0.3%|0.0%|
rosi_web_proxies|3230|3230|1|0.0%|0.0%|
ib_bluetack_webexploit|1460|1460|1|0.0%|0.0%|
feodo|58|58|1|1.7%|0.0%|

# openbl_1d

[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

The ipset `openbl_1d` has 357 entries, 357 unique IPs.

The following table shows the overlaps of \'openbl_1d\' with all the other ipsets supported.

- ` %  in ` is the percentage of each row found **in openbl_1d**.
- ` %  of ` is the percentage **of openbl_1d** found in each row.

ipset|entries|unique IPs|IPs found on both| % in| % of|
:---:|:-----:|:--------:|:---------------:|:---:|:---:|
openbl|9986|9986|357|3.5%|100.0%|
openbl_90d|9986|9986|357|3.5%|100.0%|
openbl_7d|1427|1427|357|25.0%|100.0%|
openbl_60d|7904|7904|357|4.5%|100.0%|
openbl_30d|4722|4722|357|7.5%|100.0%|
alienvault_reputation|188000|188000|355|0.1%|99.4%|
blocklist_de|26479|26479|252|0.9%|70.5%|
bruteforceblocker|2287|2287|201|8.7%|56.3%|
compromised|2436|2436|198|8.1%|55.4%|
emerging_block|965|18065466|27|0.0%|7.5%|
spamhaus_drop|640|18051584|26|0.0%|7.2%|
dshield|20|5120|21|0.4%|5.8%|
ib_bluetack_level3|18550|139108857|20|0.0%|5.6%|
ib_bluetack_level2|75927|348729520|17|0.0%|4.7%|
ib_bluetack_level1|215693|765044590|7|0.0%|1.9%|
ib_bluetack_hijacked|535|9177856|5|0.0%|1.4%|
autoshun|51|51|2|3.9%|0.5%|
stop_forum_spam_30d|91499|91499|1|0.0%|0.2%|
spamhaus_edrop|55|421120|1|0.0%|0.2%|
ib_bluetack_webexploit|1460|1460|1|0.0%|0.2%|

# openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

The ipset `openbl_30d` has 4722 entries, 4722 unique IPs.

The following table shows the overlaps of \'openbl_30d\' with all the other ipsets supported.

- ` %  in ` is the percentage of each row found **in openbl_30d**.
- ` %  of ` is the percentage **of openbl_30d** found in each row.

ipset|entries|unique IPs|IPs found on both| % in| % of|
:---:|:-----:|:--------:|:---------------:|:---:|:---:|
openbl|9986|9986|4722|47.2%|100.0%|
openbl_90d|9986|9986|4722|47.2%|100.0%|
openbl_60d|7904|7904|4722|59.7%|100.0%|
alienvault_reputation|188000|188000|4705|2.5%|99.6%|
openbl_7d|1427|1427|1427|100.0%|30.2%|
compromised|2436|2436|1337|54.8%|28.3%|
bruteforceblocker|2287|2287|1288|56.3%|27.2%|
blocklist_de|26479|26479|1101|4.1%|23.3%|
ib_bluetack_level3|18550|139108857|488|0.0%|10.3%|
openbl_1d|357|357|357|100.0%|7.5%|
ib_bluetack_level2|75927|348729520|232|0.0%|4.9%|
emerging_block|965|18065466|216|0.0%|4.5%|
spamhaus_drop|640|18051584|213|0.0%|4.5%|
ib_bluetack_level1|215693|765044590|99|0.0%|2.0%|
dshield|20|5120|37|0.7%|0.7%|
stop_forum_spam_30d|91499|91499|25|0.0%|0.5%|
ib_bluetack_hijacked|535|9177856|12|0.0%|0.2%|
autoshun|51|51|11|21.5%|0.2%|
stop_forum_spam_7d|28751|28751|7|0.0%|0.1%|
ib_bluetack_spyware|898|336971|3|0.0%|0.0%|
nixspam|18589|18589|2|0.0%|0.0%|
zeus|262|262|1|0.3%|0.0%|
zeus_badips|228|228|1|0.4%|0.0%|
stop_forum_spam_1h|6751|6751|1|0.0%|0.0%|
spamhaus_edrop|55|421120|1|0.0%|0.0%|
snort_ipfilter|6580|6580|1|0.0%|0.0%|
ib_bluetack_webexploit|1460|1460|1|0.0%|0.0%|

# openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

The ipset `openbl_60d` has 7904 entries, 7904 unique IPs.

The following table shows the overlaps of \'openbl_60d\' with all the other ipsets supported.

- ` %  in ` is the percentage of each row found **in openbl_60d**.
- ` %  of ` is the percentage **of openbl_60d** found in each row.

ipset|entries|unique IPs|IPs found on both| % in| % of|
:---:|:-----:|:--------:|:---------------:|:---:|:---:|
openbl|9986|9986|7904|79.1%|100.0%|
openbl_90d|9986|9986|7904|79.1%|100.0%|
alienvault_reputation|188000|188000|7879|4.1%|99.6%|
openbl_30d|4722|4722|4722|100.0%|59.7%|
compromised|2436|2436|1461|59.9%|18.4%|
openbl_7d|1427|1427|1427|100.0%|18.0%|
bruteforceblocker|2287|2287|1342|58.6%|16.9%|
blocklist_de|26479|26479|1242|4.6%|15.7%|
ib_bluetack_level3|18550|139108857|719|0.0%|9.0%|
ib_bluetack_level2|75927|348729520|382|0.0%|4.8%|
openbl_1d|357|357|357|100.0%|4.5%|
emerging_block|965|18065466|324|0.0%|4.0%|
spamhaus_drop|640|18051584|320|0.0%|4.0%|
ib_bluetack_level1|215693|765044590|177|0.0%|2.2%|
stop_forum_spam_30d|91499|91499|65|0.0%|0.8%|
dshield|20|5120|38|0.7%|0.4%|
stop_forum_spam_7d|28751|28751|33|0.1%|0.4%|
snort_ipfilter|6580|6580|24|0.3%|0.3%|
danmetor|6555|6555|21|0.3%|0.2%|
tor|6340|6340|20|0.3%|0.2%|
tor_servers|6539|6539|20|0.3%|0.2%|
stop_forum_spam_1h|6751|6751|20|0.2%|0.2%|
ib_bluetack_hijacked|535|9177856|17|0.0%|0.2%|
autoshun|51|51|12|23.5%|0.1%|
php_commenters|184|184|6|3.2%|0.0%|
php_bad|184|184|6|3.2%|0.0%|
php_harvesters|178|178|4|2.2%|0.0%|
ib_bluetack_spyware|898|336971|4|0.0%|0.0%|
nixspam|18589|18589|3|0.0%|0.0%|
spamhaus_edrop|55|421120|2|0.0%|0.0%|
zeus|262|262|1|0.3%|0.0%|
zeus_badips|228|228|1|0.4%|0.0%|
ib_bluetack_webexploit|1460|1460|1|0.0%|0.0%|

# openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

The ipset `openbl_7d` has 1427 entries, 1427 unique IPs.

The following table shows the overlaps of \'openbl_7d\' with all the other ipsets supported.

- ` %  in ` is the percentage of each row found **in openbl_7d**.
- ` %  of ` is the percentage **of openbl_7d** found in each row.

ipset|entries|unique IPs|IPs found on both| % in| % of|
:---:|:-----:|:--------:|:---------------:|:---:|:---:|
openbl|9986|9986|1427|14.2%|100.0%|
openbl_90d|9986|9986|1427|14.2%|100.0%|
openbl_60d|7904|7904|1427|18.0%|100.0%|
openbl_30d|4722|4722|1427|30.2%|100.0%|
alienvault_reputation|188000|188000|1412|0.7%|98.9%|
blocklist_de|26479|26479|796|3.0%|55.7%|
bruteforceblocker|2287|2287|722|31.5%|50.5%|
compromised|2436|2436|706|28.9%|49.4%|
openbl_1d|357|357|357|100.0%|25.0%|
ib_bluetack_level3|18550|139108857|117|0.0%|8.1%|
emerging_block|965|18065466|103|0.0%|7.2%|
spamhaus_drop|640|18051584|101|0.0%|7.0%|
ib_bluetack_level2|75927|348729520|81|0.0%|5.6%|
dshield|20|5120|36|0.7%|2.5%|
ib_bluetack_level1|215693|765044590|29|0.0%|2.0%|
ib_bluetack_hijacked|535|9177856|10|0.0%|0.7%|
autoshun|51|51|9|17.6%|0.6%|
stop_forum_spam_30d|91499|91499|3|0.0%|0.2%|
stop_forum_spam_7d|28751|28751|1|0.0%|0.0%|
stop_forum_spam_1h|6751|6751|1|0.0%|0.0%|
spamhaus_edrop|55|421120|1|0.0%|0.0%|
nixspam|18589|18589|1|0.0%|0.0%|
ib_bluetack_webexploit|1460|1460|1|0.0%|0.0%|
ib_bluetack_spyware|898|336971|1|0.0%|0.0%|

# openbl_90d

[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

The ipset `openbl_90d` has 9986 entries, 9986 unique IPs.

The following table shows the overlaps of \'openbl_90d\' with all the other ipsets supported.

- ` %  in ` is the percentage of each row found **in openbl_90d**.
- ` %  of ` is the percentage **of openbl_90d** found in each row.

ipset|entries|unique IPs|IPs found on both| % in| % of|
:---:|:-----:|:--------:|:---------------:|:---:|:---:|
openbl|9986|9986|9986|100.0%|100.0%|
alienvault_reputation|188000|188000|9955|5.2%|99.6%|
openbl_60d|7904|7904|7904|100.0%|79.1%|
openbl_30d|4722|4722|4722|100.0%|47.2%|
compromised|2436|2436|1473|60.4%|14.7%|
openbl_7d|1427|1427|1427|100.0%|14.2%|
bruteforceblocker|2287|2287|1353|59.1%|13.5%|
blocklist_de|26479|26479|1292|4.8%|12.9%|
ib_bluetack_level3|18550|139108857|971|0.0%|9.7%|
ib_bluetack_level2|75927|348729520|534|0.0%|5.3%|
emerging_block|965|18065466|452|0.0%|4.5%|
spamhaus_drop|640|18051584|446|0.0%|4.4%|
openbl_1d|357|357|357|100.0%|3.5%|
ib_bluetack_level1|215693|765044590|219|0.0%|2.1%|
stop_forum_spam_30d|91499|91499|73|0.0%|0.7%|
dshield|20|5120|38|0.7%|0.3%|
stop_forum_spam_7d|28751|28751|37|0.1%|0.3%|
snort_ipfilter|6580|6580|25|0.3%|0.2%|
stop_forum_spam_1h|6751|6751|22|0.3%|0.2%|
danmetor|6555|6555|21|0.3%|0.2%|
tor|6340|6340|20|0.3%|0.2%|
tor_servers|6539|6539|20|0.3%|0.2%|
ib_bluetack_hijacked|535|9177856|18|0.0%|0.1%|
spamhaus_edrop|55|421120|14|0.0%|0.1%|
autoshun|51|51|12|23.5%|0.1%|
php_commenters|184|184|6|3.2%|0.0%|
php_bad|184|184|6|3.2%|0.0%|
ib_bluetack_spyware|898|336971|5|0.0%|0.0%|
php_harvesters|178|178|4|2.2%|0.0%|
nixspam|18589|18589|3|0.0%|0.0%|
zeus|262|262|1|0.3%|0.0%|
zeus_badips|228|228|1|0.4%|0.0%|
sslbl|319|319|1|0.3%|0.0%|
rosi_web_proxies|3230|3230|1|0.0%|0.0%|
ib_bluetack_webexploit|1460|1460|1|0.0%|0.0%|
feodo|58|58|1|1.7%|0.0%|

# palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

The ipset `palevo` has 12 entries, 12 unique IPs.

The following table shows the overlaps of \'palevo\' with all the other ipsets supported.

- ` %  in ` is the percentage of each row found **in palevo**.
- ` %  of ` is the percentage **of palevo** found in each row.

ipset|entries|unique IPs|IPs found on both| % in| % of|
:---:|:-----:|:--------:|:---------------:|:---:|:---:|
emerging_block|965|18065466|12|0.0%|100.0%|
snort_ipfilter|6580|6580|10|0.1%|83.3%|
ib_bluetack_level3|18550|139108857|1|0.0%|8.3%|
ib_bluetack_level2|75927|348729520|1|0.0%|8.3%|

# php_bad

[projecthoneypot.org](http://www.projecthoneypot.org/) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)

The ipset `php_bad` has 184 entries, 184 unique IPs.

The following table shows the overlaps of \'php_bad\' with all the other ipsets supported.

- ` %  in ` is the percentage of each row found **in php_bad**.
- ` %  of ` is the percentage **of php_bad** found in each row.

ipset|entries|unique IPs|IPs found on both| % in| % of|
:---:|:-----:|:--------:|:---------------:|:---:|:---:|
php_commenters|184|184|184|100.0%|100.0%|
stop_forum_spam_30d|91499|91499|134|0.1%|72.8%|
stop_forum_spam_7d|28751|28751|126|0.4%|68.4%|
stop_forum_spam_1h|6751|6751|92|1.3%|50.0%|
blocklist_de|26479|26479|61|0.2%|33.1%|
snort_ipfilter|6580|6580|25|0.3%|13.5%|
spamhaus_drop|640|18051584|24|0.0%|13.0%|
emerging_block|965|18065466|24|0.0%|13.0%|
danmetor|6555|6555|18|0.2%|9.7%|
tor|6340|6340|17|0.2%|9.2%|
tor_servers|6539|6539|17|0.2%|9.2%|
php_spammers|261|261|15|5.7%|8.1%|
nixspam|18589|18589|14|0.0%|7.6%|
php_dictionary|275|275|10|3.6%|5.4%|
alienvault_reputation|188000|188000|10|0.0%|5.4%|
php_harvesters|178|178|8|4.4%|4.3%|
ib_bluetack_level3|18550|139108857|8|0.0%|4.3%|
spamhaus_edrop|55|421120|6|0.0%|3.2%|
openbl|9986|9986|6|0.0%|3.2%|
openbl_90d|9986|9986|6|0.0%|3.2%|
openbl_60d|7904|7904|6|0.0%|3.2%|
rosi_web_proxies|3230|3230|4|0.1%|2.1%|
ib_bluetack_level2|75927|348729520|4|0.0%|2.1%|
ib_bluetack_level1|215693|765044590|3|0.0%|1.6%|
zeus|262|262|1|0.3%|0.5%|
zeus_badips|228|228|1|0.4%|0.5%|

# php_commenters

[projecthoneypot.org](http://www.projecthoneypot.org/) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)

The ipset `php_commenters` has 184 entries, 184 unique IPs.

The following table shows the overlaps of \'php_commenters\' with all the other ipsets supported.

- ` %  in ` is the percentage of each row found **in php_commenters**.
- ` %  of ` is the percentage **of php_commenters** found in each row.

ipset|entries|unique IPs|IPs found on both| % in| % of|
:---:|:-----:|:--------:|:---------------:|:---:|:---:|
php_bad|184|184|184|100.0%|100.0%|
stop_forum_spam_30d|91499|91499|134|0.1%|72.8%|
stop_forum_spam_7d|28751|28751|126|0.4%|68.4%|
stop_forum_spam_1h|6751|6751|92|1.3%|50.0%|
blocklist_de|26479|26479|61|0.2%|33.1%|
snort_ipfilter|6580|6580|25|0.3%|13.5%|
spamhaus_drop|640|18051584|24|0.0%|13.0%|
emerging_block|965|18065466|24|0.0%|13.0%|
danmetor|6555|6555|18|0.2%|9.7%|
tor|6340|6340|17|0.2%|9.2%|
tor_servers|6539|6539|17|0.2%|9.2%|
php_spammers|261|261|15|5.7%|8.1%|
nixspam|18589|18589|14|0.0%|7.6%|
php_dictionary|275|275|10|3.6%|5.4%|
alienvault_reputation|188000|188000|10|0.0%|5.4%|
php_harvesters|178|178|8|4.4%|4.3%|
ib_bluetack_level3|18550|139108857|8|0.0%|4.3%|
spamhaus_edrop|55|421120|6|0.0%|3.2%|
openbl|9986|9986|6|0.0%|3.2%|
openbl_90d|9986|9986|6|0.0%|3.2%|
openbl_60d|7904|7904|6|0.0%|3.2%|
rosi_web_proxies|3230|3230|4|0.1%|2.1%|
ib_bluetack_level2|75927|348729520|4|0.0%|2.1%|
ib_bluetack_level1|215693|765044590|3|0.0%|1.6%|
zeus|262|262|1|0.3%|0.5%|
zeus_badips|228|228|1|0.4%|0.5%|

# php_dictionary

[projecthoneypot.org](http://www.projecthoneypot.org/) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)

The ipset `php_dictionary` has 275 entries, 275 unique IPs.

The following table shows the overlaps of \'php_dictionary\' with all the other ipsets supported.

- ` %  in ` is the percentage of each row found **in php_dictionary**.
- ` %  of ` is the percentage **of php_dictionary** found in each row.

ipset|entries|unique IPs|IPs found on both| % in| % of|
:---:|:-----:|:--------:|:---------------:|:---:|:---:|
nixspam|18589|18589|83|0.4%|30.1%|
blocklist_de|26479|26479|81|0.3%|29.4%|
snort_ipfilter|6580|6580|65|0.9%|23.6%|
stop_forum_spam_30d|91499|91499|48|0.0%|17.4%|
php_spammers|261|261|46|17.6%|16.7%|
stop_forum_spam_7d|28751|28751|31|0.1%|11.2%|
stop_forum_spam_1h|6751|6751|14|0.2%|5.0%|
rosi_web_proxies|3230|3230|13|0.4%|4.7%|
ib_bluetack_level3|18550|139108857|13|0.0%|4.7%|
php_commenters|184|184|10|5.4%|3.6%|
php_bad|184|184|10|5.4%|3.6%|
ib_bluetack_level2|75927|348729520|7|0.0%|2.5%|
ib_bluetack_level1|215693|765044590|7|0.0%|2.5%|
tor|6340|6340|4|0.0%|1.4%|
tor_servers|6539|6539|4|0.0%|1.4%|
danmetor|6555|6555|4|0.0%|1.4%|
ib_bluetack_badpeers|48134|48134|2|0.0%|0.7%|
alienvault_reputation|188000|188000|2|0.0%|0.7%|
spamhaus_drop|640|18051584|1|0.0%|0.3%|
rosi_connect_proxies|1348|1348|1|0.0%|0.3%|
php_harvesters|178|178|1|0.5%|0.3%|
ib_bluetack_spyware|898|336971|1|0.0%|0.3%|
ib_bluetack_proxies|673|673|1|0.1%|0.3%|
emerging_block|965|18065466|1|0.0%|0.3%|

# php_harvesters

[projecthoneypot.org](http://www.projecthoneypot.org/) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)

The ipset `php_harvesters` has 178 entries, 178 unique IPs.

The following table shows the overlaps of \'php_harvesters\' with all the other ipsets supported.

- ` %  in ` is the percentage of each row found **in php_harvesters**.
- ` %  of ` is the percentage **of php_harvesters** found in each row.

ipset|entries|unique IPs|IPs found on both| % in| % of|
:---:|:-----:|:--------:|:---------------:|:---:|:---:|
stop_forum_spam_30d|91499|91499|46|0.0%|25.8%|
stop_forum_spam_7d|28751|28751|40|0.1%|22.4%|
stop_forum_spam_1h|6751|6751|24|0.3%|13.4%|
blocklist_de|26479|26479|22|0.0%|12.3%|
ib_bluetack_level3|18550|139108857|12|0.0%|6.7%|
snort_ipfilter|6580|6580|10|0.1%|5.6%|
php_commenters|184|184|8|4.3%|4.4%|
php_bad|184|184|8|4.3%|4.4%|
tor|6340|6340|7|0.1%|3.9%|
tor_servers|6539|6539|7|0.1%|3.9%|
danmetor|6555|6555|7|0.1%|3.9%|
alienvault_reputation|188000|188000|7|0.0%|3.9%|
ib_bluetack_level2|75927|348729520|5|0.0%|2.8%|
openbl|9986|9986|4|0.0%|2.2%|
openbl_90d|9986|9986|4|0.0%|2.2%|
openbl_60d|7904|7904|4|0.0%|2.2%|
nixspam|18589|18589|3|0.0%|1.6%|
ib_bluetack_badpeers|48134|48134|2|0.0%|1.1%|
spamhaus_drop|640|18051584|1|0.0%|0.5%|
rosi_web_proxies|3230|3230|1|0.0%|0.5%|
php_spammers|261|261|1|0.3%|0.5%|
php_dictionary|275|275|1|0.3%|0.5%|
ib_bluetack_spyware|898|336971|1|0.0%|0.5%|
ib_bluetack_level1|215693|765044590|1|0.0%|0.5%|
ib_bluetack_hijacked|535|9177856|1|0.0%|0.5%|
fullbogons|3646|670922200|1|0.0%|0.5%|
emerging_block|965|18065466|1|0.0%|0.5%|
bogons|13|592708608|1|0.0%|0.5%|

# php_spammers

[projecthoneypot.org](http://www.projecthoneypot.org/) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)

The ipset `php_spammers` has 261 entries, 261 unique IPs.

The following table shows the overlaps of \'php_spammers\' with all the other ipsets supported.

- ` %  in ` is the percentage of each row found **in php_spammers**.
- ` %  of ` is the percentage **of php_spammers** found in each row.

ipset|entries|unique IPs|IPs found on both| % in| % of|
:---:|:-----:|:--------:|:---------------:|:---:|:---:|
blocklist_de|26479|26479|65|0.2%|24.9%|
stop_forum_spam_30d|91499|91499|61|0.0%|23.3%|
nixspam|18589|18589|61|0.3%|23.3%|
snort_ipfilter|6580|6580|55|0.8%|21.0%|
php_dictionary|275|275|46|16.7%|17.6%|
stop_forum_spam_7d|28751|28751|40|0.1%|15.3%|
stop_forum_spam_1h|6751|6751|20|0.2%|7.6%|
ib_bluetack_level3|18550|139108857|18|0.0%|6.8%|
ib_bluetack_level2|75927|348729520|18|0.0%|6.8%|
php_commenters|184|184|15|8.1%|5.7%|
php_bad|184|184|15|8.1%|5.7%|
rosi_web_proxies|3230|3230|9|0.2%|3.4%|
tor|6340|6340|5|0.0%|1.9%|
tor_servers|6539|6539|5|0.0%|1.9%|
danmetor|6555|6555|5|0.0%|1.9%|
alienvault_reputation|188000|188000|3|0.0%|1.1%|
spamhaus_drop|640|18051584|2|0.0%|0.7%|
ib_bluetack_level1|215693|765044590|2|0.0%|0.7%|
ib_bluetack_hijacked|535|9177856|2|0.0%|0.7%|
emerging_block|965|18065466|2|0.0%|0.7%|
rosi_connect_proxies|1348|1348|1|0.0%|0.3%|
php_harvesters|178|178|1|0.5%|0.3%|
ib_bluetack_badpeers|48134|48134|1|0.0%|0.3%|

# rosi_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

The ipset `rosi_connect_proxies` has 1348 entries, 1348 unique IPs.

The following table shows the overlaps of \'rosi_connect_proxies\' with all the other ipsets supported.

- ` %  in ` is the percentage of each row found **in rosi_connect_proxies**.
- ` %  of ` is the percentage **of rosi_connect_proxies** found in each row.

ipset|entries|unique IPs|IPs found on both| % in| % of|
:---:|:-----:|:--------:|:---------------:|:---:|:---:|
stop_forum_spam_30d|91499|91499|803|0.8%|59.5%|
stop_forum_spam_7d|28751|28751|681|2.3%|50.5%|
rosi_web_proxies|3230|3230|515|15.9%|38.2%|
stop_forum_spam_1h|6751|6751|171|2.5%|12.6%|
blocklist_de|26479|26479|80|0.3%|5.9%|
ib_bluetack_level2|75927|348729520|66|0.0%|4.8%|
ib_bluetack_level3|18550|139108857|29|0.0%|2.1%|
ib_bluetack_level1|215693|765044590|22|0.0%|1.6%|
nixspam|18589|18589|14|0.0%|1.0%|
ib_bluetack_proxies|673|673|5|0.7%|0.3%|
snort_ipfilter|6580|6580|4|0.0%|0.2%|
tor|6340|6340|1|0.0%|0.0%|
tor_servers|6539|6539|1|0.0%|0.0%|
php_spammers|261|261|1|0.3%|0.0%|
php_dictionary|275|275|1|0.3%|0.0%|
danmetor|6555|6555|1|0.0%|0.0%|
alienvault_reputation|188000|188000|1|0.0%|0.0%|

# rosi_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

The ipset `rosi_web_proxies` has 3230 entries, 3230 unique IPs.

The following table shows the overlaps of \'rosi_web_proxies\' with all the other ipsets supported.

- ` %  in ` is the percentage of each row found **in rosi_web_proxies**.
- ` %  of ` is the percentage **of rosi_web_proxies** found in each row.

ipset|entries|unique IPs|IPs found on both| % in| % of|
:---:|:-----:|:--------:|:---------------:|:---:|:---:|
stop_forum_spam_30d|91499|91499|1588|1.7%|49.1%|
stop_forum_spam_7d|28751|28751|1347|4.6%|41.7%|
rosi_connect_proxies|1348|1348|515|38.2%|15.9%|
stop_forum_spam_1h|6751|6751|486|7.1%|15.0%|
blocklist_de|26479|26479|351|1.3%|10.8%|
ib_bluetack_level2|75927|348729520|122|0.0%|3.7%|
ib_bluetack_level3|18550|139108857|114|0.0%|3.5%|
nixspam|18589|18589|76|0.4%|2.3%|
ib_bluetack_level1|215693|765044590|57|0.0%|1.7%|
snort_ipfilter|6580|6580|23|0.3%|0.7%|
php_dictionary|275|275|13|4.7%|0.4%|
php_spammers|261|261|9|3.4%|0.2%|
ib_bluetack_proxies|673|673|9|1.3%|0.2%|
tor|6340|6340|4|0.0%|0.1%|
tor_servers|6539|6539|4|0.0%|0.1%|
php_commenters|184|184|4|2.1%|0.1%|
php_bad|184|184|4|2.1%|0.1%|
danmetor|6555|6555|4|0.0%|0.1%|
ib_bluetack_spyware|898|336971|3|0.0%|0.0%|
alienvault_reputation|188000|188000|2|0.0%|0.0%|
php_harvesters|178|178|1|0.5%|0.0%|
openbl|9986|9986|1|0.0%|0.0%|
openbl_90d|9986|9986|1|0.0%|0.0%|
ib_bluetack_webexploit|1460|1460|1|0.0%|0.0%|
ib_bluetack_badpeers|48134|48134|1|0.0%|0.0%|

# snort_ipfilter

[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)

The ipset `snort_ipfilter` has 6580 entries, 6580 unique IPs.

The following table shows the overlaps of \'snort_ipfilter\' with all the other ipsets supported.

- ` %  in ` is the percentage of each row found **in snort_ipfilter**.
- ` %  of ` is the percentage **of snort_ipfilter** found in each row.

ipset|entries|unique IPs|IPs found on both| % in| % of|
:---:|:-----:|:--------:|:---------------:|:---:|:---:|
danmetor|6555|6555|1063|16.2%|16.1%|
tor_servers|6539|6539|1062|16.2%|16.1%|
tor|6340|6340|1039|16.3%|15.7%|
stop_forum_spam_30d|91499|91499|682|0.7%|10.3%|
stop_forum_spam_7d|28751|28751|506|1.7%|7.6%|
emerging_block|965|18065466|282|0.0%|4.2%|
stop_forum_spam_1h|6751|6751|275|4.0%|4.1%|
zeus|262|262|223|85.1%|3.3%|
ib_bluetack_level3|18550|139108857|211|0.0%|3.2%|
blocklist_de|26479|26479|208|0.7%|3.1%|
zeus_badips|228|228|200|87.7%|3.0%|
nixspam|18589|18589|188|1.0%|2.8%|
alienvault_reputation|188000|188000|115|0.0%|1.7%|
ib_bluetack_level2|75927|348729520|97|0.0%|1.4%|
php_dictionary|275|275|65|23.6%|0.9%|
php_spammers|261|261|55|21.0%|0.8%|
ib_bluetack_level1|215693|765044590|55|0.0%|0.8%|
feodo|58|58|46|79.3%|0.6%|
php_commenters|184|184|25|13.5%|0.3%|
php_bad|184|184|25|13.5%|0.3%|
openbl|9986|9986|25|0.2%|0.3%|
openbl_90d|9986|9986|25|0.2%|0.3%|
openbl_60d|7904|7904|24|0.3%|0.3%|
malwaredomainlist|1283|1283|24|1.8%|0.3%|
rosi_web_proxies|3230|3230|23|0.7%|0.3%|
sslbl|319|319|18|5.6%|0.2%|
spamhaus_drop|640|18051584|18|0.0%|0.2%|
ib_bluetack_spyware|898|336971|12|0.0%|0.1%|
ib_bluetack_hijacked|535|9177856|11|0.0%|0.1%|
php_harvesters|178|178|10|5.6%|0.1%|
palevo|12|12|10|83.3%|0.1%|
spamhaus_edrop|55|421120|6|0.0%|0.0%|
rosi_connect_proxies|1348|1348|4|0.2%|0.0%|
clean_mx_viruses|318|318|3|0.9%|0.0%|
ib_bluetack_webexploit|1460|1460|2|0.1%|0.0%|
openbl_30d|4722|4722|1|0.0%|0.0%|
ib_bluetack_proxies|673|673|1|0.1%|0.0%|
ib_bluetack_badpeers|48134|48134|1|0.0%|0.0%|
dshield|20|5120|1|0.0%|0.0%|
compromised|2436|2436|1|0.0%|0.0%|
bruteforceblocker|2287|2287|1|0.0%|0.0%|

# spamhaus_drop

[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**

The ipset `spamhaus_drop` has 640 entries, 18051584 unique IPs.

The following table shows the overlaps of \'spamhaus_drop\' with all the other ipsets supported.

- ` %  in ` is the percentage of each row found **in spamhaus_drop**.
- ` %  of ` is the percentage **of spamhaus_drop** found in each row.

ipset|entries|unique IPs|IPs found on both| % in| % of|
:---:|:-----:|:--------:|:---------------:|:---:|:---:|
emerging_block|965|18065466|17994240|99.6%|99.6%|
ib_bluetack_level2|75927|348729520|8401433|2.4%|46.5%|
ib_bluetack_hijacked|535|9177856|7211008|78.5%|39.9%|
ib_bluetack_level1|215693|765044590|2132981|0.2%|11.8%|
ib_bluetack_level3|18550|139108857|195904|0.1%|1.0%|
fullbogons|3646|670922200|20480|0.0%|0.1%|
alienvault_reputation|188000|188000|2274|1.2%|0.0%|
ib_bluetack_spyware|898|336971|1024|0.3%|0.0%|
stop_forum_spam_30d|91499|91499|741|0.8%|0.0%|
spamhaus_edrop|55|421120|512|0.1%|0.0%|
openbl|9986|9986|446|4.4%|0.0%|
openbl_90d|9986|9986|446|4.4%|0.0%|
openbl_60d|7904|7904|320|4.0%|0.0%|
dshield|20|5120|256|5.0%|0.0%|
stop_forum_spam_7d|28751|28751|216|0.7%|0.0%|
openbl_30d|4722|4722|213|4.5%|0.0%|
blocklist_de|26479|26479|194|0.7%|0.0%|
nixspam|18589|18589|173|0.9%|0.0%|
openbl_7d|1427|1427|101|7.0%|0.0%|
bruteforceblocker|2287|2287|89|3.8%|0.0%|
compromised|2436|2436|76|3.1%|0.0%|
stop_forum_spam_1h|6751|6751|56|0.8%|0.0%|
malwaredomainlist|1283|1283|28|2.1%|0.0%|
openbl_1d|357|357|26|7.2%|0.0%|
php_commenters|184|184|24|13.0%|0.0%|
php_bad|184|184|24|13.0%|0.0%|
snort_ipfilter|6580|6580|18|0.2%|0.0%|
zeus|262|262|17|6.4%|0.0%|
zeus_badips|228|228|17|7.4%|0.0%|
ib_bluetack_webexploit|1460|1460|6|0.4%|0.0%|
ib_bluetack_badpeers|48134|48134|6|0.0%|0.0%|
tor|6340|6340|2|0.0%|0.0%|
tor_servers|6539|6539|2|0.0%|0.0%|
sslbl|319|319|2|0.6%|0.0%|
php_spammers|261|261|2|0.7%|0.0%|
malc0de|426|426|2|0.4%|0.0%|
ib_bluetack_proxies|673|673|2|0.2%|0.0%|
danmetor|6555|6555|2|0.0%|0.0%|
php_harvesters|178|178|1|0.5%|0.0%|
php_dictionary|275|275|1|0.3%|0.0%|
botnet|515|515|1|0.1%|0.0%|

# spamhaus_edrop

[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**

The ipset `spamhaus_edrop` has 55 entries, 421120 unique IPs.

The following table shows the overlaps of \'spamhaus_edrop\' with all the other ipsets supported.

- ` %  in ` is the percentage of each row found **in spamhaus_edrop**.
- ` %  of ` is the percentage **of spamhaus_edrop** found in each row.

ipset|entries|unique IPs|IPs found on both| % in| % of|
:---:|:-----:|:--------:|:---------------:|:---:|:---:|
ib_bluetack_level3|18550|139108857|270785|0.1%|64.3%|
ib_bluetack_level2|75927|348729520|33368|0.0%|7.9%|
ib_bluetack_level1|215693|765044590|33152|0.0%|7.8%|
emerging_block|965|18065466|517|0.0%|0.1%|
spamhaus_drop|640|18051584|512|0.0%|0.1%|
stop_forum_spam_30d|91499|91499|109|0.1%|0.0%|
blocklist_de|26479|26479|38|0.1%|0.0%|
stop_forum_spam_7d|28751|28751|32|0.1%|0.0%|
alienvault_reputation|188000|188000|16|0.0%|0.0%|
openbl|9986|9986|14|0.1%|0.0%|
openbl_90d|9986|9986|14|0.1%|0.0%|
stop_forum_spam_1h|6751|6751|13|0.1%|0.0%|
snort_ipfilter|6580|6580|6|0.0%|0.0%|
php_commenters|184|184|6|3.2%|0.0%|
php_bad|184|184|6|3.2%|0.0%|
zeus|262|262|5|1.9%|0.0%|
zeus_badips|228|228|5|2.1%|0.0%|
openbl_60d|7904|7904|2|0.0%|0.0%|
openbl_7d|1427|1427|1|0.0%|0.0%|
openbl_30d|4722|4722|1|0.0%|0.0%|
openbl_1d|357|357|1|0.2%|0.0%|
nixspam|18589|18589|1|0.0%|0.0%|
malc0de|426|426|1|0.2%|0.0%|

# sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

The ipset `sslbl` has 319 entries, 319 unique IPs.

The following table shows the overlaps of \'sslbl\' with all the other ipsets supported.

- ` %  in ` is the percentage of each row found **in sslbl**.
- ` %  of ` is the percentage **of sslbl** found in each row.

ipset|entries|unique IPs|IPs found on both| % in| % of|
:---:|:-----:|:--------:|:---------------:|:---:|:---:|
emerging_block|965|18065466|23|0.0%|7.2%|
feodo|58|58|21|36.2%|6.5%|
snort_ipfilter|6580|6580|18|0.2%|5.6%|
ib_bluetack_level3|18550|139108857|16|0.0%|5.0%|
alienvault_reputation|188000|188000|7|0.0%|2.1%|
ib_bluetack_level2|75927|348729520|5|0.0%|1.5%|
ib_bluetack_level1|215693|765044590|3|0.0%|0.9%|
stop_forum_spam_30d|91499|91499|2|0.0%|0.6%|
spamhaus_drop|640|18051584|2|0.0%|0.6%|
openbl|9986|9986|1|0.0%|0.3%|
openbl_90d|9986|9986|1|0.0%|0.3%|
ib_bluetack_spyware|898|336971|1|0.0%|0.3%|

# stop_forum_spam_1h

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

The ipset `stop_forum_spam_1h` has 6751 entries, 6751 unique IPs.

The following table shows the overlaps of \'stop_forum_spam_1h\' with all the other ipsets supported.

- ` %  in ` is the percentage of each row found **in stop_forum_spam_1h**.
- ` %  of ` is the percentage **of stop_forum_spam_1h** found in each row.

ipset|entries|unique IPs|IPs found on both| % in| % of|
:---:|:-----:|:--------:|:---------------:|:---:|:---:|
stop_forum_spam_30d|91499|91499|4802|5.2%|71.1%|
stop_forum_spam_7d|28751|28751|4796|16.6%|71.0%|
blocklist_de|26479|26479|1318|4.9%|19.5%|
rosi_web_proxies|3230|3230|486|15.0%|7.1%|
ib_bluetack_level3|18550|139108857|435|0.0%|6.4%|
snort_ipfilter|6580|6580|275|4.1%|4.0%|
tor_servers|6539|6539|249|3.8%|3.6%|
danmetor|6555|6555|249|3.7%|3.6%|
tor|6340|6340|247|3.8%|3.6%|
ib_bluetack_level2|75927|348729520|216|0.0%|3.1%|
rosi_connect_proxies|1348|1348|171|12.6%|2.5%|
ib_bluetack_level1|215693|765044590|117|0.0%|1.7%|
php_commenters|184|184|92|50.0%|1.3%|
php_bad|184|184|92|50.0%|1.3%|
emerging_block|965|18065466|58|0.0%|0.8%|
nixspam|18589|18589|57|0.3%|0.8%|
spamhaus_drop|640|18051584|56|0.0%|0.8%|
alienvault_reputation|188000|188000|55|0.0%|0.8%|
ib_bluetack_hijacked|535|9177856|36|0.0%|0.5%|
php_harvesters|178|178|24|13.4%|0.3%|
openbl|9986|9986|22|0.2%|0.3%|
openbl_90d|9986|9986|22|0.2%|0.3%|
php_spammers|261|261|20|7.6%|0.2%|
openbl_60d|7904|7904|20|0.2%|0.2%|
php_dictionary|275|275|14|5.0%|0.2%|
spamhaus_edrop|55|421120|13|0.0%|0.1%|
ib_bluetack_spyware|898|336971|10|0.0%|0.1%|
ib_bluetack_proxies|673|673|6|0.8%|0.0%|
dshield|20|5120|3|0.0%|0.0%|
zeus|262|262|1|0.3%|0.0%|
zeus_badips|228|228|1|0.4%|0.0%|
openbl_7d|1427|1427|1|0.0%|0.0%|
openbl_30d|4722|4722|1|0.0%|0.0%|
ib_bluetack_webexploit|1460|1460|1|0.0%|0.0%|
ib_bluetack_badpeers|48134|48134|1|0.0%|0.0%|

# stop_forum_spam_30d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)

The ipset `stop_forum_spam_30d` has 91499 entries, 91499 unique IPs.

The following table shows the overlaps of \'stop_forum_spam_30d\' with all the other ipsets supported.

- ` %  in ` is the percentage of each row found **in stop_forum_spam_30d**.
- ` %  of ` is the percentage **of stop_forum_spam_30d** found in each row.

ipset|entries|unique IPs|IPs found on both| % in| % of|
:---:|:-----:|:--------:|:---------------:|:---:|:---:|
stop_forum_spam_7d|28751|28751|28407|98.8%|31.0%|
ib_bluetack_level3|18550|139108857|6228|0.0%|6.8%|
stop_forum_spam_1h|6751|6751|4802|71.1%|5.2%|
blocklist_de|26479|26479|2503|9.4%|2.7%|
ib_bluetack_level2|75927|348729520|2388|0.0%|2.6%|
rosi_web_proxies|3230|3230|1588|49.1%|1.7%|
ib_bluetack_level1|215693|765044590|1257|0.0%|1.3%|
rosi_connect_proxies|1348|1348|803|59.5%|0.8%|
emerging_block|965|18065466|752|0.0%|0.8%|
spamhaus_drop|640|18051584|741|0.0%|0.8%|
ib_bluetack_hijacked|535|9177856|708|0.0%|0.7%|
snort_ipfilter|6580|6580|682|10.3%|0.7%|
tor|6340|6340|571|9.0%|0.6%|
danmetor|6555|6555|566|8.6%|0.6%|
tor_servers|6539|6539|564|8.6%|0.6%|
alienvault_reputation|188000|188000|254|0.1%|0.2%|
nixspam|18589|18589|199|1.0%|0.2%|
php_commenters|184|184|134|72.8%|0.1%|
php_bad|184|184|134|72.8%|0.1%|
spamhaus_edrop|55|421120|109|0.0%|0.1%|
openbl|9986|9986|73|0.7%|0.0%|
openbl_90d|9986|9986|73|0.7%|0.0%|
openbl_60d|7904|7904|65|0.8%|0.0%|
php_spammers|261|261|61|23.3%|0.0%|
php_dictionary|275|275|48|17.4%|0.0%|
php_harvesters|178|178|46|25.8%|0.0%|
ib_bluetack_spyware|898|336971|41|0.0%|0.0%|
openbl_30d|4722|4722|25|0.5%|0.0%|
ib_bluetack_proxies|673|673|24|3.5%|0.0%|
ib_bluetack_badpeers|48134|48134|14|0.0%|0.0%|
dshield|20|5120|6|0.1%|0.0%|
zeus|262|262|4|1.5%|0.0%|
compromised|2436|2436|4|0.1%|0.0%|
bruteforceblocker|2287|2287|4|0.1%|0.0%|
zeus_badips|228|228|3|1.3%|0.0%|
openbl_7d|1427|1427|3|0.2%|0.0%|
fullbogons|3646|670922200|3|0.0%|0.0%|
sslbl|319|319|2|0.6%|0.0%|
malwaredomainlist|1283|1283|2|0.1%|0.0%|
ib_bluetack_webexploit|1460|1460|2|0.1%|0.0%|
openbl_1d|357|357|1|0.2%|0.0%|
clean_mx_viruses|318|318|1|0.3%|0.0%|
bogons|13|592708608|1|0.0%|0.0%|

# stop_forum_spam_7d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)

The ipset `stop_forum_spam_7d` has 28751 entries, 28751 unique IPs.

The following table shows the overlaps of \'stop_forum_spam_7d\' with all the other ipsets supported.

- ` %  in ` is the percentage of each row found **in stop_forum_spam_7d**.
- ` %  of ` is the percentage **of stop_forum_spam_7d** found in each row.

ipset|entries|unique IPs|IPs found on both| % in| % of|
:---:|:-----:|:--------:|:---------------:|:---:|:---:|
stop_forum_spam_30d|91499|91499|28407|31.0%|98.8%|
stop_forum_spam_1h|6751|6751|4796|71.0%|16.6%|
blocklist_de|26479|26479|2041|7.7%|7.0%|
ib_bluetack_level3|18550|139108857|1914|0.0%|6.6%|
rosi_web_proxies|3230|3230|1347|41.7%|4.6%|
ib_bluetack_level2|75927|348729520|819|0.0%|2.8%|
rosi_connect_proxies|1348|1348|681|50.5%|2.3%|
snort_ipfilter|6580|6580|506|7.6%|1.7%|
ib_bluetack_level1|215693|765044590|451|0.0%|1.5%|
tor|6340|6340|424|6.6%|1.4%|
danmetor|6555|6555|417|6.3%|1.4%|
tor_servers|6539|6539|415|6.3%|1.4%|
emerging_block|965|18065466|221|0.0%|0.7%|
spamhaus_drop|640|18051584|216|0.0%|0.7%|
ib_bluetack_hijacked|535|9177856|198|0.0%|0.6%|
php_commenters|184|184|126|68.4%|0.4%|
php_bad|184|184|126|68.4%|0.4%|
alienvault_reputation|188000|188000|120|0.0%|0.4%|
nixspam|18589|18589|118|0.6%|0.4%|
php_spammers|261|261|40|15.3%|0.1%|
php_harvesters|178|178|40|22.4%|0.1%|
openbl|9986|9986|37|0.3%|0.1%|
openbl_90d|9986|9986|37|0.3%|0.1%|
openbl_60d|7904|7904|33|0.4%|0.1%|
spamhaus_edrop|55|421120|32|0.0%|0.1%|
php_dictionary|275|275|31|11.2%|0.1%|
ib_bluetack_spyware|898|336971|22|0.0%|0.0%|
ib_bluetack_proxies|673|673|15|2.2%|0.0%|
openbl_30d|4722|4722|7|0.1%|0.0%|
ib_bluetack_badpeers|48134|48134|5|0.0%|0.0%|
dshield|20|5120|3|0.0%|0.0%|
ib_bluetack_webexploit|1460|1460|2|0.1%|0.0%|
compromised|2436|2436|2|0.0%|0.0%|
zeus|262|262|1|0.3%|0.0%|
zeus_badips|228|228|1|0.4%|0.0%|
openbl_7d|1427|1427|1|0.0%|0.0%|
fullbogons|3646|670922200|1|0.0%|0.0%|
clean_mx_viruses|318|318|1|0.3%|0.0%|
bruteforceblocker|2287|2287|1|0.0%|0.0%|

# tor

[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs

The ipset `tor` has 6340 entries, 6340 unique IPs.

The following table shows the overlaps of \'tor\' with all the other ipsets supported.

- ` %  in ` is the percentage of each row found **in tor**.
- ` %  of ` is the percentage **of tor** found in each row.

ipset|entries|unique IPs|IPs found on both| % in| % of|
:---:|:-----:|:--------:|:---------------:|:---:|:---:|
danmetor|6555|6555|5584|85.1%|88.0%|
tor_servers|6539|6539|5581|85.3%|88.0%|
snort_ipfilter|6580|6580|1039|15.7%|16.3%|
ib_bluetack_level3|18550|139108857|602|0.0%|9.4%|
stop_forum_spam_30d|91499|91499|571|0.6%|9.0%|
stop_forum_spam_7d|28751|28751|424|1.4%|6.6%|
stop_forum_spam_1h|6751|6751|247|3.6%|3.8%|
ib_bluetack_level2|75927|348729520|171|0.0%|2.6%|
ib_bluetack_level1|215693|765044590|148|0.0%|2.3%|
alienvault_reputation|188000|188000|44|0.0%|0.6%|
openbl|9986|9986|20|0.2%|0.3%|
openbl_90d|9986|9986|20|0.2%|0.3%|
openbl_60d|7904|7904|20|0.2%|0.3%|
ib_bluetack_spyware|898|336971|20|0.0%|0.3%|
php_commenters|184|184|17|9.2%|0.2%|
php_bad|184|184|17|9.2%|0.2%|
php_harvesters|178|178|7|3.9%|0.1%|
php_spammers|261|261|5|1.9%|0.0%|
rosi_web_proxies|3230|3230|4|0.1%|0.0%|
php_dictionary|275|275|4|1.4%|0.0%|
emerging_block|965|18065466|4|0.0%|0.0%|
blocklist_de|26479|26479|3|0.0%|0.0%|
spamhaus_drop|640|18051584|2|0.0%|0.0%|
nixspam|18589|18589|2|0.0%|0.0%|
ib_bluetack_hijacked|535|9177856|2|0.0%|0.0%|
dshield|20|5120|2|0.0%|0.0%|
rosi_connect_proxies|1348|1348|1|0.0%|0.0%|
ib_bluetack_webexploit|1460|1460|1|0.0%|0.0%|

# tor_servers

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

The ipset `tor_servers` has 6539 entries, 6539 unique IPs.

The following table shows the overlaps of \'tor_servers\' with all the other ipsets supported.

- ` %  in ` is the percentage of each row found **in tor_servers**.
- ` %  of ` is the percentage **of tor_servers** found in each row.

ipset|entries|unique IPs|IPs found on both| % in| % of|
:---:|:-----:|:--------:|:---------------:|:---:|:---:|
danmetor|6555|6555|6473|98.7%|98.9%|
tor|6340|6340|5581|88.0%|85.3%|
snort_ipfilter|6580|6580|1062|16.1%|16.2%|
ib_bluetack_level3|18550|139108857|605|0.0%|9.2%|
stop_forum_spam_30d|91499|91499|564|0.6%|8.6%|
stop_forum_spam_7d|28751|28751|415|1.4%|6.3%|
stop_forum_spam_1h|6751|6751|249|3.6%|3.8%|
ib_bluetack_level2|75927|348729520|170|0.0%|2.5%|
ib_bluetack_level1|215693|765044590|148|0.0%|2.2%|
alienvault_reputation|188000|188000|44|0.0%|0.6%|
openbl|9986|9986|20|0.2%|0.3%|
openbl_90d|9986|9986|20|0.2%|0.3%|
openbl_60d|7904|7904|20|0.2%|0.3%|
ib_bluetack_spyware|898|336971|20|0.0%|0.3%|
php_commenters|184|184|17|9.2%|0.2%|
php_bad|184|184|17|9.2%|0.2%|
php_harvesters|178|178|7|3.9%|0.1%|
blocklist_de|26479|26479|6|0.0%|0.0%|
php_spammers|261|261|5|1.9%|0.0%|
rosi_web_proxies|3230|3230|4|0.1%|0.0%|
php_dictionary|275|275|4|1.4%|0.0%|
emerging_block|965|18065466|4|0.0%|0.0%|
spamhaus_drop|640|18051584|2|0.0%|0.0%|
ib_bluetack_hijacked|535|9177856|2|0.0%|0.0%|
dshield|20|5120|2|0.0%|0.0%|
rosi_connect_proxies|1348|1348|1|0.0%|0.0%|
nixspam|18589|18589|1|0.0%|0.0%|
ib_bluetack_webexploit|1460|1460|1|0.0%|0.0%|

# zeus

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) default blocklist including hijacked sites and web hosting providers - **excellent list**

The ipset `zeus` has 262 entries, 262 unique IPs.

The following table shows the overlaps of \'zeus\' with all the other ipsets supported.

- ` %  in ` is the percentage of each row found **in zeus**.
- ` %  of ` is the percentage **of zeus** found in each row.

ipset|entries|unique IPs|IPs found on both| % in| % of|
:---:|:-----:|:--------:|:---------------:|:---:|:---:|
emerging_block|965|18065466|256|0.0%|97.7%|
zeus_badips|228|228|228|100.0%|87.0%|
snort_ipfilter|6580|6580|223|3.3%|85.1%|
alienvault_reputation|188000|188000|64|0.0%|24.4%|
ib_bluetack_level3|18550|139108857|19|0.0%|7.2%|
spamhaus_drop|640|18051584|17|0.0%|6.4%|
ib_bluetack_hijacked|535|9177856|10|0.0%|3.8%|
ib_bluetack_level2|75927|348729520|7|0.0%|2.6%|
ib_bluetack_level1|215693|765044590|7|0.0%|2.6%|
spamhaus_edrop|55|421120|5|0.0%|1.9%|
stop_forum_spam_30d|91499|91499|4|0.0%|1.5%|
stop_forum_spam_7d|28751|28751|1|0.0%|0.3%|
stop_forum_spam_1h|6751|6751|1|0.0%|0.3%|
php_commenters|184|184|1|0.5%|0.3%|
php_bad|184|184|1|0.5%|0.3%|
openbl|9986|9986|1|0.0%|0.3%|
openbl_90d|9986|9986|1|0.0%|0.3%|
openbl_60d|7904|7904|1|0.0%|0.3%|
openbl_30d|4722|4722|1|0.0%|0.3%|
compromised|2436|2436|1|0.0%|0.3%|
bruteforceblocker|2287|2287|1|0.0%|0.3%|
blocklist_de|26479|26479|1|0.0%|0.3%|

# zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) includes IPv4 addresses that are used by the ZeuS trojan

The ipset `zeus_badips` has 228 entries, 228 unique IPs.

The following table shows the overlaps of \'zeus_badips\' with all the other ipsets supported.

- ` %  in ` is the percentage of each row found **in zeus_badips**.
- ` %  of ` is the percentage **of zeus_badips** found in each row.

ipset|entries|unique IPs|IPs found on both| % in| % of|
:---:|:-----:|:--------:|:---------------:|:---:|:---:|
zeus|262|262|228|87.0%|100.0%|
emerging_block|965|18065466|225|0.0%|98.6%|
snort_ipfilter|6580|6580|200|3.0%|87.7%|
alienvault_reputation|188000|188000|37|0.0%|16.2%|
spamhaus_drop|640|18051584|17|0.0%|7.4%|
ib_bluetack_level3|18550|139108857|14|0.0%|6.1%|
ib_bluetack_hijacked|535|9177856|10|0.0%|4.3%|
ib_bluetack_level2|75927|348729520|7|0.0%|3.0%|
spamhaus_edrop|55|421120|5|0.0%|2.1%|
ib_bluetack_level1|215693|765044590|4|0.0%|1.7%|
stop_forum_spam_30d|91499|91499|3|0.0%|1.3%|
stop_forum_spam_7d|28751|28751|1|0.0%|0.4%|
stop_forum_spam_1h|6751|6751|1|0.0%|0.4%|
php_commenters|184|184|1|0.5%|0.4%|
php_bad|184|184|1|0.5%|0.4%|
openbl|9986|9986|1|0.0%|0.4%|
openbl_90d|9986|9986|1|0.0%|0.4%|
openbl_60d|7904|7904|1|0.0%|0.4%|
openbl_30d|4722|4722|1|0.0%|0.4%|
compromised|2436|2436|1|0.0%|0.4%|
bruteforceblocker|2287|2287|1|0.0%|0.4%|
blocklist_de|26479|26479|1|0.0%|0.4%|
