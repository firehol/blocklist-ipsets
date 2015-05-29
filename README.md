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

The following list was automatically generated on Fri May 29 10:10:15 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|174512 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|22183 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|12618 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|3461 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|1324 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|367 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|775 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|14650 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|89 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|2078 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|233 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6433 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD)|ipv4 hash:ip|2350 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|345 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|91 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6451 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|904 subnets, 18056697 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botnet](#et_botnet)|[EmergingThreats.net](http://www.emergingthreats.net/) botnet IPs|ipv4 hash:ip|505 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net](http://www.emergingthreats.net/) compromised hosts (seems to be a derivate of other lists)|ipv4 hash:ip|2401 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6360 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[feodo](#feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|67 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
[fullbogons](#fullbogons)|[Team-Cymru.org](http://www.team-cymru.org) IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user - **excellent list - use it only your internet interface**|ipv4 hash:net|3656 subnets, 670639576 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt)
[geolite2_country](https://github.com/ktsaou/blocklist-ipsets/tree/master/geolite2_country)|[MaxMind GeoLite2](http://dev.maxmind.com/geoip/geoip2/geolite2/) databases are free IP geolocation databases comparable to, but less accurate than, MaxMind’s GeoIP2 databases. They include IPs per country, IPs per continent, IPs used by anonymous services (VPNs, Proxies, etc) and Satellite Providers.|ipv4 hash:net|All the world|updated every 7 days  from [this link](http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country-CSV.zip)
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) IPs that have been reported for bad deeds in p2p|ipv4 hash:ip|48134 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=cwworuawihqvocglcoss&fileformat=p2p&archiveformat=gz)
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) hijacked IP-Blocks Hijacked IP space are IP blocks that are being used without permission|ipv4 hash:net|535 subnets, 9177856 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=usrcshglbiilevmyfhse&fileformat=p2p&archiveformat=gz)
[ib_bluetack_level1](#ib_bluetack_level1)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Level 1 (for use in p2p): Companies or organizations who are clearly involved with trying to stop filesharing (e.g. Baytsp, MediaDefender, Mediasentry a.o.). Companies which anti-p2p activity has been seen from. Companies that produce or have a strong financial interest in copyrighted material (e.g. music, movie, software industries a.o.). Government ranges or companies that have a strong financial interest in doing work for governments. Legal industry ranges. IPs or ranges of ISPs from which anti-p2p activity has been observed. Basically this list will block all kinds of internet connections that most people would rather not have during their internet travels.|ipv4 hash:net|236319 subnets, 765065682 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz)
[ib_bluetack_level2](#ib_bluetack_level2)|[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 2 (for use in p2p). General corporate ranges. Ranges used by labs or researchers. Proxies.|ipv4 hash:net|72774 subnets, 348707599 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw&fileformat=p2p&archiveformat=gz)
[ib_bluetack_level3](#ib_bluetack_level3)|[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 3 (for use in p2p). Many portal-type websites. ISP ranges that may be dodgy for some reason. Ranges that belong to an individual, but which have not been determined to be used by a particular company. Ranges for things that are unusual in some way. The L3 list is aka the paranoid list.|ipv4 hash:net|17802 subnets, 139104824 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh&fileformat=p2p&archiveformat=gz)
[ib_bluetack_proxies](#ib_bluetack_proxies)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Open Proxies IPs list (without TOR)|ipv4 hash:ip|673 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=xoebmbyexwuiogmbyprb&fileformat=p2p&archiveformat=gz)
[ib_bluetack_spyware](#ib_bluetack_spyware)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) known malicious SPYWARE and ADWARE IP Address ranges|ipv4 hash:net|3274 subnets, 339192 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=llvtlsjyoyiczbkjsxpf&fileformat=p2p&archiveformat=gz)
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) web server hack and exploit attempts|ipv4 hash:ip|1460 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=ghlzqtqxnzctvvajwwag&fileformat=p2p&archiveformat=gz)
[malc0de](#malc0de)|[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days|ipv4 hash:ip|411 unique IPs|updated every 1 day  from [this link](http://malc0de.com/bl/IP_Blacklist.txt)
[malwaredomainlist](#malwaredomainlist)|[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses|ipv4 hash:ip|1283 unique IPs|updated every 12 hours  from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt)
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.|ipv4 hash:ip|372 unique IPs|updated every 4 hours  from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list)
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|20758 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
[openbl](#openbl)|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|9846 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt.gz)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|357 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_1days.txt.gz)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|4426 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt.gz)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7743 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt.gz)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|988 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt.gz)
[openbl_90d](#openbl_90d)|[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|9846 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt.gz)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
[php_bad](#php_bad)|[projecthoneypot.org](http://www.projecthoneypot.org/) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|281 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|281 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|433 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|257 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|417 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1699 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|123 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1759 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|4579 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|51 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|7652 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|639 subnets, 17921280 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|55 subnets, 421120 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|345 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|7864 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|93361 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|30975 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10303 subnets, 10775 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1916 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|267 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|230 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Fri May 29 10:00:52 UTC 2015.

The ipset `alienvault_reputation` has **174512** entries, **174512** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15165|0.0%|8.6%|
[openbl_90d](#openbl_90d)|9846|9846|9825|99.7%|5.6%|
[openbl](#openbl)|9846|9846|9825|99.7%|5.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7874|0.0%|4.5%|
[openbl_60d](#openbl_60d)|7743|7743|7725|99.7%|4.4%|
[et_block](#et_block)|904|18056697|5013|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|4751|0.0%|2.7%|
[openbl_30d](#openbl_30d)|4426|4426|4416|99.7%|2.5%|
[dshield](#dshield)|20|5120|3853|75.2%|2.2%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|1625|0.0%|0.9%|
[et_compromised](#et_compromised)|2401|2401|1502|62.5%|0.8%|
[blocklist_de](#blocklist_de)|22183|22183|1481|6.6%|0.8%|
[bruteforceblocker](#bruteforceblocker)|2350|2350|1478|62.8%|0.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|2078|2078|1243|59.8%|0.7%|
[openbl_7d](#openbl_7d)|988|988|983|99.4%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|518|0.0%|0.2%|
[openbl_1d](#openbl_1d)|357|357|355|99.4%|0.2%|
[ciarmy](#ciarmy)|345|345|342|99.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|288|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|229|0.2%|0.1%|
[voipbl](#voipbl)|10303|10775|204|1.8%|0.1%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|124|1.6%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|115|0.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12618|12618|111|0.8%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|233|233|88|37.7%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14650|14650|76|0.5%|0.0%|
[zeus](#zeus)|267|267|68|25.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|775|775|61|7.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7864|7864|59|0.7%|0.0%|
[shunlist](#shunlist)|51|51|51|100.0%|0.0%|
[et_tor](#et_tor)|6360|6360|45|0.7%|0.0%|
[dm_tor](#dm_tor)|6451|6451|44|0.6%|0.0%|
[bm_tor](#bm_tor)|6433|6433|44|0.6%|0.0%|
[zeus_badips](#zeus_badips)|230|230|37|16.0%|0.0%|
[nixspam](#nixspam)|20758|20758|31|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3461|3461|24|0.6%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|23|6.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|89|89|20|22.4%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1324|1324|19|1.4%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|367|367|18|4.9%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|15|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[php_commenters](#php_commenters)|281|281|12|4.2%|0.0%|
[php_bad](#php_bad)|281|281|12|4.2%|0.0%|
[malc0de](#malc0de)|411|411|10|2.4%|0.0%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|8|0.5%|0.0%|
[sslbl](#sslbl)|345|345|7|2.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|7|1.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|7|0.5%|0.0%|
[xroxy](#xroxy)|1916|1916|4|0.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4579|4579|3|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|3|0.7%|0.0%|
[et_botnet](#et_botnet)|505|505|3|0.5%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1759|1759|2|0.1%|0.0%|
[proxyrss](#proxyrss)|1699|1699|2|0.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|91|91|2|2.1%|0.0%|
[proxz](#proxz)|123|123|1|0.8%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[feodo](#feodo)|67|67|1|1.4%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Fri May 29 09:42:04 UTC 2015.

The ipset `blocklist_de` has **22183** entries, **22183** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|14650|14650|14650|100.0%|66.0%|
[blocklist_de_apache](#blocklist_de_apache)|12618|12618|12618|100.0%|56.8%|
[blocklist_de_bots](#blocklist_de_bots)|3461|3461|3461|100.0%|15.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2818|0.0%|12.7%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|2586|2.7%|11.6%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|2455|7.9%|11.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2078|2078|2072|99.7%|9.3%|
[stopforumspam_1d](#stopforumspam_1d)|7864|7864|1656|21.0%|7.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|1487|0.0%|6.7%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|1481|0.8%|6.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1444|0.0%|6.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1324|1324|1318|99.5%|5.9%|
[openbl_90d](#openbl_90d)|9846|9846|1245|12.6%|5.6%|
[openbl](#openbl)|9846|9846|1245|12.6%|5.6%|
[openbl_60d](#openbl_60d)|7743|7743|1190|15.3%|5.3%|
[openbl_30d](#openbl_30d)|4426|4426|1101|24.8%|4.9%|
[bruteforceblocker](#bruteforceblocker)|2350|2350|1032|43.9%|4.6%|
[et_compromised](#et_compromised)|2401|2401|1001|41.6%|4.5%|
[blocklist_de_imap](#blocklist_de_imap)|775|775|764|98.5%|3.4%|
[openbl_7d](#openbl_7d)|988|988|654|66.1%|2.9%|
[nixspam](#nixspam)|20758|20758|464|2.2%|2.0%|
[ri_web_proxies](#ri_web_proxies)|4579|4579|397|8.6%|1.7%|
[blocklist_de_ftp](#blocklist_de_ftp)|367|367|367|100.0%|1.6%|
[xroxy](#xroxy)|1916|1916|305|15.9%|1.3%|
[proxyrss](#proxyrss)|1699|1699|245|14.4%|1.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|233|233|233|100.0%|1.0%|
[openbl_1d](#openbl_1d)|357|357|231|64.7%|1.0%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|226|2.9%|1.0%|
[et_block](#et_block)|904|18056697|195|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|189|0.0%|0.8%|
[dshield](#dshield)|20|5120|125|2.4%|0.5%|
[ri_connect_proxies](#ri_connect_proxies)|1759|1759|83|4.7%|0.3%|
[php_commenters](#php_commenters)|281|281|74|26.3%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|74|0.0%|0.3%|
[php_bad](#php_bad)|281|281|73|25.9%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|89|89|70|78.6%|0.3%|
[php_dictionary](#php_dictionary)|433|433|68|15.7%|0.3%|
[php_spammers](#php_spammers)|417|417|62|14.8%|0.2%|
[voipbl](#voipbl)|10303|10775|37|0.3%|0.1%|
[php_harvesters](#php_harvesters)|257|257|35|13.6%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|32|0.0%|0.1%|
[ciarmy](#ciarmy)|345|345|27|7.8%|0.1%|
[proxz](#proxz)|123|123|24|19.5%|0.1%|
[et_tor](#et_tor)|6360|6360|22|0.3%|0.0%|
[dm_tor](#dm_tor)|6451|6451|21|0.3%|0.0%|
[bm_tor](#bm_tor)|6433|6433|21|0.3%|0.0%|
[shunlist](#shunlist)|51|51|11|21.5%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|3|0.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|3|0.4%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus](#zeus)|267|267|1|0.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Fri May 29 09:42:08 UTC 2015.

The ipset `blocklist_de_apache` has **12618** entries, **12618** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22183|22183|12618|56.8%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|14650|14650|11059|75.4%|87.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2199|0.0%|17.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|1322|0.0%|10.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1324|1324|1317|99.4%|10.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1075|0.0%|8.5%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|217|0.2%|1.7%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|135|0.4%|1.0%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|111|0.0%|0.8%|
[stopforumspam_1d](#stopforumspam_1d)|7864|7864|85|1.0%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|233|233|37|15.8%|0.2%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|35|0.4%|0.2%|
[php_commenters](#php_commenters)|281|281|25|8.8%|0.1%|
[php_bad](#php_bad)|281|281|25|8.8%|0.1%|
[ciarmy](#ciarmy)|345|345|23|6.6%|0.1%|
[et_tor](#et_tor)|6360|6360|22|0.3%|0.1%|
[dm_tor](#dm_tor)|6451|6451|21|0.3%|0.1%|
[bm_tor](#bm_tor)|6433|6433|21|0.3%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3461|3461|16|0.4%|0.1%|
[openbl_90d](#openbl_90d)|9846|9846|13|0.1%|0.1%|
[openbl](#openbl)|9846|9846|13|0.1%|0.1%|
[openbl_60d](#openbl_60d)|7743|7743|10|0.1%|0.0%|
[nixspam](#nixspam)|20758|20758|8|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4426|4426|6|0.1%|0.0%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.0%|
[shunlist](#shunlist)|51|51|3|5.8%|0.0%|
[openbl_7d](#openbl_7d)|988|988|3|0.3%|0.0%|
[et_compromised](#et_compromised)|2401|2401|3|0.1%|0.0%|
[et_block](#et_block)|904|18056697|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2350|2350|3|0.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[xroxy](#xroxy)|1916|1916|1|0.0%|0.0%|
[voipbl](#voipbl)|10303|10775|1|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4579|4579|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1699|1699|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Fri May 29 09:42:12 UTC 2015.

The ipset `blocklist_de_bots` has **3461** entries, **3461** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22183|22183|3461|15.6%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|2285|2.4%|66.0%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|2277|7.3%|65.7%|
[stopforumspam_1d](#stopforumspam_1d)|7864|7864|1567|19.9%|45.2%|
[ri_web_proxies](#ri_web_proxies)|4579|4579|370|8.0%|10.6%|
[xroxy](#xroxy)|1916|1916|260|13.5%|7.5%|
[proxyrss](#proxyrss)|1699|1699|241|14.1%|6.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|157|0.0%|4.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|233|233|128|54.9%|3.6%|
[ri_connect_proxies](#ri_connect_proxies)|1759|1759|82|4.6%|2.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|80|0.0%|2.3%|
[php_commenters](#php_commenters)|281|281|57|20.2%|1.6%|
[php_bad](#php_bad)|281|281|57|20.2%|1.6%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|54|0.0%|1.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|54|0.0%|1.5%|
[et_block](#et_block)|904|18056697|54|0.0%|1.5%|
[nixspam](#nixspam)|20758|20758|50|0.2%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|44|0.0%|1.2%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|35|0.4%|1.0%|
[php_harvesters](#php_harvesters)|257|257|28|10.8%|0.8%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|26|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|24|0.0%|0.6%|
[proxz](#proxz)|123|123|23|18.6%|0.6%|
[php_spammers](#php_spammers)|417|417|17|4.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|14650|14650|16|0.1%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|12618|12618|16|0.1%|0.4%|
[php_dictionary](#php_dictionary)|433|433|13|3.0%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|3|0.4%|0.0%|
[openbl_90d](#openbl_90d)|9846|9846|2|0.0%|0.0%|
[openbl](#openbl)|9846|9846|2|0.0%|0.0%|
[voipbl](#voipbl)|10303|10775|1|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1324|1324|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Fri May 29 09:56:10 UTC 2015.

The ipset `blocklist_de_bruteforce` has **1324** entries, **1324** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22183|22183|1318|5.9%|99.5%|
[blocklist_de_apache](#blocklist_de_apache)|12618|12618|1317|10.4%|99.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|111|0.0%|8.3%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|78|0.0%|5.8%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|72|0.2%|5.4%|
[stopforumspam_1d](#stopforumspam_1d)|7864|7864|44|0.5%|3.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|41|0.0%|3.0%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|32|0.4%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|29|0.0%|2.1%|
[et_tor](#et_tor)|6360|6360|20|0.3%|1.5%|
[dm_tor](#dm_tor)|6451|6451|19|0.2%|1.4%|
[bm_tor](#bm_tor)|6433|6433|19|0.2%|1.4%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|19|0.0%|1.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|233|233|11|4.7%|0.8%|
[nixspam](#nixspam)|20758|20758|8|0.0%|0.6%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.3%|
[php_commenters](#php_commenters)|281|281|5|1.7%|0.3%|
[php_bad](#php_bad)|281|281|5|1.7%|0.3%|
[openbl_90d](#openbl_90d)|9846|9846|5|0.0%|0.3%|
[openbl](#openbl)|9846|9846|5|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7743|7743|3|0.0%|0.2%|
[xroxy](#xroxy)|1916|1916|1|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4579|4579|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1699|1699|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4426|4426|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2401|2401|1|0.0%|0.0%|
[et_block](#et_block)|904|18056697|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2350|2350|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3461|3461|1|0.0%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Fri May 29 09:42:10 UTC 2015.

The ipset `blocklist_de_ftp` has **367** entries, **367** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22183|22183|367|1.6%|100.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|28|0.0%|7.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|23|0.0%|6.2%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|18|0.0%|4.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|11|0.0%|2.9%|
[openbl_90d](#openbl_90d)|9846|9846|10|0.1%|2.7%|
[openbl](#openbl)|9846|9846|10|0.1%|2.7%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|9|0.0%|2.4%|
[openbl_60d](#openbl_60d)|7743|7743|8|0.1%|2.1%|
[nixspam](#nixspam)|20758|20758|5|0.0%|1.3%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|4|0.0%|1.0%|
[php_harvesters](#php_harvesters)|257|257|3|1.1%|0.8%|
[openbl_30d](#openbl_30d)|4426|4426|3|0.0%|0.8%|
[openbl_7d](#openbl_7d)|988|988|2|0.2%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|233|233|2|0.8%|0.5%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|1|0.0%|0.2%|
[openbl_1d](#openbl_1d)|357|357|1|0.2%|0.2%|
[dshield](#dshield)|20|5120|1|0.0%|0.2%|
[ciarmy](#ciarmy)|345|345|1|0.2%|0.2%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Fri May 29 09:56:07 UTC 2015.

The ipset `blocklist_de_imap` has **775** entries, **775** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22183|22183|764|3.4%|98.5%|
[blocklist_de_mail](#blocklist_de_mail)|14650|14650|763|5.2%|98.4%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|61|0.0%|7.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|56|0.0%|7.2%|
[openbl_90d](#openbl_90d)|9846|9846|50|0.5%|6.4%|
[openbl](#openbl)|9846|9846|50|0.5%|6.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|47|0.0%|6.0%|
[openbl_60d](#openbl_60d)|7743|7743|45|0.5%|5.8%|
[openbl_30d](#openbl_30d)|4426|4426|41|0.9%|5.2%|
[openbl_7d](#openbl_7d)|988|988|24|2.4%|3.0%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|16|0.0%|2.0%|
[et_block](#et_block)|904|18056697|16|0.0%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|14|0.0%|1.8%|
[et_compromised](#et_compromised)|2401|2401|13|0.5%|1.6%|
[bruteforceblocker](#bruteforceblocker)|2350|2350|11|0.4%|1.4%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|7|0.0%|0.9%|
[openbl_1d](#openbl_1d)|357|357|7|1.9%|0.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|2|0.0%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|233|233|2|0.8%|0.2%|
[voipbl](#voipbl)|10303|10775|1|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.1%|
[nixspam](#nixspam)|20758|20758|1|0.0%|0.1%|
[ciarmy](#ciarmy)|345|345|1|0.2%|0.1%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Fri May 29 09:42:07 UTC 2015.

The ipset `blocklist_de_mail` has **14650** entries, **14650** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22183|22183|14650|66.0%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|12618|12618|11059|87.6%|75.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2287|0.0%|15.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|1343|0.0%|9.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1165|0.0%|7.9%|
[blocklist_de_imap](#blocklist_de_imap)|775|775|763|98.4%|5.2%|
[nixspam](#nixspam)|20758|20758|400|1.9%|2.7%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|198|0.2%|1.3%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|155|2.0%|1.0%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|95|0.3%|0.6%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|76|0.0%|0.5%|
[openbl_90d](#openbl_90d)|9846|9846|58|0.5%|0.3%|
[openbl](#openbl)|9846|9846|58|0.5%|0.3%|
[php_dictionary](#php_dictionary)|433|433|55|12.7%|0.3%|
[openbl_60d](#openbl_60d)|7743|7743|53|0.6%|0.3%|
[openbl_30d](#openbl_30d)|4426|4426|47|1.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7864|7864|46|0.5%|0.3%|
[xroxy](#xroxy)|1916|1916|43|2.2%|0.2%|
[php_spammers](#php_spammers)|417|417|40|9.5%|0.2%|
[ri_web_proxies](#ri_web_proxies)|4579|4579|26|0.5%|0.1%|
[openbl_7d](#openbl_7d)|988|988|26|2.6%|0.1%|
[php_commenters](#php_commenters)|281|281|22|7.8%|0.1%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|21|0.0%|0.1%|
[php_bad](#php_bad)|281|281|21|7.4%|0.1%|
[et_block](#et_block)|904|18056697|21|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|233|233|19|8.1%|0.1%|
[et_compromised](#et_compromised)|2401|2401|16|0.6%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3461|3461|16|0.4%|0.1%|
[bruteforceblocker](#bruteforceblocker)|2350|2350|14|0.5%|0.0%|
[openbl_1d](#openbl_1d)|357|357|7|1.9%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|4|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|4|1.5%|0.0%|
[voipbl](#voipbl)|10303|10775|3|0.0%|0.0%|
[proxyrss](#proxyrss)|1699|1699|2|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.0%|
[et_tor](#et_tor)|6360|6360|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6451|6451|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6433|6433|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2078|2078|2|0.0%|0.0%|
[shunlist](#shunlist)|51|51|1|1.9%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1759|1759|1|0.0%|0.0%|
[proxz](#proxz)|123|123|1|0.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[ciarmy](#ciarmy)|345|345|1|0.2%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Fri May 29 09:42:11 UTC 2015.

The ipset `blocklist_de_sip` has **89** entries, **89** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22183|22183|70|0.3%|78.6%|
[voipbl](#voipbl)|10303|10775|28|0.2%|31.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|21|0.0%|23.5%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|20|0.0%|22.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7|0.0%|7.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|4|0.0%|4.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|2.2%|
[et_botnet](#et_botnet)|505|505|1|0.1%|1.1%|
[ciarmy](#ciarmy)|345|345|1|0.2%|1.1%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Fri May 29 09:56:03 UTC 2015.

The ipset `blocklist_de_ssh` has **2078** entries, **2078** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22183|22183|2072|9.3%|99.7%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|1243|0.7%|59.8%|
[openbl_90d](#openbl_90d)|9846|9846|1160|11.7%|55.8%|
[openbl](#openbl)|9846|9846|1160|11.7%|55.8%|
[openbl_60d](#openbl_60d)|7743|7743|1116|14.4%|53.7%|
[openbl_30d](#openbl_30d)|4426|4426|1043|23.5%|50.1%|
[bruteforceblocker](#bruteforceblocker)|2350|2350|1008|42.8%|48.5%|
[et_compromised](#et_compromised)|2401|2401|975|40.6%|46.9%|
[openbl_7d](#openbl_7d)|988|988|622|62.9%|29.9%|
[openbl_1d](#openbl_1d)|357|357|223|62.4%|10.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|205|0.0%|9.8%|
[dshield](#dshield)|20|5120|122|2.3%|5.8%|
[et_block](#et_block)|904|18056697|117|0.0%|5.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|116|0.0%|5.5%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|113|0.0%|5.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|233|233|79|33.9%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|46|0.0%|2.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.5%|
[shunlist](#shunlist)|51|51|8|15.6%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|7|0.0%|0.3%|
[voipbl](#voipbl)|10303|10775|4|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|3|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14650|14650|2|0.0%|0.0%|
[zeus](#zeus)|267|267|1|0.3%|0.0%|
[xroxy](#xroxy)|1916|1916|1|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7864|7864|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1699|1699|1|0.0%|0.0%|
[nixspam](#nixspam)|20758|20758|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[ciarmy](#ciarmy)|345|345|1|0.2%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Fri May 29 09:56:10 UTC 2015.

The ipset `blocklist_de_strongips` has **233** entries, **233** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22183|22183|233|1.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|128|0.1%|54.9%|
[blocklist_de_bots](#blocklist_de_bots)|3461|3461|128|3.6%|54.9%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|119|0.3%|51.0%|
[stopforumspam_1d](#stopforumspam_1d)|7864|7864|110|1.3%|47.2%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|88|0.0%|37.7%|
[openbl_90d](#openbl_90d)|9846|9846|80|0.8%|34.3%|
[openbl](#openbl)|9846|9846|80|0.8%|34.3%|
[openbl_60d](#openbl_60d)|7743|7743|79|1.0%|33.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|2078|2078|79|3.8%|33.9%|
[openbl_30d](#openbl_30d)|4426|4426|77|1.7%|33.0%|
[openbl_7d](#openbl_7d)|988|988|76|7.6%|32.6%|
[openbl_1d](#openbl_1d)|357|357|70|19.6%|30.0%|
[blocklist_de_apache](#blocklist_de_apache)|12618|12618|37|0.2%|15.8%|
[dshield](#dshield)|20|5120|34|0.6%|14.5%|
[php_commenters](#php_commenters)|281|281|33|11.7%|14.1%|
[php_bad](#php_bad)|281|281|33|11.7%|14.1%|
[et_compromised](#et_compromised)|2401|2401|23|0.9%|9.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|19|0.0%|8.1%|
[blocklist_de_mail](#blocklist_de_mail)|14650|14650|19|0.1%|8.1%|
[bruteforceblocker](#bruteforceblocker)|2350|2350|17|0.7%|7.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1324|1324|11|0.8%|4.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8|0.0%|3.4%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|7|0.0%|3.0%|
[et_block](#et_block)|904|18056697|7|0.0%|3.0%|
[xroxy](#xroxy)|1916|1916|6|0.3%|2.5%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|6|0.0%|2.5%|
[php_spammers](#php_spammers)|417|417|5|1.1%|2.1%|
[proxyrss](#proxyrss)|1699|1699|4|0.2%|1.7%|
[ri_web_proxies](#ri_web_proxies)|4579|4579|3|0.0%|1.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.2%|
[nixspam](#nixspam)|20758|20758|2|0.0%|0.8%|
[blocklist_de_imap](#blocklist_de_imap)|775|775|2|0.2%|0.8%|
[blocklist_de_ftp](#blocklist_de_ftp)|367|367|2|0.5%|0.8%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|1|0.0%|0.4%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.4%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.4%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Fri May 29 10:00:13 UTC 2015.

The ipset `bm_tor` has **6433** entries, **6433** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[dm_tor](#dm_tor)|6451|6451|6375|98.8%|99.0%|
[et_tor](#et_tor)|6360|6360|5730|90.0%|89.0%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|1040|13.5%|16.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|614|0.0%|9.5%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|591|0.6%|9.1%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|456|1.4%|7.0%|
[stopforumspam_1d](#stopforumspam_1d)|7864|7864|335|4.2%|5.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|184|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|176|47.3%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|164|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|44|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[php_bad](#php_bad)|281|281|29|10.3%|0.4%|
[openbl_90d](#openbl_90d)|9846|9846|21|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7743|7743|21|0.2%|0.3%|
[openbl](#openbl)|9846|9846|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|12618|12618|21|0.1%|0.3%|
[blocklist_de](#blocklist_de)|22183|22183|21|0.0%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1324|1324|19|1.4%|0.2%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4579|4579|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|904|18056697|3|0.0%|0.0%|
[xroxy](#xroxy)|1916|1916|2|0.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1759|1759|2|0.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14650|14650|2|0.0%|0.0%|
[voipbl](#voipbl)|10303|10775|1|0.0%|0.0%|
[proxz](#proxz)|123|123|1|0.8%|0.0%|
[nixspam](#nixspam)|20758|20758|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|

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
[fullbogons](#fullbogons)|3656|670639576|592708608|88.3%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|4194304|3.0%|0.7%|
[voipbl](#voipbl)|10303|10775|351|3.2%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|5|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2350|2350|1|0.0%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD)

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Fri May 29 08:45:08 UTC 2015.

The ipset `bruteforceblocker` has **2350** entries, **2350** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_compromised](#et_compromised)|2401|2401|2284|95.1%|97.1%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|1478|0.8%|62.8%|
[openbl_90d](#openbl_90d)|9846|9846|1413|14.3%|60.1%|
[openbl](#openbl)|9846|9846|1413|14.3%|60.1%|
[openbl_60d](#openbl_60d)|7743|7743|1397|18.0%|59.4%|
[openbl_30d](#openbl_30d)|4426|4426|1335|30.1%|56.8%|
[blocklist_de](#blocklist_de)|22183|22183|1032|4.6%|43.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|2078|2078|1008|48.5%|42.8%|
[openbl_7d](#openbl_7d)|988|988|511|51.7%|21.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|227|0.0%|9.6%|
[openbl_1d](#openbl_1d)|357|357|198|55.4%|8.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|139|0.0%|5.9%|
[et_block](#et_block)|904|18056697|103|0.0%|4.3%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|102|0.0%|4.3%|
[dshield](#dshield)|20|5120|91|1.7%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|71|0.0%|3.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|233|233|17|7.2%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|14650|14650|14|0.0%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|775|775|11|1.4%|0.4%|
[shunlist](#shunlist)|51|51|9|17.6%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|6|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|3|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12618|12618|3|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7864|7864|2|0.0%|0.0%|
[proxyrss](#proxyrss)|1699|1699|2|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[zeus](#zeus)|267|267|1|0.3%|0.0%|
[xroxy](#xroxy)|1916|1916|1|0.0%|0.0%|
[voipbl](#voipbl)|10303|10775|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|1|0.0%|0.0%|
[proxz](#proxz)|123|123|1|0.8%|0.0%|
[fullbogons](#fullbogons)|3656|670639576|1|0.0%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1324|1324|1|0.0%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Fri May 29 07:15:15 UTC 2015.

The ipset `ciarmy` has **345** entries, **345** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|174512|174512|342|0.1%|99.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|62|0.0%|17.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|28|0.0%|8.1%|
[blocklist_de](#blocklist_de)|22183|22183|27|0.1%|7.8%|
[blocklist_de_apache](#blocklist_de_apache)|12618|12618|23|0.1%|6.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|17|0.0%|4.9%|
[voipbl](#voipbl)|10303|10775|4|0.0%|1.1%|
[dshield](#dshield)|20|5120|3|0.0%|0.8%|
[shunlist](#shunlist)|51|51|2|3.9%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|1|0.0%|0.2%|
[openbl_90d](#openbl_90d)|9846|9846|1|0.0%|0.2%|
[openbl_7d](#openbl_7d)|988|988|1|0.1%|0.2%|
[openbl_60d](#openbl_60d)|7743|7743|1|0.0%|0.2%|
[openbl_30d](#openbl_30d)|4426|4426|1|0.0%|0.2%|
[openbl](#openbl)|9846|9846|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2078|2078|1|0.0%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|89|89|1|1.1%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|14650|14650|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|775|775|1|0.1%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|367|367|1|0.2%|0.2%|

## cleanmx_viruses

[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses

Source is downloaded from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive).

The last time downloaded was found to be dated: Fri May 29 04:45:58 UTC 2015.

The ipset `cleanmx_viruses` has **91** entries, **91** unique IPs.

The following table shows the overlaps of `cleanmx_viruses` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `cleanmx_viruses`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `cleanmx_viruses`.
- ` this % ` is the percentage **of this ipset (`cleanmx_viruses`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14|0.0%|15.3%|
[malc0de](#malc0de)|411|411|9|2.1%|9.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8|0.0%|8.7%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|2.1%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|2|0.0%|2.1%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|1.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|1|0.0%|1.0%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Fri May 29 10:00:10 UTC 2015.

The ipset `dm_tor` has **6451** entries, **6451** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6433|6433|6375|99.0%|98.8%|
[et_tor](#et_tor)|6360|6360|5721|89.9%|88.6%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|1039|13.5%|16.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|616|0.0%|9.5%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|589|0.6%|9.1%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|455|1.4%|7.0%|
[stopforumspam_1d](#stopforumspam_1d)|7864|7864|334|4.2%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|184|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|175|47.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|164|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|44|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[php_bad](#php_bad)|281|281|29|10.3%|0.4%|
[openbl_90d](#openbl_90d)|9846|9846|21|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7743|7743|21|0.2%|0.3%|
[openbl](#openbl)|9846|9846|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|12618|12618|21|0.1%|0.3%|
[blocklist_de](#blocklist_de)|22183|22183|21|0.0%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1324|1324|19|1.4%|0.2%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4579|4579|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|904|18056697|3|0.0%|0.0%|
[xroxy](#xroxy)|1916|1916|2|0.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1759|1759|2|0.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14650|14650|2|0.0%|0.0%|
[voipbl](#voipbl)|10303|10775|1|0.0%|0.0%|
[proxz](#proxz)|123|123|1|0.8%|0.0%|
[nixspam](#nixspam)|20758|20758|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Fri May 29 06:55:57 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|174512|174512|3853|2.2%|75.2%|
[et_block](#et_block)|904|18056697|768|0.0%|15.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|512|0.0%|10.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|260|0.0%|5.0%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|256|0.0%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|256|0.0%|5.0%|
[openbl_90d](#openbl_90d)|9846|9846|168|1.7%|3.2%|
[openbl](#openbl)|9846|9846|168|1.7%|3.2%|
[openbl_60d](#openbl_60d)|7743|7743|158|2.0%|3.0%|
[openbl_30d](#openbl_30d)|4426|4426|133|3.0%|2.5%|
[blocklist_de](#blocklist_de)|22183|22183|125|0.5%|2.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|2078|2078|122|5.8%|2.3%|
[bruteforceblocker](#bruteforceblocker)|2350|2350|91|3.8%|1.7%|
[openbl_7d](#openbl_7d)|988|988|90|9.1%|1.7%|
[et_compromised](#et_compromised)|2401|2401|86|3.5%|1.6%|
[openbl_1d](#openbl_1d)|357|357|45|12.6%|0.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|233|233|34|14.5%|0.6%|
[ciarmy](#ciarmy)|345|345|3|0.8%|0.0%|
[voipbl](#voipbl)|10303|10775|2|0.0%|0.0%|
[malc0de](#malc0de)|411|411|2|0.4%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12618|12618|2|0.0%|0.0%|
[nixspam](#nixspam)|20758|20758|1|0.0%|0.0%|
[et_tor](#et_tor)|6360|6360|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6451|6451|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6433|6433|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|367|367|1|0.2%|0.0%|

## et_block

[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)

Source is downloaded from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt).

The last time downloaded was found to be dated: Thu May 28 04:30:01 UTC 2015.

The ipset `et_block` has **904** entries, **18056697** unique IPs.

The following table shows the overlaps of `et_block` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_block`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_block`.
- ` this % ` is the percentage **of this ipset (`et_block`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[spamhaus_drop](#spamhaus_drop)|639|17921280|17920256|99.9%|99.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8401954|2.4%|46.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7211008|78.5%|39.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|2133269|0.2%|11.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|195924|0.1%|1.0%|
[fullbogons](#fullbogons)|3656|670639576|20480|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|5013|2.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1038|0.3%|0.0%|
[dshield](#dshield)|20|5120|768|15.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|759|0.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|517|0.1%|0.0%|
[openbl_90d](#openbl_90d)|9846|9846|450|4.5%|0.0%|
[openbl](#openbl)|9846|9846|450|4.5%|0.0%|
[zeus](#zeus)|267|267|262|98.1%|0.0%|
[openbl_60d](#openbl_60d)|7743|7743|259|3.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|229|2.9%|0.0%|
[zeus_badips](#zeus_badips)|230|230|228|99.1%|0.0%|
[nixspam](#nixspam)|20758|20758|216|1.0%|0.0%|
[openbl_30d](#openbl_30d)|4426|4426|208|4.6%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|205|0.6%|0.0%|
[blocklist_de](#blocklist_de)|22183|22183|195|0.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2078|2078|117|5.6%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2350|2350|103|4.3%|0.0%|
[et_compromised](#et_compromised)|2401|2401|98|4.0%|0.0%|
[openbl_7d](#openbl_7d)|988|988|83|8.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7864|7864|56|0.7%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3461|3461|54|1.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|28|2.1%|0.0%|
[openbl_1d](#openbl_1d)|357|357|26|7.2%|0.0%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.0%|
[php_bad](#php_bad)|281|281|24|8.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14650|14650|21|0.1%|0.0%|
[voipbl](#voipbl)|10303|10775|19|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|775|775|16|2.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|233|233|7|3.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[sslbl](#sslbl)|345|345|3|0.8%|0.0%|
[et_tor](#et_tor)|6360|6360|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6451|6451|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6433|6433|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12618|12618|3|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[malc0de](#malc0de)|411|411|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[et_botnet](#et_botnet)|505|505|1|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1324|1324|1|0.0%|0.0%|

## et_botnet

[EmergingThreats.net](http://www.emergingthreats.net/) botnet IPs

Source is downloaded from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules).

The last time downloaded was found to be dated: Thu May 28 04:30:01 UTC 2015.

The ipset `et_botnet` has **505** entries, **505** unique IPs.

The following table shows the overlaps of `et_botnet` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_botnet`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_botnet`.
- ` this % ` is the percentage **of this ipset (`et_botnet`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|74|0.0%|14.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|41|0.0%|8.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|21|0.0%|4.1%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|3|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[et_block](#et_block)|904|18056697|1|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|89|89|1|1.1%|0.1%|

## et_compromised

[EmergingThreats.net](http://www.emergingthreats.net/) compromised hosts (seems to be a derivate of other lists)

Source is downloaded from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt).

The last time downloaded was found to be dated: Thu May 28 04:30:09 UTC 2015.

The ipset `et_compromised` has **2401** entries, **2401** unique IPs.

The following table shows the overlaps of `et_compromised` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_compromised`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_compromised`.
- ` this % ` is the percentage **of this ipset (`et_compromised`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bruteforceblocker](#bruteforceblocker)|2350|2350|2284|97.1%|95.1%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|1502|0.8%|62.5%|
[openbl_90d](#openbl_90d)|9846|9846|1429|14.5%|59.5%|
[openbl](#openbl)|9846|9846|1429|14.5%|59.5%|
[openbl_60d](#openbl_60d)|7743|7743|1413|18.2%|58.8%|
[openbl_30d](#openbl_30d)|4426|4426|1344|30.3%|55.9%|
[blocklist_de](#blocklist_de)|22183|22183|1001|4.5%|41.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|2078|2078|975|46.9%|40.6%|
[openbl_7d](#openbl_7d)|988|988|502|50.8%|20.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|230|0.0%|9.5%|
[openbl_1d](#openbl_1d)|357|357|204|57.1%|8.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|148|0.0%|6.1%|
[et_block](#et_block)|904|18056697|98|0.0%|4.0%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|97|0.0%|4.0%|
[dshield](#dshield)|20|5120|86|1.6%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|74|0.0%|3.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|233|233|23|9.8%|0.9%|
[blocklist_de_mail](#blocklist_de_mail)|14650|14650|16|0.1%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|775|775|13|1.6%|0.5%|
[shunlist](#shunlist)|51|51|9|17.6%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|6|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|3|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12618|12618|3|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7864|7864|2|0.0%|0.0%|
[proxyrss](#proxyrss)|1699|1699|2|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[zeus](#zeus)|267|267|1|0.3%|0.0%|
[xroxy](#xroxy)|1916|1916|1|0.0%|0.0%|
[voipbl](#voipbl)|10303|10775|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|1|0.0%|0.0%|
[proxz](#proxz)|123|123|1|0.8%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1324|1324|1|0.0%|0.0%|

## et_tor

[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs

Source is downloaded from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules).

The last time downloaded was found to be dated: Thu May 28 04:30:09 UTC 2015.

The ipset `et_tor` has **6360** entries, **6360** unique IPs.

The following table shows the overlaps of `et_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_tor`.
- ` this % ` is the percentage **of this ipset (`et_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6433|6433|5730|89.0%|90.0%|
[dm_tor](#dm_tor)|6451|6451|5721|88.6%|89.9%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|1068|13.9%|16.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|607|0.0%|9.5%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|601|0.6%|9.4%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|465|1.5%|7.3%|
[stopforumspam_1d](#stopforumspam_1d)|7864|7864|337|4.2%|5.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|182|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|178|47.8%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|166|0.0%|2.6%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|45|0.0%|0.7%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[php_bad](#php_bad)|281|281|29|10.3%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|12618|12618|22|0.1%|0.3%|
[blocklist_de](#blocklist_de)|22183|22183|22|0.0%|0.3%|
[openbl_90d](#openbl_90d)|9846|9846|21|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7743|7743|21|0.2%|0.3%|
[openbl](#openbl)|9846|9846|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1324|1324|20|1.5%|0.3%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4579|4579|5|0.1%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|904|18056697|3|0.0%|0.0%|
[xroxy](#xroxy)|1916|1916|2|0.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1759|1759|2|0.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14650|14650|2|0.0%|0.0%|
[voipbl](#voipbl)|10303|10775|1|0.0%|0.0%|
[proxz](#proxz)|123|123|1|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Fri May 29 10:00:28 UTC 2015.

The ipset `feodo` has **67** entries, **67** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[snort_ipfilter](#snort_ipfilter)|7652|7652|53|0.6%|79.1%|
[sslbl](#sslbl)|345|345|24|6.9%|35.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|4|0.0%|5.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|3|0.0%|4.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|3|0.0%|4.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|1.4%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|1|0.0%|1.4%|

## fullbogons

[Team-Cymru.org](http://www.team-cymru.org) IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user - **excellent list - use it only your internet interface**

Source is downloaded from [this link](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt).

The last time downloaded was found to be dated: Fri May 29 09:35:09 UTC 2015.

The ipset `fullbogons` has **3656** entries, **670639576** unique IPs.

The following table shows the overlaps of `fullbogons` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `fullbogons`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `fullbogons`.
- ` this % ` is the percentage **of this ipset (`fullbogons`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bogons](#bogons)|13|592708608|592708608|100.0%|88.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|4233775|3.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|565248|6.1%|0.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|248319|0.0%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|234895|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|20480|0.1%|0.0%|
[et_block](#et_block)|904|18056697|20480|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|890|0.2%|0.0%|
[voipbl](#voipbl)|10303|10775|351|3.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|33|2.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|9|0.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2350|2350|1|0.0%|0.0%|

## ib_bluetack_badpeers

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) IPs that have been reported for bad deeds in p2p

Source is downloaded from [this link](http://list.iblocklist.com/?list=cwworuawihqvocglcoss&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Fri May 29 03:30:40 UTC 2015.

The ipset `ib_bluetack_badpeers` has **48134** entries, **48134** unique IPs.

The following table shows the overlaps of `ib_bluetack_badpeers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_badpeers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_badpeers`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_badpeers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1172|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|432|0.0%|0.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|230|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|16|0.0%|0.0%|
[fullbogons](#fullbogons)|3656|670639576|14|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|14|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.0%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|6|0.0%|0.0%|
[nixspam](#nixspam)|20758|20758|6|0.0%|0.0%|
[et_block](#et_block)|904|18056697|6|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[xroxy](#xroxy)|1916|1916|3|0.1%|0.0%|
[voipbl](#voipbl)|10303|10775|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7864|7864|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4579|4579|1|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14650|14650|1|0.0%|0.0%|
[blocklist_de](#blocklist_de)|22183|22183|1|0.0%|0.0%|

## ib_bluetack_hijacked

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) hijacked IP-Blocks Hijacked IP space are IP blocks that are being used without permission

Source is downloaded from [this link](http://list.iblocklist.com/?list=usrcshglbiilevmyfhse&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Fri May 29 04:00:04 UTC 2015.

The ipset `ib_bluetack_hijacked` has **535** entries, **9177856** unique IPs.

The following table shows the overlaps of `ib_bluetack_hijacked` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_hijacked`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_hijacked`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_hijacked`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|904|18056697|7211008|39.9%|78.5%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|7079936|39.5%|77.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2526625|0.7%|27.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|904796|0.1%|9.8%|
[fullbogons](#fullbogons)|3656|670639576|565248|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|145472|0.1%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1036|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|745|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|518|0.2%|0.0%|
[nixspam](#nixspam)|20758|20758|215|1.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|194|0.6%|0.0%|
[blocklist_de](#blocklist_de)|22183|22183|74|0.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3461|3461|54|1.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7864|7864|50|0.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|27|2.1%|0.0%|
[openbl_90d](#openbl_90d)|9846|9846|19|0.1%|0.0%|
[openbl](#openbl)|9846|9846|19|0.1%|0.0%|
[openbl_60d](#openbl_60d)|7743|7743|18|0.2%|0.0%|
[openbl_30d](#openbl_30d)|4426|4426|13|0.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|11|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2078|2078|11|0.5%|0.0%|
[zeus_badips](#zeus_badips)|230|230|10|4.3%|0.0%|
[zeus](#zeus)|267|267|10|3.7%|0.0%|
[openbl_7d](#openbl_7d)|988|988|10|1.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14650|14650|7|0.0%|0.0%|
[openbl_1d](#openbl_1d)|357|357|5|1.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2350|2350|5|0.2%|0.0%|
[et_compromised](#et_compromised)|2401|2401|4|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|775|775|4|0.5%|0.0%|
[et_tor](#et_tor)|6360|6360|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6451|6451|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6433|6433|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|233|233|3|1.2%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12618|12618|2|0.0%|0.0%|
[voipbl](#voipbl)|10303|10775|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.0%|
[php_bad](#php_bad)|281|281|1|0.3%|0.0%|
[et_botnet](#et_botnet)|505|505|1|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1324|1324|1|0.0%|0.0%|

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
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|16316979|4.6%|2.1%|
[et_block](#et_block)|904|18056697|2133269|11.8%|0.2%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|2133002|11.9%|0.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1359935|0.9%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904796|9.8%|0.1%|
[fullbogons](#fullbogons)|3656|670639576|234895|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|33155|7.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|13269|3.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|4751|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|1527|1.6%|0.0%|
[blocklist_de](#blocklist_de)|22183|22183|1487|6.7%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14650|14650|1343|9.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12618|12618|1322|10.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|580|1.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|432|0.8%|0.0%|
[nixspam](#nixspam)|20758|20758|310|1.4%|0.0%|
[voipbl](#voipbl)|10303|10775|301|2.7%|0.0%|
[dshield](#dshield)|20|5120|260|5.0%|0.0%|
[openbl_90d](#openbl_90d)|9846|9846|218|2.2%|0.0%|
[openbl](#openbl)|9846|9846|218|2.2%|0.0%|
[openbl_60d](#openbl_60d)|7743|7743|179|2.3%|0.0%|
[et_tor](#et_tor)|6360|6360|166|2.6%|0.0%|
[dm_tor](#dm_tor)|6451|6451|164|2.5%|0.0%|
[bm_tor](#bm_tor)|6433|6433|164|2.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7864|7864|153|1.9%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4579|4579|107|2.3%|0.0%|
[openbl_30d](#openbl_30d)|4426|4426|100|2.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|98|6.7%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|86|1.1%|0.0%|
[et_compromised](#et_compromised)|2401|2401|74|3.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2350|2350|71|3.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|66|5.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1759|1759|62|3.5%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|58|8.6%|0.0%|
[xroxy](#xroxy)|1916|1916|52|2.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2078|2078|46|2.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3461|3461|44|1.2%|0.0%|
[proxyrss](#proxyrss)|1699|1699|42|2.4%|0.0%|
[et_botnet](#et_botnet)|505|505|41|8.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1324|1324|29|2.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|17|4.5%|0.0%|
[ciarmy](#ciarmy)|345|345|17|4.9%|0.0%|
[openbl_7d](#openbl_7d)|988|988|15|1.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|775|775|14|1.8%|0.0%|
[malc0de](#malc0de)|411|411|12|2.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|367|367|11|2.9%|0.0%|
[php_dictionary](#php_dictionary)|433|433|9|2.0%|0.0%|
[zeus](#zeus)|267|267|8|2.9%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[openbl_1d](#openbl_1d)|357|357|7|1.9%|0.0%|
[proxz](#proxz)|123|123|5|4.0%|0.0%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.0%|
[php_commenters](#php_commenters)|281|281|5|1.7%|0.0%|
[php_bad](#php_bad)|281|281|5|1.7%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[zeus_badips](#zeus_badips)|230|230|4|1.7%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|89|89|4|4.4%|0.0%|
[sslbl](#sslbl)|345|345|3|0.8%|0.0%|
[feodo](#feodo)|67|67|3|4.4%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|91|91|1|1.0%|0.0%|

## ib_bluetack_level2

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 2 (for use in p2p). General corporate ranges. Ranges used by labs or researchers. Proxies.

Source is downloaded from [this link](http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Fri May 29 04:01:54 UTC 2015.

The ipset `ib_bluetack_level2` has **72774** entries, **348707599** unique IPs.

The following table shows the overlaps of `ib_bluetack_level2` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level2`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level2`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level2`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|16316979|2.1%|4.6%|
[et_block](#et_block)|904|18056697|8401954|46.5%|2.4%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|8401434|46.8%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2830140|2.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2526625|27.5%|0.7%|
[fullbogons](#fullbogons)|3656|670639576|248319|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|33368|7.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|7874|4.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|7733|2.2%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|2490|2.6%|0.0%|
[blocklist_de](#blocklist_de)|22183|22183|1444|6.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14650|14650|1165|7.9%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12618|12618|1075|8.5%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|904|2.9%|0.0%|
[nixspam](#nixspam)|20758|20758|560|2.6%|0.0%|
[openbl_90d](#openbl_90d)|9846|9846|507|5.1%|0.0%|
[openbl](#openbl)|9846|9846|507|5.1%|0.0%|
[voipbl](#voipbl)|10303|10775|428|3.9%|0.0%|
[openbl_60d](#openbl_60d)|7743|7743|361|4.6%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7864|7864|262|3.3%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|230|0.4%|0.0%|
[openbl_30d](#openbl_30d)|4426|4426|224|5.0%|0.0%|
[dm_tor](#dm_tor)|6451|6451|184|2.8%|0.0%|
[bm_tor](#bm_tor)|6433|6433|184|2.8%|0.0%|
[et_tor](#et_tor)|6360|6360|182|2.8%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4579|4579|163|3.5%|0.0%|
[et_compromised](#et_compromised)|2401|2401|148|6.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2350|2350|139|5.9%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2078|2078|116|5.5%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|112|1.4%|0.0%|
[xroxy](#xroxy)|1916|1916|88|4.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3461|3461|80|2.3%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1759|1759|76|4.3%|0.0%|
[proxyrss](#proxyrss)|1699|1699|66|3.8%|0.0%|
[openbl_7d](#openbl_7d)|988|988|52|5.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|775|775|47|6.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|45|3.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1324|1324|41|3.0%|0.0%|
[php_spammers](#php_spammers)|417|417|31|7.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|28|4.1%|0.0%|
[ciarmy](#ciarmy)|345|345|28|8.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|367|367|28|7.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|26|2.0%|0.0%|
[malc0de](#malc0de)|411|411|26|6.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|21|5.6%|0.0%|
[et_botnet](#et_botnet)|505|505|21|4.1%|0.0%|
[openbl_1d](#openbl_1d)|357|357|17|4.7%|0.0%|
[php_dictionary](#php_dictionary)|433|433|10|2.3%|0.0%|
[zeus](#zeus)|267|267|9|3.3%|0.0%|
[php_commenters](#php_commenters)|281|281|9|3.2%|0.0%|
[php_bad](#php_bad)|281|281|9|3.2%|0.0%|
[zeus_badips](#zeus_badips)|230|230|8|3.4%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|91|91|8|8.7%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|233|233|8|3.4%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|89|89|7|7.8%|0.0%|
[sslbl](#sslbl)|345|345|6|1.7%|0.0%|
[proxz](#proxz)|123|123|6|4.8%|0.0%|
[shunlist](#shunlist)|51|51|3|5.8%|0.0%|
[palevo](#palevo)|13|13|3|23.0%|0.0%|
[feodo](#feodo)|67|67|3|4.4%|0.0%|

## ib_bluetack_level3

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 3 (for use in p2p). Many portal-type websites. ISP ranges that may be dodgy for some reason. Ranges that belong to an individual, but which have not been determined to be used by a particular company. Ranges for things that are unusual in some way. The L3 list is aka the paranoid list.

Source is downloaded from [this link](http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Fri May 29 04:00:48 UTC 2015.

The ipset `ib_bluetack_level3` has **17802** entries, **139104824** unique IPs.

The following table shows the overlaps of `ib_bluetack_level3` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level3`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level3`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level3`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[fullbogons](#fullbogons)|3656|670639576|4233775|0.6%|3.0%|
[bogons](#bogons)|13|592708608|4194304|0.7%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2830140|0.8%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|1359935|0.1%|0.9%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|270785|64.3%|0.1%|
[et_block](#et_block)|904|18056697|195924|1.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|195904|1.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|15165|8.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|9231|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|6195|6.6%|0.0%|
[blocklist_de](#blocklist_de)|22183|22183|2818|12.7%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14650|14650|2287|15.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12618|12618|2199|17.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|2103|6.7%|0.0%|
[voipbl](#voipbl)|10303|10775|1588|14.7%|0.0%|
[nixspam](#nixspam)|20758|20758|1282|6.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1172|2.4%|0.0%|
[openbl_90d](#openbl_90d)|9846|9846|948|9.6%|0.0%|
[openbl](#openbl)|9846|9846|948|9.6%|0.0%|
[openbl_60d](#openbl_60d)|7743|7743|720|9.2%|0.0%|
[dm_tor](#dm_tor)|6451|6451|616|9.5%|0.0%|
[bm_tor](#bm_tor)|6433|6433|614|9.5%|0.0%|
[et_tor](#et_tor)|6360|6360|607|9.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7864|7864|513|6.5%|0.0%|
[dshield](#dshield)|20|5120|512|10.0%|0.0%|
[openbl_30d](#openbl_30d)|4426|4426|441|9.9%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|237|3.0%|0.0%|
[et_compromised](#et_compromised)|2401|2401|230|9.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2350|2350|227|9.6%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2078|2078|205|9.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3461|3461|157|4.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|146|11.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4579|4579|143|3.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|125|33.6%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1324|1324|111|8.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|110|7.5%|0.0%|
[openbl_7d](#openbl_7d)|988|988|93|9.4%|0.0%|
[malc0de](#malc0de)|411|411|76|18.4%|0.0%|
[et_botnet](#et_botnet)|505|505|74|14.6%|0.0%|
[xroxy](#xroxy)|1916|1916|73|3.8%|0.0%|
[ciarmy](#ciarmy)|345|345|62|17.9%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|775|775|56|7.2%|0.0%|
[proxyrss](#proxyrss)|1699|1699|51|3.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|51|7.5%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1759|1759|41|2.3%|0.0%|
[php_spammers](#php_spammers)|417|417|26|6.2%|0.0%|
[php_dictionary](#php_dictionary)|433|433|24|5.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|367|367|23|6.2%|0.0%|
[sslbl](#sslbl)|345|345|22|6.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|89|89|21|23.5%|0.0%|
[openbl_1d](#openbl_1d)|357|357|20|5.6%|0.0%|
[zeus](#zeus)|267|267|19|7.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|233|233|19|8.1%|0.0%|
[proxz](#proxz)|123|123|16|13.0%|0.0%|
[php_bad](#php_bad)|281|281|16|5.6%|0.0%|
[php_harvesters](#php_harvesters)|257|257|15|5.8%|0.0%|
[php_commenters](#php_commenters)|281|281|15|5.3%|0.0%|
[zeus_badips](#zeus_badips)|230|230|14|6.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|91|91|14|15.3%|0.0%|
[shunlist](#shunlist)|51|51|4|7.8%|0.0%|
[feodo](#feodo)|67|67|4|5.9%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|

## ib_bluetack_proxies

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Open Proxies IPs list (without TOR)

Source is downloaded from [this link](http://list.iblocklist.com/?list=xoebmbyexwuiogmbyprb&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Fri May 29 04:00:03 UTC 2015.

The ipset `ib_bluetack_proxies` has **673** entries, **673** unique IPs.

The following table shows the overlaps of `ib_bluetack_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_proxies`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|58|0.0%|8.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|51|0.0%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|28|0.0%|4.1%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|22|0.0%|3.2%|
[xroxy](#xroxy)|1916|1916|12|0.6%|1.7%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|11|0.0%|1.6%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|10|0.0%|1.4%|
[ri_web_proxies](#ri_web_proxies)|4579|4579|10|0.2%|1.4%|
[stopforumspam_1d](#stopforumspam_1d)|7864|7864|8|0.1%|1.1%|
[proxyrss](#proxyrss)|1699|1699|8|0.4%|1.1%|
[ri_connect_proxies](#ri_connect_proxies)|1759|1759|6|0.3%|0.8%|
[blocklist_de_bots](#blocklist_de_bots)|3461|3461|3|0.0%|0.4%|
[blocklist_de](#blocklist_de)|22183|22183|3|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|2|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.2%|
[et_block](#et_block)|904|18056697|2|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|1|0.0%|0.1%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.1%|
[nixspam](#nixspam)|20758|20758|1|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|1|0.0%|0.1%|

## ib_bluetack_spyware

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) known malicious SPYWARE and ADWARE IP Address ranges

Source is downloaded from [this link](http://list.iblocklist.com/?list=llvtlsjyoyiczbkjsxpf&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Fri May 29 03:30:10 UTC 2015.

The ipset `ib_bluetack_spyware` has **3274** entries, **339192** unique IPs.

The following table shows the overlaps of `ib_bluetack_spyware` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_spyware`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_spyware`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_spyware`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|13269|0.0%|3.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|9231|0.0%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7733|0.0%|2.2%|
[et_block](#et_block)|904|18056697|1038|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|1037|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1036|0.0%|0.3%|
[fullbogons](#fullbogons)|3656|670639576|890|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|288|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|42|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|25|1.9%|0.0%|
[et_tor](#et_tor)|6360|6360|21|0.3%|0.0%|
[dm_tor](#dm_tor)|6451|6451|21|0.3%|0.0%|
[bm_tor](#bm_tor)|6433|6433|21|0.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|19|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|19|1.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|15|0.1%|0.0%|
[nixspam](#nixspam)|20758|20758|12|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7864|7864|9|0.1%|0.0%|
[openbl_90d](#openbl_90d)|9846|9846|6|0.0%|0.0%|
[openbl](#openbl)|9846|9846|6|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7743|7743|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|5|1.3%|0.0%|
[voipbl](#voipbl)|10303|10775|4|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4579|4579|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4426|4426|4|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[malc0de](#malc0de)|411|411|3|0.7%|0.0%|
[blocklist_de](#blocklist_de)|22183|22183|3|0.0%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|91|91|2|2.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|89|89|2|2.2%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[zeus](#zeus)|267|267|1|0.3%|0.0%|
[xroxy](#xroxy)|1916|1916|1|0.0%|0.0%|
[sslbl](#sslbl)|345|345|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.0%|
[openbl_7d](#openbl_7d)|988|988|1|0.1%|0.0%|
[feodo](#feodo)|67|67|1|1.4%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2078|2078|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14650|14650|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3461|3461|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12618|12618|1|0.0%|0.0%|

## ib_bluetack_webexploit

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) web server hack and exploit attempts

Source is downloaded from [this link](http://list.iblocklist.com/?list=ghlzqtqxnzctvvajwwag&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Fri May 29 03:30:12 UTC 2015.

The ipset `ib_bluetack_webexploit` has **1460** entries, **1460** unique IPs.

The following table shows the overlaps of `ib_bluetack_webexploit` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_webexploit`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_webexploit`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_webexploit`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|110|0.0%|7.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|98|0.0%|6.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|45|0.0%|3.0%|
[fullbogons](#fullbogons)|3656|670639576|33|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|19|0.0%|1.3%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|8|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|6|0.0%|0.4%|
[et_block](#et_block)|904|18056697|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|3|0.2%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|2|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|2|0.0%|0.1%|
[openbl_90d](#openbl_90d)|9846|9846|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7743|7743|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|4426|4426|2|0.0%|0.1%|
[openbl](#openbl)|9846|9846|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.1%|
[et_compromised](#et_compromised)|2401|2401|2|0.0%|0.1%|
[bruteforceblocker](#bruteforceblocker)|2350|2350|2|0.0%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|2078|2078|2|0.0%|0.1%|
[blocklist_de](#blocklist_de)|22183|22183|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7864|7864|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4579|4579|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|988|988|1|0.1%|0.0%|
[openbl_1d](#openbl_1d)|357|357|1|0.2%|0.0%|
[nixspam](#nixspam)|20758|20758|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_tor](#et_tor)|6360|6360|1|0.0%|0.0%|
[et_botnet](#et_botnet)|505|505|1|0.1%|0.0%|
[dm_tor](#dm_tor)|6451|6451|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6433|6433|1|0.0%|0.0%|

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
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|76|0.0%|18.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|26|0.0%|6.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|12|0.0%|2.9%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|10|0.0%|2.4%|
[cleanmx_viruses](#cleanmx_viruses)|91|91|9|9.8%|2.1%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|4|0.3%|0.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|2|0.0%|0.4%|
[et_block](#et_block)|904|18056697|2|0.0%|0.4%|
[dshield](#dshield)|20|5120|2|0.0%|0.4%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|1|0.0%|0.2%|

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
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|146|0.0%|11.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|66|0.0%|5.1%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|29|0.0%|2.2%|
[et_block](#et_block)|904|18056697|28|0.0%|2.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|26|0.0%|2.0%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|25|0.3%|1.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|25|0.0%|1.9%|
[fullbogons](#fullbogons)|3656|670639576|9|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|7|0.0%|0.5%|
[malc0de](#malc0de)|411|411|4|0.9%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|2|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7864|7864|1|0.0%|0.0%|
[et_botnet](#et_botnet)|505|505|1|0.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|91|91|1|1.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3461|3461|1|0.0%|0.0%|
[blocklist_de](#blocklist_de)|22183|22183|1|0.0%|0.0%|

## maxmind_proxy_fraud

[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.

Source is downloaded from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list).

The last time downloaded was found to be dated: Fri May 29 08:00:03 UTC 2015.

The ipset `maxmind_proxy_fraud` has **372** entries, **372** unique IPs.

The following table shows the overlaps of `maxmind_proxy_fraud` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `maxmind_proxy_fraud`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `maxmind_proxy_fraud`.
- ` this % ` is the percentage **of this ipset (`maxmind_proxy_fraud`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|236|0.2%|63.4%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|200|0.6%|53.7%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|185|2.4%|49.7%|
[et_tor](#et_tor)|6360|6360|178|2.7%|47.8%|
[bm_tor](#bm_tor)|6433|6433|176|2.7%|47.3%|
[dm_tor](#dm_tor)|6451|6451|175|2.7%|47.0%|
[stopforumspam_1d](#stopforumspam_1d)|7864|7864|171|2.1%|45.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|125|0.0%|33.6%|
[php_commenters](#php_commenters)|281|281|28|9.9%|7.5%|
[php_bad](#php_bad)|281|281|28|9.9%|7.5%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|23|0.0%|6.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|21|0.0%|5.6%|
[openbl_90d](#openbl_90d)|9846|9846|18|0.1%|4.8%|
[openbl_60d](#openbl_60d)|7743|7743|18|0.2%|4.8%|
[openbl](#openbl)|9846|9846|18|0.1%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|17|0.0%|4.5%|
[php_harvesters](#php_harvesters)|257|257|6|2.3%|1.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|1.3%|
[ri_web_proxies](#ri_web_proxies)|4579|4579|4|0.0%|1.0%|
[php_spammers](#php_spammers)|417|417|4|0.9%|1.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|1.0%|
[blocklist_de](#blocklist_de)|22183|22183|3|0.0%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|14650|14650|2|0.0%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|12618|12618|2|0.0%|0.5%|
[xroxy](#xroxy)|1916|1916|1|0.0%|0.2%|
[voipbl](#voipbl)|10303|10775|1|0.0%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|1759|1759|1|0.0%|0.2%|
[nixspam](#nixspam)|20758|20758|1|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1324|1324|1|0.0%|0.2%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Fri May 29 10:00:02 UTC 2015.

The ipset `nixspam` has **20758** entries, **20758** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1282|0.0%|6.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|560|0.0%|2.6%|
[blocklist_de](#blocklist_de)|22183|22183|464|2.0%|2.2%|
[blocklist_de_mail](#blocklist_de_mail)|14650|14650|400|2.7%|1.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|310|0.0%|1.4%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|221|0.2%|1.0%|
[et_block](#et_block)|904|18056697|216|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|215|0.0%|1.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|215|0.0%|1.0%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|190|2.4%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|130|0.4%|0.6%|
[php_dictionary](#php_dictionary)|433|433|84|19.3%|0.4%|
[ri_web_proxies](#ri_web_proxies)|4579|4579|73|1.5%|0.3%|
[xroxy](#xroxy)|1916|1916|65|3.3%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7864|7864|61|0.7%|0.2%|
[php_spammers](#php_spammers)|417|417|59|14.1%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3461|3461|50|1.4%|0.2%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|31|0.0%|0.1%|
[ri_connect_proxies](#ri_connect_proxies)|1759|1759|12|0.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|12|0.0%|0.0%|
[php_commenters](#php_commenters)|281|281|10|3.5%|0.0%|
[php_bad](#php_bad)|281|281|10|3.5%|0.0%|
[proxyrss](#proxyrss)|1699|1699|9|0.5%|0.0%|
[openbl_90d](#openbl_90d)|9846|9846|8|0.0%|0.0%|
[openbl](#openbl)|9846|9846|8|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1324|1324|8|0.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12618|12618|8|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7743|7743|6|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|367|367|5|1.3%|0.0%|
[proxz](#proxz)|123|123|4|3.2%|0.0%|
[php_harvesters](#php_harvesters)|257|257|4|1.5%|0.0%|
[openbl_30d](#openbl_30d)|4426|4426|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|233|233|2|0.8%|0.0%|
[zeus](#zeus)|267|267|1|0.3%|0.0%|
[voipbl](#voipbl)|10303|10775|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6451|6451|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6433|6433|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2078|2078|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|775|775|1|0.1%|0.0%|

## openbl

[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**

Source is downloaded from [this link](http://www.openbl.org/lists/base.txt.gz).

The last time downloaded was found to be dated: Fri May 29 07:32:01 UTC 2015.

The ipset `openbl` has **9846** entries, **9846** unique IPs.

The following table shows the overlaps of `openbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl`.
- ` this % ` is the percentage **of this ipset (`openbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9846|9846|9846|100.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|9825|5.6%|99.7%|
[openbl_60d](#openbl_60d)|7743|7743|7743|100.0%|78.6%|
[openbl_30d](#openbl_30d)|4426|4426|4426|100.0%|44.9%|
[et_compromised](#et_compromised)|2401|2401|1429|59.5%|14.5%|
[bruteforceblocker](#bruteforceblocker)|2350|2350|1413|60.1%|14.3%|
[blocklist_de](#blocklist_de)|22183|22183|1245|5.6%|12.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|2078|2078|1160|55.8%|11.7%|
[openbl_7d](#openbl_7d)|988|988|988|100.0%|10.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|948|0.0%|9.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|507|0.0%|5.1%|
[et_block](#et_block)|904|18056697|450|0.0%|4.5%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|447|0.0%|4.5%|
[openbl_1d](#openbl_1d)|357|357|357|100.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|218|0.0%|2.2%|
[dshield](#dshield)|20|5120|168|3.2%|1.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|233|233|80|34.3%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|66|0.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|14650|14650|58|0.3%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|775|775|50|6.4%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|33|0.1%|0.3%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|29|0.3%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7864|7864|22|0.2%|0.2%|
[et_tor](#et_tor)|6360|6360|21|0.3%|0.2%|
[dm_tor](#dm_tor)|6451|6451|21|0.3%|0.2%|
[bm_tor](#bm_tor)|6433|6433|21|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|19|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|14|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12618|12618|13|0.1%|0.1%|
[voipbl](#voipbl)|10303|10775|12|0.1%|0.1%|
[shunlist](#shunlist)|51|51|11|21.5%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|367|367|10|2.7%|0.1%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.0%|
[php_bad](#php_bad)|281|281|8|2.8%|0.0%|
[nixspam](#nixspam)|20758|20758|8|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|6|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|5|1.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1324|1324|5|0.3%|0.0%|
[zeus](#zeus)|267|267|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3461|3461|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[sslbl](#sslbl)|345|345|1|0.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4579|4579|1|0.0%|0.0%|
[ciarmy](#ciarmy)|345|345|1|0.2%|0.0%|

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
[openbl_90d](#openbl_90d)|9846|9846|357|3.6%|100.0%|
[openbl_60d](#openbl_60d)|7743|7743|357|4.6%|100.0%|
[openbl_30d](#openbl_30d)|4426|4426|357|8.0%|100.0%|
[openbl](#openbl)|9846|9846|357|3.6%|100.0%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|355|0.2%|99.4%|
[blocklist_de](#blocklist_de)|22183|22183|231|1.0%|64.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|2078|2078|223|10.7%|62.4%|
[openbl_7d](#openbl_7d)|988|988|206|20.8%|57.7%|
[et_compromised](#et_compromised)|2401|2401|204|8.4%|57.1%|
[bruteforceblocker](#bruteforceblocker)|2350|2350|198|8.4%|55.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|233|233|70|30.0%|19.6%|
[dshield](#dshield)|20|5120|45|0.8%|12.6%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|26|0.0%|7.2%|
[et_block](#et_block)|904|18056697|26|0.0%|7.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|20|0.0%|5.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|17|0.0%|4.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|7|0.0%|1.9%|
[blocklist_de_mail](#blocklist_de_mail)|14650|14650|7|0.0%|1.9%|
[blocklist_de_imap](#blocklist_de_imap)|775|775|7|0.9%|1.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|1.4%|
[shunlist](#shunlist)|51|51|2|3.9%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|1|0.0%|0.2%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|1|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|367|367|1|0.2%|0.2%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt.gz).

The last time downloaded was found to be dated: Fri May 29 07:32:00 UTC 2015.

The ipset `openbl_30d` has **4426** entries, **4426** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9846|9846|4426|44.9%|100.0%|
[openbl_60d](#openbl_60d)|7743|7743|4426|57.1%|100.0%|
[openbl](#openbl)|9846|9846|4426|44.9%|100.0%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|4416|2.5%|99.7%|
[et_compromised](#et_compromised)|2401|2401|1344|55.9%|30.3%|
[bruteforceblocker](#bruteforceblocker)|2350|2350|1335|56.8%|30.1%|
[blocklist_de](#blocklist_de)|22183|22183|1101|4.9%|24.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|2078|2078|1043|50.1%|23.5%|
[openbl_7d](#openbl_7d)|988|988|988|100.0%|22.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|441|0.0%|9.9%|
[openbl_1d](#openbl_1d)|357|357|357|100.0%|8.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|224|0.0%|5.0%|
[et_block](#et_block)|904|18056697|208|0.0%|4.6%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|206|0.0%|4.6%|
[dshield](#dshield)|20|5120|133|2.5%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|100|0.0%|2.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|233|233|77|33.0%|1.7%|
[blocklist_de_mail](#blocklist_de_mail)|14650|14650|47|0.3%|1.0%|
[blocklist_de_imap](#blocklist_de_imap)|775|775|41|5.2%|0.9%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|18|0.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|13|0.0%|0.2%|
[shunlist](#shunlist)|51|51|10|19.6%|0.2%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|6|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12618|12618|6|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|5|0.0%|0.1%|
[voipbl](#voipbl)|10303|10775|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[nixspam](#nixspam)|20758|20758|3|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|367|367|3|0.8%|0.0%|
[zeus](#zeus)|267|267|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7864|7864|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|345|345|1|0.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1324|1324|1|0.0%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt.gz).

The last time downloaded was found to be dated: Fri May 29 07:32:00 UTC 2015.

The ipset `openbl_60d` has **7743** entries, **7743** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9846|9846|7743|78.6%|100.0%|
[openbl](#openbl)|9846|9846|7743|78.6%|100.0%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|7725|4.4%|99.7%|
[openbl_30d](#openbl_30d)|4426|4426|4426|100.0%|57.1%|
[et_compromised](#et_compromised)|2401|2401|1413|58.8%|18.2%|
[bruteforceblocker](#bruteforceblocker)|2350|2350|1397|59.4%|18.0%|
[blocklist_de](#blocklist_de)|22183|22183|1190|5.3%|15.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|2078|2078|1116|53.7%|14.4%|
[openbl_7d](#openbl_7d)|988|988|988|100.0%|12.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|720|0.0%|9.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|361|0.0%|4.6%|
[openbl_1d](#openbl_1d)|357|357|357|100.0%|4.6%|
[et_block](#et_block)|904|18056697|259|0.0%|3.3%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|257|0.0%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|179|0.0%|2.3%|
[dshield](#dshield)|20|5120|158|3.0%|2.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|233|233|79|33.9%|1.0%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|59|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|14650|14650|53|0.3%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|775|775|45|5.8%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|31|0.1%|0.4%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|29|0.3%|0.3%|
[et_tor](#et_tor)|6360|6360|21|0.3%|0.2%|
[dm_tor](#dm_tor)|6451|6451|21|0.3%|0.2%|
[bm_tor](#bm_tor)|6433|6433|21|0.3%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7864|7864|20|0.2%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|18|0.0%|0.2%|
[shunlist](#shunlist)|51|51|11|21.5%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12618|12618|10|0.0%|0.1%|
[voipbl](#voipbl)|10303|10775|9|0.0%|0.1%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.1%|
[php_bad](#php_bad)|281|281|8|2.8%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|367|367|8|2.1%|0.1%|
[nixspam](#nixspam)|20758|20758|6|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|5|1.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1324|1324|3|0.2%|0.0%|
[zeus](#zeus)|267|267|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|345|345|1|0.2%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt.gz).

The last time downloaded was found to be dated: Fri May 29 07:32:00 UTC 2015.

The ipset `openbl_7d` has **988** entries, **988** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9846|9846|988|10.0%|100.0%|
[openbl_60d](#openbl_60d)|7743|7743|988|12.7%|100.0%|
[openbl_30d](#openbl_30d)|4426|4426|988|22.3%|100.0%|
[openbl](#openbl)|9846|9846|988|10.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|983|0.5%|99.4%|
[blocklist_de](#blocklist_de)|22183|22183|654|2.9%|66.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|2078|2078|622|29.9%|62.9%|
[bruteforceblocker](#bruteforceblocker)|2350|2350|511|21.7%|51.7%|
[et_compromised](#et_compromised)|2401|2401|502|20.9%|50.8%|
[openbl_1d](#openbl_1d)|357|357|206|57.7%|20.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|93|0.0%|9.4%|
[dshield](#dshield)|20|5120|90|1.7%|9.1%|
[et_block](#et_block)|904|18056697|83|0.0%|8.4%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|82|0.0%|8.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|233|233|76|32.6%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|52|0.0%|5.2%|
[blocklist_de_mail](#blocklist_de_mail)|14650|14650|26|0.1%|2.6%|
[blocklist_de_imap](#blocklist_de_imap)|775|775|24|3.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|15|0.0%|1.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|1.0%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|5|0.0%|0.5%|
[shunlist](#shunlist)|51|51|5|9.8%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|12618|12618|3|0.0%|0.3%|
[voipbl](#voipbl)|10303|10775|2|0.0%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|2|0.0%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|367|367|2|0.5%|0.2%|
[zeus](#zeus)|267|267|1|0.3%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.1%|
[ciarmy](#ciarmy)|345|345|1|0.2%|0.1%|

## openbl_90d

[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_90days.txt.gz).

The last time downloaded was found to be dated: Fri May 29 07:32:01 UTC 2015.

The ipset `openbl_90d` has **9846** entries, **9846** unique IPs.

The following table shows the overlaps of `openbl_90d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_90d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_90d`.
- ` this % ` is the percentage **of this ipset (`openbl_90d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl](#openbl)|9846|9846|9846|100.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|9825|5.6%|99.7%|
[openbl_60d](#openbl_60d)|7743|7743|7743|100.0%|78.6%|
[openbl_30d](#openbl_30d)|4426|4426|4426|100.0%|44.9%|
[et_compromised](#et_compromised)|2401|2401|1429|59.5%|14.5%|
[bruteforceblocker](#bruteforceblocker)|2350|2350|1413|60.1%|14.3%|
[blocklist_de](#blocklist_de)|22183|22183|1245|5.6%|12.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|2078|2078|1160|55.8%|11.7%|
[openbl_7d](#openbl_7d)|988|988|988|100.0%|10.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|948|0.0%|9.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|507|0.0%|5.1%|
[et_block](#et_block)|904|18056697|450|0.0%|4.5%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|447|0.0%|4.5%|
[openbl_1d](#openbl_1d)|357|357|357|100.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|218|0.0%|2.2%|
[dshield](#dshield)|20|5120|168|3.2%|1.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|233|233|80|34.3%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|66|0.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|14650|14650|58|0.3%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|775|775|50|6.4%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|33|0.1%|0.3%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|29|0.3%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7864|7864|22|0.2%|0.2%|
[et_tor](#et_tor)|6360|6360|21|0.3%|0.2%|
[dm_tor](#dm_tor)|6451|6451|21|0.3%|0.2%|
[bm_tor](#bm_tor)|6433|6433|21|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|19|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|14|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12618|12618|13|0.1%|0.1%|
[voipbl](#voipbl)|10303|10775|12|0.1%|0.1%|
[shunlist](#shunlist)|51|51|11|21.5%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|367|367|10|2.7%|0.1%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.0%|
[php_bad](#php_bad)|281|281|8|2.8%|0.0%|
[nixspam](#nixspam)|20758|20758|8|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|6|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|5|1.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1324|1324|5|0.3%|0.0%|
[zeus](#zeus)|267|267|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3461|3461|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[sslbl](#sslbl)|345|345|1|0.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4579|4579|1|0.0%|0.0%|
[ciarmy](#ciarmy)|345|345|1|0.2%|0.0%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Fri May 29 10:00:26 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[snort_ipfilter](#snort_ipfilter)|7652|7652|11|0.1%|84.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|3|0.0%|23.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|15.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1|0.0%|7.6%|

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
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|202|0.2%|71.8%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|188|0.6%|66.9%|
[stopforumspam_1d](#stopforumspam_1d)|7864|7864|118|1.5%|41.9%|
[blocklist_de](#blocklist_de)|22183|22183|73|0.3%|25.9%|
[blocklist_de_bots](#blocklist_de_bots)|3461|3461|57|1.6%|20.2%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|41|0.5%|14.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|233|233|33|14.1%|11.7%|
[php_spammers](#php_spammers)|417|417|32|7.6%|11.3%|
[et_tor](#et_tor)|6360|6360|29|0.4%|10.3%|
[dm_tor](#dm_tor)|6451|6451|29|0.4%|10.3%|
[bm_tor](#bm_tor)|6433|6433|29|0.4%|10.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|28|7.5%|9.9%|
[blocklist_de_apache](#blocklist_de_apache)|12618|12618|25|0.1%|8.8%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|24|0.0%|8.5%|
[et_block](#et_block)|904|18056697|24|0.0%|8.5%|
[php_dictionary](#php_dictionary)|433|433|22|5.0%|7.8%|
[blocklist_de_mail](#blocklist_de_mail)|14650|14650|21|0.1%|7.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|16|0.0%|5.6%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|12|0.0%|4.2%|
[nixspam](#nixspam)|20758|20758|10|0.0%|3.5%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.2%|
[ri_web_proxies](#ri_web_proxies)|4579|4579|8|0.1%|2.8%|
[openbl_90d](#openbl_90d)|9846|9846|8|0.0%|2.8%|
[openbl_60d](#openbl_60d)|7743|7743|8|0.1%|2.8%|
[openbl](#openbl)|9846|9846|8|0.0%|2.8%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|7|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|5|0.0%|1.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1324|1324|5|0.3%|1.7%|
[xroxy](#xroxy)|1916|1916|3|0.1%|1.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.3%|
[zeus](#zeus)|267|267|1|0.3%|0.3%|
[proxz](#proxz)|123|123|1|0.8%|0.3%|
[proxyrss](#proxyrss)|1699|1699|1|0.0%|0.3%|
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
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|203|0.2%|72.2%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|189|0.6%|67.2%|
[stopforumspam_1d](#stopforumspam_1d)|7864|7864|118|1.5%|41.9%|
[blocklist_de](#blocklist_de)|22183|22183|74|0.3%|26.3%|
[blocklist_de_bots](#blocklist_de_bots)|3461|3461|57|1.6%|20.2%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|42|0.5%|14.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|233|233|33|14.1%|11.7%|
[php_spammers](#php_spammers)|417|417|32|7.6%|11.3%|
[et_tor](#et_tor)|6360|6360|29|0.4%|10.3%|
[dm_tor](#dm_tor)|6451|6451|29|0.4%|10.3%|
[bm_tor](#bm_tor)|6433|6433|29|0.4%|10.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|28|7.5%|9.9%|
[blocklist_de_apache](#blocklist_de_apache)|12618|12618|25|0.1%|8.8%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|24|0.0%|8.5%|
[et_block](#et_block)|904|18056697|24|0.0%|8.5%|
[php_dictionary](#php_dictionary)|433|433|22|5.0%|7.8%|
[blocklist_de_mail](#blocklist_de_mail)|14650|14650|22|0.1%|7.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|5.3%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|12|0.0%|4.2%|
[nixspam](#nixspam)|20758|20758|10|0.0%|3.5%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.2%|
[ri_web_proxies](#ri_web_proxies)|4579|4579|8|0.1%|2.8%|
[openbl_90d](#openbl_90d)|9846|9846|8|0.0%|2.8%|
[openbl_60d](#openbl_60d)|7743|7743|8|0.1%|2.8%|
[openbl](#openbl)|9846|9846|8|0.0%|2.8%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|7|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|5|0.0%|1.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1324|1324|5|0.3%|1.7%|
[xroxy](#xroxy)|1916|1916|3|0.1%|1.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.3%|
[zeus](#zeus)|267|267|1|0.3%|0.3%|
[proxz](#proxz)|123|123|1|0.8%|0.3%|
[proxyrss](#proxyrss)|1699|1699|1|0.0%|0.3%|
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
[php_spammers](#php_spammers)|417|417|84|20.1%|19.3%|
[nixspam](#nixspam)|20758|20758|84|0.4%|19.3%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|77|1.0%|17.7%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|75|0.0%|17.3%|
[blocklist_de](#blocklist_de)|22183|22183|68|0.3%|15.7%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|59|0.1%|13.6%|
[blocklist_de_mail](#blocklist_de_mail)|14650|14650|55|0.3%|12.7%|
[stopforumspam_1d](#stopforumspam_1d)|7864|7864|25|0.3%|5.7%|
[xroxy](#xroxy)|1916|1916|24|1.2%|5.5%|
[ri_web_proxies](#ri_web_proxies)|4579|4579|24|0.5%|5.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|24|0.0%|5.5%|
[php_commenters](#php_commenters)|281|281|22|7.8%|5.0%|
[php_bad](#php_bad)|281|281|22|7.8%|5.0%|
[blocklist_de_bots](#blocklist_de_bots)|3461|3461|13|0.3%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|10|0.0%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|9|0.0%|2.0%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|7|0.0%|1.6%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|4|0.0%|0.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.9%|
[et_tor](#et_tor)|6360|6360|4|0.0%|0.9%|
[et_block](#et_block)|904|18056697|4|0.0%|0.9%|
[dm_tor](#dm_tor)|6451|6451|4|0.0%|0.9%|
[bm_tor](#bm_tor)|6433|6433|4|0.0%|0.9%|
[ri_connect_proxies](#ri_connect_proxies)|1759|1759|3|0.1%|0.6%|
[proxz](#proxz)|123|123|2|1.6%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.4%|
[proxyrss](#proxyrss)|1699|1699|1|0.0%|0.2%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|233|233|1|0.4%|0.2%|

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
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|62|0.0%|24.1%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|50|0.1%|19.4%|
[stopforumspam_1d](#stopforumspam_1d)|7864|7864|36|0.4%|14.0%|
[blocklist_de](#blocklist_de)|22183|22183|35|0.1%|13.6%|
[blocklist_de_bots](#blocklist_de_bots)|3461|3461|28|0.8%|10.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|5.8%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|10|0.1%|3.8%|
[php_commenters](#php_commenters)|281|281|9|3.2%|3.5%|
[php_bad](#php_bad)|281|281|9|3.2%|3.5%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|9|0.0%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|7|0.0%|2.7%|
[et_tor](#et_tor)|6360|6360|7|0.1%|2.7%|
[dm_tor](#dm_tor)|6451|6451|7|0.1%|2.7%|
[bm_tor](#bm_tor)|6433|6433|7|0.1%|2.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|6|1.6%|2.3%|
[openbl_90d](#openbl_90d)|9846|9846|5|0.0%|1.9%|
[openbl_60d](#openbl_60d)|7743|7743|5|0.0%|1.9%|
[openbl](#openbl)|9846|9846|5|0.0%|1.9%|
[nixspam](#nixspam)|20758|20758|4|0.0%|1.5%|
[blocklist_de_mail](#blocklist_de_mail)|14650|14650|4|0.0%|1.5%|
[blocklist_de_ftp](#blocklist_de_ftp)|367|367|3|0.8%|1.1%|
[xroxy](#xroxy)|1916|1916|2|0.1%|0.7%|
[proxyrss](#proxyrss)|1699|1699|2|0.1%|0.7%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.7%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|1|0.0%|0.3%|
[ri_web_proxies](#ri_web_proxies)|4579|4579|1|0.0%|0.3%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.3%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|
[fullbogons](#fullbogons)|3656|670639576|1|0.0%|0.3%|
[et_block](#et_block)|904|18056697|1|0.0%|0.3%|
[bogons](#bogons)|13|592708608|1|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|233|233|1|0.4%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|12618|12618|1|0.0%|0.3%|

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
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|95|0.1%|22.7%|
[php_dictionary](#php_dictionary)|433|433|84|19.3%|20.1%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|68|0.8%|16.3%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|65|0.2%|15.5%|
[blocklist_de](#blocklist_de)|22183|22183|62|0.2%|14.8%|
[nixspam](#nixspam)|20758|20758|59|0.2%|14.1%|
[blocklist_de_mail](#blocklist_de_mail)|14650|14650|40|0.2%|9.5%|
[stopforumspam_1d](#stopforumspam_1d)|7864|7864|34|0.4%|8.1%|
[php_commenters](#php_commenters)|281|281|32|11.3%|7.6%|
[php_bad](#php_bad)|281|281|32|11.3%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|31|0.0%|7.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|26|0.0%|6.2%|
[ri_web_proxies](#ri_web_proxies)|4579|4579|20|0.4%|4.7%|
[xroxy](#xroxy)|1916|1916|18|0.9%|4.3%|
[blocklist_de_bots](#blocklist_de_bots)|3461|3461|17|0.4%|4.0%|
[et_tor](#et_tor)|6360|6360|6|0.0%|1.4%|
[dm_tor](#dm_tor)|6451|6451|6|0.0%|1.4%|
[bm_tor](#bm_tor)|6433|6433|6|0.0%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|5|0.0%|1.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|233|233|5|2.1%|1.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1324|1324|5|0.3%|1.1%|
[blocklist_de_apache](#blocklist_de_apache)|12618|12618|5|0.0%|1.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.9%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|3|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|2|0.0%|0.4%|
[ri_connect_proxies](#ri_connect_proxies)|1759|1759|2|0.1%|0.4%|
[proxyrss](#proxyrss)|1699|1699|2|0.1%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[et_block](#et_block)|904|18056697|2|0.0%|0.4%|
[proxz](#proxz)|123|123|1|0.8%|0.2%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.2%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Fri May 29 08:11:35 UTC 2015.

The ipset `proxyrss` has **1699** entries, **1699** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|888|0.9%|52.2%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|795|2.5%|46.7%|
[xroxy](#xroxy)|1916|1916|745|38.8%|43.8%|
[ri_web_proxies](#ri_web_proxies)|4579|4579|664|14.5%|39.0%|
[stopforumspam_1d](#stopforumspam_1d)|7864|7864|471|5.9%|27.7%|
[ri_connect_proxies](#ri_connect_proxies)|1759|1759|247|14.0%|14.5%|
[blocklist_de](#blocklist_de)|22183|22183|245|1.1%|14.4%|
[blocklist_de_bots](#blocklist_de_bots)|3461|3461|241|6.9%|14.1%|
[proxz](#proxz)|123|123|76|61.7%|4.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|66|0.0%|3.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|51|0.0%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|42|0.0%|2.4%|
[nixspam](#nixspam)|20758|20758|9|0.0%|0.5%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|8|1.1%|0.4%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|5|0.0%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|233|233|4|1.7%|0.2%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.1%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.1%|
[et_compromised](#et_compromised)|2401|2401|2|0.0%|0.1%|
[bruteforceblocker](#bruteforceblocker)|2350|2350|2|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|14650|14650|2|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|2|0.0%|0.1%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.0%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.0%|
[php_bad](#php_bad)|281|281|1|0.3%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2078|2078|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1324|1324|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12618|12618|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Fri May 29 08:11:40 UTC 2015.

The ipset `proxz` has **123** entries, **123** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[xroxy](#xroxy)|1916|1916|90|4.6%|73.1%|
[proxyrss](#proxyrss)|1699|1699|76|4.4%|61.7%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|66|0.0%|53.6%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|65|0.2%|52.8%|
[stopforumspam_1d](#stopforumspam_1d)|7864|7864|45|0.5%|36.5%|
[ri_web_proxies](#ri_web_proxies)|4579|4579|44|0.9%|35.7%|
[blocklist_de](#blocklist_de)|22183|22183|24|0.1%|19.5%|
[blocklist_de_bots](#blocklist_de_bots)|3461|3461|23|0.6%|18.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|16|0.0%|13.0%|
[ri_connect_proxies](#ri_connect_proxies)|1759|1759|10|0.5%|8.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|6|0.0%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|5|0.0%|4.0%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|4|0.0%|3.2%|
[nixspam](#nixspam)|20758|20758|4|0.0%|3.2%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|1.6%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.8%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.8%|
[php_bad](#php_bad)|281|281|1|0.3%|0.8%|
[et_tor](#et_tor)|6360|6360|1|0.0%|0.8%|
[et_compromised](#et_compromised)|2401|2401|1|0.0%|0.8%|
[dm_tor](#dm_tor)|6451|6451|1|0.0%|0.8%|
[bruteforceblocker](#bruteforceblocker)|2350|2350|1|0.0%|0.8%|
[bm_tor](#bm_tor)|6433|6433|1|0.0%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|14650|14650|1|0.0%|0.8%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|1|0.0%|0.8%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Fri May 29 04:33:27 UTC 2015.

The ipset `ri_connect_proxies` has **1759** entries, **1759** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|1027|1.1%|58.3%|
[ri_web_proxies](#ri_web_proxies)|4579|4579|715|15.6%|40.6%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|708|2.2%|40.2%|
[xroxy](#xroxy)|1916|1916|279|14.5%|15.8%|
[proxyrss](#proxyrss)|1699|1699|247|14.5%|14.0%|
[stopforumspam_1d](#stopforumspam_1d)|7864|7864|172|2.1%|9.7%|
[blocklist_de](#blocklist_de)|22183|22183|83|0.3%|4.7%|
[blocklist_de_bots](#blocklist_de_bots)|3461|3461|82|2.3%|4.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|76|0.0%|4.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|62|0.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|41|0.0%|2.3%|
[nixspam](#nixspam)|20758|20758|12|0.0%|0.6%|
[proxz](#proxz)|123|123|10|8.1%|0.5%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|6|0.0%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.3%|
[php_dictionary](#php_dictionary)|433|433|3|0.6%|0.1%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.1%|
[et_tor](#et_tor)|6360|6360|2|0.0%|0.1%|
[dm_tor](#dm_tor)|6451|6451|2|0.0%|0.1%|
[bm_tor](#bm_tor)|6433|6433|2|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|2|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14650|14650|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Fri May 29 06:34:50 UTC 2015.

The ipset `ri_web_proxies` has **4579** entries, **4579** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|2260|2.4%|49.3%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|1672|5.3%|36.5%|
[xroxy](#xroxy)|1916|1916|730|38.1%|15.9%|
[ri_connect_proxies](#ri_connect_proxies)|1759|1759|715|40.6%|15.6%|
[proxyrss](#proxyrss)|1699|1699|664|39.0%|14.5%|
[stopforumspam_1d](#stopforumspam_1d)|7864|7864|587|7.4%|12.8%|
[blocklist_de](#blocklist_de)|22183|22183|397|1.7%|8.6%|
[blocklist_de_bots](#blocklist_de_bots)|3461|3461|370|10.6%|8.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|163|0.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|143|0.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|107|0.0%|2.3%|
[nixspam](#nixspam)|20758|20758|73|0.3%|1.5%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|46|0.6%|1.0%|
[proxz](#proxz)|123|123|44|35.7%|0.9%|
[blocklist_de_mail](#blocklist_de_mail)|14650|14650|26|0.1%|0.5%|
[php_dictionary](#php_dictionary)|433|433|24|5.5%|0.5%|
[php_spammers](#php_spammers)|417|417|20|4.7%|0.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|10|1.4%|0.2%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.1%|
[php_bad](#php_bad)|281|281|8|2.8%|0.1%|
[et_tor](#et_tor)|6360|6360|5|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6451|6451|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6433|6433|4|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|233|233|3|1.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[openbl_90d](#openbl_90d)|9846|9846|1|0.0%|0.0%|
[openbl](#openbl)|9846|9846|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1324|1324|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12618|12618|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Fri May 29 06:30:03 UTC 2015.

The ipset `shunlist` has **51** entries, **51** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|174512|174512|51|0.0%|100.0%|
[openbl_90d](#openbl_90d)|9846|9846|11|0.1%|21.5%|
[openbl_60d](#openbl_60d)|7743|7743|11|0.1%|21.5%|
[openbl](#openbl)|9846|9846|11|0.1%|21.5%|
[blocklist_de](#blocklist_de)|22183|22183|11|0.0%|21.5%|
[openbl_30d](#openbl_30d)|4426|4426|10|0.2%|19.6%|
[et_compromised](#et_compromised)|2401|2401|9|0.3%|17.6%|
[bruteforceblocker](#bruteforceblocker)|2350|2350|9|0.3%|17.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|2078|2078|8|0.3%|15.6%|
[openbl_7d](#openbl_7d)|988|988|5|0.5%|9.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|4|0.0%|7.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|3|0.0%|5.8%|
[blocklist_de_apache](#blocklist_de_apache)|12618|12618|3|0.0%|5.8%|
[voipbl](#voipbl)|10303|10775|2|0.0%|3.9%|
[openbl_1d](#openbl_1d)|357|357|2|0.5%|3.9%|
[ciarmy](#ciarmy)|345|345|2|0.5%|3.9%|
[blocklist_de_mail](#blocklist_de_mail)|14650|14650|1|0.0%|1.9%|

## snort_ipfilter

[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)

Source is downloaded from [this link](http://labs.snort.org/feeds/ip-filter.blf).

The last time downloaded was found to be dated: Fri May 29 01:30:00 UTC 2015.

The ipset `snort_ipfilter` has **7652** entries, **7652** unique IPs.

The following table shows the overlaps of `snort_ipfilter` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `snort_ipfilter`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `snort_ipfilter`.
- ` this % ` is the percentage **of this ipset (`snort_ipfilter`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_tor](#et_tor)|6360|6360|1068|16.7%|13.9%|
[bm_tor](#bm_tor)|6433|6433|1040|16.1%|13.5%|
[dm_tor](#dm_tor)|6451|6451|1039|16.1%|13.5%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|765|0.8%|9.9%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|581|1.8%|7.5%|
[stopforumspam_1d](#stopforumspam_1d)|7864|7864|387|4.9%|5.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|237|0.0%|3.0%|
[et_block](#et_block)|904|18056697|229|0.0%|2.9%|
[zeus](#zeus)|267|267|227|85.0%|2.9%|
[blocklist_de](#blocklist_de)|22183|22183|226|1.0%|2.9%|
[zeus_badips](#zeus_badips)|230|230|201|87.3%|2.6%|
[nixspam](#nixspam)|20758|20758|190|0.9%|2.4%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|185|49.7%|2.4%|
[blocklist_de_mail](#blocklist_de_mail)|14650|14650|155|1.0%|2.0%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|124|0.0%|1.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|112|0.0%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|86|0.0%|1.1%|
[php_dictionary](#php_dictionary)|433|433|77|17.7%|1.0%|
[php_spammers](#php_spammers)|417|417|68|16.3%|0.8%|
[xroxy](#xroxy)|1916|1916|54|2.8%|0.7%|
[feodo](#feodo)|67|67|53|79.1%|0.6%|
[ri_web_proxies](#ri_web_proxies)|4579|4579|46|1.0%|0.6%|
[php_commenters](#php_commenters)|281|281|42|14.9%|0.5%|
[php_bad](#php_bad)|281|281|41|14.5%|0.5%|
[blocklist_de_bots](#blocklist_de_bots)|3461|3461|35|1.0%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|12618|12618|35|0.2%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1324|1324|32|2.4%|0.4%|
[openbl_90d](#openbl_90d)|9846|9846|29|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7743|7743|29|0.3%|0.3%|
[openbl](#openbl)|9846|9846|29|0.2%|0.3%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|25|1.9%|0.3%|
[sslbl](#sslbl)|345|345|21|6.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|18|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|15|0.0%|0.1%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|10|3.8%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|775|775|7|0.9%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|6|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1759|1759|6|0.3%|0.0%|
[openbl_30d](#openbl_30d)|4426|4426|6|0.1%|0.0%|
[proxyrss](#proxyrss)|1699|1699|5|0.2%|0.0%|
[openbl_7d](#openbl_7d)|988|988|5|0.5%|0.0%|
[proxz](#proxz)|123|123|4|3.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2078|2078|3|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[openbl_1d](#openbl_1d)|357|357|1|0.2%|0.0%|
[malc0de](#malc0de)|411|411|1|0.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2401|2401|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2350|2350|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|233|233|1|0.4%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|367|367|1|0.2%|0.0%|

## spamhaus_drop

[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**

Source is downloaded from [this link](http://www.spamhaus.org/drop/drop.txt).

The last time downloaded was found to be dated: Fri May 29 04:17:36 UTC 2015.

The ipset `spamhaus_drop` has **639** entries, **17921280** unique IPs.

The following table shows the overlaps of `spamhaus_drop` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `spamhaus_drop`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `spamhaus_drop`.
- ` this % ` is the percentage **of this ipset (`spamhaus_drop`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|904|18056697|17920256|99.2%|99.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8401434|2.4%|46.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7079936|77.1%|39.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|2133002|0.2%|11.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|195904|0.1%|1.0%|
[fullbogons](#fullbogons)|3656|670639576|20480|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|1625|0.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|756|0.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|512|0.1%|0.0%|
[openbl_90d](#openbl_90d)|9846|9846|447|4.5%|0.0%|
[openbl](#openbl)|9846|9846|447|4.5%|0.0%|
[openbl_60d](#openbl_60d)|7743|7743|257|3.3%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[nixspam](#nixspam)|20758|20758|215|1.0%|0.0%|
[openbl_30d](#openbl_30d)|4426|4426|206|4.6%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|204|0.6%|0.0%|
[blocklist_de](#blocklist_de)|22183|22183|189|0.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2078|2078|113|5.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2350|2350|102|4.3%|0.0%|
[et_compromised](#et_compromised)|2401|2401|97|4.0%|0.0%|
[openbl_7d](#openbl_7d)|988|988|82|8.2%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7864|7864|55|0.6%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3461|3461|54|1.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|29|2.2%|0.0%|
[openbl_1d](#openbl_1d)|357|357|26|7.2%|0.0%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.0%|
[php_bad](#php_bad)|281|281|24|8.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14650|14650|21|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|18|0.2%|0.0%|
[zeus_badips](#zeus_badips)|230|230|16|6.9%|0.0%|
[zeus](#zeus)|267|267|16|5.9%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|775|775|16|2.0%|0.0%|
[voipbl](#voipbl)|10303|10775|14|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|233|233|7|3.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[sslbl](#sslbl)|345|345|3|0.8%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[malc0de](#malc0de)|411|411|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6360|6360|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6451|6451|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6433|6433|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[et_botnet](#et_botnet)|505|505|1|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1324|1324|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12618|12618|1|0.0%|0.0%|

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
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|270785|0.1%|64.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|33368|0.0%|7.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|33155|0.0%|7.8%|
[et_block](#et_block)|904|18056697|517|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|512|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|106|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|42|0.1%|0.0%|
[blocklist_de](#blocklist_de)|22183|22183|32|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3461|3461|26|0.7%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7864|7864|16|0.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|15|0.0%|0.0%|
[openbl_90d](#openbl_90d)|9846|9846|14|0.1%|0.0%|
[openbl](#openbl)|9846|9846|14|0.1%|0.0%|
[php_commenters](#php_commenters)|281|281|7|2.4%|0.0%|
[php_bad](#php_bad)|281|281|7|2.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|233|233|6|2.5%|0.0%|
[zeus_badips](#zeus_badips)|230|230|5|2.1%|0.0%|
[zeus](#zeus)|267|267|5|1.8%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14650|14650|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12618|12618|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[openbl_60d](#openbl_60d)|7743|7743|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4426|4426|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|357|357|1|0.2%|0.0%|
[malc0de](#malc0de)|411|411|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|775|775|1|0.1%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Fri May 29 09:45:06 UTC 2015.

The ipset `sslbl` has **345** entries, **345** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[feodo](#feodo)|67|67|24|35.8%|6.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|22|0.0%|6.3%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|21|0.2%|6.0%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|7|0.0%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|6|0.0%|1.7%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|3|0.0%|0.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|3|0.0%|0.8%|
[et_block](#et_block)|904|18056697|3|0.0%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|1|0.0%|0.2%|
[openbl_90d](#openbl_90d)|9846|9846|1|0.0%|0.2%|
[openbl](#openbl)|9846|9846|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Fri May 29 10:00:01 UTC 2015.

The ipset `stopforumspam_1d` has **7864** entries, **7864** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|6792|21.9%|86.3%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|5098|5.4%|64.8%|
[blocklist_de](#blocklist_de)|22183|22183|1656|7.4%|21.0%|
[blocklist_de_bots](#blocklist_de_bots)|3461|3461|1567|45.2%|19.9%|
[ri_web_proxies](#ri_web_proxies)|4579|4579|587|12.8%|7.4%|
[xroxy](#xroxy)|1916|1916|529|27.6%|6.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|513|0.0%|6.5%|
[proxyrss](#proxyrss)|1699|1699|471|27.7%|5.9%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|387|5.0%|4.9%|
[et_tor](#et_tor)|6360|6360|337|5.2%|4.2%|
[bm_tor](#bm_tor)|6433|6433|335|5.2%|4.2%|
[dm_tor](#dm_tor)|6451|6451|334|5.1%|4.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|262|0.0%|3.3%|
[ri_connect_proxies](#ri_connect_proxies)|1759|1759|172|9.7%|2.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|171|45.9%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|153|0.0%|1.9%|
[php_commenters](#php_commenters)|281|281|118|41.9%|1.5%|
[php_bad](#php_bad)|281|281|118|41.9%|1.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|233|233|110|47.2%|1.3%|
[blocklist_de_apache](#blocklist_de_apache)|12618|12618|85|0.6%|1.0%|
[nixspam](#nixspam)|20758|20758|61|0.2%|0.7%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|59|0.0%|0.7%|
[et_block](#et_block)|904|18056697|56|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|55|0.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|50|0.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|14650|14650|46|0.3%|0.5%|
[proxz](#proxz)|123|123|45|36.5%|0.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1324|1324|44|3.3%|0.5%|
[php_harvesters](#php_harvesters)|257|257|36|14.0%|0.4%|
[php_spammers](#php_spammers)|417|417|34|8.1%|0.4%|
[php_dictionary](#php_dictionary)|433|433|25|5.7%|0.3%|
[openbl_90d](#openbl_90d)|9846|9846|22|0.2%|0.2%|
[openbl](#openbl)|9846|9846|22|0.2%|0.2%|
[openbl_60d](#openbl_60d)|7743|7743|20|0.2%|0.2%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|16|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|9|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|8|1.1%|0.1%|
[voipbl](#voipbl)|10303|10775|3|0.0%|0.0%|
[et_compromised](#et_compromised)|2401|2401|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2350|2350|2|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4426|4426|1|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2078|2078|1|0.0%|0.0%|

## stopforumspam_30d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip).

The last time downloaded was found to be dated: Thu May 28 12:00:44 UTC 2015.

The ipset `stopforumspam_30d` has **93361** entries, **93361** unique IPs.

The following table shows the overlaps of `stopforumspam_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_30d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|29116|93.9%|31.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|6195|0.0%|6.6%|
[stopforumspam_1d](#stopforumspam_1d)|7864|7864|5098|64.8%|5.4%|
[blocklist_de](#blocklist_de)|22183|22183|2586|11.6%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2490|0.0%|2.6%|
[blocklist_de_bots](#blocklist_de_bots)|3461|3461|2285|66.0%|2.4%|
[ri_web_proxies](#ri_web_proxies)|4579|4579|2260|49.3%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|1527|0.0%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|1759|1759|1027|58.3%|1.1%|
[xroxy](#xroxy)|1916|1916|1005|52.4%|1.0%|
[proxyrss](#proxyrss)|1699|1699|888|52.2%|0.9%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|765|9.9%|0.8%|
[et_block](#et_block)|904|18056697|759|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|756|0.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|745|0.0%|0.7%|
[et_tor](#et_tor)|6360|6360|601|9.4%|0.6%|
[bm_tor](#bm_tor)|6433|6433|591|9.1%|0.6%|
[dm_tor](#dm_tor)|6451|6451|589|9.1%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|236|63.4%|0.2%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|229|0.1%|0.2%|
[nixspam](#nixspam)|20758|20758|221|1.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|12618|12618|217|1.7%|0.2%|
[php_commenters](#php_commenters)|281|281|203|72.2%|0.2%|
[php_bad](#php_bad)|281|281|202|71.8%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|14650|14650|198|1.3%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|233|233|128|54.9%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|106|0.0%|0.1%|
[php_spammers](#php_spammers)|417|417|95|22.7%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1324|1324|78|5.8%|0.0%|
[php_dictionary](#php_dictionary)|433|433|75|17.3%|0.0%|
[proxz](#proxz)|123|123|66|53.6%|0.0%|
[openbl_90d](#openbl_90d)|9846|9846|66|0.6%|0.0%|
[openbl](#openbl)|9846|9846|66|0.6%|0.0%|
[php_harvesters](#php_harvesters)|257|257|62|24.1%|0.0%|
[openbl_60d](#openbl_60d)|7743|7743|59|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|42|0.0%|0.0%|
[voipbl](#voipbl)|10303|10775|41|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|22|3.2%|0.0%|
[openbl_30d](#openbl_30d)|4426|4426|18|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|16|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|367|367|9|2.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2078|2078|7|0.3%|0.0%|
[et_compromised](#et_compromised)|2401|2401|6|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2350|2350|6|0.2%|0.0%|
[zeus_badips](#zeus_badips)|230|230|3|1.3%|0.0%|
[zeus](#zeus)|267|267|3|1.1%|0.0%|
[openbl_7d](#openbl_7d)|988|988|2|0.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|2|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3656|670639576|2|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|775|775|2|0.2%|0.0%|
[sslbl](#sslbl)|345|345|1|0.2%|0.0%|
[openbl_1d](#openbl_1d)|357|357|1|0.2%|0.0%|
[ciarmy](#ciarmy)|345|345|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|

## stopforumspam_7d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip).

The last time downloaded was found to be dated: Fri May 29 02:02:23 UTC 2015.

The ipset `stopforumspam_7d` has **30975** entries, **30975** unique IPs.

The following table shows the overlaps of `stopforumspam_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_7d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|29116|31.1%|93.9%|
[stopforumspam_1d](#stopforumspam_1d)|7864|7864|6792|86.3%|21.9%|
[blocklist_de](#blocklist_de)|22183|22183|2455|11.0%|7.9%|
[blocklist_de_bots](#blocklist_de_bots)|3461|3461|2277|65.7%|7.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2103|0.0%|6.7%|
[ri_web_proxies](#ri_web_proxies)|4579|4579|1672|36.5%|5.3%|
[xroxy](#xroxy)|1916|1916|915|47.7%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|904|0.0%|2.9%|
[proxyrss](#proxyrss)|1699|1699|795|46.7%|2.5%|
[ri_connect_proxies](#ri_connect_proxies)|1759|1759|708|40.2%|2.2%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|581|7.5%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|580|0.0%|1.8%|
[et_tor](#et_tor)|6360|6360|465|7.3%|1.5%|
[bm_tor](#bm_tor)|6433|6433|456|7.0%|1.4%|
[dm_tor](#dm_tor)|6451|6451|455|7.0%|1.4%|
[et_block](#et_block)|904|18056697|205|0.0%|0.6%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|204|0.0%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|200|53.7%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|194|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|189|67.2%|0.6%|
[php_bad](#php_bad)|281|281|188|66.9%|0.6%|
[blocklist_de_apache](#blocklist_de_apache)|12618|12618|135|1.0%|0.4%|
[nixspam](#nixspam)|20758|20758|130|0.6%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|233|233|119|51.0%|0.3%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|115|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|14650|14650|95|0.6%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1324|1324|72|5.4%|0.2%|
[proxz](#proxz)|123|123|65|52.8%|0.2%|
[php_spammers](#php_spammers)|417|417|65|15.5%|0.2%|
[php_dictionary](#php_dictionary)|433|433|59|13.6%|0.1%|
[php_harvesters](#php_harvesters)|257|257|50|19.4%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|42|0.0%|0.1%|
[openbl_90d](#openbl_90d)|9846|9846|33|0.3%|0.1%|
[openbl](#openbl)|9846|9846|33|0.3%|0.1%|
[openbl_60d](#openbl_60d)|7743|7743|31|0.4%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|19|0.0%|0.0%|
[voipbl](#voipbl)|10303|10775|10|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|10|1.4%|0.0%|
[openbl_30d](#openbl_30d)|4426|4426|5|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|5|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|367|367|4|1.0%|0.0%|
[et_compromised](#et_compromised)|2401|2401|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2350|2350|3|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[zeus](#zeus)|267|267|1|0.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2078|2078|1|0.0%|0.0%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Fri May 29 06:18:23 UTC 2015.

The ipset `voipbl` has **10303** entries, **10775** unique IPs.

The following table shows the overlaps of `voipbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `voipbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `voipbl`.
- ` this % ` is the percentage **of this ipset (`voipbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1588|0.0%|14.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|428|0.0%|3.9%|
[fullbogons](#fullbogons)|3656|670639576|351|0.0%|3.2%|
[bogons](#bogons)|13|592708608|351|0.0%|3.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|301|0.0%|2.7%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|204|0.1%|1.8%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|41|0.0%|0.3%|
[blocklist_de](#blocklist_de)|22183|22183|37|0.1%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|89|89|28|31.4%|0.2%|
[et_block](#et_block)|904|18056697|19|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|14|0.0%|0.1%|
[openbl_90d](#openbl_90d)|9846|9846|12|0.1%|0.1%|
[openbl](#openbl)|9846|9846|12|0.1%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|10|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7743|7743|9|0.1%|0.0%|
[openbl_30d](#openbl_30d)|4426|4426|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[ciarmy](#ciarmy)|345|345|4|1.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2078|2078|4|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7864|7864|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14650|14650|3|0.0%|0.0%|
[shunlist](#shunlist)|51|51|2|3.9%|0.0%|
[openbl_7d](#openbl_7d)|988|988|2|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[nixspam](#nixspam)|20758|20758|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[et_tor](#et_tor)|6360|6360|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2401|2401|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6451|6451|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2350|2350|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6433|6433|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|775|775|1|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3461|3461|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12618|12618|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Fri May 29 09:33:01 UTC 2015.

The ipset `xroxy` has **1916** entries, **1916** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|1005|1.0%|52.4%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|915|2.9%|47.7%|
[proxyrss](#proxyrss)|1699|1699|745|43.8%|38.8%|
[ri_web_proxies](#ri_web_proxies)|4579|4579|730|15.9%|38.1%|
[stopforumspam_1d](#stopforumspam_1d)|7864|7864|529|6.7%|27.6%|
[blocklist_de](#blocklist_de)|22183|22183|305|1.3%|15.9%|
[ri_connect_proxies](#ri_connect_proxies)|1759|1759|279|15.8%|14.5%|
[blocklist_de_bots](#blocklist_de_bots)|3461|3461|260|7.5%|13.5%|
[proxz](#proxz)|123|123|90|73.1%|4.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|88|0.0%|4.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|73|0.0%|3.8%|
[nixspam](#nixspam)|20758|20758|65|0.3%|3.3%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|54|0.7%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|52|0.0%|2.7%|
[blocklist_de_mail](#blocklist_de_mail)|14650|14650|43|0.2%|2.2%|
[php_dictionary](#php_dictionary)|433|433|24|5.5%|1.2%|
[php_spammers](#php_spammers)|417|417|18|4.3%|0.9%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|12|1.7%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|233|233|6|2.5%|0.3%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|4|0.0%|0.2%|
[php_commenters](#php_commenters)|281|281|3|1.0%|0.1%|
[php_bad](#php_bad)|281|281|3|1.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.1%|
[et_tor](#et_tor)|6360|6360|2|0.0%|0.1%|
[dm_tor](#dm_tor)|6451|6451|2|0.0%|0.1%|
[bm_tor](#bm_tor)|6433|6433|2|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2401|2401|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2350|2350|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2078|2078|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1324|1324|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12618|12618|1|0.0%|0.0%|

## zeus

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist).

The last time downloaded was found to be dated: Fri May 29 09:44:51 UTC 2015.

The ipset `zeus` has **267** entries, **267** unique IPs.

The following table shows the overlaps of `zeus` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus`.
- ` this % ` is the percentage **of this ipset (`zeus`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|904|18056697|262|0.0%|98.1%|
[zeus_badips](#zeus_badips)|230|230|230|100.0%|86.1%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|227|2.9%|85.0%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|68|0.0%|25.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|19|0.0%|7.1%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|16|0.0%|5.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|8|0.0%|2.9%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|5|0.0%|1.8%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|3|0.0%|1.1%|
[openbl_90d](#openbl_90d)|9846|9846|2|0.0%|0.7%|
[openbl_60d](#openbl_60d)|7743|7743|2|0.0%|0.7%|
[openbl_30d](#openbl_30d)|4426|4426|2|0.0%|0.7%|
[openbl](#openbl)|9846|9846|2|0.0%|0.7%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|1|0.0%|0.3%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.3%|
[php_bad](#php_bad)|281|281|1|0.3%|0.3%|
[openbl_7d](#openbl_7d)|988|988|1|0.1%|0.3%|
[nixspam](#nixspam)|20758|20758|1|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|
[et_compromised](#et_compromised)|2401|2401|1|0.0%|0.3%|
[bruteforceblocker](#bruteforceblocker)|2350|2350|1|0.0%|0.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|2078|2078|1|0.0%|0.3%|
[blocklist_de](#blocklist_de)|22183|22183|1|0.0%|0.3%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Fri May 29 10:00:23 UTC 2015.

The ipset `zeus_badips` has **230** entries, **230** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|267|267|230|86.1%|100.0%|
[et_block](#et_block)|904|18056697|228|0.0%|99.1%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|201|2.6%|87.3%|
[alienvault_reputation](#alienvault_reputation)|174512|174512|37|0.0%|16.0%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|16|0.0%|6.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8|0.0%|3.4%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|5|0.0%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|4|0.0%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|3|0.0%|1.3%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|1|0.0%|0.4%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.4%|
[php_bad](#php_bad)|281|281|1|0.3%|0.4%|
[openbl_90d](#openbl_90d)|9846|9846|1|0.0%|0.4%|
[openbl_60d](#openbl_60d)|7743|7743|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|4426|4426|1|0.0%|0.4%|
[openbl](#openbl)|9846|9846|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.4%|
[et_compromised](#et_compromised)|2401|2401|1|0.0%|0.4%|
[bruteforceblocker](#bruteforceblocker)|2350|2350|1|0.0%|0.4%|
