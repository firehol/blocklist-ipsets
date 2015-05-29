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

The following list was automatically generated on Fri May 29 04:14:36 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|173474 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|22102 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|12623 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|3488 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|1327 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|285 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|695 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|14566 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|94 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|2134 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|234 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6385 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD)|ipv4 hash:ip|2392 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|334 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|509 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6370 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|904 subnets, 18056697 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botnet](#et_botnet)|[EmergingThreats.net](http://www.emergingthreats.net/) botnet IPs|ipv4 hash:ip|505 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net](http://www.emergingthreats.net/) compromised hosts (seems to be a derivate of other lists)|ipv4 hash:ip|2401 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6360 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
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
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.|ipv4 hash:ip|372 unique IPs|updated every 4 hours  from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list)
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|20085 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
[openbl](#openbl)|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|9850 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt.gz)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|357 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_1days.txt.gz)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|4437 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt.gz)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7759 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt.gz)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|986 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt.gz)
[openbl_90d](#openbl_90d)|[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|9850 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt.gz)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
[php_bad](#php_bad)|[projecthoneypot.org](http://www.projecthoneypot.org/) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|281 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|281 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|433 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|257 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|417 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1651 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|97 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1750 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|4524 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|51 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|7652 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|639 subnets, 17921280 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|55 subnets, 421120 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|345 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|7511 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|93361 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|30975 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10303 subnets, 10775 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1906 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|267 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|230 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Fri May 29 04:00:56 UTC 2015.

The ipset `alienvault_reputation` has **173474** entries, **173474** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|14916|0.0%|8.5%|
[openbl_90d](#openbl_90d)|9850|9850|9829|99.7%|5.6%|
[openbl](#openbl)|9850|9850|9829|99.7%|5.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|7878|0.0%|4.5%|
[openbl_60d](#openbl_60d)|7759|7759|7741|99.7%|4.4%|
[et_block](#et_block)|904|18056697|5013|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|4679|0.0%|2.6%|
[openbl_30d](#openbl_30d)|4437|4437|4427|99.7%|2.5%|
[dshield](#dshield)|20|5120|3077|60.0%|1.7%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|1624|0.0%|0.9%|
[blocklist_de](#blocklist_de)|22102|22102|1509|6.8%|0.8%|
[et_compromised](#et_compromised)|2401|2401|1500|62.4%|0.8%|
[bruteforceblocker](#bruteforceblocker)|2392|2392|1497|62.5%|0.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|2134|2134|1279|59.9%|0.7%|
[openbl_7d](#openbl_7d)|986|986|981|99.4%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|518|0.0%|0.2%|
[openbl_1d](#openbl_1d)|357|357|355|99.4%|0.2%|
[ciarmy](#ciarmy)|334|334|331|99.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|293|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|229|0.2%|0.1%|
[voipbl](#voipbl)|10303|10775|204|1.8%|0.1%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|124|1.6%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|115|0.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12623|12623|107|0.8%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|88|37.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14566|14566|77|0.5%|0.0%|
[zeus](#zeus)|267|267|68|25.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7511|7511|62|0.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|695|695|59|8.4%|0.0%|
[shunlist](#shunlist)|51|51|51|100.0%|0.0%|
[et_tor](#et_tor)|6360|6360|45|0.7%|0.0%|
[dm_tor](#dm_tor)|6370|6370|44|0.6%|0.0%|
[bm_tor](#bm_tor)|6385|6385|44|0.6%|0.0%|
[nixspam](#nixspam)|20085|20085|43|0.2%|0.0%|
[zeus_badips](#zeus_badips)|230|230|37|16.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|23|6.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3488|3488|23|0.6%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|94|94|20|21.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1327|1327|18|1.3%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|15|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|285|285|15|5.2%|0.0%|
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
[xroxy](#xroxy)|1906|1906|3|0.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4524|4524|3|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|3|0.7%|0.0%|
[et_botnet](#et_botnet)|505|505|3|0.5%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1750|1750|2|0.1%|0.0%|
[proxyrss](#proxyrss)|1651|1651|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[feodo](#feodo)|67|67|1|1.4%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Fri May 29 03:42:05 UTC 2015.

The ipset `blocklist_de` has **22102** entries, **22102** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|14566|14566|14566|100.0%|65.9%|
[blocklist_de_apache](#blocklist_de_apache)|12623|12623|12623|100.0%|57.1%|
[blocklist_de_bots](#blocklist_de_bots)|3488|3488|3488|100.0%|15.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|2803|0.0%|12.6%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|2681|2.8%|12.1%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|2544|8.2%|11.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|2134|2134|2134|100.0%|9.6%|
[stopforumspam_1d](#stopforumspam_1d)|7511|7511|1624|21.6%|7.3%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|1509|0.8%|6.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|1485|0.0%|6.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|1456|0.0%|6.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1327|1327|1327|100.0%|6.0%|
[openbl_90d](#openbl_90d)|9850|9850|1282|13.0%|5.8%|
[openbl](#openbl)|9850|9850|1282|13.0%|5.8%|
[openbl_60d](#openbl_60d)|7759|7759|1230|15.8%|5.5%|
[openbl_30d](#openbl_30d)|4437|4437|1137|25.6%|5.1%|
[bruteforceblocker](#bruteforceblocker)|2392|2392|1074|44.8%|4.8%|
[et_compromised](#et_compromised)|2401|2401|1042|43.3%|4.7%|
[blocklist_de_imap](#blocklist_de_imap)|695|695|695|100.0%|3.1%|
[openbl_7d](#openbl_7d)|986|986|653|66.2%|2.9%|
[nixspam](#nixspam)|20085|20085|473|2.3%|2.1%|
[ri_web_proxies](#ri_web_proxies)|4524|4524|394|8.7%|1.7%|
[xroxy](#xroxy)|1906|1906|304|15.9%|1.3%|
[blocklist_de_ftp](#blocklist_de_ftp)|285|285|285|100.0%|1.2%|
[proxyrss](#proxyrss)|1651|1651|245|14.8%|1.1%|
[openbl_1d](#openbl_1d)|357|357|238|66.6%|1.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|234|100.0%|1.0%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|229|2.9%|1.0%|
[et_block](#et_block)|904|18056697|193|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|187|0.0%|0.8%|
[dshield](#dshield)|20|5120|160|3.1%|0.7%|
[ri_connect_proxies](#ri_connect_proxies)|1750|1750|87|4.9%|0.3%|
[php_commenters](#php_commenters)|281|281|76|27.0%|0.3%|
[php_bad](#php_bad)|281|281|75|26.6%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|94|94|75|79.7%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|74|0.0%|0.3%|
[php_dictionary](#php_dictionary)|433|433|70|16.1%|0.3%|
[php_spammers](#php_spammers)|417|417|65|15.5%|0.2%|
[voipbl](#voipbl)|10303|10775|36|0.3%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|36|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|34|13.2%|0.1%|
[ciarmy](#ciarmy)|334|334|28|8.3%|0.1%|
[et_tor](#et_tor)|6360|6360|22|0.3%|0.0%|
[dm_tor](#dm_tor)|6370|6370|22|0.3%|0.0%|
[bm_tor](#bm_tor)|6385|6385|22|0.3%|0.0%|
[proxz](#proxz)|97|97|19|19.5%|0.0%|
[shunlist](#shunlist)|51|51|13|25.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|6|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|3|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|509|509|2|0.3%|0.0%|
[zeus](#zeus)|267|267|1|0.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Fri May 29 03:56:07 UTC 2015.

The ipset `blocklist_de_apache` has **12623** entries, **12623** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22102|22102|12623|57.1%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|14566|14566|11059|75.9%|87.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|2200|0.0%|17.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1327|1327|1325|99.8%|10.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|1322|0.0%|10.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|1076|0.0%|8.5%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|218|0.2%|1.7%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|135|0.4%|1.0%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|107|0.0%|0.8%|
[stopforumspam_1d](#stopforumspam_1d)|7511|7511|86|1.1%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|36|15.3%|0.2%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|35|0.4%|0.2%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.1%|
[php_bad](#php_bad)|281|281|24|8.5%|0.1%|
[ciarmy](#ciarmy)|334|334|24|7.1%|0.1%|
[et_tor](#et_tor)|6360|6360|22|0.3%|0.1%|
[dm_tor](#dm_tor)|6370|6370|22|0.3%|0.1%|
[bm_tor](#bm_tor)|6385|6385|22|0.3%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3488|3488|17|0.4%|0.1%|
[openbl_90d](#openbl_90d)|9850|9850|13|0.1%|0.1%|
[openbl](#openbl)|9850|9850|13|0.1%|0.1%|
[nixspam](#nixspam)|20085|20085|11|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7759|7759|10|0.1%|0.0%|
[openbl_30d](#openbl_30d)|4437|4437|6|0.1%|0.0%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.0%|
[shunlist](#shunlist)|51|51|3|5.8%|0.0%|
[openbl_7d](#openbl_7d)|986|986|3|0.3%|0.0%|
[et_compromised](#et_compromised)|2401|2401|3|0.1%|0.0%|
[et_block](#et_block)|904|18056697|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2392|2392|3|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|2|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|509|509|2|0.3%|0.0%|
[xroxy](#xroxy)|1906|1906|1|0.0%|0.0%|
[voipbl](#voipbl)|10303|10775|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4524|4524|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1651|1651|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Fri May 29 03:42:13 UTC 2015.

The ipset `blocklist_de_bots` has **3488** entries, **3488** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22102|22102|3488|15.7%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|2373|2.5%|68.0%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|2360|7.6%|67.6%|
[stopforumspam_1d](#stopforumspam_1d)|7511|7511|1536|20.4%|44.0%|
[ri_web_proxies](#ri_web_proxies)|4524|4524|362|8.0%|10.3%|
[xroxy](#xroxy)|1906|1906|257|13.4%|7.3%|
[proxyrss](#proxyrss)|1651|1651|243|14.7%|6.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|151|0.0%|4.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|131|55.9%|3.7%|
[ri_connect_proxies](#ri_connect_proxies)|1750|1750|85|4.8%|2.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|83|0.0%|2.3%|
[php_commenters](#php_commenters)|281|281|60|21.3%|1.7%|
[php_bad](#php_bad)|281|281|60|21.3%|1.7%|
[nixspam](#nixspam)|20085|20085|58|0.2%|1.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|54|0.0%|1.5%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|53|0.0%|1.5%|
[et_block](#et_block)|904|18056697|53|0.0%|1.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|41|0.0%|1.1%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|31|0.4%|0.8%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|30|0.0%|0.8%|
[php_harvesters](#php_harvesters)|257|257|28|10.8%|0.8%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|23|0.0%|0.6%|
[proxz](#proxz)|97|97|18|18.5%|0.5%|
[php_spammers](#php_spammers)|417|417|18|4.3%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|14566|14566|17|0.1%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|12623|12623|17|0.1%|0.4%|
[php_dictionary](#php_dictionary)|433|433|12|2.7%|0.3%|
[openbl_90d](#openbl_90d)|9850|9850|2|0.0%|0.0%|
[openbl](#openbl)|9850|9850|2|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[voipbl](#voipbl)|10303|10775|1|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Fri May 29 03:42:15 UTC 2015.

The ipset `blocklist_de_bruteforce` has **1327** entries, **1327** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22102|22102|1327|6.0%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|12623|12623|1325|10.4%|99.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|113|0.0%|8.5%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|81|0.0%|6.1%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|75|0.2%|5.6%|
[stopforumspam_1d](#stopforumspam_1d)|7511|7511|51|0.6%|3.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|41|0.0%|3.0%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|32|0.4%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|29|0.0%|2.1%|
[et_tor](#et_tor)|6360|6360|20|0.3%|1.5%|
[dm_tor](#dm_tor)|6370|6370|19|0.2%|1.4%|
[bm_tor](#bm_tor)|6385|6385|19|0.2%|1.4%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|18|0.0%|1.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|11|4.7%|0.8%|
[nixspam](#nixspam)|20085|20085|10|0.0%|0.7%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.3%|
[php_commenters](#php_commenters)|281|281|5|1.7%|0.3%|
[php_bad](#php_bad)|281|281|5|1.7%|0.3%|
[openbl_90d](#openbl_90d)|9850|9850|5|0.0%|0.3%|
[openbl](#openbl)|9850|9850|5|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7759|7759|3|0.0%|0.2%|
[cleanmx_viruses](#cleanmx_viruses)|509|509|2|0.3%|0.1%|
[xroxy](#xroxy)|1906|1906|1|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4524|4524|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1651|1651|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4437|4437|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2401|2401|1|0.0%|0.0%|
[et_block](#et_block)|904|18056697|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2392|2392|1|0.0%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Fri May 29 03:42:12 UTC 2015.

The ipset `blocklist_de_ftp` has **285** entries, **285** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22102|22102|285|1.2%|100.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|23|0.0%|8.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|17|0.0%|5.9%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|15|0.0%|5.2%|
[openbl_90d](#openbl_90d)|9850|9850|9|0.0%|3.1%|
[openbl](#openbl)|9850|9850|9|0.0%|3.1%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|8|0.0%|2.8%|
[openbl_60d](#openbl_60d)|7759|7759|7|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|7|0.0%|2.4%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|3|0.0%|1.0%|
[openbl_30d](#openbl_30d)|4437|4437|3|0.0%|1.0%|
[nixspam](#nixspam)|20085|20085|3|0.0%|1.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.7%|
[openbl_7d](#openbl_7d)|986|986|2|0.2%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|2|0.8%|0.7%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|1|0.0%|0.3%|
[openbl_1d](#openbl_1d)|357|357|1|0.2%|0.3%|
[ciarmy](#ciarmy)|334|334|1|0.2%|0.3%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Fri May 29 03:42:12 UTC 2015.

The ipset `blocklist_de_imap` has **695** entries, **695** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|14566|14566|695|4.7%|100.0%|
[blocklist_de](#blocklist_de)|22102|22102|695|3.1%|100.0%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|59|0.0%|8.4%|
[openbl_90d](#openbl_90d)|9850|9850|49|0.4%|7.0%|
[openbl](#openbl)|9850|9850|49|0.4%|7.0%|
[openbl_60d](#openbl_60d)|7759|7759|46|0.5%|6.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|45|0.0%|6.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|45|0.0%|6.4%|
[openbl_30d](#openbl_30d)|4437|4437|42|0.9%|6.0%|
[openbl_7d](#openbl_7d)|986|986|26|2.6%|3.7%|
[et_compromised](#et_compromised)|2401|2401|14|0.5%|2.0%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|13|0.0%|1.8%|
[et_block](#et_block)|904|18056697|13|0.0%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|12|0.0%|1.7%|
[bruteforceblocker](#bruteforceblocker)|2392|2392|12|0.5%|1.7%|
[openbl_1d](#openbl_1d)|357|357|9|2.5%|1.2%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|6|0.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|2|0.0%|0.2%|
[shunlist](#shunlist)|51|51|2|3.9%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|2|0.8%|0.2%|
[voipbl](#voipbl)|10303|10775|1|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.1%|
[nixspam](#nixspam)|20085|20085|1|0.0%|0.1%|
[ciarmy](#ciarmy)|334|334|1|0.2%|0.1%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Fri May 29 03:42:11 UTC 2015.

The ipset `blocklist_de_mail` has **14566** entries, **14566** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22102|22102|14566|65.9%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|12623|12623|11059|87.6%|75.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|2285|0.0%|15.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|1347|0.0%|9.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|1175|0.0%|8.0%|
[blocklist_de_imap](#blocklist_de_imap)|695|695|695|100.0%|4.7%|
[nixspam](#nixspam)|20085|20085|399|1.9%|2.7%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|202|0.2%|1.3%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|162|2.1%|1.1%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|99|0.3%|0.6%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|77|0.0%|0.5%|
[openbl_90d](#openbl_90d)|9850|9850|61|0.6%|0.4%|
[openbl](#openbl)|9850|9850|61|0.6%|0.4%|
[php_dictionary](#php_dictionary)|433|433|58|13.3%|0.3%|
[openbl_60d](#openbl_60d)|7759|7759|58|0.7%|0.3%|
[openbl_30d](#openbl_30d)|4437|4437|51|1.1%|0.3%|
[xroxy](#xroxy)|1906|1906|45|2.3%|0.3%|
[php_spammers](#php_spammers)|417|417|42|10.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7511|7511|39|0.5%|0.2%|
[ri_web_proxies](#ri_web_proxies)|4524|4524|30|0.6%|0.2%|
[openbl_7d](#openbl_7d)|986|986|29|2.9%|0.1%|
[php_commenters](#php_commenters)|281|281|22|7.8%|0.1%|
[php_bad](#php_bad)|281|281|21|7.4%|0.1%|
[et_compromised](#et_compromised)|2401|2401|21|0.8%|0.1%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|19|0.0%|0.1%|
[et_block](#et_block)|904|18056697|19|0.0%|0.1%|
[bruteforceblocker](#bruteforceblocker)|2392|2392|19|0.7%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|18|7.6%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3488|3488|17|0.4%|0.1%|
[openbl_1d](#openbl_1d)|357|357|10|2.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|5|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|4|1.5%|0.0%|
[voipbl](#voipbl)|10303|10775|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6370|6370|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6385|6385|3|0.0%|0.0%|
[shunlist](#shunlist)|51|51|2|3.9%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1750|1750|2|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.0%|
[et_tor](#et_tor)|6360|6360|2|0.0%|0.0%|
[proxz](#proxz)|97|97|1|1.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[ciarmy](#ciarmy)|334|334|1|0.2%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Fri May 29 03:42:12 UTC 2015.

The ipset `blocklist_de_sip` has **94** entries, **94** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22102|22102|75|0.3%|79.7%|
[voipbl](#voipbl)|10303|10775|28|0.2%|29.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|21|0.0%|22.3%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|20|0.0%|21.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|7|0.0%|7.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|4|0.0%|4.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|2|0.0%|2.1%|
[et_botnet](#et_botnet)|505|505|1|0.1%|1.0%|
[ciarmy](#ciarmy)|334|334|1|0.2%|1.0%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Fri May 29 03:42:07 UTC 2015.

The ipset `blocklist_de_ssh` has **2134** entries, **2134** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22102|22102|2134|9.6%|100.0%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|1279|0.7%|59.9%|
[openbl_90d](#openbl_90d)|9850|9850|1197|12.1%|56.0%|
[openbl](#openbl)|9850|9850|1197|12.1%|56.0%|
[openbl_60d](#openbl_60d)|7759|7759|1155|14.8%|54.1%|
[openbl_30d](#openbl_30d)|4437|4437|1077|24.2%|50.4%|
[bruteforceblocker](#bruteforceblocker)|2392|2392|1052|43.9%|49.2%|
[et_compromised](#et_compromised)|2401|2401|1018|42.3%|47.7%|
[openbl_7d](#openbl_7d)|986|986|619|62.7%|29.0%|
[openbl_1d](#openbl_1d)|357|357|227|63.5%|10.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|204|0.0%|9.5%|
[dshield](#dshield)|20|5120|158|3.0%|7.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|119|0.0%|5.5%|
[et_block](#et_block)|904|18056697|118|0.0%|5.5%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|114|0.0%|5.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|79|33.7%|3.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|46|0.0%|2.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|13|0.0%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|8|0.0%|0.3%|
[shunlist](#shunlist)|51|51|8|15.6%|0.3%|
[voipbl](#voipbl)|10303|10775|3|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|3|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|3|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|2|0.0%|0.0%|
[nixspam](#nixspam)|20085|20085|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus](#zeus)|267|267|1|0.3%|0.0%|
[xroxy](#xroxy)|1906|1906|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7511|7511|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4524|4524|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1651|1651|1|0.0%|0.0%|
[ciarmy](#ciarmy)|334|334|1|0.2%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Fri May 29 03:56:11 UTC 2015.

The ipset `blocklist_de_strongips` has **234** entries, **234** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22102|22102|234|1.0%|100.0%|
[blocklist_de_bots](#blocklist_de_bots)|3488|3488|131|3.7%|55.9%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|130|0.1%|55.5%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|120|0.3%|51.2%|
[stopforumspam_1d](#stopforumspam_1d)|7511|7511|112|1.4%|47.8%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|88|0.0%|37.6%|
[openbl_90d](#openbl_90d)|9850|9850|80|0.8%|34.1%|
[openbl](#openbl)|9850|9850|80|0.8%|34.1%|
[openbl_60d](#openbl_60d)|7759|7759|79|1.0%|33.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|2134|2134|79|3.7%|33.7%|
[openbl_30d](#openbl_30d)|4437|4437|77|1.7%|32.9%|
[openbl_7d](#openbl_7d)|986|986|76|7.7%|32.4%|
[openbl_1d](#openbl_1d)|357|357|70|19.6%|29.9%|
[blocklist_de_apache](#blocklist_de_apache)|12623|12623|36|0.2%|15.3%|
[dshield](#dshield)|20|5120|34|0.6%|14.5%|
[php_commenters](#php_commenters)|281|281|33|11.7%|14.1%|
[php_bad](#php_bad)|281|281|33|11.7%|14.1%|
[et_compromised](#et_compromised)|2401|2401|23|0.9%|9.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|20|0.0%|8.5%|
[bruteforceblocker](#bruteforceblocker)|2392|2392|19|0.7%|8.1%|
[blocklist_de_mail](#blocklist_de_mail)|14566|14566|18|0.1%|7.6%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1327|1327|11|0.8%|4.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|8|0.0%|3.4%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|7|0.0%|2.9%|
[et_block](#et_block)|904|18056697|7|0.0%|2.9%|
[xroxy](#xroxy)|1906|1906|6|0.3%|2.5%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|6|0.0%|2.5%|
[php_spammers](#php_spammers)|417|417|5|1.1%|2.1%|
[ri_web_proxies](#ri_web_proxies)|4524|4524|3|0.0%|1.2%|
[proxyrss](#proxyrss)|1651|1651|3|0.1%|1.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.2%|
[nixspam](#nixspam)|20085|20085|2|0.0%|0.8%|
[blocklist_de_imap](#blocklist_de_imap)|695|695|2|0.2%|0.8%|
[blocklist_de_ftp](#blocklist_de_ftp)|285|285|2|0.7%|0.8%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|1|0.0%|0.4%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.4%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.4%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Fri May 29 03:45:06 UTC 2015.

The ipset `bm_tor` has **6385** entries, **6385** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[dm_tor](#dm_tor)|6370|6370|6277|98.5%|98.3%|
[et_tor](#et_tor)|6360|6360|5858|92.1%|91.7%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|1057|13.8%|16.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|618|0.0%|9.6%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|600|0.6%|9.3%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|462|1.4%|7.2%|
[stopforumspam_1d](#stopforumspam_1d)|7511|7511|329|4.3%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|182|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|179|48.1%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|163|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|44|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[php_bad](#php_bad)|281|281|29|10.3%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|12623|12623|22|0.1%|0.3%|
[blocklist_de](#blocklist_de)|22102|22102|22|0.0%|0.3%|
[openbl_90d](#openbl_90d)|9850|9850|21|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7759|7759|21|0.2%|0.3%|
[openbl](#openbl)|9850|9850|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|21|0.0%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1327|1327|19|1.4%|0.2%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4524|4524|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|904|18056697|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14566|14566|3|0.0%|0.0%|
[xroxy](#xroxy)|1906|1906|2|0.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1750|1750|2|0.1%|0.0%|
[voipbl](#voipbl)|10303|10775|1|0.0%|0.0%|
[proxz](#proxz)|97|97|1|1.0%|0.0%|
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
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2392|2392|1|0.0%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD)

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Fri May 29 02:27:07 UTC 2015.

The ipset `bruteforceblocker` has **2392** entries, **2392** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_compromised](#et_compromised)|2401|2401|2336|97.2%|97.6%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|1497|0.8%|62.5%|
[openbl_90d](#openbl_90d)|9850|9850|1429|14.5%|59.7%|
[openbl](#openbl)|9850|9850|1429|14.5%|59.7%|
[openbl_60d](#openbl_60d)|7759|7759|1413|18.2%|59.0%|
[openbl_30d](#openbl_30d)|4437|4437|1350|30.4%|56.4%|
[blocklist_de](#blocklist_de)|22102|22102|1074|4.8%|44.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|2134|2134|1052|49.2%|43.9%|
[openbl_7d](#openbl_7d)|986|986|508|51.5%|21.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|228|0.0%|9.5%|
[openbl_1d](#openbl_1d)|357|357|200|56.0%|8.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|143|0.0%|5.9%|
[dshield](#dshield)|20|5120|125|2.4%|5.2%|
[et_block](#et_block)|904|18056697|103|0.0%|4.3%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|102|0.0%|4.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|72|0.0%|3.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|19|8.1%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|14566|14566|19|0.1%|0.7%|
[blocklist_de_imap](#blocklist_de_imap)|695|695|12|1.7%|0.5%|
[shunlist](#shunlist)|51|51|9|17.6%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|6|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|3|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12623|12623|3|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7511|7511|2|0.0%|0.0%|
[proxyrss](#proxyrss)|1651|1651|2|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[zeus](#zeus)|267|267|1|0.3%|0.0%|
[xroxy](#xroxy)|1906|1906|1|0.0%|0.0%|
[voipbl](#voipbl)|10303|10775|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|1|0.0%|0.0%|
[proxz](#proxz)|97|97|1|1.0%|0.0%|
[fullbogons](#fullbogons)|3656|670735064|1|0.0%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1327|1327|1|0.0%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Fri May 29 01:15:15 UTC 2015.

The ipset `ciarmy` has **334** entries, **334** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|173474|173474|331|0.1%|99.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|62|0.0%|18.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|28|0.0%|8.3%|
[blocklist_de](#blocklist_de)|22102|22102|28|0.1%|8.3%|
[blocklist_de_apache](#blocklist_de_apache)|12623|12623|24|0.1%|7.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|16|0.0%|4.7%|
[voipbl](#voipbl)|10303|10775|3|0.0%|0.8%|
[shunlist](#shunlist)|51|51|2|3.9%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|1|0.0%|0.2%|
[openbl_90d](#openbl_90d)|9850|9850|1|0.0%|0.2%|
[openbl_7d](#openbl_7d)|986|986|1|0.1%|0.2%|
[openbl_60d](#openbl_60d)|7759|7759|1|0.0%|0.2%|
[openbl_30d](#openbl_30d)|4437|4437|1|0.0%|0.2%|
[openbl](#openbl)|9850|9850|1|0.0%|0.2%|
[dshield](#dshield)|20|5120|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2134|2134|1|0.0%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|94|94|1|1.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|14566|14566|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|695|695|1|0.1%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|285|285|1|0.3%|0.2%|

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
[alienvault_reputation](#alienvault_reputation)|173474|173474|10|0.0%|1.9%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|4|0.0%|0.7%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|3|0.2%|0.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|3|0.0%|0.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1327|1327|2|0.1%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|12623|12623|2|0.0%|0.3%|
[blocklist_de](#blocklist_de)|22102|22102|2|0.0%|0.3%|
[zeus](#zeus)|267|267|1|0.3%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|1|0.0%|0.1%|
[et_block](#et_block)|904|18056697|1|0.0%|0.1%|
[dshield](#dshield)|20|5120|1|0.0%|0.1%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Fri May 29 03:45:04 UTC 2015.

The ipset `dm_tor` has **6370** entries, **6370** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6385|6385|6277|98.3%|98.5%|
[et_tor](#et_tor)|6360|6360|5807|91.3%|91.1%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|1049|13.7%|16.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|616|0.0%|9.6%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|602|0.6%|9.4%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|463|1.4%|7.2%|
[stopforumspam_1d](#stopforumspam_1d)|7511|7511|329|4.3%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|183|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|179|48.1%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|163|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|44|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[php_bad](#php_bad)|281|281|29|10.3%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|12623|12623|22|0.1%|0.3%|
[blocklist_de](#blocklist_de)|22102|22102|22|0.0%|0.3%|
[openbl_90d](#openbl_90d)|9850|9850|21|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7759|7759|21|0.2%|0.3%|
[openbl](#openbl)|9850|9850|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|21|0.0%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1327|1327|19|1.4%|0.2%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4524|4524|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|904|18056697|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14566|14566|3|0.0%|0.0%|
[xroxy](#xroxy)|1906|1906|2|0.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1750|1750|2|0.1%|0.0%|
[voipbl](#voipbl)|10303|10775|1|0.0%|0.0%|
[proxz](#proxz)|97|97|1|1.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Fri May 29 02:55:59 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|173474|173474|3077|1.7%|60.0%|
[et_block](#et_block)|904|18056697|768|0.0%|15.0%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|512|0.0%|10.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|256|0.0%|5.0%|
[openbl_90d](#openbl_90d)|9850|9850|189|1.9%|3.6%|
[openbl](#openbl)|9850|9850|189|1.9%|3.6%|
[openbl_60d](#openbl_60d)|7759|7759|185|2.3%|3.6%|
[openbl_30d](#openbl_30d)|4437|4437|166|3.7%|3.2%|
[blocklist_de](#blocklist_de)|22102|22102|160|0.7%|3.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|2134|2134|158|7.4%|3.0%|
[bruteforceblocker](#bruteforceblocker)|2392|2392|125|5.2%|2.4%|
[openbl_7d](#openbl_7d)|986|986|123|12.4%|2.4%|
[et_compromised](#et_compromised)|2401|2401|120|4.9%|2.3%|
[openbl_1d](#openbl_1d)|357|357|65|18.2%|1.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|34|14.5%|0.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|4|0.0%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|4|0.0%|0.0%|
[malc0de](#malc0de)|411|411|3|0.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12623|12623|2|0.0%|0.0%|
[nixspam](#nixspam)|20085|20085|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|509|509|1|0.1%|0.0%|
[ciarmy](#ciarmy)|334|334|1|0.2%|0.0%|

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
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|8401954|2.4%|46.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7211008|78.5%|39.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|2133269|0.2%|11.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|195924|0.1%|1.0%|
[fullbogons](#fullbogons)|3656|670735064|20480|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|5013|2.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1042|0.3%|0.0%|
[dshield](#dshield)|20|5120|768|15.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|759|0.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|517|0.1%|0.0%|
[openbl_90d](#openbl_90d)|9850|9850|450|4.5%|0.0%|
[openbl](#openbl)|9850|9850|450|4.5%|0.0%|
[openbl_60d](#openbl_60d)|7759|7759|269|3.4%|0.0%|
[zeus](#zeus)|267|267|262|98.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|229|2.9%|0.0%|
[zeus_badips](#zeus_badips)|230|230|228|99.1%|0.0%|
[openbl_30d](#openbl_30d)|4437|4437|208|4.6%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|205|0.6%|0.0%|
[blocklist_de](#blocklist_de)|22102|22102|193|0.8%|0.0%|
[nixspam](#nixspam)|20085|20085|175|0.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2134|2134|118|5.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2392|2392|103|4.3%|0.0%|
[et_compromised](#et_compromised)|2401|2401|98|4.0%|0.0%|
[openbl_7d](#openbl_7d)|986|986|82|8.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3488|3488|53|1.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7511|7511|48|0.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|28|2.1%|0.0%|
[openbl_1d](#openbl_1d)|357|357|26|7.2%|0.0%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.0%|
[php_bad](#php_bad)|281|281|24|8.5%|0.0%|
[voipbl](#voipbl)|10303|10775|19|0.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14566|14566|19|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|695|695|13|1.8%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|7|2.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[sslbl](#sslbl)|345|345|3|0.8%|0.0%|
[et_tor](#et_tor)|6360|6360|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6370|6370|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6385|6385|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12623|12623|3|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[malc0de](#malc0de)|411|411|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[et_botnet](#et_botnet)|505|505|1|0.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|509|509|1|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1327|1327|1|0.0%|0.0%|

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
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|74|0.0%|14.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|41|0.0%|8.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|21|0.0%|4.1%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|3|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[et_block](#et_block)|904|18056697|1|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|94|94|1|1.0%|0.1%|

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
[bruteforceblocker](#bruteforceblocker)|2392|2392|2336|97.6%|97.2%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|1500|0.8%|62.4%|
[openbl_90d](#openbl_90d)|9850|9850|1427|14.4%|59.4%|
[openbl](#openbl)|9850|9850|1427|14.4%|59.4%|
[openbl_60d](#openbl_60d)|7759|7759|1412|18.1%|58.8%|
[openbl_30d](#openbl_30d)|4437|4437|1346|30.3%|56.0%|
[blocklist_de](#blocklist_de)|22102|22102|1042|4.7%|43.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|2134|2134|1018|47.7%|42.3%|
[openbl_7d](#openbl_7d)|986|986|500|50.7%|20.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|230|0.0%|9.5%|
[openbl_1d](#openbl_1d)|357|357|204|57.1%|8.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|148|0.0%|6.1%|
[dshield](#dshield)|20|5120|120|2.3%|4.9%|
[et_block](#et_block)|904|18056697|98|0.0%|4.0%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|97|0.0%|4.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|74|0.0%|3.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|23|9.8%|0.9%|
[blocklist_de_mail](#blocklist_de_mail)|14566|14566|21|0.1%|0.8%|
[blocklist_de_imap](#blocklist_de_imap)|695|695|14|2.0%|0.5%|
[shunlist](#shunlist)|51|51|9|17.6%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|6|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|3|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12623|12623|3|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7511|7511|2|0.0%|0.0%|
[proxyrss](#proxyrss)|1651|1651|2|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[zeus](#zeus)|267|267|1|0.3%|0.0%|
[xroxy](#xroxy)|1906|1906|1|0.0%|0.0%|
[voipbl](#voipbl)|10303|10775|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|1|0.0%|0.0%|
[proxz](#proxz)|97|97|1|1.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1327|1327|1|0.0%|0.0%|

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
[bm_tor](#bm_tor)|6385|6385|5858|91.7%|92.1%|
[dm_tor](#dm_tor)|6370|6370|5807|91.1%|91.3%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|1068|13.9%|16.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|607|0.0%|9.5%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|601|0.6%|9.4%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|465|1.5%|7.3%|
[stopforumspam_1d](#stopforumspam_1d)|7511|7511|329|4.3%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|182|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|178|47.8%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|166|0.0%|2.6%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|45|0.0%|0.7%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[php_bad](#php_bad)|281|281|29|10.3%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|12623|12623|22|0.1%|0.3%|
[blocklist_de](#blocklist_de)|22102|22102|22|0.0%|0.3%|
[openbl_90d](#openbl_90d)|9850|9850|21|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7759|7759|21|0.2%|0.3%|
[openbl](#openbl)|9850|9850|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|21|0.0%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1327|1327|20|1.5%|0.3%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4524|4524|5|0.1%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|904|18056697|3|0.0%|0.0%|
[xroxy](#xroxy)|1906|1906|2|0.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1750|1750|2|0.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14566|14566|2|0.0%|0.0%|
[voipbl](#voipbl)|10303|10775|1|0.0%|0.0%|
[proxz](#proxz)|97|97|1|1.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Fri May 29 03:45:15 UTC 2015.

The ipset `feodo` has **67** entries, **67** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[snort_ipfilter](#snort_ipfilter)|7652|7652|53|0.6%|79.1%|
[sslbl](#sslbl)|345|345|24|6.9%|35.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|4|0.0%|5.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|3|0.0%|4.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|3|0.0%|4.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|1.4%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|1|0.0%|1.4%|

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
[spamhaus_drop](#spamhaus_drop)|639|17921280|20480|0.1%|0.0%|
[et_block](#et_block)|904|18056697|20480|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|894|0.2%|0.0%|
[voipbl](#voipbl)|10303|10775|351|3.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|33|2.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|9|0.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2392|2392|1|0.0%|0.0%|

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
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|16|0.0%|0.0%|
[fullbogons](#fullbogons)|3656|670735064|14|0.0%|0.0%|
[nixspam](#nixspam)|20085|20085|13|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|13|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.0%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|6|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|6|0.0%|0.0%|
[et_block](#et_block)|904|18056697|6|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|5|0.0%|0.0%|
[xroxy](#xroxy)|1906|1906|3|0.1%|0.0%|
[voipbl](#voipbl)|10303|10775|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7511|7511|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4524|4524|1|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14566|14566|1|0.0%|0.0%|
[blocklist_de](#blocklist_de)|22102|22102|1|0.0%|0.0%|

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
[et_block](#et_block)|904|18056697|7211008|39.9%|78.5%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|7079936|39.5%|77.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|2526625|0.7%|27.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|904796|0.1%|9.8%|
[fullbogons](#fullbogons)|3656|670735064|565248|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|145472|0.1%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1036|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|745|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|518|0.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|194|0.6%|0.0%|
[nixspam](#nixspam)|20085|20085|174|0.8%|0.0%|
[blocklist_de](#blocklist_de)|22102|22102|74|0.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3488|3488|54|1.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7511|7511|49|0.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|27|2.1%|0.0%|
[openbl_90d](#openbl_90d)|9850|9850|19|0.1%|0.0%|
[openbl](#openbl)|9850|9850|19|0.1%|0.0%|
[openbl_60d](#openbl_60d)|7759|7759|18|0.2%|0.0%|
[openbl_30d](#openbl_30d)|4437|4437|13|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2134|2134|13|0.6%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|11|0.1%|0.0%|
[zeus_badips](#zeus_badips)|230|230|10|4.3%|0.0%|
[zeus](#zeus)|267|267|10|3.7%|0.0%|
[openbl_7d](#openbl_7d)|986|986|8|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[openbl_1d](#openbl_1d)|357|357|5|1.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2392|2392|5|0.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14566|14566|5|0.0%|0.0%|
[et_compromised](#et_compromised)|2401|2401|4|0.1%|0.0%|
[et_tor](#et_tor)|6360|6360|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6370|6370|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6385|6385|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|3|1.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|695|695|3|0.4%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12623|12623|2|0.0%|0.0%|
[voipbl](#voipbl)|10303|10775|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.0%|
[php_bad](#php_bad)|281|281|1|0.3%|0.0%|
[et_botnet](#et_botnet)|505|505|1|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1327|1327|1|0.0%|0.0%|

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
[et_block](#et_block)|904|18056697|2133269|11.8%|0.2%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|2133002|11.9%|0.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|1360049|0.9%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904796|9.8%|0.1%|
[fullbogons](#fullbogons)|3656|670735064|235151|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|33155|7.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|13328|3.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|4679|2.6%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|1527|1.6%|0.0%|
[blocklist_de](#blocklist_de)|22102|22102|1485|6.7%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14566|14566|1347|9.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12623|12623|1322|10.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|580|1.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|432|0.8%|0.0%|
[nixspam](#nixspam)|20085|20085|358|1.7%|0.0%|
[voipbl](#voipbl)|10303|10775|301|2.7%|0.0%|
[openbl_90d](#openbl_90d)|9850|9850|219|2.2%|0.0%|
[openbl](#openbl)|9850|9850|219|2.2%|0.0%|
[openbl_60d](#openbl_60d)|7759|7759|180|2.3%|0.0%|
[et_tor](#et_tor)|6360|6360|166|2.6%|0.0%|
[dm_tor](#dm_tor)|6370|6370|163|2.5%|0.0%|
[bm_tor](#bm_tor)|6385|6385|163|2.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7511|7511|150|1.9%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4524|4524|107|2.3%|0.0%|
[openbl_30d](#openbl_30d)|4437|4437|100|2.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|98|6.7%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|86|1.1%|0.0%|
[et_compromised](#et_compromised)|2401|2401|74|3.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2392|2392|72|3.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|66|5.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1750|1750|62|3.5%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|58|8.6%|0.0%|
[xroxy](#xroxy)|1906|1906|51|2.6%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2134|2134|46|2.1%|0.0%|
[et_botnet](#et_botnet)|505|505|41|8.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3488|3488|41|1.1%|0.0%|
[proxyrss](#proxyrss)|1651|1651|36|2.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1327|1327|29|2.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|17|4.5%|0.0%|
[openbl_7d](#openbl_7d)|986|986|16|1.6%|0.0%|
[ciarmy](#ciarmy)|334|334|16|4.7%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|509|509|14|2.7%|0.0%|
[malc0de](#malc0de)|411|411|12|2.9%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|695|695|12|1.7%|0.0%|
[php_dictionary](#php_dictionary)|433|433|9|2.0%|0.0%|
[zeus](#zeus)|267|267|8|2.9%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[openbl_1d](#openbl_1d)|357|357|7|1.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|285|285|7|2.4%|0.0%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.0%|
[php_commenters](#php_commenters)|281|281|5|1.7%|0.0%|
[php_bad](#php_bad)|281|281|5|1.7%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[zeus_badips](#zeus_badips)|230|230|4|1.7%|0.0%|
[proxz](#proxz)|97|97|4|4.1%|0.0%|
[dshield](#dshield)|20|5120|4|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|94|94|4|4.2%|0.0%|
[sslbl](#sslbl)|345|345|3|0.8%|0.0%|
[feodo](#feodo)|67|67|3|4.4%|0.0%|

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
[et_block](#et_block)|904|18056697|8401954|46.5%|2.4%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|8401434|46.8%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|2832265|2.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2526625|27.5%|0.7%|
[fullbogons](#fullbogons)|3656|670735064|248327|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|33368|7.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|7878|4.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|7752|2.2%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|2490|2.6%|0.0%|
[blocklist_de](#blocklist_de)|22102|22102|1456|6.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14566|14566|1175|8.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12623|12623|1076|8.5%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|904|2.9%|0.0%|
[nixspam](#nixspam)|20085|20085|522|2.5%|0.0%|
[openbl_90d](#openbl_90d)|9850|9850|507|5.1%|0.0%|
[openbl](#openbl)|9850|9850|507|5.1%|0.0%|
[voipbl](#voipbl)|10303|10775|428|3.9%|0.0%|
[openbl_60d](#openbl_60d)|7759|7759|361|4.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|233|0.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7511|7511|227|3.0%|0.0%|
[openbl_30d](#openbl_30d)|4437|4437|227|5.1%|0.0%|
[dm_tor](#dm_tor)|6370|6370|183|2.8%|0.0%|
[et_tor](#et_tor)|6360|6360|182|2.8%|0.0%|
[bm_tor](#bm_tor)|6385|6385|182|2.8%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4524|4524|161|3.5%|0.0%|
[et_compromised](#et_compromised)|2401|2401|148|6.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2392|2392|143|5.9%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2134|2134|119|5.5%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|112|1.4%|0.0%|
[xroxy](#xroxy)|1906|1906|88|4.6%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3488|3488|83|2.3%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1750|1750|76|4.3%|0.0%|
[proxyrss](#proxyrss)|1651|1651|70|4.2%|0.0%|
[openbl_7d](#openbl_7d)|986|986|52|5.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|45|3.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|695|695|45|6.4%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1327|1327|41|3.0%|0.0%|
[php_spammers](#php_spammers)|417|417|31|7.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|28|4.1%|0.0%|
[ciarmy](#ciarmy)|334|334|28|8.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|26|2.0%|0.0%|
[malc0de](#malc0de)|411|411|26|6.3%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|285|285|23|8.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|509|509|22|4.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|21|5.6%|0.0%|
[et_botnet](#et_botnet)|505|505|21|4.1%|0.0%|
[openbl_1d](#openbl_1d)|357|357|17|4.7%|0.0%|
[php_dictionary](#php_dictionary)|433|433|10|2.3%|0.0%|
[zeus](#zeus)|267|267|9|3.3%|0.0%|
[php_commenters](#php_commenters)|281|281|9|3.2%|0.0%|
[php_bad](#php_bad)|281|281|9|3.2%|0.0%|
[zeus_badips](#zeus_badips)|230|230|8|3.4%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|8|3.4%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|94|94|7|7.4%|0.0%|
[sslbl](#sslbl)|345|345|6|1.7%|0.0%|
[proxz](#proxz)|97|97|4|4.1%|0.0%|
[shunlist](#shunlist)|51|51|3|5.8%|0.0%|
[palevo](#palevo)|13|13|3|23.0%|0.0%|
[feodo](#feodo)|67|67|3|4.4%|0.0%|

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
[et_block](#et_block)|904|18056697|195924|1.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|195904|1.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|14916|8.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|9278|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|6195|6.6%|0.0%|
[blocklist_de](#blocklist_de)|22102|22102|2803|12.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14566|14566|2285|15.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12623|12623|2200|17.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|2103|6.7%|0.0%|
[voipbl](#voipbl)|10303|10775|1588|14.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1172|2.4%|0.0%|
[openbl_90d](#openbl_90d)|9850|9850|948|9.6%|0.0%|
[openbl](#openbl)|9850|9850|948|9.6%|0.0%|
[nixspam](#nixspam)|20085|20085|916|4.5%|0.0%|
[openbl_60d](#openbl_60d)|7759|7759|721|9.2%|0.0%|
[bm_tor](#bm_tor)|6385|6385|618|9.6%|0.0%|
[dm_tor](#dm_tor)|6370|6370|616|9.6%|0.0%|
[et_tor](#et_tor)|6360|6360|607|9.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7511|7511|509|6.7%|0.0%|
[openbl_30d](#openbl_30d)|4437|4437|445|10.0%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|237|3.0%|0.0%|
[et_compromised](#et_compromised)|2401|2401|230|9.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2392|2392|228|9.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2134|2134|204|9.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3488|3488|151|4.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|146|11.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4524|4524|142|3.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|125|33.6%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1327|1327|113|8.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|110|7.5%|0.0%|
[openbl_7d](#openbl_7d)|986|986|94|9.5%|0.0%|
[malc0de](#malc0de)|411|411|76|18.4%|0.0%|
[et_botnet](#et_botnet)|505|505|74|14.6%|0.0%|
[xroxy](#xroxy)|1906|1906|73|3.8%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|509|509|73|14.3%|0.0%|
[ciarmy](#ciarmy)|334|334|62|18.5%|0.0%|
[proxyrss](#proxyrss)|1651|1651|54|3.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|51|7.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|695|695|45|6.4%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1750|1750|41|2.3%|0.0%|
[php_spammers](#php_spammers)|417|417|26|6.2%|0.0%|
[php_dictionary](#php_dictionary)|433|433|24|5.5%|0.0%|
[sslbl](#sslbl)|345|345|22|6.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|94|94|21|22.3%|0.0%|
[openbl_1d](#openbl_1d)|357|357|20|5.6%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|20|8.5%|0.0%|
[zeus](#zeus)|267|267|19|7.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|285|285|17|5.9%|0.0%|
[php_bad](#php_bad)|281|281|16|5.6%|0.0%|
[php_harvesters](#php_harvesters)|257|257|15|5.8%|0.0%|
[php_commenters](#php_commenters)|281|281|15|5.3%|0.0%|
[zeus_badips](#zeus_badips)|230|230|14|6.0%|0.0%|
[proxz](#proxz)|97|97|11|11.3%|0.0%|
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
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|22|0.0%|3.2%|
[xroxy](#xroxy)|1906|1906|12|0.6%|1.7%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|11|0.0%|1.6%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|10|0.0%|1.4%|
[ri_web_proxies](#ri_web_proxies)|4524|4524|10|0.2%|1.4%|
[stopforumspam_1d](#stopforumspam_1d)|7511|7511|7|0.0%|1.0%|
[proxyrss](#proxyrss)|1651|1651|7|0.4%|1.0%|
[ri_connect_proxies](#ri_connect_proxies)|1750|1750|6|0.3%|0.8%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|2|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.2%|
[et_block](#et_block)|904|18056697|2|0.0%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3488|3488|2|0.0%|0.2%|
[blocklist_de](#blocklist_de)|22102|22102|2|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|1|0.0%|0.1%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.1%|
[nixspam](#nixspam)|20085|20085|1|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|1|0.0%|0.1%|

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
[et_block](#et_block)|904|18056697|1042|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|1037|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1036|0.0%|0.3%|
[fullbogons](#fullbogons)|3656|670735064|894|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|293|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|44|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|25|1.9%|0.0%|
[et_tor](#et_tor)|6360|6360|21|0.3%|0.0%|
[dm_tor](#dm_tor)|6370|6370|21|0.3%|0.0%|
[bm_tor](#bm_tor)|6385|6385|21|0.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|19|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|19|1.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|15|0.1%|0.0%|
[nixspam](#nixspam)|20085|20085|14|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7511|7511|7|0.0%|0.0%|
[openbl_90d](#openbl_90d)|9850|9850|6|0.0%|0.0%|
[openbl](#openbl)|9850|9850|6|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[blocklist_de](#blocklist_de)|22102|22102|6|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7759|7759|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|5|1.3%|0.0%|
[voipbl](#voipbl)|10303|10775|4|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4524|4524|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4437|4437|4|0.0%|0.0%|
[dshield](#dshield)|20|5120|4|0.0%|0.0%|
[malc0de](#malc0de)|411|411|3|0.7%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|509|509|3|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2134|2134|3|0.1%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|94|94|2|2.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12623|12623|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[zeus](#zeus)|267|267|1|0.3%|0.0%|
[xroxy](#xroxy)|1906|1906|1|0.0%|0.0%|
[sslbl](#sslbl)|345|345|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.0%|
[openbl_7d](#openbl_7d)|986|986|1|0.1%|0.0%|
[feodo](#feodo)|67|67|1|1.4%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14566|14566|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3488|3488|1|0.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|173474|173474|8|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|6|0.0%|0.4%|
[et_block](#et_block)|904|18056697|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|3|0.2%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|2|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|2|0.0%|0.1%|
[openbl_90d](#openbl_90d)|9850|9850|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7759|7759|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|4437|4437|2|0.0%|0.1%|
[openbl](#openbl)|9850|9850|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.1%|
[et_compromised](#et_compromised)|2401|2401|2|0.0%|0.1%|
[bruteforceblocker](#bruteforceblocker)|2392|2392|2|0.0%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|2134|2134|2|0.0%|0.1%|
[blocklist_de](#blocklist_de)|22102|22102|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7511|7511|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4524|4524|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|986|986|1|0.1%|0.0%|
[openbl_1d](#openbl_1d)|357|357|1|0.2%|0.0%|
[nixspam](#nixspam)|20085|20085|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_tor](#et_tor)|6360|6360|1|0.0%|0.0%|
[et_botnet](#et_botnet)|505|505|1|0.1%|0.0%|
[dm_tor](#dm_tor)|6370|6370|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6385|6385|1|0.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|173474|173474|10|0.0%|2.4%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|4|0.3%|0.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|3|0.0%|0.7%|
[dshield](#dshield)|20|5120|3|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|2|0.0%|0.4%|
[et_block](#et_block)|904|18056697|2|0.0%|0.4%|
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
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|146|0.0%|11.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|66|0.0%|5.1%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|29|0.0%|2.2%|
[et_block](#et_block)|904|18056697|28|0.0%|2.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|26|0.0%|2.0%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|25|0.3%|1.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|25|0.0%|1.9%|
[fullbogons](#fullbogons)|3656|670735064|9|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|7|0.0%|0.5%|
[malc0de](#malc0de)|411|411|4|0.9%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.2%|
[cleanmx_viruses](#cleanmx_viruses)|509|509|3|0.5%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|2|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7511|7511|1|0.0%|0.0%|
[nixspam](#nixspam)|20085|20085|1|0.0%|0.0%|
[et_botnet](#et_botnet)|505|505|1|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3488|3488|1|0.0%|0.0%|
[blocklist_de](#blocklist_de)|22102|22102|1|0.0%|0.0%|

## maxmind_proxy_fraud

[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.

Source is downloaded from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list).

The last time downloaded was found to be dated: Fri May 29 03:54:18 UTC 2015.

The ipset `maxmind_proxy_fraud` has **372** entries, **372** unique IPs.

The following table shows the overlaps of `maxmind_proxy_fraud` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `maxmind_proxy_fraud`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `maxmind_proxy_fraud`.
- ` this % ` is the percentage **of this ipset (`maxmind_proxy_fraud`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|236|0.2%|63.4%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|200|0.6%|53.7%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|185|2.4%|49.7%|
[dm_tor](#dm_tor)|6370|6370|179|2.8%|48.1%|
[bm_tor](#bm_tor)|6385|6385|179|2.8%|48.1%|
[et_tor](#et_tor)|6360|6360|178|2.7%|47.8%|
[stopforumspam_1d](#stopforumspam_1d)|7511|7511|169|2.2%|45.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|125|0.0%|33.6%|
[php_commenters](#php_commenters)|281|281|28|9.9%|7.5%|
[php_bad](#php_bad)|281|281|28|9.9%|7.5%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|23|0.0%|6.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|21|0.0%|5.6%|
[openbl_90d](#openbl_90d)|9850|9850|18|0.1%|4.8%|
[openbl_60d](#openbl_60d)|7759|7759|18|0.2%|4.8%|
[openbl](#openbl)|9850|9850|18|0.1%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|17|0.0%|4.5%|
[php_harvesters](#php_harvesters)|257|257|6|2.3%|1.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|5|0.0%|1.3%|
[ri_web_proxies](#ri_web_proxies)|4524|4524|4|0.0%|1.0%|
[php_spammers](#php_spammers)|417|417|4|0.9%|1.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|1.0%|
[blocklist_de](#blocklist_de)|22102|22102|3|0.0%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|14566|14566|2|0.0%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|12623|12623|2|0.0%|0.5%|
[xroxy](#xroxy)|1906|1906|1|0.0%|0.2%|
[voipbl](#voipbl)|10303|10775|1|0.0%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|1750|1750|1|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1327|1327|1|0.0%|0.2%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Fri May 29 04:00:02 UTC 2015.

The ipset `nixspam` has **20085** entries, **20085** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|916|0.0%|4.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|522|0.0%|2.5%|
[blocklist_de](#blocklist_de)|22102|22102|473|2.1%|2.3%|
[blocklist_de_mail](#blocklist_de_mail)|14566|14566|399|2.7%|1.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|358|0.0%|1.7%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|254|3.3%|1.2%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|239|0.2%|1.1%|
[et_block](#et_block)|904|18056697|175|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|174|0.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|174|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|153|0.4%|0.7%|
[php_dictionary](#php_dictionary)|433|433|86|19.8%|0.4%|
[xroxy](#xroxy)|1906|1906|81|4.2%|0.4%|
[ri_web_proxies](#ri_web_proxies)|4524|4524|78|1.7%|0.3%|
[php_spammers](#php_spammers)|417|417|73|17.5%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7511|7511|71|0.9%|0.3%|
[blocklist_de_bots](#blocklist_de_bots)|3488|3488|58|1.6%|0.2%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|43|0.0%|0.2%|
[proxyrss](#proxyrss)|1651|1651|18|1.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1750|1750|15|0.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|14|0.0%|0.0%|
[openbl_90d](#openbl_90d)|9850|9850|13|0.1%|0.0%|
[openbl](#openbl)|9850|9850|13|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|13|0.0%|0.0%|
[php_commenters](#php_commenters)|281|281|11|3.9%|0.0%|
[openbl_60d](#openbl_60d)|7759|7759|11|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12623|12623|11|0.0%|0.0%|
[php_bad](#php_bad)|281|281|10|3.5%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1327|1327|10|0.7%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[openbl_30d](#openbl_30d)|4437|4437|5|0.1%|0.0%|
[proxz](#proxz)|97|97|3|3.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|285|285|3|1.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|2|0.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2134|2134|2|0.0%|0.0%|
[voipbl](#voipbl)|10303|10775|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[shunlist](#shunlist)|51|51|1|1.9%|0.0%|
[openbl_7d](#openbl_7d)|986|986|1|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|695|695|1|0.1%|0.0%|

## openbl

[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**

Source is downloaded from [this link](http://www.openbl.org/lists/base.txt.gz).

The last time downloaded was found to be dated: Fri May 29 03:32:01 UTC 2015.

The ipset `openbl` has **9850** entries, **9850** unique IPs.

The following table shows the overlaps of `openbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl`.
- ` this % ` is the percentage **of this ipset (`openbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9850|9850|9850|100.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|9829|5.6%|99.7%|
[openbl_60d](#openbl_60d)|7759|7759|7759|100.0%|78.7%|
[openbl_30d](#openbl_30d)|4437|4437|4437|100.0%|45.0%|
[bruteforceblocker](#bruteforceblocker)|2392|2392|1429|59.7%|14.5%|
[et_compromised](#et_compromised)|2401|2401|1427|59.4%|14.4%|
[blocklist_de](#blocklist_de)|22102|22102|1282|5.8%|13.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2134|2134|1197|56.0%|12.1%|
[openbl_7d](#openbl_7d)|986|986|986|100.0%|10.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|948|0.0%|9.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|507|0.0%|5.1%|
[et_block](#et_block)|904|18056697|450|0.0%|4.5%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|447|0.0%|4.5%|
[openbl_1d](#openbl_1d)|357|357|357|100.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|219|0.0%|2.2%|
[dshield](#dshield)|20|5120|189|3.6%|1.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|80|34.1%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|66|0.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|14566|14566|61|0.4%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|695|695|49|7.0%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|33|0.1%|0.3%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|29|0.3%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7511|7511|23|0.3%|0.2%|
[et_tor](#et_tor)|6360|6360|21|0.3%|0.2%|
[dm_tor](#dm_tor)|6370|6370|21|0.3%|0.2%|
[bm_tor](#bm_tor)|6385|6385|21|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|19|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|14|0.0%|0.1%|
[nixspam](#nixspam)|20085|20085|13|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12623|12623|13|0.1%|0.1%|
[voipbl](#voipbl)|10303|10775|12|0.1%|0.1%|
[shunlist](#shunlist)|51|51|11|21.5%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|285|285|9|3.1%|0.0%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.0%|
[php_bad](#php_bad)|281|281|8|2.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|6|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|5|1.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1327|1327|5|0.3%|0.0%|
[zeus](#zeus)|267|267|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3488|3488|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[sslbl](#sslbl)|345|345|1|0.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4524|4524|1|0.0%|0.0%|
[ciarmy](#ciarmy)|334|334|1|0.2%|0.0%|

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
[openbl_90d](#openbl_90d)|9850|9850|357|3.6%|100.0%|
[openbl_60d](#openbl_60d)|7759|7759|357|4.6%|100.0%|
[openbl_30d](#openbl_30d)|4437|4437|357|8.0%|100.0%|
[openbl](#openbl)|9850|9850|357|3.6%|100.0%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|355|0.2%|99.4%|
[blocklist_de](#blocklist_de)|22102|22102|238|1.0%|66.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|2134|2134|227|10.6%|63.5%|
[openbl_7d](#openbl_7d)|986|986|205|20.7%|57.4%|
[et_compromised](#et_compromised)|2401|2401|204|8.4%|57.1%|
[bruteforceblocker](#bruteforceblocker)|2392|2392|200|8.3%|56.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|70|29.9%|19.6%|
[dshield](#dshield)|20|5120|65|1.2%|18.2%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|26|0.0%|7.2%|
[et_block](#et_block)|904|18056697|26|0.0%|7.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|20|0.0%|5.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|17|0.0%|4.7%|
[blocklist_de_mail](#blocklist_de_mail)|14566|14566|10|0.0%|2.8%|
[blocklist_de_imap](#blocklist_de_imap)|695|695|9|1.2%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|7|0.0%|1.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|1.4%|
[shunlist](#shunlist)|51|51|2|3.9%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|1|0.0%|0.2%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|1|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|285|285|1|0.3%|0.2%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt.gz).

The last time downloaded was found to be dated: Fri May 29 03:32:00 UTC 2015.

The ipset `openbl_30d` has **4437** entries, **4437** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9850|9850|4437|45.0%|100.0%|
[openbl_60d](#openbl_60d)|7759|7759|4437|57.1%|100.0%|
[openbl](#openbl)|9850|9850|4437|45.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|4427|2.5%|99.7%|
[bruteforceblocker](#bruteforceblocker)|2392|2392|1350|56.4%|30.4%|
[et_compromised](#et_compromised)|2401|2401|1346|56.0%|30.3%|
[blocklist_de](#blocklist_de)|22102|22102|1137|5.1%|25.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|2134|2134|1077|50.4%|24.2%|
[openbl_7d](#openbl_7d)|986|986|986|100.0%|22.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|445|0.0%|10.0%|
[openbl_1d](#openbl_1d)|357|357|357|100.0%|8.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|227|0.0%|5.1%|
[et_block](#et_block)|904|18056697|208|0.0%|4.6%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|206|0.0%|4.6%|
[dshield](#dshield)|20|5120|166|3.2%|3.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|100|0.0%|2.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|77|32.9%|1.7%|
[blocklist_de_mail](#blocklist_de_mail)|14566|14566|51|0.3%|1.1%|
[blocklist_de_imap](#blocklist_de_imap)|695|695|42|6.0%|0.9%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|18|0.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|13|0.0%|0.2%|
[shunlist](#shunlist)|51|51|10|19.6%|0.2%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|6|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12623|12623|6|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|5|0.0%|0.1%|
[nixspam](#nixspam)|20085|20085|5|0.0%|0.1%|
[voipbl](#voipbl)|10303|10775|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|4|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|285|285|3|1.0%|0.0%|
[zeus](#zeus)|267|267|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7511|7511|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|334|334|1|0.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1327|1327|1|0.0%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt.gz).

The last time downloaded was found to be dated: Fri May 29 03:32:01 UTC 2015.

The ipset `openbl_60d` has **7759** entries, **7759** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9850|9850|7759|78.7%|100.0%|
[openbl](#openbl)|9850|9850|7759|78.7%|100.0%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|7741|4.4%|99.7%|
[openbl_30d](#openbl_30d)|4437|4437|4437|100.0%|57.1%|
[bruteforceblocker](#bruteforceblocker)|2392|2392|1413|59.0%|18.2%|
[et_compromised](#et_compromised)|2401|2401|1412|58.8%|18.1%|
[blocklist_de](#blocklist_de)|22102|22102|1230|5.5%|15.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|2134|2134|1155|54.1%|14.8%|
[openbl_7d](#openbl_7d)|986|986|986|100.0%|12.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|721|0.0%|9.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|361|0.0%|4.6%|
[openbl_1d](#openbl_1d)|357|357|357|100.0%|4.6%|
[et_block](#et_block)|904|18056697|269|0.0%|3.4%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|267|0.0%|3.4%|
[dshield](#dshield)|20|5120|185|3.6%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|180|0.0%|2.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|79|33.7%|1.0%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|59|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|14566|14566|58|0.3%|0.7%|
[blocklist_de_imap](#blocklist_de_imap)|695|695|46|6.6%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|31|0.1%|0.3%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|29|0.3%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7511|7511|21|0.2%|0.2%|
[et_tor](#et_tor)|6360|6360|21|0.3%|0.2%|
[dm_tor](#dm_tor)|6370|6370|21|0.3%|0.2%|
[bm_tor](#bm_tor)|6385|6385|21|0.3%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|18|0.0%|0.2%|
[shunlist](#shunlist)|51|51|11|21.5%|0.1%|
[nixspam](#nixspam)|20085|20085|11|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12623|12623|10|0.0%|0.1%|
[voipbl](#voipbl)|10303|10775|9|0.0%|0.1%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.1%|
[php_bad](#php_bad)|281|281|8|2.8%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|285|285|7|2.4%|0.0%|
[php_harvesters](#php_harvesters)|257|257|5|1.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|5|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1327|1327|3|0.2%|0.0%|
[zeus](#zeus)|267|267|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|334|334|1|0.2%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt.gz).

The last time downloaded was found to be dated: Fri May 29 03:32:00 UTC 2015.

The ipset `openbl_7d` has **986** entries, **986** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9850|9850|986|10.0%|100.0%|
[openbl_60d](#openbl_60d)|7759|7759|986|12.7%|100.0%|
[openbl_30d](#openbl_30d)|4437|4437|986|22.2%|100.0%|
[openbl](#openbl)|9850|9850|986|10.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|981|0.5%|99.4%|
[blocklist_de](#blocklist_de)|22102|22102|653|2.9%|66.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2134|2134|619|29.0%|62.7%|
[bruteforceblocker](#bruteforceblocker)|2392|2392|508|21.2%|51.5%|
[et_compromised](#et_compromised)|2401|2401|500|20.8%|50.7%|
[openbl_1d](#openbl_1d)|357|357|205|57.4%|20.7%|
[dshield](#dshield)|20|5120|123|2.4%|12.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|94|0.0%|9.5%|
[et_block](#et_block)|904|18056697|82|0.0%|8.3%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|81|0.0%|8.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|76|32.4%|7.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|52|0.0%|5.2%|
[blocklist_de_mail](#blocklist_de_mail)|14566|14566|29|0.1%|2.9%|
[blocklist_de_imap](#blocklist_de_imap)|695|695|26|3.7%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|16|0.0%|1.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|8|0.0%|0.8%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|5|0.0%|0.5%|
[shunlist](#shunlist)|51|51|5|9.8%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|12623|12623|3|0.0%|0.3%|
[voipbl](#voipbl)|10303|10775|2|0.0%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|2|0.0%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|285|285|2|0.7%|0.2%|
[zeus](#zeus)|267|267|1|0.3%|0.1%|
[nixspam](#nixspam)|20085|20085|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.1%|
[ciarmy](#ciarmy)|334|334|1|0.2%|0.1%|

## openbl_90d

[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_90days.txt.gz).

The last time downloaded was found to be dated: Fri May 29 03:32:01 UTC 2015.

The ipset `openbl_90d` has **9850** entries, **9850** unique IPs.

The following table shows the overlaps of `openbl_90d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_90d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_90d`.
- ` this % ` is the percentage **of this ipset (`openbl_90d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl](#openbl)|9850|9850|9850|100.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|9829|5.6%|99.7%|
[openbl_60d](#openbl_60d)|7759|7759|7759|100.0%|78.7%|
[openbl_30d](#openbl_30d)|4437|4437|4437|100.0%|45.0%|
[bruteforceblocker](#bruteforceblocker)|2392|2392|1429|59.7%|14.5%|
[et_compromised](#et_compromised)|2401|2401|1427|59.4%|14.4%|
[blocklist_de](#blocklist_de)|22102|22102|1282|5.8%|13.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2134|2134|1197|56.0%|12.1%|
[openbl_7d](#openbl_7d)|986|986|986|100.0%|10.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|948|0.0%|9.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|507|0.0%|5.1%|
[et_block](#et_block)|904|18056697|450|0.0%|4.5%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|447|0.0%|4.5%|
[openbl_1d](#openbl_1d)|357|357|357|100.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|219|0.0%|2.2%|
[dshield](#dshield)|20|5120|189|3.6%|1.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|80|34.1%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|66|0.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|14566|14566|61|0.4%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|695|695|49|7.0%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|33|0.1%|0.3%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|29|0.3%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7511|7511|23|0.3%|0.2%|
[et_tor](#et_tor)|6360|6360|21|0.3%|0.2%|
[dm_tor](#dm_tor)|6370|6370|21|0.3%|0.2%|
[bm_tor](#bm_tor)|6385|6385|21|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|19|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|14|0.0%|0.1%|
[nixspam](#nixspam)|20085|20085|13|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12623|12623|13|0.1%|0.1%|
[voipbl](#voipbl)|10303|10775|12|0.1%|0.1%|
[shunlist](#shunlist)|51|51|11|21.5%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|285|285|9|3.1%|0.0%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.0%|
[php_bad](#php_bad)|281|281|8|2.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|6|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|5|1.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1327|1327|5|0.3%|0.0%|
[zeus](#zeus)|267|267|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3488|3488|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[sslbl](#sslbl)|345|345|1|0.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4524|4524|1|0.0%|0.0%|
[ciarmy](#ciarmy)|334|334|1|0.2%|0.0%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Fri May 29 03:45:13 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[snort_ipfilter](#snort_ipfilter)|7652|7652|11|0.1%|84.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|3|0.0%|23.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|2|0.0%|15.3%|
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
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|202|0.2%|71.8%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|188|0.6%|66.9%|
[stopforumspam_1d](#stopforumspam_1d)|7511|7511|112|1.4%|39.8%|
[blocklist_de](#blocklist_de)|22102|22102|75|0.3%|26.6%|
[blocklist_de_bots](#blocklist_de_bots)|3488|3488|60|1.7%|21.3%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|41|0.5%|14.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|33|14.1%|11.7%|
[php_spammers](#php_spammers)|417|417|32|7.6%|11.3%|
[et_tor](#et_tor)|6360|6360|29|0.4%|10.3%|
[dm_tor](#dm_tor)|6370|6370|29|0.4%|10.3%|
[bm_tor](#bm_tor)|6385|6385|29|0.4%|10.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|28|7.5%|9.9%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|24|0.0%|8.5%|
[et_block](#et_block)|904|18056697|24|0.0%|8.5%|
[blocklist_de_apache](#blocklist_de_apache)|12623|12623|24|0.1%|8.5%|
[php_dictionary](#php_dictionary)|433|433|22|5.0%|7.8%|
[blocklist_de_mail](#blocklist_de_mail)|14566|14566|21|0.1%|7.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|16|0.0%|5.6%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|12|0.0%|4.2%|
[nixspam](#nixspam)|20085|20085|10|0.0%|3.5%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|9|0.0%|3.2%|
[ri_web_proxies](#ri_web_proxies)|4524|4524|8|0.1%|2.8%|
[openbl_90d](#openbl_90d)|9850|9850|8|0.0%|2.8%|
[openbl_60d](#openbl_60d)|7759|7759|8|0.1%|2.8%|
[openbl](#openbl)|9850|9850|8|0.0%|2.8%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|7|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|5|0.0%|1.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1327|1327|5|0.3%|1.7%|
[xroxy](#xroxy)|1906|1906|3|0.1%|1.0%|
[proxyrss](#proxyrss)|1651|1651|2|0.1%|0.7%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.3%|
[zeus](#zeus)|267|267|1|0.3%|0.3%|
[proxz](#proxz)|97|97|1|1.0%|0.3%|
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
[stopforumspam_1d](#stopforumspam_1d)|7511|7511|112|1.4%|39.8%|
[blocklist_de](#blocklist_de)|22102|22102|76|0.3%|27.0%|
[blocklist_de_bots](#blocklist_de_bots)|3488|3488|60|1.7%|21.3%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|42|0.5%|14.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|33|14.1%|11.7%|
[php_spammers](#php_spammers)|417|417|32|7.6%|11.3%|
[et_tor](#et_tor)|6360|6360|29|0.4%|10.3%|
[dm_tor](#dm_tor)|6370|6370|29|0.4%|10.3%|
[bm_tor](#bm_tor)|6385|6385|29|0.4%|10.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|28|7.5%|9.9%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|24|0.0%|8.5%|
[et_block](#et_block)|904|18056697|24|0.0%|8.5%|
[blocklist_de_apache](#blocklist_de_apache)|12623|12623|24|0.1%|8.5%|
[php_dictionary](#php_dictionary)|433|433|22|5.0%|7.8%|
[blocklist_de_mail](#blocklist_de_mail)|14566|14566|22|0.1%|7.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|15|0.0%|5.3%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|12|0.0%|4.2%|
[nixspam](#nixspam)|20085|20085|11|0.0%|3.9%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|9|0.0%|3.2%|
[ri_web_proxies](#ri_web_proxies)|4524|4524|8|0.1%|2.8%|
[openbl_90d](#openbl_90d)|9850|9850|8|0.0%|2.8%|
[openbl_60d](#openbl_60d)|7759|7759|8|0.1%|2.8%|
[openbl](#openbl)|9850|9850|8|0.0%|2.8%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|7|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|5|0.0%|1.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1327|1327|5|0.3%|1.7%|
[xroxy](#xroxy)|1906|1906|3|0.1%|1.0%|
[proxyrss](#proxyrss)|1651|1651|2|0.1%|0.7%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.3%|
[zeus](#zeus)|267|267|1|0.3%|0.3%|
[proxz](#proxz)|97|97|1|1.0%|0.3%|
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
[nixspam](#nixspam)|20085|20085|86|0.4%|19.8%|
[php_spammers](#php_spammers)|417|417|84|20.1%|19.3%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|77|1.0%|17.7%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|75|0.0%|17.3%|
[blocklist_de](#blocklist_de)|22102|22102|70|0.3%|16.1%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|59|0.1%|13.6%|
[blocklist_de_mail](#blocklist_de_mail)|14566|14566|58|0.3%|13.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|24|0.0%|5.5%|
[xroxy](#xroxy)|1906|1906|23|1.2%|5.3%|
[stopforumspam_1d](#stopforumspam_1d)|7511|7511|23|0.3%|5.3%|
[ri_web_proxies](#ri_web_proxies)|4524|4524|23|0.5%|5.3%|
[php_commenters](#php_commenters)|281|281|22|7.8%|5.0%|
[php_bad](#php_bad)|281|281|22|7.8%|5.0%|
[blocklist_de_bots](#blocklist_de_bots)|3488|3488|12|0.3%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|10|0.0%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|9|0.0%|2.0%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|7|0.0%|1.6%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|4|0.0%|0.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.9%|
[et_tor](#et_tor)|6360|6360|4|0.0%|0.9%|
[et_block](#et_block)|904|18056697|4|0.0%|0.9%|
[dm_tor](#dm_tor)|6370|6370|4|0.0%|0.9%|
[bm_tor](#bm_tor)|6385|6385|4|0.0%|0.9%|
[ri_connect_proxies](#ri_connect_proxies)|1750|1750|3|0.1%|0.6%|
[proxz](#proxz)|97|97|2|2.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.4%|
[proxyrss](#proxyrss)|1651|1651|1|0.0%|0.2%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|1|0.4%|0.2%|

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
[stopforumspam_1d](#stopforumspam_1d)|7511|7511|37|0.4%|14.3%|
[blocklist_de](#blocklist_de)|22102|22102|34|0.1%|13.2%|
[blocklist_de_bots](#blocklist_de_bots)|3488|3488|28|0.8%|10.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|15|0.0%|5.8%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|10|0.1%|3.8%|
[php_commenters](#php_commenters)|281|281|9|3.2%|3.5%|
[php_bad](#php_bad)|281|281|9|3.2%|3.5%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|9|0.0%|3.5%|
[nixspam](#nixspam)|20085|20085|7|0.0%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|7|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|7|0.0%|2.7%|
[et_tor](#et_tor)|6360|6360|7|0.1%|2.7%|
[dm_tor](#dm_tor)|6370|6370|7|0.1%|2.7%|
[bm_tor](#bm_tor)|6385|6385|7|0.1%|2.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|6|1.6%|2.3%|
[openbl_90d](#openbl_90d)|9850|9850|5|0.0%|1.9%|
[openbl_60d](#openbl_60d)|7759|7759|5|0.0%|1.9%|
[openbl](#openbl)|9850|9850|5|0.0%|1.9%|
[blocklist_de_mail](#blocklist_de_mail)|14566|14566|4|0.0%|1.5%|
[xroxy](#xroxy)|1906|1906|2|0.1%|0.7%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.7%|
[blocklist_de_ftp](#blocklist_de_ftp)|285|285|2|0.7%|0.7%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|1|0.0%|0.3%|
[ri_web_proxies](#ri_web_proxies)|4524|4524|1|0.0%|0.3%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.3%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|
[fullbogons](#fullbogons)|3656|670735064|1|0.0%|0.3%|
[et_block](#et_block)|904|18056697|1|0.0%|0.3%|
[bogons](#bogons)|13|592708608|1|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|1|0.4%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|12623|12623|1|0.0%|0.3%|

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
[nixspam](#nixspam)|20085|20085|73|0.3%|17.5%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|68|0.8%|16.3%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|65|0.2%|15.5%|
[blocklist_de](#blocklist_de)|22102|22102|65|0.2%|15.5%|
[blocklist_de_mail](#blocklist_de_mail)|14566|14566|42|0.2%|10.0%|
[php_commenters](#php_commenters)|281|281|32|11.3%|7.6%|
[php_bad](#php_bad)|281|281|32|11.3%|7.6%|
[stopforumspam_1d](#stopforumspam_1d)|7511|7511|31|0.4%|7.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|31|0.0%|7.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|26|0.0%|6.2%|
[ri_web_proxies](#ri_web_proxies)|4524|4524|19|0.4%|4.5%|
[blocklist_de_bots](#blocklist_de_bots)|3488|3488|18|0.5%|4.3%|
[xroxy](#xroxy)|1906|1906|17|0.8%|4.0%|
[et_tor](#et_tor)|6360|6360|6|0.0%|1.4%|
[dm_tor](#dm_tor)|6370|6370|6|0.0%|1.4%|
[bm_tor](#bm_tor)|6385|6385|6|0.0%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|5|0.0%|1.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|5|2.1%|1.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1327|1327|5|0.3%|1.1%|
[blocklist_de_apache](#blocklist_de_apache)|12623|12623|5|0.0%|1.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.9%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|3|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|2|0.0%|0.4%|
[ri_connect_proxies](#ri_connect_proxies)|1750|1750|2|0.1%|0.4%|
[proxyrss](#proxyrss)|1651|1651|2|0.1%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[et_block](#et_block)|904|18056697|2|0.0%|0.4%|
[proxz](#proxz)|97|97|1|1.0%|0.2%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.2%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Fri May 29 00:11:30 UTC 2015.

The ipset `proxyrss` has **1651** entries, **1651** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|894|0.9%|54.1%|
[xroxy](#xroxy)|1906|1906|823|43.1%|49.8%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|811|2.6%|49.1%|
[ri_web_proxies](#ri_web_proxies)|4524|4524|632|13.9%|38.2%|
[stopforumspam_1d](#stopforumspam_1d)|7511|7511|468|6.2%|28.3%|
[blocklist_de](#blocklist_de)|22102|22102|245|1.1%|14.8%|
[blocklist_de_bots](#blocklist_de_bots)|3488|3488|243|6.9%|14.7%|
[ri_connect_proxies](#ri_connect_proxies)|1750|1750|215|12.2%|13.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|70|0.0%|4.2%|
[proxz](#proxz)|97|97|68|70.1%|4.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|54|0.0%|3.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|36|0.0%|2.1%|
[nixspam](#nixspam)|20085|20085|18|0.0%|1.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|7|1.0%|0.4%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|3|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|3|1.2%|0.1%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.1%|
[php_commenters](#php_commenters)|281|281|2|0.7%|0.1%|
[php_bad](#php_bad)|281|281|2|0.7%|0.1%|
[et_compromised](#et_compromised)|2401|2401|2|0.0%|0.1%|
[bruteforceblocker](#bruteforceblocker)|2392|2392|2|0.0%|0.1%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2134|2134|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1327|1327|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12623|12623|1|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Fri May 29 02:51:38 UTC 2015.

The ipset `proxz` has **97** entries, **97** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[xroxy](#xroxy)|1906|1906|73|3.8%|75.2%|
[proxyrss](#proxyrss)|1651|1651|68|4.1%|70.1%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|54|0.1%|55.6%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|54|0.0%|55.6%|
[stopforumspam_1d](#stopforumspam_1d)|7511|7511|34|0.4%|35.0%|
[ri_web_proxies](#ri_web_proxies)|4524|4524|34|0.7%|35.0%|
[blocklist_de](#blocklist_de)|22102|22102|19|0.0%|19.5%|
[blocklist_de_bots](#blocklist_de_bots)|3488|3488|18|0.5%|18.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|11|0.0%|11.3%|
[ri_connect_proxies](#ri_connect_proxies)|1750|1750|7|0.4%|7.2%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|4|0.0%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|4|0.0%|4.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|4|0.0%|4.1%|
[nixspam](#nixspam)|20085|20085|3|0.0%|3.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|2.0%|
[php_spammers](#php_spammers)|417|417|1|0.2%|1.0%|
[php_commenters](#php_commenters)|281|281|1|0.3%|1.0%|
[php_bad](#php_bad)|281|281|1|0.3%|1.0%|
[et_tor](#et_tor)|6360|6360|1|0.0%|1.0%|
[et_compromised](#et_compromised)|2401|2401|1|0.0%|1.0%|
[dm_tor](#dm_tor)|6370|6370|1|0.0%|1.0%|
[bruteforceblocker](#bruteforceblocker)|2392|2392|1|0.0%|1.0%|
[bm_tor](#bm_tor)|6385|6385|1|0.0%|1.0%|
[blocklist_de_mail](#blocklist_de_mail)|14566|14566|1|0.0%|1.0%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Fri May 29 01:40:45 UTC 2015.

The ipset `ri_connect_proxies` has **1750** entries, **1750** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|1021|1.0%|58.3%|
[ri_web_proxies](#ri_web_proxies)|4524|4524|712|15.7%|40.6%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|702|2.2%|40.1%|
[xroxy](#xroxy)|1906|1906|272|14.2%|15.5%|
[proxyrss](#proxyrss)|1651|1651|215|13.0%|12.2%|
[stopforumspam_1d](#stopforumspam_1d)|7511|7511|177|2.3%|10.1%|
[blocklist_de](#blocklist_de)|22102|22102|87|0.3%|4.9%|
[blocklist_de_bots](#blocklist_de_bots)|3488|3488|85|2.4%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|76|0.0%|4.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|62|0.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|41|0.0%|2.3%|
[nixspam](#nixspam)|20085|20085|15|0.0%|0.8%|
[proxz](#proxz)|97|97|7|7.2%|0.4%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|6|0.0%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.3%|
[php_dictionary](#php_dictionary)|433|433|3|0.6%|0.1%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.1%|
[et_tor](#et_tor)|6360|6360|2|0.0%|0.1%|
[dm_tor](#dm_tor)|6370|6370|2|0.0%|0.1%|
[bm_tor](#bm_tor)|6385|6385|2|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|14566|14566|2|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|2|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Fri May 29 01:40:38 UTC 2015.

The ipset `ri_web_proxies` has **4524** entries, **4524** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|2249|2.4%|49.7%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|1660|5.3%|36.6%|
[xroxy](#xroxy)|1906|1906|722|37.8%|15.9%|
[ri_connect_proxies](#ri_connect_proxies)|1750|1750|712|40.6%|15.7%|
[proxyrss](#proxyrss)|1651|1651|632|38.2%|13.9%|
[stopforumspam_1d](#stopforumspam_1d)|7511|7511|569|7.5%|12.5%|
[blocklist_de](#blocklist_de)|22102|22102|394|1.7%|8.7%|
[blocklist_de_bots](#blocklist_de_bots)|3488|3488|362|10.3%|8.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|161|0.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|142|0.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|107|0.0%|2.3%|
[nixspam](#nixspam)|20085|20085|78|0.3%|1.7%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|42|0.5%|0.9%|
[proxz](#proxz)|97|97|34|35.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|14566|14566|30|0.2%|0.6%|
[php_dictionary](#php_dictionary)|433|433|23|5.3%|0.5%|
[php_spammers](#php_spammers)|417|417|19|4.5%|0.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|10|1.4%|0.2%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.1%|
[php_bad](#php_bad)|281|281|8|2.8%|0.1%|
[et_tor](#et_tor)|6360|6360|5|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6370|6370|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6385|6385|4|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|3|1.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[openbl_90d](#openbl_90d)|9850|9850|1|0.0%|0.0%|
[openbl](#openbl)|9850|9850|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2134|2134|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1327|1327|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12623|12623|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Fri May 29 02:30:03 UTC 2015.

The ipset `shunlist` has **51** entries, **51** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|173474|173474|51|0.0%|100.0%|
[blocklist_de](#blocklist_de)|22102|22102|13|0.0%|25.4%|
[openbl_90d](#openbl_90d)|9850|9850|11|0.1%|21.5%|
[openbl_60d](#openbl_60d)|7759|7759|11|0.1%|21.5%|
[openbl](#openbl)|9850|9850|11|0.1%|21.5%|
[openbl_30d](#openbl_30d)|4437|4437|10|0.2%|19.6%|
[et_compromised](#et_compromised)|2401|2401|9|0.3%|17.6%|
[bruteforceblocker](#bruteforceblocker)|2392|2392|9|0.3%|17.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|2134|2134|8|0.3%|15.6%|
[openbl_7d](#openbl_7d)|986|986|5|0.5%|9.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|4|0.0%|7.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|3|0.0%|5.8%|
[blocklist_de_apache](#blocklist_de_apache)|12623|12623|3|0.0%|5.8%|
[voipbl](#voipbl)|10303|10775|2|0.0%|3.9%|
[openbl_1d](#openbl_1d)|357|357|2|0.5%|3.9%|
[ciarmy](#ciarmy)|334|334|2|0.5%|3.9%|
[blocklist_de_mail](#blocklist_de_mail)|14566|14566|2|0.0%|3.9%|
[blocklist_de_imap](#blocklist_de_imap)|695|695|2|0.2%|3.9%|
[nixspam](#nixspam)|20085|20085|1|0.0%|1.9%|

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
[bm_tor](#bm_tor)|6385|6385|1057|16.5%|13.8%|
[dm_tor](#dm_tor)|6370|6370|1049|16.4%|13.7%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|765|0.8%|9.9%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|581|1.8%|7.5%|
[stopforumspam_1d](#stopforumspam_1d)|7511|7511|371|4.9%|4.8%|
[nixspam](#nixspam)|20085|20085|254|1.2%|3.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|237|0.0%|3.0%|
[et_block](#et_block)|904|18056697|229|0.0%|2.9%|
[blocklist_de](#blocklist_de)|22102|22102|229|1.0%|2.9%|
[zeus](#zeus)|267|267|227|85.0%|2.9%|
[zeus_badips](#zeus_badips)|230|230|201|87.3%|2.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|185|49.7%|2.4%|
[blocklist_de_mail](#blocklist_de_mail)|14566|14566|162|1.1%|2.1%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|124|0.0%|1.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|112|0.0%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|86|0.0%|1.1%|
[php_dictionary](#php_dictionary)|433|433|77|17.7%|1.0%|
[php_spammers](#php_spammers)|417|417|68|16.3%|0.8%|
[xroxy](#xroxy)|1906|1906|53|2.7%|0.6%|
[feodo](#feodo)|67|67|53|79.1%|0.6%|
[ri_web_proxies](#ri_web_proxies)|4524|4524|42|0.9%|0.5%|
[php_commenters](#php_commenters)|281|281|42|14.9%|0.5%|
[php_bad](#php_bad)|281|281|41|14.5%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|12623|12623|35|0.2%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1327|1327|32|2.4%|0.4%|
[blocklist_de_bots](#blocklist_de_bots)|3488|3488|31|0.8%|0.4%|
[openbl_90d](#openbl_90d)|9850|9850|29|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7759|7759|29|0.3%|0.3%|
[openbl](#openbl)|9850|9850|29|0.2%|0.3%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|25|1.9%|0.3%|
[sslbl](#sslbl)|345|345|21|6.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|18|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|15|0.0%|0.1%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|10|3.8%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|6|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1750|1750|6|0.3%|0.0%|
[openbl_30d](#openbl_30d)|4437|4437|6|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|695|695|6|0.8%|0.0%|
[openbl_7d](#openbl_7d)|986|986|5|0.5%|0.0%|
[proxz](#proxz)|97|97|4|4.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|509|509|4|0.7%|0.0%|
[proxyrss](#proxyrss)|1651|1651|3|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2134|2134|3|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[openbl_1d](#openbl_1d)|357|357|1|0.2%|0.0%|
[malc0de](#malc0de)|411|411|1|0.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2401|2401|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2392|2392|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|1|0.4%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|285|285|1|0.3%|0.0%|

## spamhaus_drop

[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**

Source is downloaded from [this link](http://www.spamhaus.org/drop/drop.txt).

The last time downloaded was found to be dated: Thu May 28 17:23:44 UTC 2015.

The ipset `spamhaus_drop` has **639** entries, **17921280** unique IPs.

The following table shows the overlaps of `spamhaus_drop` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `spamhaus_drop`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `spamhaus_drop`.
- ` this % ` is the percentage **of this ipset (`spamhaus_drop`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|904|18056697|17920256|99.2%|99.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|8401434|2.4%|46.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7079936|77.1%|39.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|2133002|0.2%|11.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|195904|0.1%|1.0%|
[fullbogons](#fullbogons)|3656|670735064|20480|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|1624|0.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|756|0.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|512|0.1%|0.0%|
[dshield](#dshield)|20|5120|512|10.0%|0.0%|
[openbl_90d](#openbl_90d)|9850|9850|447|4.5%|0.0%|
[openbl](#openbl)|9850|9850|447|4.5%|0.0%|
[openbl_60d](#openbl_60d)|7759|7759|267|3.4%|0.0%|
[openbl_30d](#openbl_30d)|4437|4437|206|4.6%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|204|0.6%|0.0%|
[blocklist_de](#blocklist_de)|22102|22102|187|0.8%|0.0%|
[nixspam](#nixspam)|20085|20085|174|0.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2134|2134|114|5.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2392|2392|102|4.2%|0.0%|
[et_compromised](#et_compromised)|2401|2401|97|4.0%|0.0%|
[openbl_7d](#openbl_7d)|986|986|81|8.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3488|3488|53|1.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7511|7511|47|0.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|29|2.2%|0.0%|
[openbl_1d](#openbl_1d)|357|357|26|7.2%|0.0%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.0%|
[php_bad](#php_bad)|281|281|24|8.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14566|14566|19|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|18|0.2%|0.0%|
[zeus_badips](#zeus_badips)|230|230|16|6.9%|0.0%|
[zeus](#zeus)|267|267|16|5.9%|0.0%|
[voipbl](#voipbl)|10303|10775|14|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|695|695|13|1.8%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|7|2.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[sslbl](#sslbl)|345|345|3|0.8%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[malc0de](#malc0de)|411|411|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6360|6360|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6370|6370|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6385|6385|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[et_botnet](#et_botnet)|505|505|1|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1327|1327|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12623|12623|1|0.0%|0.0%|

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
[et_block](#et_block)|904|18056697|517|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|512|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|106|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|42|0.1%|0.0%|
[blocklist_de](#blocklist_de)|22102|22102|36|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3488|3488|30|0.8%|0.0%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|15|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7511|7511|14|0.1%|0.0%|
[openbl_90d](#openbl_90d)|9850|9850|14|0.1%|0.0%|
[openbl](#openbl)|9850|9850|14|0.1%|0.0%|
[php_commenters](#php_commenters)|281|281|7|2.4%|0.0%|
[php_bad](#php_bad)|281|281|7|2.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|6|2.5%|0.0%|
[zeus_badips](#zeus_badips)|230|230|5|2.1%|0.0%|
[zeus](#zeus)|267|267|5|1.8%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14566|14566|5|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[openbl_60d](#openbl_60d)|7759|7759|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4437|4437|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|357|357|1|0.2%|0.0%|
[nixspam](#nixspam)|20085|20085|1|0.0%|0.0%|
[malc0de](#malc0de)|411|411|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|695|695|1|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12623|12623|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Fri May 29 03:45:06 UTC 2015.

The ipset `sslbl` has **345** entries, **345** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[feodo](#feodo)|67|67|24|35.8%|6.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|22|0.0%|6.3%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|21|0.2%|6.0%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|7|0.0%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|6|0.0%|1.7%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|3|0.0%|0.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|3|0.0%|0.8%|
[et_block](#et_block)|904|18056697|3|0.0%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|1|0.0%|0.2%|
[openbl_90d](#openbl_90d)|9850|9850|1|0.0%|0.2%|
[openbl](#openbl)|9850|9850|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Fri May 29 04:00:02 UTC 2015.

The ipset `stopforumspam_1d` has **7511** entries, **7511** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|7306|23.5%|97.2%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|5488|5.8%|73.0%|
[blocklist_de](#blocklist_de)|22102|22102|1624|7.3%|21.6%|
[blocklist_de_bots](#blocklist_de_bots)|3488|3488|1536|44.0%|20.4%|
[ri_web_proxies](#ri_web_proxies)|4524|4524|569|12.5%|7.5%|
[xroxy](#xroxy)|1906|1906|526|27.5%|7.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|509|0.0%|6.7%|
[proxyrss](#proxyrss)|1651|1651|468|28.3%|6.2%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|371|4.8%|4.9%|
[et_tor](#et_tor)|6360|6360|329|5.1%|4.3%|
[dm_tor](#dm_tor)|6370|6370|329|5.1%|4.3%|
[bm_tor](#bm_tor)|6385|6385|329|5.1%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|227|0.0%|3.0%|
[ri_connect_proxies](#ri_connect_proxies)|1750|1750|177|10.1%|2.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|169|45.4%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|150|0.0%|1.9%|
[php_commenters](#php_commenters)|281|281|112|39.8%|1.4%|
[php_bad](#php_bad)|281|281|112|39.8%|1.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|112|47.8%|1.4%|
[blocklist_de_apache](#blocklist_de_apache)|12623|12623|86|0.6%|1.1%|
[nixspam](#nixspam)|20085|20085|71|0.3%|0.9%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|62|0.0%|0.8%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1327|1327|51|3.8%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|49|0.0%|0.6%|
[et_block](#et_block)|904|18056697|48|0.0%|0.6%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|47|0.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|14566|14566|39|0.2%|0.5%|
[php_harvesters](#php_harvesters)|257|257|37|14.3%|0.4%|
[proxz](#proxz)|97|97|34|35.0%|0.4%|
[php_spammers](#php_spammers)|417|417|31|7.4%|0.4%|
[php_dictionary](#php_dictionary)|433|433|23|5.3%|0.3%|
[openbl_90d](#openbl_90d)|9850|9850|23|0.2%|0.3%|
[openbl](#openbl)|9850|9850|23|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7759|7759|21|0.2%|0.2%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|14|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|7|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|7|1.0%|0.0%|
[voipbl](#voipbl)|10303|10775|4|0.0%|0.0%|
[et_compromised](#et_compromised)|2401|2401|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2392|2392|2|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4437|4437|1|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2134|2134|1|0.0%|0.0%|

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
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|6195|0.0%|6.6%|
[stopforumspam_1d](#stopforumspam_1d)|7511|7511|5488|73.0%|5.8%|
[blocklist_de](#blocklist_de)|22102|22102|2681|12.1%|2.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|2490|0.0%|2.6%|
[blocklist_de_bots](#blocklist_de_bots)|3488|3488|2373|68.0%|2.5%|
[ri_web_proxies](#ri_web_proxies)|4524|4524|2249|49.7%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|1527|0.0%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|1750|1750|1021|58.3%|1.0%|
[xroxy](#xroxy)|1906|1906|1002|52.5%|1.0%|
[proxyrss](#proxyrss)|1651|1651|894|54.1%|0.9%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|765|9.9%|0.8%|
[et_block](#et_block)|904|18056697|759|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|756|0.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|745|0.0%|0.7%|
[dm_tor](#dm_tor)|6370|6370|602|9.4%|0.6%|
[et_tor](#et_tor)|6360|6360|601|9.4%|0.6%|
[bm_tor](#bm_tor)|6385|6385|600|9.3%|0.6%|
[nixspam](#nixspam)|20085|20085|239|1.1%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|236|63.4%|0.2%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|229|0.1%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|12623|12623|218|1.7%|0.2%|
[php_commenters](#php_commenters)|281|281|203|72.2%|0.2%|
[php_bad](#php_bad)|281|281|202|71.8%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|14566|14566|202|1.3%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|130|55.5%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|106|0.0%|0.1%|
[php_spammers](#php_spammers)|417|417|95|22.7%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1327|1327|81|6.1%|0.0%|
[php_dictionary](#php_dictionary)|433|433|75|17.3%|0.0%|
[openbl_90d](#openbl_90d)|9850|9850|66|0.6%|0.0%|
[openbl](#openbl)|9850|9850|66|0.6%|0.0%|
[php_harvesters](#php_harvesters)|257|257|62|24.1%|0.0%|
[openbl_60d](#openbl_60d)|7759|7759|59|0.7%|0.0%|
[proxz](#proxz)|97|97|54|55.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|44|0.0%|0.0%|
[voipbl](#voipbl)|10303|10775|41|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|22|3.2%|0.0%|
[openbl_30d](#openbl_30d)|4437|4437|18|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|16|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2134|2134|8|0.3%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|285|285|8|2.8%|0.0%|
[et_compromised](#et_compromised)|2401|2401|6|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2392|2392|6|0.2%|0.0%|
[zeus_badips](#zeus_badips)|230|230|3|1.3%|0.0%|
[zeus](#zeus)|267|267|3|1.1%|0.0%|
[openbl_7d](#openbl_7d)|986|986|2|0.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|2|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3656|670735064|2|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|695|695|2|0.2%|0.0%|
[sslbl](#sslbl)|345|345|1|0.2%|0.0%|
[openbl_1d](#openbl_1d)|357|357|1|0.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|509|509|1|0.1%|0.0%|
[ciarmy](#ciarmy)|334|334|1|0.2%|0.0%|
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
[stopforumspam_1d](#stopforumspam_1d)|7511|7511|7306|97.2%|23.5%|
[blocklist_de](#blocklist_de)|22102|22102|2544|11.5%|8.2%|
[blocklist_de_bots](#blocklist_de_bots)|3488|3488|2360|67.6%|7.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|2103|0.0%|6.7%|
[ri_web_proxies](#ri_web_proxies)|4524|4524|1660|36.6%|5.3%|
[xroxy](#xroxy)|1906|1906|914|47.9%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|904|0.0%|2.9%|
[proxyrss](#proxyrss)|1651|1651|811|49.1%|2.6%|
[ri_connect_proxies](#ri_connect_proxies)|1750|1750|702|40.1%|2.2%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|581|7.5%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|580|0.0%|1.8%|
[et_tor](#et_tor)|6360|6360|465|7.3%|1.5%|
[dm_tor](#dm_tor)|6370|6370|463|7.2%|1.4%|
[bm_tor](#bm_tor)|6385|6385|462|7.2%|1.4%|
[et_block](#et_block)|904|18056697|205|0.0%|0.6%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|204|0.0%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|200|53.7%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|194|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|189|67.2%|0.6%|
[php_bad](#php_bad)|281|281|188|66.9%|0.6%|
[nixspam](#nixspam)|20085|20085|153|0.7%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|12623|12623|135|1.0%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|120|51.2%|0.3%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|115|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|14566|14566|99|0.6%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1327|1327|75|5.6%|0.2%|
[php_spammers](#php_spammers)|417|417|65|15.5%|0.2%|
[php_dictionary](#php_dictionary)|433|433|59|13.6%|0.1%|
[proxz](#proxz)|97|97|54|55.6%|0.1%|
[php_harvesters](#php_harvesters)|257|257|50|19.4%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|42|0.0%|0.1%|
[openbl_90d](#openbl_90d)|9850|9850|33|0.3%|0.1%|
[openbl](#openbl)|9850|9850|33|0.3%|0.1%|
[openbl_60d](#openbl_60d)|7759|7759|31|0.3%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|19|0.0%|0.0%|
[voipbl](#voipbl)|10303|10775|10|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|10|1.4%|0.0%|
[openbl_30d](#openbl_30d)|4437|4437|5|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|5|0.0%|0.0%|
[et_compromised](#et_compromised)|2401|2401|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2392|2392|3|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|285|285|3|1.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2134|2134|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[zeus](#zeus)|267|267|1|0.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Fri May 29 02:10:05 UTC 2015.

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
[alienvault_reputation](#alienvault_reputation)|173474|173474|204|0.1%|1.8%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|41|0.0%|0.3%|
[blocklist_de](#blocklist_de)|22102|22102|36|0.1%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|94|94|28|29.7%|0.2%|
[et_block](#et_block)|904|18056697|19|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|14|0.0%|0.1%|
[openbl_90d](#openbl_90d)|9850|9850|12|0.1%|0.1%|
[openbl](#openbl)|9850|9850|12|0.1%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|10|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7759|7759|9|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7511|7511|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4437|4437|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|4|0.0%|0.0%|
[ciarmy](#ciarmy)|334|334|3|0.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2134|2134|3|0.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14566|14566|3|0.0%|0.0%|
[shunlist](#shunlist)|51|51|2|3.9%|0.0%|
[openbl_7d](#openbl_7d)|986|986|2|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[nixspam](#nixspam)|20085|20085|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[et_tor](#et_tor)|6360|6360|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2401|2401|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6370|6370|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2392|2392|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6385|6385|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|695|695|1|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3488|3488|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12623|12623|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Fri May 29 03:33:01 UTC 2015.

The ipset `xroxy` has **1906** entries, **1906** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|1002|1.0%|52.5%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|914|2.9%|47.9%|
[proxyrss](#proxyrss)|1651|1651|823|49.8%|43.1%|
[ri_web_proxies](#ri_web_proxies)|4524|4524|722|15.9%|37.8%|
[stopforumspam_1d](#stopforumspam_1d)|7511|7511|526|7.0%|27.5%|
[blocklist_de](#blocklist_de)|22102|22102|304|1.3%|15.9%|
[ri_connect_proxies](#ri_connect_proxies)|1750|1750|272|15.5%|14.2%|
[blocklist_de_bots](#blocklist_de_bots)|3488|3488|257|7.3%|13.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|88|0.0%|4.6%|
[nixspam](#nixspam)|20085|20085|81|0.4%|4.2%|
[proxz](#proxz)|97|97|73|75.2%|3.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|73|0.0%|3.8%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|53|0.6%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|51|0.0%|2.6%|
[blocklist_de_mail](#blocklist_de_mail)|14566|14566|45|0.3%|2.3%|
[php_dictionary](#php_dictionary)|433|433|23|5.3%|1.2%|
[php_spammers](#php_spammers)|417|417|17|4.0%|0.8%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|12|1.7%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|6|2.5%|0.3%|
[php_commenters](#php_commenters)|281|281|3|1.0%|0.1%|
[php_bad](#php_bad)|281|281|3|1.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.1%|
[et_tor](#et_tor)|6360|6360|2|0.0%|0.1%|
[dm_tor](#dm_tor)|6370|6370|2|0.0%|0.1%|
[bm_tor](#bm_tor)|6385|6385|2|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2401|2401|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2392|2392|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2134|2134|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1327|1327|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12623|12623|1|0.0%|0.0%|

## zeus

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist).

The last time downloaded was found to be dated: Fri May 29 00:56:00 UTC 2015.

The ipset `zeus` has **267** entries, **267** unique IPs.

The following table shows the overlaps of `zeus` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus`.
- ` this % ` is the percentage **of this ipset (`zeus`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|904|18056697|262|0.0%|98.1%|
[zeus_badips](#zeus_badips)|230|230|230|100.0%|86.1%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|227|2.9%|85.0%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|68|0.0%|25.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|19|0.0%|7.1%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|16|0.0%|5.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|9|0.0%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|8|0.0%|2.9%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|5|0.0%|1.8%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|3|0.0%|1.1%|
[openbl_90d](#openbl_90d)|9850|9850|2|0.0%|0.7%|
[openbl_60d](#openbl_60d)|7759|7759|2|0.0%|0.7%|
[openbl_30d](#openbl_30d)|4437|4437|2|0.0%|0.7%|
[openbl](#openbl)|9850|9850|2|0.0%|0.7%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|1|0.0%|0.3%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.3%|
[php_bad](#php_bad)|281|281|1|0.3%|0.3%|
[openbl_7d](#openbl_7d)|986|986|1|0.1%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.3%|
[et_compromised](#et_compromised)|2401|2401|1|0.0%|0.3%|
[cleanmx_viruses](#cleanmx_viruses)|509|509|1|0.1%|0.3%|
[bruteforceblocker](#bruteforceblocker)|2392|2392|1|0.0%|0.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|2134|2134|1|0.0%|0.3%|
[blocklist_de](#blocklist_de)|22102|22102|1|0.0%|0.3%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Fri May 29 03:45:12 UTC 2015.

The ipset `zeus_badips` has **230** entries, **230** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|267|267|230|86.1%|100.0%|
[et_block](#et_block)|904|18056697|228|0.0%|99.1%|
[snort_ipfilter](#snort_ipfilter)|7652|7652|201|2.6%|87.3%|
[alienvault_reputation](#alienvault_reputation)|173474|173474|37|0.0%|16.0%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|16|0.0%|6.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|18879|139109195|14|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|78389|348732007|8|0.0%|3.4%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|5|0.0%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|236319|765065682|4|0.0%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|93361|93361|3|0.0%|1.3%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|1|0.0%|0.4%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.4%|
[php_bad](#php_bad)|281|281|1|0.3%|0.4%|
[openbl_90d](#openbl_90d)|9850|9850|1|0.0%|0.4%|
[openbl_60d](#openbl_60d)|7759|7759|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|4437|4437|1|0.0%|0.4%|
[openbl](#openbl)|9850|9850|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3339|339461|1|0.0%|0.4%|
[et_compromised](#et_compromised)|2401|2401|1|0.0%|0.4%|
[bruteforceblocker](#bruteforceblocker)|2392|2392|1|0.0%|0.4%|
