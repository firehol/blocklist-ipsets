### Contents

- [About this repo](#about-this-repo)

- [Using these ipsets](#using-these-ipsets)
 - [Which ones to use?](#which-ones-to-use)

 - [Why are open proxy lists included](#why-are-open-proxy-lists-included)
   
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

To get an idea, check for example the [XRumer](http://en.wikipedia.org/wiki/XRumer) software. This thing mimics human
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
   They only include IPs that have attacked them in the last 48 hours.
   Their goal is also to report abuse back, so that the infection is disabled.


Of course there are more lists included. You can check them and decide if they fit for your needs.


## Why are open proxy lists included

Of course, I haven't included them for you to use the open proxies. The port the proxy is listening, or the type of proxy, are not included (although most of them use the standard proxy ports and do serve web requests).

If you check the comparisons for the open proxy lists (`ri_connect_proxies`, `ri_web_proxies`, `xroxy`, `proxz`, `proxyrss`, etc)
you will find that they overlap to a great degree with other blocklists, like `blocklist_de`, `stopforumspam`, etc.

> This means the attackers also use open proxies to execute attacks.

So, if you are under attack, blocking the open proxies may help isolate a large part of the attack.

I don't suggest to permanenly block IPs using the proxy lists. Their purpose of existance is questionable.
Their quality though may be acceptable, since lot of these sites advertise that they test open proxies before including them in their lists, so that there are no false positives, at least at the time they tested them.

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

The following list was automatically generated on Fri May 29 23:47:39 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|171480 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|22510 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|12828 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|3474 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|1475 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|410 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|811 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|14794 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|93 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|1985 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|237 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6453 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD)|ipv4 hash:ip|2309 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|370 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|395 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6451 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|986 subnets, 18056524 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botnet](#et_botnet)|[EmergingThreats.net](http://www.emergingthreats.net/) botnet IPs|ipv4 hash:ip|501 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net](http://www.emergingthreats.net/) compromised hosts (seems to be a derivate of other lists)|ipv4 hash:ip|2367 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6470 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[feodo](#feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|68 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
[fullbogons](#fullbogons)|[Team-Cymru.org](http://www.team-cymru.org) IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user - **excellent list - use it only your internet interface**|ipv4 hash:net|3656 subnets, 670639576 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt)
[geolite2_country](https://github.com/ktsaou/blocklist-ipsets/tree/master/geolite2_country)|[MaxMind GeoLite2](http://dev.maxmind.com/geoip/geoip2/geolite2/) databases are free IP geolocation databases comparable to, but less accurate than, MaxMind’s GeoIP2 databases. They include IPs per country, IPs per continent, IPs used by anonymous services (VPNs, Proxies, etc) and Satellite Providers.|ipv4 hash:net|All the world|updated every 7 days  from [this link](http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country-CSV.zip)
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) IPs that have been reported for bad deeds in p2p|ipv4 hash:ip|48134 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=cwworuawihqvocglcoss&fileformat=p2p&archiveformat=gz)
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) hijacked IP-Blocks Hijacked IP space are IP blocks that are being used without permission|ipv4 hash:net|535 subnets, 9177856 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=usrcshglbiilevmyfhse&fileformat=p2p&archiveformat=gz)
[ib_bluetack_level1](#ib_bluetack_level1)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Level 1 (for use in p2p): Companies or organizations who are clearly involved with trying to stop filesharing (e.g. Baytsp, MediaDefender, Mediasentry a.o.). Companies which anti-p2p activity has been seen from. Companies that produce or have a strong financial interest in copyrighted material (e.g. music, movie, software industries a.o.). Government ranges or companies that have a strong financial interest in doing work for governments. Legal industry ranges. IPs or ranges of ISPs from which anti-p2p activity has been observed. Basically this list will block all kinds of internet connections that most people would rather not have during their internet travels.|ipv4 hash:net|218309 subnets, 764987411 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz)
[ib_bluetack_level2](#ib_bluetack_level2)|[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 2 (for use in p2p). General corporate ranges. Ranges used by labs or researchers. Proxies.|ipv4 hash:net|72774 subnets, 348707599 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw&fileformat=p2p&archiveformat=gz)
[ib_bluetack_level3](#ib_bluetack_level3)|[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 3 (for use in p2p). Many portal-type websites. ISP ranges that may be dodgy for some reason. Ranges that belong to an individual, but which have not been determined to be used by a particular company. Ranges for things that are unusual in some way. The L3 list is aka the paranoid list.|ipv4 hash:net|17802 subnets, 139104824 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh&fileformat=p2p&archiveformat=gz)
[ib_bluetack_proxies](#ib_bluetack_proxies)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Open Proxies IPs list (without TOR)|ipv4 hash:ip|673 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=xoebmbyexwuiogmbyprb&fileformat=p2p&archiveformat=gz)
[ib_bluetack_spyware](#ib_bluetack_spyware)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) known malicious SPYWARE and ADWARE IP Address ranges|ipv4 hash:net|3274 subnets, 339192 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=llvtlsjyoyiczbkjsxpf&fileformat=p2p&archiveformat=gz)
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) web server hack and exploit attempts|ipv4 hash:ip|1460 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=ghlzqtqxnzctvvajwwag&fileformat=p2p&archiveformat=gz)
[malc0de](#malc0de)|[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days|ipv4 hash:ip|410 unique IPs|updated every 1 day  from [this link](http://malc0de.com/bl/IP_Blacklist.txt)
[malwaredomainlist](#malwaredomainlist)|[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses|ipv4 hash:ip|1282 unique IPs|updated every 12 hours  from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt)
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.|ipv4 hash:ip|372 unique IPs|updated every 4 hours  from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list)
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|21367 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
[openbl](#openbl)|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|9814 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|243 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|4363 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7699 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|949 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
[openbl_90d](#openbl_90d)|[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|9814 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
[php_bad](#php_bad)|[projecthoneypot.org](http://www.projecthoneypot.org/) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|281 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|281 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|433 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|257 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|417 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1569 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|184 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1812 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|4741 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1146 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|6827 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|639 subnets, 17921280 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|55 subnets, 421120 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|347 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|6982 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|92405 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|30975 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10305 subnets, 10714 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1949 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|266 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|228 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Fri May 29 22:00:40 UTC 2015.

The ipset `alienvault_reputation` has **171480** entries, **171480** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14628|0.0%|8.5%|
[openbl_90d](#openbl_90d)|9814|9814|9791|99.7%|5.7%|
[openbl](#openbl)|9814|9814|9791|99.7%|5.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7861|0.0%|4.5%|
[openbl_60d](#openbl_60d)|7699|7699|7679|99.7%|4.4%|
[et_block](#et_block)|986|18056524|6043|0.0%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4704|0.0%|2.7%|
[openbl_30d](#openbl_30d)|4363|4363|4351|99.7%|2.5%|
[dshield](#dshield)|20|5120|3840|75.0%|2.2%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|1625|0.0%|0.9%|
[et_compromised](#et_compromised)|2367|2367|1495|63.1%|0.8%|
[bruteforceblocker](#bruteforceblocker)|2309|2309|1456|63.0%|0.8%|
[blocklist_de](#blocklist_de)|22510|22510|1413|6.2%|0.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|1985|1985|1159|58.3%|0.6%|
[openbl_7d](#openbl_7d)|949|949|943|99.3%|0.5%|
[shunlist](#shunlist)|1146|1146|911|79.4%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|518|0.0%|0.3%|
[ciarmy](#ciarmy)|370|370|362|97.8%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|289|0.0%|0.1%|
[openbl_1d](#openbl_1d)|243|243|241|99.1%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|221|0.2%|0.1%|
[voipbl](#voipbl)|10305|10714|206|1.9%|0.1%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|119|1.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12828|12828|119|0.9%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|115|0.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|237|237|89|37.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14794|14794|85|0.5%|0.0%|
[zeus](#zeus)|266|266|68|25.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|811|811|64|7.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6982|6982|63|0.9%|0.0%|
[et_tor](#et_tor)|6470|6470|44|0.6%|0.0%|
[dm_tor](#dm_tor)|6451|6451|43|0.6%|0.0%|
[bm_tor](#bm_tor)|6453|6453|43|0.6%|0.0%|
[zeus_badips](#zeus_badips)|228|228|36|15.7%|0.0%|
[nixspam](#nixspam)|21367|21367|32|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3474|3474|24|0.6%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|23|6.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1475|1475|20|1.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|93|93|18|19.3%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|410|410|18|4.3%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|15|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|13|0.0%|0.0%|
[php_commenters](#php_commenters)|281|281|12|4.2%|0.0%|
[php_bad](#php_bad)|281|281|12|4.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|395|395|10|2.5%|0.0%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|0.0%|
[malc0de](#malc0de)|410|410|9|2.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|8|0.5%|0.0%|
[sslbl](#sslbl)|347|347|7|2.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|7|1.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|7|0.5%|0.0%|
[xroxy](#xroxy)|1949|1949|5|0.2%|0.0%|
[proxyrss](#proxyrss)|1569|1569|4|0.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4741|4741|3|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|3|0.7%|0.0%|
[et_botnet](#et_botnet)|501|501|3|0.5%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1812|1812|2|0.1%|0.0%|
[proxz](#proxz)|184|184|2|1.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[feodo](#feodo)|68|68|1|1.4%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Fri May 29 23:42:05 UTC 2015.

The ipset `blocklist_de` has **22510** entries, **22510** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|14794|14794|14780|99.9%|65.6%|
[blocklist_de_apache](#blocklist_de_apache)|12828|12828|12827|99.9%|56.9%|
[blocklist_de_bots](#blocklist_de_bots)|3474|3474|3470|99.8%|15.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2853|0.0%|12.6%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|2687|2.9%|11.9%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|2307|7.4%|10.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1985|1985|1978|99.6%|8.7%|
[stopforumspam_1d](#stopforumspam_1d)|6982|6982|1581|22.6%|7.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1475|1475|1474|99.9%|6.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1473|0.0%|6.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1449|0.0%|6.4%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|1413|0.8%|6.2%|
[openbl_90d](#openbl_90d)|9814|9814|1164|11.8%|5.1%|
[openbl](#openbl)|9814|9814|1164|11.8%|5.1%|
[openbl_60d](#openbl_60d)|7699|7699|1111|14.4%|4.9%|
[openbl_30d](#openbl_30d)|4363|4363|1027|23.5%|4.5%|
[bruteforceblocker](#bruteforceblocker)|2309|2309|942|40.7%|4.1%|
[et_compromised](#et_compromised)|2367|2367|932|39.3%|4.1%|
[blocklist_de_imap](#blocklist_de_imap)|811|811|811|100.0%|3.6%|
[openbl_7d](#openbl_7d)|949|949|638|67.2%|2.8%|
[shunlist](#shunlist)|1146|1146|549|47.9%|2.4%|
[nixspam](#nixspam)|21367|21367|525|2.4%|2.3%|
[blocklist_de_ftp](#blocklist_de_ftp)|410|410|410|100.0%|1.8%|
[ri_web_proxies](#ri_web_proxies)|4741|4741|397|8.3%|1.7%|
[xroxy](#xroxy)|1949|1949|317|16.2%|1.4%|
[proxyrss](#proxyrss)|1569|1569|240|15.2%|1.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|237|237|237|100.0%|1.0%|
[openbl_1d](#openbl_1d)|243|243|215|88.4%|0.9%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|214|3.1%|0.9%|
[et_block](#et_block)|986|18056524|195|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|184|0.0%|0.8%|
[dshield](#dshield)|20|5120|164|3.2%|0.7%|
[ri_connect_proxies](#ri_connect_proxies)|1812|1812|88|4.8%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|93|93|74|79.5%|0.3%|
[php_commenters](#php_commenters)|281|281|70|24.9%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|70|0.0%|0.3%|
[php_dictionary](#php_dictionary)|433|433|69|15.9%|0.3%|
[php_bad](#php_bad)|281|281|69|24.5%|0.3%|
[php_spammers](#php_spammers)|417|417|63|15.1%|0.2%|
[voipbl](#voipbl)|10305|10714|42|0.3%|0.1%|
[proxz](#proxz)|184|184|42|22.8%|0.1%|
[php_harvesters](#php_harvesters)|257|257|33|12.8%|0.1%|
[ciarmy](#ciarmy)|370|370|33|8.9%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|26|0.0%|0.1%|
[et_tor](#et_tor)|6470|6470|22|0.3%|0.0%|
[dm_tor](#dm_tor)|6451|6451|22|0.3%|0.0%|
[bm_tor](#bm_tor)|6453|6453|22|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|5|0.7%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|3|0.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|395|395|2|0.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Fri May 29 23:28:11 UTC 2015.

The ipset `blocklist_de_apache` has **12828** entries, **12828** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22510|22510|12827|56.9%|99.9%|
[blocklist_de_mail](#blocklist_de_mail)|14794|14794|11059|74.7%|86.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2207|0.0%|17.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1475|1475|1475|100.0%|11.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1318|0.0%|10.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1081|0.0%|8.4%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|234|0.2%|1.8%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|142|0.4%|1.1%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|119|0.0%|0.9%|
[stopforumspam_1d](#stopforumspam_1d)|6982|6982|82|1.1%|0.6%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|37|0.5%|0.2%|
[shunlist](#shunlist)|1146|1146|36|3.1%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|237|237|36|15.1%|0.2%|
[ciarmy](#ciarmy)|370|370|28|7.5%|0.2%|
[php_commenters](#php_commenters)|281|281|25|8.8%|0.1%|
[php_bad](#php_bad)|281|281|25|8.8%|0.1%|
[et_tor](#et_tor)|6470|6470|22|0.3%|0.1%|
[dm_tor](#dm_tor)|6451|6451|22|0.3%|0.1%|
[bm_tor](#bm_tor)|6453|6453|22|0.3%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3474|3474|17|0.4%|0.1%|
[openbl_90d](#openbl_90d)|9814|9814|13|0.1%|0.1%|
[openbl](#openbl)|9814|9814|13|0.1%|0.1%|
[openbl_60d](#openbl_60d)|7699|7699|10|0.1%|0.0%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[openbl_30d](#openbl_30d)|4363|4363|6|0.1%|0.0%|
[nixspam](#nixspam)|21367|21367|6|0.0%|0.0%|
[et_block](#et_block)|986|18056524|6|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|3|0.0%|0.0%|
[openbl_7d](#openbl_7d)|949|949|3|0.3%|0.0%|
[et_compromised](#et_compromised)|2367|2367|3|0.1%|0.0%|
[dshield](#dshield)|20|5120|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2309|2309|3|0.1%|0.0%|
[voipbl](#voipbl)|10305|10714|2|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|395|395|2|0.5%|0.0%|
[xroxy](#xroxy)|1949|1949|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4741|4741|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1812|1812|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1569|1569|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[openbl_1d](#openbl_1d)|243|243|1|0.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Fri May 29 23:28:12 UTC 2015.

The ipset `blocklist_de_bots` has **3474** entries, **3474** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22510|22510|3470|15.4%|99.8%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|2360|2.5%|67.9%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|2119|6.8%|60.9%|
[stopforumspam_1d](#stopforumspam_1d)|6982|6982|1493|21.3%|42.9%|
[ri_web_proxies](#ri_web_proxies)|4741|4741|367|7.7%|10.5%|
[xroxy](#xroxy)|1949|1949|270|13.8%|7.7%|
[proxyrss](#proxyrss)|1569|1569|239|15.2%|6.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|158|0.0%|4.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|237|237|135|56.9%|3.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|101|0.0%|2.9%|
[ri_connect_proxies](#ri_connect_proxies)|1812|1812|86|4.7%|2.4%|
[php_commenters](#php_commenters)|281|281|53|18.8%|1.5%|
[php_bad](#php_bad)|281|281|53|18.8%|1.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|53|0.0%|1.5%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|52|0.0%|1.4%|
[nixspam](#nixspam)|21367|21367|52|0.2%|1.4%|
[et_block](#et_block)|986|18056524|52|0.0%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|44|0.0%|1.2%|
[proxz](#proxz)|184|184|41|22.2%|1.1%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|34|0.4%|0.9%|
[php_harvesters](#php_harvesters)|257|257|27|10.5%|0.7%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|24|0.0%|0.6%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|22|0.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|14794|14794|17|0.1%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|12828|12828|17|0.1%|0.4%|
[php_spammers](#php_spammers)|417|417|15|3.5%|0.4%|
[php_dictionary](#php_dictionary)|433|433|14|3.2%|0.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|5|0.7%|0.1%|
[voipbl](#voipbl)|10305|10714|2|0.0%|0.0%|
[openbl_90d](#openbl_90d)|9814|9814|1|0.0%|0.0%|
[openbl](#openbl)|9814|9814|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Fri May 29 23:14:14 UTC 2015.

The ipset `blocklist_de_bruteforce` has **1475** entries, **1475** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_apache](#blocklist_de_apache)|12828|12828|1475|11.4%|100.0%|
[blocklist_de](#blocklist_de)|22510|22510|1474|6.5%|99.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|112|0.0%|7.5%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|87|0.0%|5.8%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|75|0.2%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|43|0.0%|2.9%|
[stopforumspam_1d](#stopforumspam_1d)|6982|6982|37|0.5%|2.5%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|34|0.4%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|29|0.0%|1.9%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|20|0.0%|1.3%|
[et_tor](#et_tor)|6470|6470|19|0.2%|1.2%|
[dm_tor](#dm_tor)|6451|6451|19|0.2%|1.2%|
[bm_tor](#bm_tor)|6453|6453|19|0.2%|1.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|237|237|11|4.6%|0.7%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.4%|
[php_commenters](#php_commenters)|281|281|6|2.1%|0.4%|
[php_bad](#php_bad)|281|281|6|2.1%|0.4%|
[openbl_90d](#openbl_90d)|9814|9814|5|0.0%|0.3%|
[openbl](#openbl)|9814|9814|5|0.0%|0.3%|
[nixspam](#nixspam)|21367|21367|5|0.0%|0.3%|
[et_block](#et_block)|986|18056524|4|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|3|0.0%|0.2%|
[shunlist](#shunlist)|1146|1146|3|0.2%|0.2%|
[openbl_60d](#openbl_60d)|7699|7699|3|0.0%|0.2%|
[cleanmx_viruses](#cleanmx_viruses)|395|395|2|0.5%|0.1%|
[xroxy](#xroxy)|1949|1949|1|0.0%|0.0%|
[voipbl](#voipbl)|10305|10714|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4741|4741|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1812|1812|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1569|1569|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4363|4363|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2309|2309|1|0.0%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Fri May 29 23:14:11 UTC 2015.

The ipset `blocklist_de_ftp` has **410** entries, **410** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22510|22510|410|1.8%|100.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|30|0.0%|7.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|24|0.0%|5.8%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|18|0.0%|4.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|13|0.0%|3.1%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|9|0.0%|2.1%|
[openbl_90d](#openbl_90d)|9814|9814|8|0.0%|1.9%|
[openbl](#openbl)|9814|9814|8|0.0%|1.9%|
[openbl_60d](#openbl_60d)|7699|7699|7|0.0%|1.7%|
[nixspam](#nixspam)|21367|21367|6|0.0%|1.4%|
[php_harvesters](#php_harvesters)|257|257|4|1.5%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|3|0.0%|0.7%|
[stopforumspam_1d](#stopforumspam_1d)|6982|6982|2|0.0%|0.4%|
[openbl_7d](#openbl_7d)|949|949|2|0.2%|0.4%|
[openbl_30d](#openbl_30d)|4363|4363|2|0.0%|0.4%|
[ciarmy](#ciarmy)|370|370|2|0.5%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|237|237|2|0.8%|0.4%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|1|0.0%|0.2%|
[shunlist](#shunlist)|1146|1146|1|0.0%|0.2%|
[openbl_1d](#openbl_1d)|243|243|1|0.4%|0.2%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Fri May 29 23:28:11 UTC 2015.

The ipset `blocklist_de_imap` has **811** entries, **811** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22510|22510|811|3.6%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|14794|14794|810|5.4%|99.8%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|64|0.0%|7.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|58|0.0%|7.1%|
[openbl_90d](#openbl_90d)|9814|9814|50|0.5%|6.1%|
[openbl](#openbl)|9814|9814|50|0.5%|6.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|47|0.0%|5.7%|
[openbl_60d](#openbl_60d)|7699|7699|46|0.5%|5.6%|
[openbl_30d](#openbl_30d)|4363|4363|42|0.9%|5.1%|
[openbl_7d](#openbl_7d)|949|949|25|2.6%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|16|0.0%|1.9%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|13|0.0%|1.6%|
[et_compromised](#et_compromised)|2367|2367|13|0.5%|1.6%|
[et_block](#et_block)|986|18056524|13|0.0%|1.6%|
[bruteforceblocker](#bruteforceblocker)|2309|2309|11|0.4%|1.3%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|7|0.1%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|4|0.0%|0.4%|
[shunlist](#shunlist)|1146|1146|4|0.3%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.3%|
[openbl_1d](#openbl_1d)|243|243|2|0.8%|0.2%|
[voipbl](#voipbl)|10305|10714|1|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|1|0.0%|0.1%|
[nixspam](#nixspam)|21367|21367|1|0.0%|0.1%|
[ciarmy](#ciarmy)|370|370|1|0.2%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|237|237|1|0.4%|0.1%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Fri May 29 23:14:09 UTC 2015.

The ipset `blocklist_de_mail` has **14794** entries, **14794** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22510|22510|14780|65.6%|99.9%|
[blocklist_de_apache](#blocklist_de_apache)|12828|12828|11059|86.2%|74.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2307|0.0%|15.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1336|0.0%|9.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1159|0.0%|7.8%|
[blocklist_de_imap](#blocklist_de_imap)|811|811|810|99.8%|5.4%|
[nixspam](#nixspam)|21367|21367|457|2.1%|3.0%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|210|0.2%|1.4%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|144|2.1%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|98|0.3%|0.6%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|85|0.0%|0.5%|
[openbl_90d](#openbl_90d)|9814|9814|61|0.6%|0.4%|
[openbl](#openbl)|9814|9814|61|0.6%|0.4%|
[openbl_60d](#openbl_60d)|7699|7699|57|0.7%|0.3%|
[php_dictionary](#php_dictionary)|433|433|55|12.7%|0.3%|
[openbl_30d](#openbl_30d)|4363|4363|52|1.1%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6982|6982|48|0.6%|0.3%|
[xroxy](#xroxy)|1949|1949|45|2.3%|0.3%|
[php_spammers](#php_spammers)|417|417|41|9.8%|0.2%|
[ri_web_proxies](#ri_web_proxies)|4741|4741|30|0.6%|0.2%|
[openbl_7d](#openbl_7d)|949|949|29|3.0%|0.1%|
[php_commenters](#php_commenters)|281|281|22|7.8%|0.1%|
[php_bad](#php_bad)|281|281|21|7.4%|0.1%|
[et_block](#et_block)|986|18056524|20|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|19|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|237|237|18|7.5%|0.1%|
[et_compromised](#et_compromised)|2367|2367|17|0.7%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3474|3474|17|0.4%|0.1%|
[bruteforceblocker](#bruteforceblocker)|2309|2309|15|0.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6|0.0%|0.0%|
[shunlist](#shunlist)|1146|1146|4|0.3%|0.0%|
[voipbl](#voipbl)|10305|10714|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|3|1.1%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6451|6451|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6453|6453|3|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|2|0.0%|0.0%|
[openbl_1d](#openbl_1d)|243|243|2|0.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1812|1812|1|0.0%|0.0%|
[proxz](#proxz)|184|184|1|0.5%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[ciarmy](#ciarmy)|370|370|1|0.2%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Fri May 29 23:28:11 UTC 2015.

The ipset `blocklist_de_sip` has **93** entries, **93** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22510|22510|74|0.3%|79.5%|
[voipbl](#voipbl)|10305|10714|31|0.2%|33.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|18|0.0%|19.3%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|18|0.0%|19.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7|0.0%|7.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|5.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|2.1%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|1|0.0%|1.0%|
[shunlist](#shunlist)|1146|1146|1|0.0%|1.0%|
[nixspam](#nixspam)|21367|21367|1|0.0%|1.0%|
[et_botnet](#et_botnet)|501|501|1|0.1%|1.0%|
[et_block](#et_block)|986|18056524|1|0.0%|1.0%|
[ciarmy](#ciarmy)|370|370|1|0.2%|1.0%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Fri May 29 23:14:06 UTC 2015.

The ipset `blocklist_de_ssh` has **1985** entries, **1985** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22510|22510|1978|8.7%|99.6%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|1159|0.6%|58.3%|
[openbl_90d](#openbl_90d)|9814|9814|1080|11.0%|54.4%|
[openbl](#openbl)|9814|9814|1080|11.0%|54.4%|
[openbl_60d](#openbl_60d)|7699|7699|1038|13.4%|52.2%|
[openbl_30d](#openbl_30d)|4363|4363|969|22.2%|48.8%|
[bruteforceblocker](#bruteforceblocker)|2309|2309|922|39.9%|46.4%|
[et_compromised](#et_compromised)|2367|2367|911|38.4%|45.8%|
[openbl_7d](#openbl_7d)|949|949|604|63.6%|30.4%|
[shunlist](#shunlist)|1146|1146|507|44.2%|25.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|213|0.0%|10.7%|
[openbl_1d](#openbl_1d)|243|243|211|86.8%|10.6%|
[dshield](#dshield)|20|5120|161|3.1%|8.1%|
[et_block](#et_block)|986|18056524|117|0.0%|5.8%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|110|0.0%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|94|0.0%|4.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|237|237|78|32.9%|3.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|39|0.0%|1.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|6|0.0%|0.3%|
[voipbl](#voipbl)|10305|10714|4|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|2|0.0%|0.1%|
[xroxy](#xroxy)|1949|1949|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6982|6982|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|1|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.0%|
[nixspam](#nixspam)|21367|21367|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[ciarmy](#ciarmy)|370|370|1|0.2%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Fri May 29 23:14:14 UTC 2015.

The ipset `blocklist_de_strongips` has **237** entries, **237** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22510|22510|237|1.0%|100.0%|
[blocklist_de_bots](#blocklist_de_bots)|3474|3474|135|3.8%|56.9%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|133|0.1%|56.1%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|122|0.3%|51.4%|
[stopforumspam_1d](#stopforumspam_1d)|6982|6982|101|1.4%|42.6%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|89|0.0%|37.5%|
[openbl_90d](#openbl_90d)|9814|9814|80|0.8%|33.7%|
[openbl](#openbl)|9814|9814|80|0.8%|33.7%|
[openbl_60d](#openbl_60d)|7699|7699|79|1.0%|33.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|1985|1985|78|3.9%|32.9%|
[openbl_30d](#openbl_30d)|4363|4363|77|1.7%|32.4%|
[openbl_7d](#openbl_7d)|949|949|76|8.0%|32.0%|
[shunlist](#shunlist)|1146|1146|72|6.2%|30.3%|
[openbl_1d](#openbl_1d)|243|243|39|16.0%|16.4%|
[blocklist_de_apache](#blocklist_de_apache)|12828|12828|36|0.2%|15.1%|
[dshield](#dshield)|20|5120|34|0.6%|14.3%|
[php_commenters](#php_commenters)|281|281|33|11.7%|13.9%|
[php_bad](#php_bad)|281|281|33|11.7%|13.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|20|0.0%|8.4%|
[et_compromised](#et_compromised)|2367|2367|18|0.7%|7.5%|
[blocklist_de_mail](#blocklist_de_mail)|14794|14794|18|0.1%|7.5%|
[bruteforceblocker](#bruteforceblocker)|2309|2309|17|0.7%|7.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1475|1475|11|0.7%|4.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8|0.0%|3.3%|
[xroxy](#xroxy)|1949|1949|6|0.3%|2.5%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|6|0.0%|2.5%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|6|0.0%|2.5%|
[et_block](#et_block)|986|18056524|6|0.0%|2.5%|
[php_spammers](#php_spammers)|417|417|5|1.1%|2.1%|
[ri_web_proxies](#ri_web_proxies)|4741|4741|3|0.0%|1.2%|
[nixspam](#nixspam)|21367|21367|3|0.0%|1.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.2%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.8%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.8%|
[blocklist_de_ftp](#blocklist_de_ftp)|410|410|2|0.4%|0.8%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|1|0.0%|0.4%|
[proxyrss](#proxyrss)|1569|1569|1|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|811|811|1|0.1%|0.4%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Fri May 29 23:36:15 UTC 2015.

The ipset `bm_tor` has **6453** entries, **6453** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[dm_tor](#dm_tor)|6451|6451|6367|98.6%|98.6%|
[et_tor](#et_tor)|6470|6470|5939|91.7%|92.0%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|1026|15.0%|15.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|612|0.0%|9.4%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|581|0.6%|9.0%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|448|1.4%|6.9%|
[stopforumspam_1d](#stopforumspam_1d)|6982|6982|320|4.5%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|183|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|173|46.5%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|159|0.0%|2.4%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|43|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|28|9.9%|0.4%|
[php_bad](#php_bad)|281|281|28|9.9%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|12828|12828|22|0.1%|0.3%|
[blocklist_de](#blocklist_de)|22510|22510|22|0.0%|0.3%|
[openbl_90d](#openbl_90d)|9814|9814|21|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7699|7699|21|0.2%|0.3%|
[openbl](#openbl)|9814|9814|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1475|1475|19|1.2%|0.2%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4741|4741|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|986|18056524|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14794|14794|3|0.0%|0.0%|
[xroxy](#xroxy)|1949|1949|2|0.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1812|1812|2|0.1%|0.0%|
[nixspam](#nixspam)|21367|21367|2|0.0%|0.0%|
[voipbl](#voipbl)|10305|10714|1|0.0%|0.0%|
[shunlist](#shunlist)|1146|1146|1|0.0%|0.0%|
[proxz](#proxz)|184|184|1|0.5%|0.0%|
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
[fullbogons](#fullbogons)|3656|670639576|592708608|88.3%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|4194304|3.0%|0.7%|
[voipbl](#voipbl)|10305|10714|319|2.9%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2309|2309|1|0.0%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD)

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Fri May 29 21:27:08 UTC 2015.

The ipset `bruteforceblocker` has **2309** entries, **2309** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_compromised](#et_compromised)|2367|2367|2280|96.3%|98.7%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|1456|0.8%|63.0%|
[openbl_90d](#openbl_90d)|9814|9814|1398|14.2%|60.5%|
[openbl](#openbl)|9814|9814|1398|14.2%|60.5%|
[openbl_60d](#openbl_60d)|7699|7699|1383|17.9%|59.8%|
[openbl_30d](#openbl_30d)|4363|4363|1320|30.2%|57.1%|
[blocklist_de](#blocklist_de)|22510|22510|942|4.1%|40.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|1985|1985|922|46.4%|39.9%|
[openbl_7d](#openbl_7d)|949|949|502|52.8%|21.7%|
[shunlist](#shunlist)|1146|1146|481|41.9%|20.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|221|0.0%|9.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|137|0.0%|5.9%|
[openbl_1d](#openbl_1d)|243|243|129|53.0%|5.5%|
[dshield](#dshield)|20|5120|126|2.4%|5.4%|
[et_block](#et_block)|986|18056524|103|0.0%|4.4%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|102|0.0%|4.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|65|0.0%|2.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|237|237|17|7.1%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|14794|14794|15|0.1%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|811|811|11|1.3%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|6|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|3|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12828|12828|3|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6982|6982|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|228|228|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[xroxy](#xroxy)|1949|1949|1|0.0%|0.0%|
[voipbl](#voipbl)|10305|10714|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|1|0.0%|0.0%|
[proxz](#proxz)|184|184|1|0.5%|0.0%|
[proxyrss](#proxyrss)|1569|1569|1|0.0%|0.0%|
[nixspam](#nixspam)|21367|21367|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3656|670639576|1|0.0%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1475|1475|1|0.0%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Fri May 29 22:15:16 UTC 2015.

The ipset `ciarmy` has **370** entries, **370** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|171480|171480|362|0.2%|97.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|67|0.0%|18.1%|
[blocklist_de](#blocklist_de)|22510|22510|33|0.1%|8.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|30|0.0%|8.1%|
[blocklist_de_apache](#blocklist_de_apache)|12828|12828|28|0.2%|7.5%|
[shunlist](#shunlist)|1146|1146|20|1.7%|5.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|17|0.0%|4.5%|
[voipbl](#voipbl)|10305|10714|3|0.0%|0.8%|
[blocklist_de_ftp](#blocklist_de_ftp)|410|410|2|0.4%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|1|0.0%|0.2%|
[openbl_90d](#openbl_90d)|9814|9814|1|0.0%|0.2%|
[openbl_7d](#openbl_7d)|949|949|1|0.1%|0.2%|
[openbl_60d](#openbl_60d)|7699|7699|1|0.0%|0.2%|
[openbl_30d](#openbl_30d)|4363|4363|1|0.0%|0.2%|
[openbl](#openbl)|9814|9814|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1985|1985|1|0.0%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|93|93|1|1.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|14794|14794|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|811|811|1|0.1%|0.2%|

## cleanmx_viruses

[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses

Source is downloaded from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive).

The last time downloaded was found to be dated: Fri May 29 17:09:25 UTC 2015.

The ipset `cleanmx_viruses` has **395** entries, **395** unique IPs.

The following table shows the overlaps of `cleanmx_viruses` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `cleanmx_viruses`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `cleanmx_viruses`.
- ` this % ` is the percentage **of this ipset (`cleanmx_viruses`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|49|0.0%|12.4%|
[malc0de](#malc0de)|410|410|38|9.2%|9.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|20|0.0%|5.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|12|0.0%|3.0%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|10|0.0%|2.5%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|5|0.0%|1.2%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|4|0.3%|1.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.7%|
[et_block](#et_block)|986|18056524|3|0.0%|0.7%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|2|0.0%|0.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1475|1475|2|0.1%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|12828|12828|2|0.0%|0.5%|
[blocklist_de](#blocklist_de)|22510|22510|2|0.0%|0.5%|
[zeus_badips](#zeus_badips)|228|228|1|0.4%|0.2%|
[zeus](#zeus)|266|266|1|0.3%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|1|0.0%|0.2%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Fri May 29 23:36:13 UTC 2015.

The ipset `dm_tor` has **6451** entries, **6451** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6453|6453|6367|98.6%|98.6%|
[et_tor](#et_tor)|6470|6470|5950|91.9%|92.2%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|1029|15.0%|15.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|614|0.0%|9.5%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|586|0.6%|9.0%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|451|1.4%|6.9%|
[stopforumspam_1d](#stopforumspam_1d)|6982|6982|322|4.6%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|183|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|174|46.7%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|159|0.0%|2.4%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|43|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[php_bad](#php_bad)|281|281|29|10.3%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|12828|12828|22|0.1%|0.3%|
[blocklist_de](#blocklist_de)|22510|22510|22|0.0%|0.3%|
[openbl_90d](#openbl_90d)|9814|9814|21|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7699|7699|21|0.2%|0.3%|
[openbl](#openbl)|9814|9814|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1475|1475|19|1.2%|0.2%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4741|4741|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|986|18056524|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14794|14794|3|0.0%|0.0%|
[xroxy](#xroxy)|1949|1949|2|0.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1812|1812|2|0.1%|0.0%|
[nixspam](#nixspam)|21367|21367|2|0.0%|0.0%|
[voipbl](#voipbl)|10305|10714|1|0.0%|0.0%|
[shunlist](#shunlist)|1146|1146|1|0.0%|0.0%|
[proxz](#proxz)|184|184|1|0.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Fri May 29 22:55:55 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|171480|171480|3840|2.2%|75.0%|
[et_block](#et_block)|986|18056524|768|0.0%|15.0%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|512|0.0%|10.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|256|0.0%|5.0%|
[openbl_90d](#openbl_90d)|9814|9814|194|1.9%|3.7%|
[openbl](#openbl)|9814|9814|194|1.9%|3.7%|
[openbl_60d](#openbl_60d)|7699|7699|190|2.4%|3.7%|
[openbl_30d](#openbl_30d)|4363|4363|172|3.9%|3.3%|
[blocklist_de](#blocklist_de)|22510|22510|164|0.7%|3.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1985|1985|161|8.1%|3.1%|
[shunlist](#shunlist)|1146|1146|152|13.2%|2.9%|
[openbl_7d](#openbl_7d)|949|949|126|13.2%|2.4%|
[et_compromised](#et_compromised)|2367|2367|126|5.3%|2.4%|
[bruteforceblocker](#bruteforceblocker)|2309|2309|126|5.4%|2.4%|
[openbl_1d](#openbl_1d)|243|243|43|17.6%|0.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|237|237|34|14.3%|0.6%|
[blocklist_de_apache](#blocklist_de_apache)|12828|12828|3|0.0%|0.0%|
[malc0de](#malc0de)|410|410|1|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1475|1475|1|0.0%|0.0%|

## et_block

[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)

Source is downloaded from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt).

The last time downloaded was found to be dated: Fri May 29 04:30:01 UTC 2015.

The ipset `et_block` has **986** entries, **18056524** unique IPs.

The following table shows the overlaps of `et_block` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_block`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_block`.
- ` this % ` is the percentage **of this ipset (`et_block`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[spamhaus_drop](#spamhaus_drop)|639|17921280|17920256|99.9%|99.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8402471|2.4%|46.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7211008|78.5%|39.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|2133460|0.2%|11.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|196184|0.1%|1.0%|
[fullbogons](#fullbogons)|3656|670639576|20480|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|6043|3.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1040|0.3%|0.0%|
[dshield](#dshield)|20|5120|768|15.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|743|0.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|517|0.1%|0.0%|
[openbl_90d](#openbl_90d)|9814|9814|453|4.6%|0.0%|
[openbl](#openbl)|9814|9814|453|4.6%|0.0%|
[nixspam](#nixspam)|21367|21367|334|1.5%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|294|4.3%|0.0%|
[zeus](#zeus)|266|266|264|99.2%|0.0%|
[openbl_60d](#openbl_60d)|7699|7699|240|3.1%|0.0%|
[zeus_badips](#zeus_badips)|228|228|228|100.0%|0.0%|
[openbl_30d](#openbl_30d)|4363|4363|210|4.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|204|0.6%|0.0%|
[blocklist_de](#blocklist_de)|22510|22510|195|0.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1985|1985|117|5.8%|0.0%|
[shunlist](#shunlist)|1146|1146|109|9.5%|0.0%|
[et_compromised](#et_compromised)|2367|2367|103|4.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2309|2309|103|4.4%|0.0%|
[openbl_7d](#openbl_7d)|949|949|85|8.9%|0.0%|
[feodo](#feodo)|68|68|67|98.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6982|6982|61|0.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3474|3474|52|1.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|28|2.1%|0.0%|
[sslbl](#sslbl)|347|347|27|7.7%|0.0%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.0%|
[php_bad](#php_bad)|281|281|24|8.5%|0.0%|
[openbl_1d](#openbl_1d)|243|243|24|9.8%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14794|14794|20|0.1%|0.0%|
[voipbl](#voipbl)|10305|10714|17|0.1%|0.0%|
[palevo](#palevo)|13|13|13|100.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|811|811|13|1.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|7|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|237|237|6|2.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12828|12828|6|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1475|1475|4|0.2%|0.0%|
[malc0de](#malc0de)|410|410|3|0.7%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6451|6451|3|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|395|395|3|0.7%|0.0%|
[bm_tor](#bm_tor)|6453|6453|3|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[et_botnet](#et_botnet)|501|501|1|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|93|93|1|1.0%|0.0%|

## et_botnet

[EmergingThreats.net](http://www.emergingthreats.net/) botnet IPs

Source is downloaded from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules).

The last time downloaded was found to be dated: Fri May 29 04:30:01 UTC 2015.

The ipset `et_botnet` has **501** entries, **501** unique IPs.

The following table shows the overlaps of `et_botnet` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_botnet`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_botnet`.
- ` this % ` is the percentage **of this ipset (`et_botnet`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|74|0.0%|14.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|40|0.0%|7.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|21|0.0%|4.1%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|3|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[et_block](#et_block)|986|18056524|1|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|93|93|1|1.0%|0.1%|

## et_compromised

[EmergingThreats.net](http://www.emergingthreats.net/) compromised hosts (seems to be a derivate of other lists)

Source is downloaded from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt).

The last time downloaded was found to be dated: Fri May 29 04:30:09 UTC 2015.

The ipset `et_compromised` has **2367** entries, **2367** unique IPs.

The following table shows the overlaps of `et_compromised` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_compromised`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_compromised`.
- ` this % ` is the percentage **of this ipset (`et_compromised`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bruteforceblocker](#bruteforceblocker)|2309|2309|2280|98.7%|96.3%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|1495|0.8%|63.1%|
[openbl_90d](#openbl_90d)|9814|9814|1430|14.5%|60.4%|
[openbl](#openbl)|9814|9814|1430|14.5%|60.4%|
[openbl_60d](#openbl_60d)|7699|7699|1415|18.3%|59.7%|
[openbl_30d](#openbl_30d)|4363|4363|1341|30.7%|56.6%|
[blocklist_de](#blocklist_de)|22510|22510|932|4.1%|39.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|1985|1985|911|45.8%|38.4%|
[openbl_7d](#openbl_7d)|949|949|499|52.5%|21.0%|
[shunlist](#shunlist)|1146|1146|482|42.0%|20.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|227|0.0%|9.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|140|0.0%|5.9%|
[openbl_1d](#openbl_1d)|243|243|126|51.8%|5.3%|
[dshield](#dshield)|20|5120|126|2.4%|5.3%|
[et_block](#et_block)|986|18056524|103|0.0%|4.3%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|102|0.0%|4.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|70|0.0%|2.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|237|237|18|7.5%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|14794|14794|17|0.1%|0.7%|
[blocklist_de_imap](#blocklist_de_imap)|811|811|13|1.6%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|6|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|3|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12828|12828|3|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6982|6982|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|228|228|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[xroxy](#xroxy)|1949|1949|1|0.0%|0.0%|
[voipbl](#voipbl)|10305|10714|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|1|0.0%|0.0%|
[proxz](#proxz)|184|184|1|0.5%|0.0%|
[proxyrss](#proxyrss)|1569|1569|1|0.0%|0.0%|
[nixspam](#nixspam)|21367|21367|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1475|1475|1|0.0%|0.0%|

## et_tor

[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs

Source is downloaded from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules).

The last time downloaded was found to be dated: Fri May 29 04:30:08 UTC 2015.

The ipset `et_tor` has **6470** entries, **6470** unique IPs.

The following table shows the overlaps of `et_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_tor`.
- ` this % ` is the percentage **of this ipset (`et_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[dm_tor](#dm_tor)|6451|6451|5950|92.2%|91.9%|
[bm_tor](#bm_tor)|6453|6453|5939|92.0%|91.7%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|1072|15.7%|16.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|619|0.0%|9.5%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|602|0.6%|9.3%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|463|1.4%|7.1%|
[stopforumspam_1d](#stopforumspam_1d)|6982|6982|326|4.6%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|184|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|179|48.1%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|163|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|44|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[php_bad](#php_bad)|281|281|29|10.3%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|12828|12828|22|0.1%|0.3%|
[blocklist_de](#blocklist_de)|22510|22510|22|0.0%|0.3%|
[openbl_90d](#openbl_90d)|9814|9814|21|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7699|7699|21|0.2%|0.3%|
[openbl](#openbl)|9814|9814|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1475|1475|19|1.2%|0.2%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4741|4741|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|986|18056524|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14794|14794|3|0.0%|0.0%|
[xroxy](#xroxy)|1949|1949|2|0.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1812|1812|2|0.1%|0.0%|
[nixspam](#nixspam)|21367|21367|2|0.0%|0.0%|
[voipbl](#voipbl)|10305|10714|1|0.0%|0.0%|
[shunlist](#shunlist)|1146|1146|1|0.0%|0.0%|
[proxz](#proxz)|184|184|1|0.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Fri May 29 23:36:23 UTC 2015.

The ipset `feodo` has **68** entries, **68** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|986|18056524|67|0.0%|98.5%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|53|0.7%|77.9%|
[sslbl](#sslbl)|347|347|25|7.2%|36.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|4|0.0%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|3|0.0%|4.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|4.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|1.4%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|1|0.0%|1.4%|

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
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|234871|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|20480|0.1%|0.0%|
[et_block](#et_block)|986|18056524|20480|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|890|0.2%|0.0%|
[voipbl](#voipbl)|10305|10714|319|2.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|33|2.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|9|0.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2309|2309|1|0.0%|0.0%|

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
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|406|0.0%|0.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|230|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|15|0.0%|0.0%|
[fullbogons](#fullbogons)|3656|670639576|14|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|13|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.0%|
[nixspam](#nixspam)|21367|21367|9|0.0%|0.0%|
[et_block](#et_block)|986|18056524|7|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|6|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[xroxy](#xroxy)|1949|1949|3|0.1%|0.0%|
[voipbl](#voipbl)|10305|10714|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14794|14794|2|0.0%|0.0%|
[blocklist_de](#blocklist_de)|22510|22510|2|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6982|6982|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4741|4741|1|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|

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
[et_block](#et_block)|986|18056524|7211008|39.9%|78.5%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|7079936|39.5%|77.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2526625|0.7%|27.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|904796|0.1%|9.8%|
[fullbogons](#fullbogons)|3656|670639576|565248|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|145472|0.1%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1036|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|742|0.8%|0.0%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|518|0.3%|0.0%|
[nixspam](#nixspam)|21367|21367|333|1.5%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|194|0.6%|0.0%|
[blocklist_de](#blocklist_de)|22510|22510|70|0.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3474|3474|53|1.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6982|6982|39|0.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|27|2.1%|0.0%|
[openbl_90d](#openbl_90d)|9814|9814|20|0.2%|0.0%|
[openbl](#openbl)|9814|9814|20|0.2%|0.0%|
[openbl_60d](#openbl_60d)|7699|7699|19|0.2%|0.0%|
[openbl_30d](#openbl_30d)|4363|4363|14|0.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|11|0.1%|0.0%|
[openbl_7d](#openbl_7d)|949|949|11|1.1%|0.0%|
[zeus_badips](#zeus_badips)|228|228|10|4.3%|0.0%|
[zeus](#zeus)|266|266|10|3.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1985|1985|10|0.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[openbl_1d](#openbl_1d)|243|243|6|2.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14794|14794|6|0.0%|0.0%|
[et_compromised](#et_compromised)|2367|2367|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2309|2309|5|0.2%|0.0%|
[shunlist](#shunlist)|1146|1146|4|0.3%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6451|6451|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6453|6453|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|237|237|3|1.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|811|811|3|0.3%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12828|12828|2|0.0%|0.0%|
[voipbl](#voipbl)|10305|10714|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.0%|
[php_bad](#php_bad)|281|281|1|0.3%|0.0%|
[et_botnet](#et_botnet)|501|501|1|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1475|1475|1|0.0%|0.0%|

## ib_bluetack_level1

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Level 1 (for use in p2p): Companies or organizations who are clearly involved with trying to stop filesharing (e.g. Baytsp, MediaDefender, Mediasentry a.o.). Companies which anti-p2p activity has been seen from. Companies that produce or have a strong financial interest in copyrighted material (e.g. music, movie, software industries a.o.). Government ranges or companies that have a strong financial interest in doing work for governments. Legal industry ranges. IPs or ranges of ISPs from which anti-p2p activity has been observed. Basically this list will block all kinds of internet connections that most people would rather not have during their internet travels.

Source is downloaded from [this link](http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Fri May 29 09:30:03 UTC 2015.

The ipset `ib_bluetack_level1` has **218309** entries, **764987411** unique IPs.

The following table shows the overlaps of `ib_bluetack_level1` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level1`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level1`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level1`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|16300309|4.6%|2.1%|
[et_block](#et_block)|986|18056524|2133460|11.8%|0.2%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|2133002|11.9%|0.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1354348|0.9%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904796|9.8%|0.1%|
[fullbogons](#fullbogons)|3656|670639576|234871|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|33155|7.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|13248|3.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|4704|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|1511|1.6%|0.0%|
[blocklist_de](#blocklist_de)|22510|22510|1473|6.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14794|14794|1336|9.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12828|12828|1318|10.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|576|1.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|406|0.8%|0.0%|
[voipbl](#voipbl)|10305|10714|295|2.7%|0.0%|
[nixspam](#nixspam)|21367|21367|275|1.2%|0.0%|
[openbl_90d](#openbl_90d)|9814|9814|216|2.2%|0.0%|
[openbl](#openbl)|9814|9814|216|2.2%|0.0%|
[openbl_60d](#openbl_60d)|7699|7699|179|2.3%|0.0%|
[et_tor](#et_tor)|6470|6470|163|2.5%|0.0%|
[dm_tor](#dm_tor)|6451|6451|159|2.4%|0.0%|
[bm_tor](#bm_tor)|6453|6453|159|2.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6982|6982|149|2.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4741|4741|108|2.2%|0.0%|
[openbl_30d](#openbl_30d)|4363|4363|98|2.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|97|6.6%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|78|1.1%|0.0%|
[et_compromised](#et_compromised)|2367|2367|70|2.9%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|66|5.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2309|2309|65|2.8%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1812|1812|63|3.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|58|8.6%|0.0%|
[xroxy](#xroxy)|1949|1949|53|2.7%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3474|3474|44|1.2%|0.0%|
[et_botnet](#et_botnet)|501|501|40|7.9%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1985|1985|39|1.9%|0.0%|
[proxyrss](#proxyrss)|1569|1569|38|2.4%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1475|1475|29|1.9%|0.0%|
[shunlist](#shunlist)|1146|1146|24|2.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|17|4.5%|0.0%|
[ciarmy](#ciarmy)|370|370|17|4.5%|0.0%|
[openbl_7d](#openbl_7d)|949|949|16|1.6%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|811|811|16|1.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|410|410|13|3.1%|0.0%|
[malc0de](#malc0de)|410|410|12|2.9%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|395|395|12|3.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|9|2.0%|0.0%|
[zeus](#zeus)|266|266|8|3.0%|0.0%|
[proxz](#proxz)|184|184|8|4.3%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.0%|
[php_commenters](#php_commenters)|281|281|5|1.7%|0.0%|
[php_bad](#php_bad)|281|281|5|1.7%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|93|93|5|5.3%|0.0%|
[zeus_badips](#zeus_badips)|228|228|4|1.7%|0.0%|
[sslbl](#sslbl)|347|347|3|0.8%|0.0%|
[feodo](#feodo)|68|68|3|4.4%|0.0%|
[openbl_1d](#openbl_1d)|243|243|2|0.8%|0.0%|

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
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|16300309|2.1%|4.6%|
[et_block](#et_block)|986|18056524|8402471|46.5%|2.4%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|8401434|46.8%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2830140|2.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2526625|27.5%|0.7%|
[fullbogons](#fullbogons)|3656|670639576|248319|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|33368|7.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|7861|4.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|7733|2.2%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|2445|2.6%|0.0%|
[blocklist_de](#blocklist_de)|22510|22510|1449|6.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14794|14794|1159|7.8%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12828|12828|1081|8.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|904|2.9%|0.0%|
[nixspam](#nixspam)|21367|21367|540|2.5%|0.0%|
[openbl_90d](#openbl_90d)|9814|9814|503|5.1%|0.0%|
[openbl](#openbl)|9814|9814|503|5.1%|0.0%|
[voipbl](#voipbl)|10305|10714|429|4.0%|0.0%|
[openbl_60d](#openbl_60d)|7699|7699|359|4.6%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6982|6982|247|3.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|230|0.4%|0.0%|
[openbl_30d](#openbl_30d)|4363|4363|220|5.0%|0.0%|
[et_tor](#et_tor)|6470|6470|184|2.8%|0.0%|
[dm_tor](#dm_tor)|6451|6451|183|2.8%|0.0%|
[bm_tor](#bm_tor)|6453|6453|183|2.8%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4741|4741|165|3.4%|0.0%|
[et_compromised](#et_compromised)|2367|2367|140|5.9%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2309|2309|137|5.9%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|103|1.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3474|3474|101|2.9%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1985|1985|94|4.7%|0.0%|
[xroxy](#xroxy)|1949|1949|92|4.7%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1812|1812|76|4.1%|0.0%|
[proxyrss](#proxyrss)|1569|1569|71|4.5%|0.0%|
[shunlist](#shunlist)|1146|1146|69|6.0%|0.0%|
[openbl_7d](#openbl_7d)|949|949|49|5.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|811|811|47|5.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|45|3.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1475|1475|43|2.9%|0.0%|
[php_spammers](#php_spammers)|417|417|31|7.4%|0.0%|
[ciarmy](#ciarmy)|370|370|30|8.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|410|410|30|7.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|28|4.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|26|2.0%|0.0%|
[malc0de](#malc0de)|410|410|26|6.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|21|5.6%|0.0%|
[et_botnet](#et_botnet)|501|501|21|4.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|395|395|20|5.0%|0.0%|
[openbl_1d](#openbl_1d)|243|243|12|4.9%|0.0%|
[php_dictionary](#php_dictionary)|433|433|10|2.3%|0.0%|
[zeus](#zeus)|266|266|9|3.3%|0.0%|
[php_commenters](#php_commenters)|281|281|9|3.2%|0.0%|
[php_bad](#php_bad)|281|281|9|3.2%|0.0%|
[zeus_badips](#zeus_badips)|228|228|8|3.5%|0.0%|
[proxz](#proxz)|184|184|8|4.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|237|237|8|3.3%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|93|93|7|7.5%|0.0%|
[sslbl](#sslbl)|347|347|6|1.7%|0.0%|
[feodo](#feodo)|68|68|3|4.4%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|

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
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1354348|0.1%|0.9%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|270785|64.3%|0.1%|
[et_block](#et_block)|986|18056524|196184|1.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|195904|1.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|14628|8.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|9231|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|6079|6.5%|0.0%|
[blocklist_de](#blocklist_de)|22510|22510|2853|12.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14794|14794|2307|15.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12828|12828|2207|17.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|2103|6.7%|0.0%|
[voipbl](#voipbl)|10305|10714|1586|14.8%|0.0%|
[nixspam](#nixspam)|21367|21367|1206|5.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1172|2.4%|0.0%|
[openbl_90d](#openbl_90d)|9814|9814|944|9.6%|0.0%|
[openbl](#openbl)|9814|9814|944|9.6%|0.0%|
[openbl_60d](#openbl_60d)|7699|7699|720|9.3%|0.0%|
[et_tor](#et_tor)|6470|6470|619|9.5%|0.0%|
[dm_tor](#dm_tor)|6451|6451|614|9.5%|0.0%|
[bm_tor](#bm_tor)|6453|6453|612|9.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6982|6982|445|6.3%|0.0%|
[openbl_30d](#openbl_30d)|4363|4363|438|10.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|231|3.3%|0.0%|
[et_compromised](#et_compromised)|2367|2367|227|9.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2309|2309|221|9.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1985|1985|213|10.7%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3474|3474|158|4.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|146|11.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4741|4741|144|3.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|125|33.6%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1475|1475|112|7.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|110|7.5%|0.0%|
[openbl_7d](#openbl_7d)|949|949|95|10.0%|0.0%|
[shunlist](#shunlist)|1146|1146|88|7.6%|0.0%|
[xroxy](#xroxy)|1949|1949|77|3.9%|0.0%|
[malc0de](#malc0de)|410|410|76|18.5%|0.0%|
[et_botnet](#et_botnet)|501|501|74|14.7%|0.0%|
[ciarmy](#ciarmy)|370|370|67|18.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|811|811|58|7.1%|0.0%|
[proxyrss](#proxyrss)|1569|1569|55|3.5%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|51|7.5%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|395|395|49|12.4%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1812|1812|42|2.3%|0.0%|
[proxz](#proxz)|184|184|26|14.1%|0.0%|
[php_spammers](#php_spammers)|417|417|26|6.2%|0.0%|
[php_dictionary](#php_dictionary)|433|433|24|5.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|410|410|24|5.8%|0.0%|
[sslbl](#sslbl)|347|347|23|6.6%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|237|237|20|8.4%|0.0%|
[zeus](#zeus)|266|266|19|7.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|93|93|18|19.3%|0.0%|
[openbl_1d](#openbl_1d)|243|243|17|6.9%|0.0%|
[php_bad](#php_bad)|281|281|16|5.6%|0.0%|
[php_harvesters](#php_harvesters)|257|257|15|5.8%|0.0%|
[php_commenters](#php_commenters)|281|281|15|5.3%|0.0%|
[zeus_badips](#zeus_badips)|228|228|14|6.1%|0.0%|
[feodo](#feodo)|68|68|4|5.8%|0.0%|
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
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|58|0.0%|8.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|51|0.0%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|28|0.0%|4.1%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|22|0.0%|3.2%|
[xroxy](#xroxy)|1949|1949|13|0.6%|1.9%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|11|0.0%|1.6%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|10|0.0%|1.4%|
[ri_web_proxies](#ri_web_proxies)|4741|4741|10|0.2%|1.4%|
[ri_connect_proxies](#ri_connect_proxies)|1812|1812|6|0.3%|0.8%|
[proxyrss](#proxyrss)|1569|1569|6|0.3%|0.8%|
[stopforumspam_1d](#stopforumspam_1d)|6982|6982|5|0.0%|0.7%|
[blocklist_de_bots](#blocklist_de_bots)|3474|3474|5|0.1%|0.7%|
[blocklist_de](#blocklist_de)|22510|22510|5|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|2|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.2%|
[et_block](#et_block)|986|18056524|2|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|1|0.0%|0.1%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.1%|
[nixspam](#nixspam)|21367|21367|1|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|1|0.0%|0.1%|

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
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|13248|0.0%|3.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|9231|0.0%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7733|0.0%|2.2%|
[et_block](#et_block)|986|18056524|1040|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|1037|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1036|0.0%|0.3%|
[fullbogons](#fullbogons)|3656|670639576|890|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|289|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|41|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|25|1.9%|0.0%|
[et_tor](#et_tor)|6470|6470|21|0.3%|0.0%|
[dm_tor](#dm_tor)|6451|6451|21|0.3%|0.0%|
[bm_tor](#bm_tor)|6453|6453|21|0.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|19|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|19|1.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|15|0.2%|0.0%|
[nixspam](#nixspam)|21367|21367|11|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6982|6982|10|0.1%|0.0%|
[openbl_90d](#openbl_90d)|9814|9814|6|0.0%|0.0%|
[openbl](#openbl)|9814|9814|6|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7699|7699|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|5|1.3%|0.0%|
[voipbl](#voipbl)|10305|10714|4|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4741|4741|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4363|4363|4|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[malc0de](#malc0de)|410|410|3|0.7%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|395|395|3|0.7%|0.0%|
[blocklist_de](#blocklist_de)|22510|22510|3|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|93|93|2|2.1%|0.0%|
[zeus_badips](#zeus_badips)|228|228|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[xroxy](#xroxy)|1949|1949|1|0.0%|0.0%|
[sslbl](#sslbl)|347|347|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[shunlist](#shunlist)|1146|1146|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|
[openbl_7d](#openbl_7d)|949|949|1|0.1%|0.0%|
[feodo](#feodo)|68|68|1|1.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2309|2309|1|0.0%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1985|1985|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14794|14794|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3474|3474|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12828|12828|1|0.0%|0.0%|

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
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|97|0.0%|6.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|45|0.0%|3.0%|
[fullbogons](#fullbogons)|3656|670639576|33|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|19|0.0%|1.3%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|8|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|6|0.0%|0.4%|
[et_block](#et_block)|986|18056524|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|3|0.2%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|2|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|2|0.0%|0.1%|
[openbl_90d](#openbl_90d)|9814|9814|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7699|7699|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|4363|4363|2|0.0%|0.1%|
[openbl](#openbl)|9814|9814|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.1%|
[et_compromised](#et_compromised)|2367|2367|2|0.0%|0.1%|
[bruteforceblocker](#bruteforceblocker)|2309|2309|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6982|6982|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4741|4741|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|949|949|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[et_botnet](#et_botnet)|501|501|1|0.1%|0.0%|
[dm_tor](#dm_tor)|6451|6451|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6453|6453|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1985|1985|1|0.0%|0.0%|
[blocklist_de](#blocklist_de)|22510|22510|1|0.0%|0.0%|

## malc0de

[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days

Source is downloaded from [this link](http://malc0de.com/bl/IP_Blacklist.txt).

The last time downloaded was found to be dated: Fri May 29 13:17:02 UTC 2015.

The ipset `malc0de` has **410** entries, **410** unique IPs.

The following table shows the overlaps of `malc0de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `malc0de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `malc0de`.
- ` this % ` is the percentage **of this ipset (`malc0de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|76|0.0%|18.5%|
[cleanmx_viruses](#cleanmx_viruses)|395|395|38|9.6%|9.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|26|0.0%|6.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|12|0.0%|2.9%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|9|0.0%|2.1%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|4|0.3%|0.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.7%|
[et_block](#et_block)|986|18056524|3|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|2|0.0%|0.4%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|1|0.0%|0.2%|
[dshield](#dshield)|20|5120|1|0.0%|0.2%|

## malwaredomainlist

[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses

Source is downloaded from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt).

The last time downloaded was found to be dated: Fri May 29 07:57:25 UTC 2015.

The ipset `malwaredomainlist` has **1282** entries, **1282** unique IPs.

The following table shows the overlaps of `malwaredomainlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `malwaredomainlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `malwaredomainlist`.
- ` this % ` is the percentage **of this ipset (`malwaredomainlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|146|0.0%|11.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|66|0.0%|5.1%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|29|0.0%|2.2%|
[et_block](#et_block)|986|18056524|28|0.0%|2.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.1%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|26|0.3%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|26|0.0%|2.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|25|0.0%|1.9%|
[fullbogons](#fullbogons)|3656|670639576|9|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|7|0.0%|0.5%|
[malc0de](#malc0de)|410|410|4|0.9%|0.3%|
[cleanmx_viruses](#cleanmx_viruses)|395|395|4|1.0%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|2|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6982|6982|1|0.0%|0.0%|
[et_botnet](#et_botnet)|501|501|1|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3474|3474|1|0.0%|0.0%|
[blocklist_de](#blocklist_de)|22510|22510|1|0.0%|0.0%|

## maxmind_proxy_fraud

[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.

Source is downloaded from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list).

The last time downloaded was found to be dated: Fri May 29 20:27:04 UTC 2015.

The ipset `maxmind_proxy_fraud` has **372** entries, **372** unique IPs.

The following table shows the overlaps of `maxmind_proxy_fraud` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `maxmind_proxy_fraud`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `maxmind_proxy_fraud`.
- ` this % ` is the percentage **of this ipset (`maxmind_proxy_fraud`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|237|0.2%|63.7%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|200|0.6%|53.7%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|184|2.6%|49.4%|
[et_tor](#et_tor)|6470|6470|179|2.7%|48.1%|
[dm_tor](#dm_tor)|6451|6451|174|2.6%|46.7%|
[bm_tor](#bm_tor)|6453|6453|173|2.6%|46.5%|
[stopforumspam_1d](#stopforumspam_1d)|6982|6982|162|2.3%|43.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|125|0.0%|33.6%|
[php_commenters](#php_commenters)|281|281|28|9.9%|7.5%|
[php_bad](#php_bad)|281|281|28|9.9%|7.5%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|23|0.0%|6.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|21|0.0%|5.6%|
[openbl_90d](#openbl_90d)|9814|9814|18|0.1%|4.8%|
[openbl_60d](#openbl_60d)|7699|7699|18|0.2%|4.8%|
[openbl](#openbl)|9814|9814|18|0.1%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|17|0.0%|4.5%|
[php_harvesters](#php_harvesters)|257|257|6|2.3%|1.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|1.3%|
[ri_web_proxies](#ri_web_proxies)|4741|4741|4|0.0%|1.0%|
[php_spammers](#php_spammers)|417|417|4|0.9%|1.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|1.0%|
[blocklist_de](#blocklist_de)|22510|22510|3|0.0%|0.8%|
[shunlist](#shunlist)|1146|1146|2|0.1%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|12828|12828|2|0.0%|0.5%|
[xroxy](#xroxy)|1949|1949|1|0.0%|0.2%|
[voipbl](#voipbl)|10305|10714|1|0.0%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|1812|1812|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|14794|14794|1|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1475|1475|1|0.0%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3474|3474|1|0.0%|0.2%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Fri May 29 23:30:01 UTC 2015.

The ipset `nixspam` has **21367** entries, **21367** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1206|0.0%|5.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|540|0.0%|2.5%|
[blocklist_de](#blocklist_de)|22510|22510|525|2.3%|2.4%|
[blocklist_de_mail](#blocklist_de_mail)|14794|14794|457|3.0%|2.1%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|334|0.0%|1.5%|
[et_block](#et_block)|986|18056524|334|0.0%|1.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|333|0.0%|1.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|275|0.0%|1.2%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|227|0.2%|1.0%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|205|3.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|126|0.4%|0.5%|
[php_dictionary](#php_dictionary)|433|433|88|20.3%|0.4%|
[ri_web_proxies](#ri_web_proxies)|4741|4741|83|1.7%|0.3%|
[xroxy](#xroxy)|1949|1949|78|4.0%|0.3%|
[php_spammers](#php_spammers)|417|417|71|17.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6982|6982|70|1.0%|0.3%|
[blocklist_de_bots](#blocklist_de_bots)|3474|3474|52|1.4%|0.2%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|32|0.0%|0.1%|
[proxyrss](#proxyrss)|1569|1569|13|0.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|11|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1812|1812|9|0.4%|0.0%|
[php_commenters](#php_commenters)|281|281|9|3.2%|0.0%|
[php_bad](#php_bad)|281|281|9|3.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|9|0.0%|0.0%|
[openbl_90d](#openbl_90d)|9814|9814|7|0.0%|0.0%|
[openbl](#openbl)|9814|9814|7|0.0%|0.0%|
[proxz](#proxz)|184|184|6|3.2%|0.0%|
[php_harvesters](#php_harvesters)|257|257|6|2.3%|0.0%|
[openbl_60d](#openbl_60d)|7699|7699|6|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|410|410|6|1.4%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12828|12828|6|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1475|1475|5|0.3%|0.0%|
[voipbl](#voipbl)|10305|10714|3|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|237|237|3|1.2%|0.0%|
[openbl_30d](#openbl_30d)|4363|4363|2|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6451|6451|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6453|6453|2|0.0%|0.0%|
[shunlist](#shunlist)|1146|1146|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2309|2309|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1985|1985|1|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|93|93|1|1.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|811|811|1|0.1%|0.0%|

## openbl

[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**

Source is downloaded from [this link](http://www.openbl.org/lists/base.txt).

The last time downloaded was found to be dated: Fri May 29 23:32:00 UTC 2015.

The ipset `openbl` has **9814** entries, **9814** unique IPs.

The following table shows the overlaps of `openbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl`.
- ` this % ` is the percentage **of this ipset (`openbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9814|9814|9814|100.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|9791|5.7%|99.7%|
[openbl_60d](#openbl_60d)|7699|7699|7699|100.0%|78.4%|
[openbl_30d](#openbl_30d)|4363|4363|4363|100.0%|44.4%|
[et_compromised](#et_compromised)|2367|2367|1430|60.4%|14.5%|
[bruteforceblocker](#bruteforceblocker)|2309|2309|1398|60.5%|14.2%|
[blocklist_de](#blocklist_de)|22510|22510|1164|5.1%|11.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|1985|1985|1080|54.4%|11.0%|
[openbl_7d](#openbl_7d)|949|949|949|100.0%|9.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|944|0.0%|9.6%|
[shunlist](#shunlist)|1146|1146|584|50.9%|5.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|503|0.0%|5.1%|
[et_block](#et_block)|986|18056524|453|0.0%|4.6%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|448|0.0%|4.5%|
[openbl_1d](#openbl_1d)|243|243|243|100.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|216|0.0%|2.2%|
[dshield](#dshield)|20|5120|194|3.7%|1.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|237|237|80|33.7%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|63|0.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|14794|14794|61|0.4%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|811|811|50|6.1%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|33|0.1%|0.3%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|27|0.3%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6982|6982|21|0.3%|0.2%|
[et_tor](#et_tor)|6470|6470|21|0.3%|0.2%|
[dm_tor](#dm_tor)|6451|6451|21|0.3%|0.2%|
[bm_tor](#bm_tor)|6453|6453|21|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|20|0.0%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|14|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12828|12828|13|0.1%|0.1%|
[voipbl](#voipbl)|10305|10714|12|0.1%|0.1%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.0%|
[php_bad](#php_bad)|281|281|8|2.8%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|410|410|8|1.9%|0.0%|
[nixspam](#nixspam)|21367|21367|7|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|6|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|5|1.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1475|1475|5|0.3%|0.0%|
[zeus](#zeus)|266|266|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|228|228|1|0.4%|0.0%|
[xroxy](#xroxy)|1949|1949|1|0.0%|0.0%|
[sslbl](#sslbl)|347|347|1|0.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4741|4741|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1569|1569|1|0.0%|0.0%|
[ciarmy](#ciarmy)|370|370|1|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3474|3474|1|0.0%|0.0%|

## openbl_1d

[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_1days.txt).

The last time downloaded was found to be dated: Fri May 29 22:07:00 UTC 2015.

The ipset `openbl_1d` has **243** entries, **243** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9814|9814|243|2.4%|100.0%|
[openbl_7d](#openbl_7d)|949|949|243|25.6%|100.0%|
[openbl_60d](#openbl_60d)|7699|7699|243|3.1%|100.0%|
[openbl_30d](#openbl_30d)|4363|4363|243|5.5%|100.0%|
[openbl](#openbl)|9814|9814|243|2.4%|100.0%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|241|0.1%|99.1%|
[blocklist_de](#blocklist_de)|22510|22510|215|0.9%|88.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|1985|1985|211|10.6%|86.8%|
[bruteforceblocker](#bruteforceblocker)|2309|2309|129|5.5%|53.0%|
[et_compromised](#et_compromised)|2367|2367|126|5.3%|51.8%|
[shunlist](#shunlist)|1146|1146|125|10.9%|51.4%|
[dshield](#dshield)|20|5120|43|0.8%|17.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|237|237|39|16.4%|16.0%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|24|0.0%|9.8%|
[et_block](#et_block)|986|18056524|24|0.0%|9.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|17|0.0%|6.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|12|0.0%|4.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|2|0.0%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|14794|14794|2|0.0%|0.8%|
[blocklist_de_imap](#blocklist_de_imap)|811|811|2|0.2%|0.8%|
[blocklist_de_ftp](#blocklist_de_ftp)|410|410|1|0.2%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|12828|12828|1|0.0%|0.4%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt).

The last time downloaded was found to be dated: Fri May 29 23:32:00 UTC 2015.

The ipset `openbl_30d` has **4363** entries, **4363** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9814|9814|4363|44.4%|100.0%|
[openbl_60d](#openbl_60d)|7699|7699|4363|56.6%|100.0%|
[openbl](#openbl)|9814|9814|4363|44.4%|100.0%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|4351|2.5%|99.7%|
[et_compromised](#et_compromised)|2367|2367|1341|56.6%|30.7%|
[bruteforceblocker](#bruteforceblocker)|2309|2309|1320|57.1%|30.2%|
[blocklist_de](#blocklist_de)|22510|22510|1027|4.5%|23.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|1985|1985|969|48.8%|22.2%|
[openbl_7d](#openbl_7d)|949|949|949|100.0%|21.7%|
[shunlist](#shunlist)|1146|1146|562|49.0%|12.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|438|0.0%|10.0%|
[openbl_1d](#openbl_1d)|243|243|243|100.0%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|220|0.0%|5.0%|
[et_block](#et_block)|986|18056524|210|0.0%|4.8%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|206|0.0%|4.7%|
[dshield](#dshield)|20|5120|172|3.3%|3.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|98|0.0%|2.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|237|237|77|32.4%|1.7%|
[blocklist_de_mail](#blocklist_de_mail)|14794|14794|52|0.3%|1.1%|
[blocklist_de_imap](#blocklist_de_imap)|811|811|42|5.1%|0.9%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|15|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|14|0.0%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|12828|12828|6|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|5|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|5|0.0%|0.1%|
[voipbl](#voipbl)|10305|10714|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[zeus](#zeus)|266|266|2|0.7%|0.0%|
[nixspam](#nixspam)|21367|21367|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|410|410|2|0.4%|0.0%|
[zeus_badips](#zeus_badips)|228|228|1|0.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6982|6982|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|370|370|1|0.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1475|1475|1|0.0%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt).

The last time downloaded was found to be dated: Fri May 29 23:32:00 UTC 2015.

The ipset `openbl_60d` has **7699** entries, **7699** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9814|9814|7699|78.4%|100.0%|
[openbl](#openbl)|9814|9814|7699|78.4%|100.0%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|7679|4.4%|99.7%|
[openbl_30d](#openbl_30d)|4363|4363|4363|100.0%|56.6%|
[et_compromised](#et_compromised)|2367|2367|1415|59.7%|18.3%|
[bruteforceblocker](#bruteforceblocker)|2309|2309|1383|59.8%|17.9%|
[blocklist_de](#blocklist_de)|22510|22510|1111|4.9%|14.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|1985|1985|1038|52.2%|13.4%|
[openbl_7d](#openbl_7d)|949|949|949|100.0%|12.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|720|0.0%|9.3%|
[shunlist](#shunlist)|1146|1146|576|50.2%|7.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|359|0.0%|4.6%|
[openbl_1d](#openbl_1d)|243|243|243|100.0%|3.1%|
[et_block](#et_block)|986|18056524|240|0.0%|3.1%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|236|0.0%|3.0%|
[dshield](#dshield)|20|5120|190|3.7%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|179|0.0%|2.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|237|237|79|33.3%|1.0%|
[blocklist_de_mail](#blocklist_de_mail)|14794|14794|57|0.3%|0.7%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|56|0.0%|0.7%|
[blocklist_de_imap](#blocklist_de_imap)|811|811|46|5.6%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|31|0.1%|0.4%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|27|0.3%|0.3%|
[et_tor](#et_tor)|6470|6470|21|0.3%|0.2%|
[dm_tor](#dm_tor)|6451|6451|21|0.3%|0.2%|
[bm_tor](#bm_tor)|6453|6453|21|0.3%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6982|6982|20|0.2%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|19|0.0%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|12828|12828|10|0.0%|0.1%|
[voipbl](#voipbl)|10305|10714|9|0.0%|0.1%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.1%|
[php_bad](#php_bad)|281|281|8|2.8%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|410|410|7|1.7%|0.0%|
[nixspam](#nixspam)|21367|21367|6|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|5|1.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1475|1475|3|0.2%|0.0%|
[zeus](#zeus)|266|266|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|228|228|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|370|370|1|0.2%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt).

The last time downloaded was found to be dated: Fri May 29 23:32:00 UTC 2015.

The ipset `openbl_7d` has **949** entries, **949** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9814|9814|949|9.6%|100.0%|
[openbl_60d](#openbl_60d)|7699|7699|949|12.3%|100.0%|
[openbl_30d](#openbl_30d)|4363|4363|949|21.7%|100.0%|
[openbl](#openbl)|9814|9814|949|9.6%|100.0%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|943|0.5%|99.3%|
[blocklist_de](#blocklist_de)|22510|22510|638|2.8%|67.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1985|1985|604|30.4%|63.6%|
[bruteforceblocker](#bruteforceblocker)|2309|2309|502|21.7%|52.8%|
[et_compromised](#et_compromised)|2367|2367|499|21.0%|52.5%|
[shunlist](#shunlist)|1146|1146|359|31.3%|37.8%|
[openbl_1d](#openbl_1d)|243|243|243|100.0%|25.6%|
[dshield](#dshield)|20|5120|126|2.4%|13.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|95|0.0%|10.0%|
[et_block](#et_block)|986|18056524|85|0.0%|8.9%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|84|0.0%|8.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|237|237|76|32.0%|8.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|49|0.0%|5.1%|
[blocklist_de_mail](#blocklist_de_mail)|14794|14794|29|0.1%|3.0%|
[blocklist_de_imap](#blocklist_de_imap)|811|811|25|3.0%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|16|0.0%|1.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|1.1%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|4|0.0%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|12828|12828|3|0.0%|0.3%|
[voipbl](#voipbl)|10305|10714|2|0.0%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|410|410|2|0.4%|0.2%|
[zeus](#zeus)|266|266|1|0.3%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.1%|
[ciarmy](#ciarmy)|370|370|1|0.2%|0.1%|

## openbl_90d

[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_90days.txt).

The last time downloaded was found to be dated: Fri May 29 23:32:00 UTC 2015.

The ipset `openbl_90d` has **9814** entries, **9814** unique IPs.

The following table shows the overlaps of `openbl_90d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_90d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_90d`.
- ` this % ` is the percentage **of this ipset (`openbl_90d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl](#openbl)|9814|9814|9814|100.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|9791|5.7%|99.7%|
[openbl_60d](#openbl_60d)|7699|7699|7699|100.0%|78.4%|
[openbl_30d](#openbl_30d)|4363|4363|4363|100.0%|44.4%|
[et_compromised](#et_compromised)|2367|2367|1430|60.4%|14.5%|
[bruteforceblocker](#bruteforceblocker)|2309|2309|1398|60.5%|14.2%|
[blocklist_de](#blocklist_de)|22510|22510|1164|5.1%|11.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|1985|1985|1080|54.4%|11.0%|
[openbl_7d](#openbl_7d)|949|949|949|100.0%|9.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|944|0.0%|9.6%|
[shunlist](#shunlist)|1146|1146|584|50.9%|5.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|503|0.0%|5.1%|
[et_block](#et_block)|986|18056524|453|0.0%|4.6%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|448|0.0%|4.5%|
[openbl_1d](#openbl_1d)|243|243|243|100.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|216|0.0%|2.2%|
[dshield](#dshield)|20|5120|194|3.7%|1.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|237|237|80|33.7%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|63|0.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|14794|14794|61|0.4%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|811|811|50|6.1%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|33|0.1%|0.3%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|27|0.3%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6982|6982|21|0.3%|0.2%|
[et_tor](#et_tor)|6470|6470|21|0.3%|0.2%|
[dm_tor](#dm_tor)|6451|6451|21|0.3%|0.2%|
[bm_tor](#bm_tor)|6453|6453|21|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|20|0.0%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|14|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12828|12828|13|0.1%|0.1%|
[voipbl](#voipbl)|10305|10714|12|0.1%|0.1%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.0%|
[php_bad](#php_bad)|281|281|8|2.8%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|410|410|8|1.9%|0.0%|
[nixspam](#nixspam)|21367|21367|7|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|6|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|5|1.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1475|1475|5|0.3%|0.0%|
[zeus](#zeus)|266|266|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|228|228|1|0.4%|0.0%|
[xroxy](#xroxy)|1949|1949|1|0.0%|0.0%|
[sslbl](#sslbl)|347|347|1|0.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4741|4741|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1569|1569|1|0.0%|0.0%|
[ciarmy](#ciarmy)|370|370|1|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3474|3474|1|0.0%|0.0%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Fri May 29 23:36:22 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|986|18056524|13|0.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|11|0.1%|84.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2|0.0%|15.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|7.6%|
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
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|202|0.2%|71.8%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|188|0.6%|66.9%|
[stopforumspam_1d](#stopforumspam_1d)|6982|6982|117|1.6%|41.6%|
[blocklist_de](#blocklist_de)|22510|22510|69|0.3%|24.5%|
[blocklist_de_bots](#blocklist_de_bots)|3474|3474|53|1.5%|18.8%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|41|0.6%|14.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|237|237|33|13.9%|11.7%|
[php_spammers](#php_spammers)|417|417|32|7.6%|11.3%|
[et_tor](#et_tor)|6470|6470|29|0.4%|10.3%|
[dm_tor](#dm_tor)|6451|6451|29|0.4%|10.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|28|7.5%|9.9%|
[bm_tor](#bm_tor)|6453|6453|28|0.4%|9.9%|
[blocklist_de_apache](#blocklist_de_apache)|12828|12828|25|0.1%|8.8%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|24|0.0%|8.5%|
[et_block](#et_block)|986|18056524|24|0.0%|8.5%|
[php_dictionary](#php_dictionary)|433|433|22|5.0%|7.8%|
[blocklist_de_mail](#blocklist_de_mail)|14794|14794|21|0.1%|7.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|16|0.0%|5.6%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|12|0.0%|4.2%|
[ri_web_proxies](#ri_web_proxies)|4741|4741|9|0.1%|3.2%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|3.2%|
[nixspam](#nixspam)|21367|21367|9|0.0%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.2%|
[openbl_90d](#openbl_90d)|9814|9814|8|0.0%|2.8%|
[openbl_60d](#openbl_60d)|7699|7699|8|0.1%|2.8%|
[openbl](#openbl)|9814|9814|8|0.0%|2.8%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|7|0.0%|2.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1475|1475|6|0.4%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|1.7%|
[xroxy](#xroxy)|1949|1949|3|0.1%|1.0%|
[proxz](#proxz)|184|184|2|1.0%|0.7%|
[proxyrss](#proxyrss)|1569|1569|2|0.1%|0.7%|
[zeus_badips](#zeus_badips)|228|228|1|0.4%|0.3%|
[zeus](#zeus)|266|266|1|0.3%|0.3%|
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
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|203|0.2%|72.2%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|189|0.6%|67.2%|
[stopforumspam_1d](#stopforumspam_1d)|6982|6982|117|1.6%|41.6%|
[blocklist_de](#blocklist_de)|22510|22510|70|0.3%|24.9%|
[blocklist_de_bots](#blocklist_de_bots)|3474|3474|53|1.5%|18.8%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|42|0.6%|14.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|237|237|33|13.9%|11.7%|
[php_spammers](#php_spammers)|417|417|32|7.6%|11.3%|
[et_tor](#et_tor)|6470|6470|29|0.4%|10.3%|
[dm_tor](#dm_tor)|6451|6451|29|0.4%|10.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|28|7.5%|9.9%|
[bm_tor](#bm_tor)|6453|6453|28|0.4%|9.9%|
[blocklist_de_apache](#blocklist_de_apache)|12828|12828|25|0.1%|8.8%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|24|0.0%|8.5%|
[et_block](#et_block)|986|18056524|24|0.0%|8.5%|
[php_dictionary](#php_dictionary)|433|433|22|5.0%|7.8%|
[blocklist_de_mail](#blocklist_de_mail)|14794|14794|22|0.1%|7.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|5.3%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|12|0.0%|4.2%|
[ri_web_proxies](#ri_web_proxies)|4741|4741|9|0.1%|3.2%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|3.2%|
[nixspam](#nixspam)|21367|21367|9|0.0%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.2%|
[openbl_90d](#openbl_90d)|9814|9814|8|0.0%|2.8%|
[openbl_60d](#openbl_60d)|7699|7699|8|0.1%|2.8%|
[openbl](#openbl)|9814|9814|8|0.0%|2.8%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|7|0.0%|2.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1475|1475|6|0.4%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|1.7%|
[xroxy](#xroxy)|1949|1949|3|0.1%|1.0%|
[proxz](#proxz)|184|184|2|1.0%|0.7%|
[proxyrss](#proxyrss)|1569|1569|2|0.1%|0.7%|
[zeus_badips](#zeus_badips)|228|228|1|0.4%|0.3%|
[zeus](#zeus)|266|266|1|0.3%|0.3%|
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
[nixspam](#nixspam)|21367|21367|88|0.4%|20.3%|
[php_spammers](#php_spammers)|417|417|84|20.1%|19.3%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|77|0.0%|17.7%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|75|1.0%|17.3%|
[blocklist_de](#blocklist_de)|22510|22510|69|0.3%|15.9%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|59|0.1%|13.6%|
[blocklist_de_mail](#blocklist_de_mail)|14794|14794|55|0.3%|12.7%|
[stopforumspam_1d](#stopforumspam_1d)|6982|6982|26|0.3%|6.0%|
[ri_web_proxies](#ri_web_proxies)|4741|4741|25|0.5%|5.7%|
[xroxy](#xroxy)|1949|1949|24|1.2%|5.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|24|0.0%|5.5%|
[php_commenters](#php_commenters)|281|281|22|7.8%|5.0%|
[php_bad](#php_bad)|281|281|22|7.8%|5.0%|
[blocklist_de_bots](#blocklist_de_bots)|3474|3474|14|0.4%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|10|0.0%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|9|0.0%|2.0%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|7|0.0%|1.6%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|4|0.0%|0.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.9%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.9%|
[et_block](#et_block)|986|18056524|4|0.0%|0.9%|
[dm_tor](#dm_tor)|6451|6451|4|0.0%|0.9%|
[bm_tor](#bm_tor)|6453|6453|4|0.0%|0.9%|
[ri_connect_proxies](#ri_connect_proxies)|1812|1812|3|0.1%|0.6%|
[proxyrss](#proxyrss)|1569|1569|3|0.1%|0.6%|
[proxz](#proxz)|184|184|2|1.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|237|237|2|0.8%|0.4%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.2%|

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
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|62|0.0%|24.1%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|50|0.1%|19.4%|
[blocklist_de](#blocklist_de)|22510|22510|33|0.1%|12.8%|
[stopforumspam_1d](#stopforumspam_1d)|6982|6982|32|0.4%|12.4%|
[blocklist_de_bots](#blocklist_de_bots)|3474|3474|27|0.7%|10.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|5.8%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|9|0.1%|3.5%|
[php_commenters](#php_commenters)|281|281|9|3.2%|3.5%|
[php_bad](#php_bad)|281|281|9|3.2%|3.5%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|9|0.0%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|7|0.0%|2.7%|
[et_tor](#et_tor)|6470|6470|7|0.1%|2.7%|
[dm_tor](#dm_tor)|6451|6451|7|0.1%|2.7%|
[bm_tor](#bm_tor)|6453|6453|7|0.1%|2.7%|
[nixspam](#nixspam)|21367|21367|6|0.0%|2.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|6|1.6%|2.3%|
[openbl_90d](#openbl_90d)|9814|9814|5|0.0%|1.9%|
[openbl_60d](#openbl_60d)|7699|7699|5|0.0%|1.9%|
[openbl](#openbl)|9814|9814|5|0.0%|1.9%|
[blocklist_de_ftp](#blocklist_de_ftp)|410|410|4|0.9%|1.5%|
[blocklist_de_mail](#blocklist_de_mail)|14794|14794|3|0.0%|1.1%|
[xroxy](#xroxy)|1949|1949|2|0.1%|0.7%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|237|237|2|0.8%|0.7%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|1|0.0%|0.3%|
[ri_web_proxies](#ri_web_proxies)|4741|4741|1|0.0%|0.3%|
[proxyrss](#proxyrss)|1569|1569|1|0.0%|0.3%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.3%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|
[fullbogons](#fullbogons)|3656|670639576|1|0.0%|0.3%|
[et_block](#et_block)|986|18056524|1|0.0%|0.3%|
[bogons](#bogons)|13|592708608|1|0.0%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|12828|12828|1|0.0%|0.3%|

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
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|97|0.1%|23.2%|
[php_dictionary](#php_dictionary)|433|433|84|19.3%|20.1%|
[nixspam](#nixspam)|21367|21367|71|0.3%|17.0%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|65|0.2%|15.5%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|63|0.9%|15.1%|
[blocklist_de](#blocklist_de)|22510|22510|63|0.2%|15.1%|
[blocklist_de_mail](#blocklist_de_mail)|14794|14794|41|0.2%|9.8%|
[php_commenters](#php_commenters)|281|281|32|11.3%|7.6%|
[php_bad](#php_bad)|281|281|32|11.3%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|31|0.0%|7.4%|
[stopforumspam_1d](#stopforumspam_1d)|6982|6982|30|0.4%|7.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|26|0.0%|6.2%|
[ri_web_proxies](#ri_web_proxies)|4741|4741|20|0.4%|4.7%|
[xroxy](#xroxy)|1949|1949|18|0.9%|4.3%|
[blocklist_de_bots](#blocklist_de_bots)|3474|3474|15|0.4%|3.5%|
[et_tor](#et_tor)|6470|6470|6|0.0%|1.4%|
[dm_tor](#dm_tor)|6451|6451|6|0.0%|1.4%|
[bm_tor](#bm_tor)|6453|6453|6|0.0%|1.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1475|1475|6|0.4%|1.4%|
[blocklist_de_apache](#blocklist_de_apache)|12828|12828|6|0.0%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|1.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|237|237|5|2.1%|1.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.9%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|3|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|2|0.0%|0.4%|
[ri_connect_proxies](#ri_connect_proxies)|1812|1812|2|0.1%|0.4%|
[proxz](#proxz)|184|184|2|1.0%|0.4%|
[proxyrss](#proxyrss)|1569|1569|2|0.1%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[et_block](#et_block)|986|18056524|2|0.0%|0.4%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1985|1985|1|0.0%|0.2%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Fri May 29 21:41:26 UTC 2015.

The ipset `proxyrss` has **1569** entries, **1569** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|778|0.8%|49.5%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|645|2.0%|41.1%|
[ri_web_proxies](#ri_web_proxies)|4741|4741|591|12.4%|37.6%|
[xroxy](#xroxy)|1949|1949|550|28.2%|35.0%|
[stopforumspam_1d](#stopforumspam_1d)|6982|6982|398|5.7%|25.3%|
[blocklist_de](#blocklist_de)|22510|22510|240|1.0%|15.2%|
[blocklist_de_bots](#blocklist_de_bots)|3474|3474|239|6.8%|15.2%|
[ri_connect_proxies](#ri_connect_proxies)|1812|1812|206|11.3%|13.1%|
[proxz](#proxz)|184|184|95|51.6%|6.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|71|0.0%|4.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|55|0.0%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|38|0.0%|2.4%|
[nixspam](#nixspam)|21367|21367|13|0.0%|0.8%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.3%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|5|0.0%|0.3%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|4|0.0%|0.2%|
[php_dictionary](#php_dictionary)|433|433|3|0.6%|0.1%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.1%|
[php_commenters](#php_commenters)|281|281|2|0.7%|0.1%|
[php_bad](#php_bad)|281|281|2|0.7%|0.1%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[openbl_90d](#openbl_90d)|9814|9814|1|0.0%|0.0%|
[openbl](#openbl)|9814|9814|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2309|2309|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|237|237|1|0.4%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1475|1475|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12828|12828|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Fri May 29 21:41:32 UTC 2015.

The ipset `proxz` has **184** entries, **184** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[xroxy](#xroxy)|1949|1949|121|6.2%|65.7%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|101|0.1%|54.8%|
[proxyrss](#proxyrss)|1569|1569|95|6.0%|51.6%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|92|0.2%|50.0%|
[ri_web_proxies](#ri_web_proxies)|4741|4741|75|1.5%|40.7%|
[stopforumspam_1d](#stopforumspam_1d)|6982|6982|55|0.7%|29.8%|
[blocklist_de](#blocklist_de)|22510|22510|42|0.1%|22.8%|
[blocklist_de_bots](#blocklist_de_bots)|3474|3474|41|1.1%|22.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|26|0.0%|14.1%|
[ri_connect_proxies](#ri_connect_proxies)|1812|1812|21|1.1%|11.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8|0.0%|4.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|8|0.0%|4.3%|
[nixspam](#nixspam)|21367|21367|6|0.0%|3.2%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|3|0.0%|1.6%|
[php_spammers](#php_spammers)|417|417|2|0.4%|1.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|1.0%|
[php_commenters](#php_commenters)|281|281|2|0.7%|1.0%|
[php_bad](#php_bad)|281|281|2|0.7%|1.0%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|2|0.0%|1.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.5%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.5%|
[dm_tor](#dm_tor)|6451|6451|1|0.0%|0.5%|
[bruteforceblocker](#bruteforceblocker)|2309|2309|1|0.0%|0.5%|
[bm_tor](#bm_tor)|6453|6453|1|0.0%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|14794|14794|1|0.0%|0.5%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Fri May 29 21:36:46 UTC 2015.

The ipset `ri_connect_proxies` has **1812** entries, **1812** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|1061|1.1%|58.5%|
[ri_web_proxies](#ri_web_proxies)|4741|4741|727|15.3%|40.1%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|718|2.3%|39.6%|
[xroxy](#xroxy)|1949|1949|290|14.8%|16.0%|
[proxyrss](#proxyrss)|1569|1569|206|13.1%|11.3%|
[stopforumspam_1d](#stopforumspam_1d)|6982|6982|138|1.9%|7.6%|
[blocklist_de](#blocklist_de)|22510|22510|88|0.3%|4.8%|
[blocklist_de_bots](#blocklist_de_bots)|3474|3474|86|2.4%|4.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|76|0.0%|4.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|63|0.0%|3.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|42|0.0%|2.3%|
[proxz](#proxz)|184|184|21|11.4%|1.1%|
[nixspam](#nixspam)|21367|21367|9|0.0%|0.4%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|7|0.1%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.3%|
[php_dictionary](#php_dictionary)|433|433|3|0.6%|0.1%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.1%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.1%|
[dm_tor](#dm_tor)|6451|6451|2|0.0%|0.1%|
[bm_tor](#bm_tor)|6453|6453|2|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|2|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14794|14794|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1475|1475|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12828|12828|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Fri May 29 21:35:28 UTC 2015.

The ipset `ri_web_proxies` has **4741** entries, **4741** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|2350|2.5%|49.5%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|1714|5.5%|36.1%|
[xroxy](#xroxy)|1949|1949|759|38.9%|16.0%|
[ri_connect_proxies](#ri_connect_proxies)|1812|1812|727|40.1%|15.3%|
[proxyrss](#proxyrss)|1569|1569|591|37.6%|12.4%|
[stopforumspam_1d](#stopforumspam_1d)|6982|6982|501|7.1%|10.5%|
[blocklist_de](#blocklist_de)|22510|22510|397|1.7%|8.3%|
[blocklist_de_bots](#blocklist_de_bots)|3474|3474|367|10.5%|7.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|165|0.0%|3.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|144|0.0%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|108|0.0%|2.2%|
[nixspam](#nixspam)|21367|21367|83|0.3%|1.7%|
[proxz](#proxz)|184|184|75|40.7%|1.5%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|50|0.7%|1.0%|
[blocklist_de_mail](#blocklist_de_mail)|14794|14794|30|0.2%|0.6%|
[php_dictionary](#php_dictionary)|433|433|25|5.7%|0.5%|
[php_spammers](#php_spammers)|417|417|20|4.7%|0.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|10|1.4%|0.2%|
[php_commenters](#php_commenters)|281|281|9|3.2%|0.1%|
[php_bad](#php_bad)|281|281|9|3.2%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6451|6451|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6453|6453|4|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|237|237|3|1.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[openbl_90d](#openbl_90d)|9814|9814|1|0.0%|0.0%|
[openbl](#openbl)|9814|9814|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1475|1475|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12828|12828|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Fri May 29 22:30:05 UTC 2015.

The ipset `shunlist` has **1146** entries, **1146** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|171480|171480|911|0.5%|79.4%|
[openbl_90d](#openbl_90d)|9814|9814|584|5.9%|50.9%|
[openbl](#openbl)|9814|9814|584|5.9%|50.9%|
[openbl_60d](#openbl_60d)|7699|7699|576|7.4%|50.2%|
[openbl_30d](#openbl_30d)|4363|4363|562|12.8%|49.0%|
[blocklist_de](#blocklist_de)|22510|22510|549|2.4%|47.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|1985|1985|507|25.5%|44.2%|
[et_compromised](#et_compromised)|2367|2367|482|20.3%|42.0%|
[bruteforceblocker](#bruteforceblocker)|2309|2309|481|20.8%|41.9%|
[openbl_7d](#openbl_7d)|949|949|359|37.8%|31.3%|
[dshield](#dshield)|20|5120|152|2.9%|13.2%|
[openbl_1d](#openbl_1d)|243|243|125|51.4%|10.9%|
[et_block](#et_block)|986|18056524|109|0.0%|9.5%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|100|0.0%|8.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|88|0.0%|7.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|237|237|72|30.3%|6.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|69|0.0%|6.0%|
[blocklist_de_apache](#blocklist_de_apache)|12828|12828|36|0.2%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|24|0.0%|2.0%|
[ciarmy](#ciarmy)|370|370|20|5.4%|1.7%|
[voipbl](#voipbl)|10305|10714|12|0.1%|1.0%|
[sslbl](#sslbl)|347|347|4|1.1%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|14794|14794|4|0.0%|0.3%|
[blocklist_de_imap](#blocklist_de_imap)|811|811|4|0.4%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1475|1475|3|0.2%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6982|6982|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|2|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|1|0.0%|0.0%|
[nixspam](#nixspam)|21367|21367|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6451|6451|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6453|6453|1|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|93|93|1|1.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|410|410|1|0.2%|0.0%|

## snort_ipfilter

[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)

Source is downloaded from [this link](http://labs.snort.org/feeds/ip-filter.blf).

The last time downloaded was found to be dated: Fri May 29 13:30:00 UTC 2015.

The ipset `snort_ipfilter` has **6827** entries, **6827** unique IPs.

The following table shows the overlaps of `snort_ipfilter` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `snort_ipfilter`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `snort_ipfilter`.
- ` this % ` is the percentage **of this ipset (`snort_ipfilter`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_tor](#et_tor)|6470|6470|1072|16.5%|15.7%|
[dm_tor](#dm_tor)|6451|6451|1029|15.9%|15.0%|
[bm_tor](#bm_tor)|6453|6453|1026|15.8%|15.0%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|766|0.8%|11.2%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|575|1.8%|8.4%|
[stopforumspam_1d](#stopforumspam_1d)|6982|6982|370|5.2%|5.4%|
[et_block](#et_block)|986|18056524|294|0.0%|4.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|231|0.0%|3.3%|
[zeus](#zeus)|266|266|226|84.9%|3.3%|
[blocklist_de](#blocklist_de)|22510|22510|214|0.9%|3.1%|
[nixspam](#nixspam)|21367|21367|205|0.9%|3.0%|
[zeus_badips](#zeus_badips)|228|228|199|87.2%|2.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|184|49.4%|2.6%|
[blocklist_de_mail](#blocklist_de_mail)|14794|14794|144|0.9%|2.1%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|119|0.0%|1.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|103|0.0%|1.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|78|0.0%|1.1%|
[php_dictionary](#php_dictionary)|433|433|75|17.3%|1.0%|
[php_spammers](#php_spammers)|417|417|63|15.1%|0.9%|
[xroxy](#xroxy)|1949|1949|54|2.7%|0.7%|
[feodo](#feodo)|68|68|53|77.9%|0.7%|
[ri_web_proxies](#ri_web_proxies)|4741|4741|50|1.0%|0.7%|
[php_commenters](#php_commenters)|281|281|42|14.9%|0.6%|
[php_bad](#php_bad)|281|281|41|14.5%|0.6%|
[blocklist_de_apache](#blocklist_de_apache)|12828|12828|37|0.2%|0.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1475|1475|34|2.3%|0.4%|
[blocklist_de_bots](#blocklist_de_bots)|3474|3474|34|0.9%|0.4%|
[openbl_90d](#openbl_90d)|9814|9814|27|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7699|7699|27|0.3%|0.3%|
[openbl](#openbl)|9814|9814|27|0.2%|0.3%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|26|2.0%|0.3%|
[sslbl](#sslbl)|347|347|21|6.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|18|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|15|0.0%|0.2%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|0.1%|
[ri_connect_proxies](#ri_connect_proxies)|1812|1812|7|0.3%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|811|811|7|0.8%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|6|0.0%|0.0%|
[proxyrss](#proxyrss)|1569|1569|5|0.3%|0.0%|
[openbl_30d](#openbl_30d)|4363|4363|5|0.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|395|395|5|1.2%|0.0%|
[openbl_7d](#openbl_7d)|949|949|4|0.4%|0.0%|
[proxz](#proxz)|184|184|3|1.6%|0.0%|
[shunlist](#shunlist)|1146|1146|2|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[malc0de](#malc0de)|410|410|1|0.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2309|2309|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|237|237|1|0.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1985|1985|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|410|410|1|0.2%|0.0%|

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
[et_block](#et_block)|986|18056524|17920256|99.2%|99.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8401434|2.4%|46.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7079936|77.1%|39.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|2133002|0.2%|11.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|195904|0.1%|1.0%|
[fullbogons](#fullbogons)|3656|670639576|20480|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|1625|0.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|741|0.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|512|0.1%|0.0%|
[dshield](#dshield)|20|5120|512|10.0%|0.0%|
[openbl_90d](#openbl_90d)|9814|9814|448|4.5%|0.0%|
[openbl](#openbl)|9814|9814|448|4.5%|0.0%|
[nixspam](#nixspam)|21367|21367|334|1.5%|0.0%|
[openbl_60d](#openbl_60d)|7699|7699|236|3.0%|0.0%|
[openbl_30d](#openbl_30d)|4363|4363|206|4.7%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|204|0.6%|0.0%|
[blocklist_de](#blocklist_de)|22510|22510|184|0.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1985|1985|110|5.5%|0.0%|
[et_compromised](#et_compromised)|2367|2367|102|4.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2309|2309|102|4.4%|0.0%|
[shunlist](#shunlist)|1146|1146|100|8.7%|0.0%|
[openbl_7d](#openbl_7d)|949|949|84|8.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6982|6982|61|0.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3474|3474|52|1.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|29|2.2%|0.0%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.0%|
[php_bad](#php_bad)|281|281|24|8.5%|0.0%|
[openbl_1d](#openbl_1d)|243|243|24|9.8%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14794|14794|19|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|18|0.2%|0.0%|
[zeus_badips](#zeus_badips)|228|228|16|7.0%|0.0%|
[zeus](#zeus)|266|266|16|6.0%|0.0%|
[voipbl](#voipbl)|10305|10714|14|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|811|811|13|1.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|237|237|6|2.5%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[sslbl](#sslbl)|347|347|3|0.8%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1475|1475|3|0.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12828|12828|3|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[malc0de](#malc0de)|410|410|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6451|6451|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6453|6453|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[et_botnet](#et_botnet)|501|501|1|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|93|93|1|1.0%|0.0%|

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
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|33155|0.0%|7.8%|
[et_block](#et_block)|986|18056524|517|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|512|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|106|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|42|0.1%|0.0%|
[blocklist_de](#blocklist_de)|22510|22510|26|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3474|3474|22|0.6%|0.0%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|15|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6982|6982|14|0.2%|0.0%|
[openbl_90d](#openbl_90d)|9814|9814|14|0.1%|0.0%|
[openbl](#openbl)|9814|9814|14|0.1%|0.0%|
[php_commenters](#php_commenters)|281|281|7|2.4%|0.0%|
[php_bad](#php_bad)|281|281|7|2.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|237|237|6|2.5%|0.0%|
[zeus_badips](#zeus_badips)|228|228|5|2.1%|0.0%|
[zeus](#zeus)|266|266|5|1.8%|0.0%|
[nixspam](#nixspam)|21367|21367|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14794|14794|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12828|12828|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[openbl_60d](#openbl_60d)|7699|7699|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4363|4363|1|0.0%|0.0%|
[malc0de](#malc0de)|410|410|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Fri May 29 23:15:06 UTC 2015.

The ipset `sslbl` has **347** entries, **347** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|986|18056524|27|0.0%|7.7%|
[feodo](#feodo)|68|68|25|36.7%|7.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|23|0.0%|6.6%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|21|0.3%|6.0%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|7|0.0%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|6|0.0%|1.7%|
[shunlist](#shunlist)|1146|1146|4|0.3%|1.1%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|3|0.0%|0.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|1|0.0%|0.2%|
[openbl_90d](#openbl_90d)|9814|9814|1|0.0%|0.2%|
[openbl](#openbl)|9814|9814|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Fri May 29 23:00:02 UTC 2015.

The ipset `stopforumspam_1d` has **6982** entries, **6982** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|4438|4.8%|63.5%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|4168|13.4%|59.6%|
[blocklist_de](#blocklist_de)|22510|22510|1581|7.0%|22.6%|
[blocklist_de_bots](#blocklist_de_bots)|3474|3474|1493|42.9%|21.3%|
[ri_web_proxies](#ri_web_proxies)|4741|4741|501|10.5%|7.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|445|0.0%|6.3%|
[xroxy](#xroxy)|1949|1949|430|22.0%|6.1%|
[proxyrss](#proxyrss)|1569|1569|398|25.3%|5.7%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|370|5.4%|5.2%|
[et_tor](#et_tor)|6470|6470|326|5.0%|4.6%|
[dm_tor](#dm_tor)|6451|6451|322|4.9%|4.6%|
[bm_tor](#bm_tor)|6453|6453|320|4.9%|4.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|247|0.0%|3.5%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|162|43.5%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|149|0.0%|2.1%|
[ri_connect_proxies](#ri_connect_proxies)|1812|1812|138|7.6%|1.9%|
[php_commenters](#php_commenters)|281|281|117|41.6%|1.6%|
[php_bad](#php_bad)|281|281|117|41.6%|1.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|237|237|101|42.6%|1.4%|
[blocklist_de_apache](#blocklist_de_apache)|12828|12828|82|0.6%|1.1%|
[nixspam](#nixspam)|21367|21367|70|0.3%|1.0%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|63|0.0%|0.9%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|61|0.0%|0.8%|
[et_block](#et_block)|986|18056524|61|0.0%|0.8%|
[proxz](#proxz)|184|184|55|29.8%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|14794|14794|48|0.3%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|39|0.0%|0.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1475|1475|37|2.5%|0.5%|
[php_harvesters](#php_harvesters)|257|257|32|12.4%|0.4%|
[php_spammers](#php_spammers)|417|417|30|7.1%|0.4%|
[php_dictionary](#php_dictionary)|433|433|26|6.0%|0.3%|
[openbl_90d](#openbl_90d)|9814|9814|21|0.2%|0.3%|
[openbl](#openbl)|9814|9814|21|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7699|7699|20|0.2%|0.2%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|14|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|10|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|5|0.7%|0.0%|
[voipbl](#voipbl)|10305|10714|3|0.0%|0.0%|
[shunlist](#shunlist)|1146|1146|2|0.1%|0.0%|
[et_compromised](#et_compromised)|2367|2367|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2309|2309|2|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|410|410|2|0.4%|0.0%|
[zeus_badips](#zeus_badips)|228|228|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[openbl_30d](#openbl_30d)|4363|4363|1|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1985|1985|1|0.0%|0.0%|

## stopforumspam_30d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip).

The last time downloaded was found to be dated: Fri May 29 00:00:47 UTC 2015.

The ipset `stopforumspam_30d` has **92405** entries, **92405** unique IPs.

The following table shows the overlaps of `stopforumspam_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_30d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|30809|99.4%|33.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|6079|0.0%|6.5%|
[stopforumspam_1d](#stopforumspam_1d)|6982|6982|4438|63.5%|4.8%|
[blocklist_de](#blocklist_de)|22510|22510|2687|11.9%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2445|0.0%|2.6%|
[blocklist_de_bots](#blocklist_de_bots)|3474|3474|2360|67.9%|2.5%|
[ri_web_proxies](#ri_web_proxies)|4741|4741|2350|49.5%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1511|0.0%|1.6%|
[xroxy](#xroxy)|1949|1949|1085|55.6%|1.1%|
[ri_connect_proxies](#ri_connect_proxies)|1812|1812|1061|58.5%|1.1%|
[proxyrss](#proxyrss)|1569|1569|778|49.5%|0.8%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|766|11.2%|0.8%|
[et_block](#et_block)|986|18056524|743|0.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|742|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|741|0.0%|0.8%|
[et_tor](#et_tor)|6470|6470|602|9.3%|0.6%|
[dm_tor](#dm_tor)|6451|6451|586|9.0%|0.6%|
[bm_tor](#bm_tor)|6453|6453|581|9.0%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|237|63.7%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|12828|12828|234|1.8%|0.2%|
[nixspam](#nixspam)|21367|21367|227|1.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|221|0.1%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|14794|14794|210|1.4%|0.2%|
[php_commenters](#php_commenters)|281|281|203|72.2%|0.2%|
[php_bad](#php_bad)|281|281|202|71.8%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|237|237|133|56.1%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|106|0.0%|0.1%|
[proxz](#proxz)|184|184|101|54.8%|0.1%|
[php_spammers](#php_spammers)|417|417|97|23.2%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1475|1475|87|5.8%|0.0%|
[php_dictionary](#php_dictionary)|433|433|77|17.7%|0.0%|
[openbl_90d](#openbl_90d)|9814|9814|63|0.6%|0.0%|
[openbl](#openbl)|9814|9814|63|0.6%|0.0%|
[php_harvesters](#php_harvesters)|257|257|62|24.1%|0.0%|
[openbl_60d](#openbl_60d)|7699|7699|56|0.7%|0.0%|
[voipbl](#voipbl)|10305|10714|41|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|41|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|22|3.2%|0.0%|
[openbl_30d](#openbl_30d)|4363|4363|15|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|15|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|410|410|9|2.1%|0.0%|
[et_compromised](#et_compromised)|2367|2367|6|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2309|2309|6|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1985|1985|6|0.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|811|811|4|0.4%|0.0%|
[zeus_badips](#zeus_badips)|228|228|3|1.3%|0.0%|
[zeus](#zeus)|266|266|3|1.1%|0.0%|
[shunlist](#shunlist)|1146|1146|2|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|2|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3656|670639576|2|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|395|395|2|0.5%|0.0%|
[sslbl](#sslbl)|347|347|1|0.2%|0.0%|
[openbl_7d](#openbl_7d)|949|949|1|0.1%|0.0%|
[ciarmy](#ciarmy)|370|370|1|0.2%|0.0%|
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
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|30809|33.3%|99.4%|
[stopforumspam_1d](#stopforumspam_1d)|6982|6982|4168|59.6%|13.4%|
[blocklist_de](#blocklist_de)|22510|22510|2307|10.2%|7.4%|
[blocklist_de_bots](#blocklist_de_bots)|3474|3474|2119|60.9%|6.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2103|0.0%|6.7%|
[ri_web_proxies](#ri_web_proxies)|4741|4741|1714|36.1%|5.5%|
[xroxy](#xroxy)|1949|1949|932|47.8%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|904|0.0%|2.9%|
[ri_connect_proxies](#ri_connect_proxies)|1812|1812|718|39.6%|2.3%|
[proxyrss](#proxyrss)|1569|1569|645|41.1%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|576|0.0%|1.8%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|575|8.4%|1.8%|
[et_tor](#et_tor)|6470|6470|463|7.1%|1.4%|
[dm_tor](#dm_tor)|6451|6451|451|6.9%|1.4%|
[bm_tor](#bm_tor)|6453|6453|448|6.9%|1.4%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|204|0.0%|0.6%|
[et_block](#et_block)|986|18056524|204|0.0%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|200|53.7%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|194|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|189|67.2%|0.6%|
[php_bad](#php_bad)|281|281|188|66.9%|0.6%|
[blocklist_de_apache](#blocklist_de_apache)|12828|12828|142|1.1%|0.4%|
[nixspam](#nixspam)|21367|21367|126|0.5%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|237|237|122|51.4%|0.3%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|115|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|14794|14794|98|0.6%|0.3%|
[proxz](#proxz)|184|184|92|50.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1475|1475|75|5.0%|0.2%|
[php_spammers](#php_spammers)|417|417|65|15.5%|0.2%|
[php_dictionary](#php_dictionary)|433|433|59|13.6%|0.1%|
[php_harvesters](#php_harvesters)|257|257|50|19.4%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|42|0.0%|0.1%|
[openbl_90d](#openbl_90d)|9814|9814|33|0.3%|0.1%|
[openbl](#openbl)|9814|9814|33|0.3%|0.1%|
[openbl_60d](#openbl_60d)|7699|7699|31|0.4%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|19|0.0%|0.0%|
[voipbl](#voipbl)|10305|10714|10|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|10|1.4%|0.0%|
[openbl_30d](#openbl_30d)|4363|4363|5|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|5|0.0%|0.0%|
[et_compromised](#et_compromised)|2367|2367|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2309|2309|3|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|410|410|3|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1985|1985|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|228|228|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[shunlist](#shunlist)|1146|1146|1|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|395|395|1|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|811|811|1|0.1%|0.0%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Fri May 29 22:54:16 UTC 2015.

The ipset `voipbl` has **10305** entries, **10714** unique IPs.

The following table shows the overlaps of `voipbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `voipbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `voipbl`.
- ` this % ` is the percentage **of this ipset (`voipbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1586|0.0%|14.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|429|0.0%|4.0%|
[fullbogons](#fullbogons)|3656|670639576|319|0.0%|2.9%|
[bogons](#bogons)|13|592708608|319|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|295|0.0%|2.7%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|206|0.1%|1.9%|
[blocklist_de](#blocklist_de)|22510|22510|42|0.1%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|41|0.0%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|93|93|31|33.3%|0.2%|
[et_block](#et_block)|986|18056524|17|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|14|0.0%|0.1%|
[shunlist](#shunlist)|1146|1146|12|1.0%|0.1%|
[openbl_90d](#openbl_90d)|9814|9814|12|0.1%|0.1%|
[openbl](#openbl)|9814|9814|12|0.1%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|10|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7699|7699|9|0.1%|0.0%|
[openbl_30d](#openbl_30d)|4363|4363|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1985|1985|4|0.2%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6982|6982|3|0.0%|0.0%|
[nixspam](#nixspam)|21367|21367|3|0.0%|0.0%|
[ciarmy](#ciarmy)|370|370|3|0.8%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14794|14794|3|0.0%|0.0%|
[openbl_7d](#openbl_7d)|949|949|2|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3474|3474|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12828|12828|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6451|6451|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2309|2309|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6453|6453|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|811|811|1|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1475|1475|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Fri May 29 23:33:01 UTC 2015.

The ipset `xroxy` has **1949** entries, **1949** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|1085|1.1%|55.6%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|932|3.0%|47.8%|
[ri_web_proxies](#ri_web_proxies)|4741|4741|759|16.0%|38.9%|
[proxyrss](#proxyrss)|1569|1569|550|35.0%|28.2%|
[stopforumspam_1d](#stopforumspam_1d)|6982|6982|430|6.1%|22.0%|
[blocklist_de](#blocklist_de)|22510|22510|317|1.4%|16.2%|
[ri_connect_proxies](#ri_connect_proxies)|1812|1812|290|16.0%|14.8%|
[blocklist_de_bots](#blocklist_de_bots)|3474|3474|270|7.7%|13.8%|
[proxz](#proxz)|184|184|121|65.7%|6.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|92|0.0%|4.7%|
[nixspam](#nixspam)|21367|21367|78|0.3%|4.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|77|0.0%|3.9%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|54|0.7%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|53|0.0%|2.7%|
[blocklist_de_mail](#blocklist_de_mail)|14794|14794|45|0.3%|2.3%|
[php_dictionary](#php_dictionary)|433|433|24|5.5%|1.2%|
[php_spammers](#php_spammers)|417|417|18|4.3%|0.9%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|13|1.9%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|237|237|6|2.5%|0.3%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|5|0.0%|0.2%|
[php_commenters](#php_commenters)|281|281|3|1.0%|0.1%|
[php_bad](#php_bad)|281|281|3|1.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.1%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.1%|
[dm_tor](#dm_tor)|6451|6451|2|0.0%|0.1%|
[bm_tor](#bm_tor)|6453|6453|2|0.0%|0.1%|
[openbl_90d](#openbl_90d)|9814|9814|1|0.0%|0.0%|
[openbl](#openbl)|9814|9814|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2309|2309|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1985|1985|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1475|1475|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12828|12828|1|0.0%|0.0%|

## zeus

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist).

The last time downloaded was found to be dated: Fri May 29 22:08:12 UTC 2015.

The ipset `zeus` has **266** entries, **266** unique IPs.

The following table shows the overlaps of `zeus` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus`.
- ` this % ` is the percentage **of this ipset (`zeus`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|986|18056524|264|0.0%|99.2%|
[zeus_badips](#zeus_badips)|228|228|228|100.0%|85.7%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|226|3.3%|84.9%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|68|0.0%|25.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|19|0.0%|7.1%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|16|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|8|0.0%|3.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|5|0.0%|1.8%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|3|0.0%|1.1%|
[openbl_90d](#openbl_90d)|9814|9814|2|0.0%|0.7%|
[openbl_60d](#openbl_60d)|7699|7699|2|0.0%|0.7%|
[openbl_30d](#openbl_30d)|4363|4363|2|0.0%|0.7%|
[openbl](#openbl)|9814|9814|2|0.0%|0.7%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|1|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6982|6982|1|0.0%|0.3%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.3%|
[php_bad](#php_bad)|281|281|1|0.3%|0.3%|
[openbl_7d](#openbl_7d)|949|949|1|0.1%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.3%|
[cleanmx_viruses](#cleanmx_viruses)|395|395|1|0.2%|0.3%|
[bruteforceblocker](#bruteforceblocker)|2309|2309|1|0.0%|0.3%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Fri May 29 23:36:20 UTC 2015.

The ipset `zeus_badips` has **228** entries, **228** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|266|266|228|85.7%|100.0%|
[et_block](#et_block)|986|18056524|228|0.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|199|2.9%|87.2%|
[alienvault_reputation](#alienvault_reputation)|171480|171480|36|0.0%|15.7%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|16|0.0%|7.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14|0.0%|6.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8|0.0%|3.5%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|5|0.0%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4|0.0%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|3|0.0%|1.3%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6982|6982|1|0.0%|0.4%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.4%|
[php_bad](#php_bad)|281|281|1|0.3%|0.4%|
[openbl_90d](#openbl_90d)|9814|9814|1|0.0%|0.4%|
[openbl_60d](#openbl_60d)|7699|7699|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|4363|4363|1|0.0%|0.4%|
[openbl](#openbl)|9814|9814|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.4%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.4%|
[cleanmx_viruses](#cleanmx_viruses)|395|395|1|0.2%|0.4%|
[bruteforceblocker](#bruteforceblocker)|2309|2309|1|0.0%|0.4%|
