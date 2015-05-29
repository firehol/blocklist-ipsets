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

The following list was automatically generated on Fri May 29 16:16:40 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|176841 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|22246 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|12632 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|3470 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|1325 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|409 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|803 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|14691 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|85 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|2038 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|234 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6477 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD)|ipv4 hash:ip|2329 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|360 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|91 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6483 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|904 subnets, 18056697 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botnet](#et_botnet)|[EmergingThreats.net](http://www.emergingthreats.net/) botnet IPs|ipv4 hash:ip|505 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net](http://www.emergingthreats.net/) compromised hosts (seems to be a derivate of other lists)|ipv4 hash:ip|2401 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6360 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
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
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|22937 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
[openbl](#openbl)|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|9833 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|255 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|4386 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7718 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|984 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
[openbl_90d](#openbl_90d)|[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|9833 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
[php_bad](#php_bad)|[projecthoneypot.org](http://www.projecthoneypot.org/) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|281 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|281 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|433 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|257 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|417 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1570 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|157 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1794 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|4670 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|51 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|6827 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|639 subnets, 17921280 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|55 subnets, 421120 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|347 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|7243 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|92405 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|30975 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10305 subnets, 10714 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1931 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|266 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|228 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Fri May 29 16:00:21 UTC 2015.

The ipset `alienvault_reputation` has **176841** entries, **176841** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15168|0.0%|8.5%|
[openbl_90d](#openbl_90d)|9833|9833|9811|99.7%|5.5%|
[openbl](#openbl)|9833|9833|9811|99.7%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7875|0.0%|4.4%|
[openbl_60d](#openbl_60d)|7718|7718|7699|99.7%|4.3%|
[et_block](#et_block)|904|18056697|5013|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4720|0.0%|2.6%|
[openbl_30d](#openbl_30d)|4386|4386|4375|99.7%|2.4%|
[dshield](#dshield)|20|5120|3588|70.0%|2.0%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|1625|0.0%|0.9%|
[et_compromised](#et_compromised)|2401|2401|1505|62.6%|0.8%|
[bruteforceblocker](#bruteforceblocker)|2329|2329|1473|63.2%|0.8%|
[blocklist_de](#blocklist_de)|22246|22246|1436|6.4%|0.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|2038|2038|1198|58.7%|0.6%|
[openbl_7d](#openbl_7d)|984|984|978|99.3%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|518|0.0%|0.2%|
[ciarmy](#ciarmy)|360|360|357|99.1%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|289|0.0%|0.1%|
[openbl_1d](#openbl_1d)|255|255|254|99.6%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|221|0.2%|0.1%|
[voipbl](#voipbl)|10305|10714|205|1.9%|0.1%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|120|1.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12632|12632|116|0.9%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|115|0.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|88|37.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14691|14691|75|0.5%|0.0%|
[zeus](#zeus)|266|266|68|25.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7243|7243|60|0.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|803|803|52|6.4%|0.0%|
[shunlist](#shunlist)|51|51|51|100.0%|0.0%|
[et_tor](#et_tor)|6360|6360|46|0.7%|0.0%|
[dm_tor](#dm_tor)|6483|6483|44|0.6%|0.0%|
[bm_tor](#bm_tor)|6477|6477|44|0.6%|0.0%|
[zeus_badips](#zeus_badips)|228|228|36|15.7%|0.0%|
[nixspam](#nixspam)|22937|22937|30|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|23|6.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3470|3470|23|0.6%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1325|1325|19|1.4%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|85|85|18|21.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|409|409|18|4.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|15|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[php_commenters](#php_commenters)|281|281|12|4.2%|0.0%|
[php_bad](#php_bad)|281|281|12|4.2%|0.0%|
[malc0de](#malc0de)|410|410|10|2.4%|0.0%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|8|0.5%|0.0%|
[sslbl](#sslbl)|347|347|7|2.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|7|1.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|7|0.5%|0.0%|
[xroxy](#xroxy)|1931|1931|4|0.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4670|4670|3|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|3|0.7%|0.0%|
[et_botnet](#et_botnet)|505|505|3|0.5%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1794|1794|2|0.1%|0.0%|
[proxyrss](#proxyrss)|1570|1570|2|0.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|91|91|2|2.1%|0.0%|
[proxz](#proxz)|157|157|1|0.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[feodo](#feodo)|68|68|1|1.4%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Fri May 29 15:42:05 UTC 2015.

The ipset `blocklist_de` has **22246** entries, **22246** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|14691|14691|14688|99.9%|66.0%|
[blocklist_de_apache](#blocklist_de_apache)|12632|12632|12629|99.9%|56.7%|
[blocklist_de_bots](#blocklist_de_bots)|3470|3470|3457|99.6%|15.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2833|0.0%|12.7%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|2722|2.9%|12.2%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|2356|7.6%|10.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|2038|2038|2038|100.0%|9.1%|
[stopforumspam_1d](#stopforumspam_1d)|7243|7243|1574|21.7%|7.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1473|0.0%|6.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1445|0.0%|6.4%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|1436|0.8%|6.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1325|1325|1325|100.0%|5.9%|
[openbl_90d](#openbl_90d)|9833|9833|1201|12.2%|5.3%|
[openbl](#openbl)|9833|9833|1201|12.2%|5.3%|
[openbl_60d](#openbl_60d)|7718|7718|1149|14.8%|5.1%|
[openbl_30d](#openbl_30d)|4386|4386|1065|24.2%|4.7%|
[bruteforceblocker](#bruteforceblocker)|2329|2329|990|42.5%|4.4%|
[et_compromised](#et_compromised)|2401|2401|948|39.4%|4.2%|
[blocklist_de_imap](#blocklist_de_imap)|803|803|802|99.8%|3.6%|
[openbl_7d](#openbl_7d)|984|984|651|66.1%|2.9%|
[nixspam](#nixspam)|22937|22937|585|2.5%|2.6%|
[blocklist_de_ftp](#blocklist_de_ftp)|409|409|409|100.0%|1.8%|
[ri_web_proxies](#ri_web_proxies)|4670|4670|376|8.0%|1.6%|
[xroxy](#xroxy)|1931|1931|297|15.3%|1.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|234|100.0%|1.0%|
[openbl_1d](#openbl_1d)|255|255|222|87.0%|0.9%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|214|3.1%|0.9%|
[proxyrss](#proxyrss)|1570|1570|208|13.2%|0.9%|
[et_block](#et_block)|904|18056697|193|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|187|0.0%|0.8%|
[dshield](#dshield)|20|5120|164|3.2%|0.7%|
[ri_connect_proxies](#ri_connect_proxies)|1794|1794|90|5.0%|0.4%|
[php_commenters](#php_commenters)|281|281|75|26.6%|0.3%|
[php_bad](#php_bad)|281|281|74|26.3%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|73|0.0%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|85|85|66|77.6%|0.2%|
[php_dictionary](#php_dictionary)|433|433|65|15.0%|0.2%|
[php_spammers](#php_spammers)|417|417|63|15.1%|0.2%|
[voipbl](#voipbl)|10305|10714|37|0.3%|0.1%|
[php_harvesters](#php_harvesters)|257|257|35|13.6%|0.1%|
[ciarmy](#ciarmy)|360|360|31|8.6%|0.1%|
[proxz](#proxz)|157|157|29|18.4%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|28|0.0%|0.1%|
[et_tor](#et_tor)|6360|6360|22|0.3%|0.0%|
[dm_tor](#dm_tor)|6483|6483|22|0.3%|0.0%|
[bm_tor](#bm_tor)|6477|6477|22|0.3%|0.0%|
[shunlist](#shunlist)|51|51|10|19.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|4|0.5%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|3|0.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|1|0.0%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Fri May 29 15:56:06 UTC 2015.

The ipset `blocklist_de_apache` has **12632** entries, **12632** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22246|22246|12629|56.7%|99.9%|
[blocklist_de_mail](#blocklist_de_mail)|14691|14691|11059|75.2%|87.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2201|0.0%|17.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1325|1325|1324|99.9%|10.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1323|0.0%|10.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1079|0.0%|8.5%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|227|0.2%|1.7%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|136|0.4%|1.0%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|116|0.0%|0.9%|
[stopforumspam_1d](#stopforumspam_1d)|7243|7243|79|1.0%|0.6%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|38|0.5%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|32|13.6%|0.2%|
[ciarmy](#ciarmy)|360|360|27|7.5%|0.2%|
[php_commenters](#php_commenters)|281|281|22|7.8%|0.1%|
[php_bad](#php_bad)|281|281|22|7.8%|0.1%|
[et_tor](#et_tor)|6360|6360|22|0.3%|0.1%|
[dm_tor](#dm_tor)|6483|6483|22|0.3%|0.1%|
[bm_tor](#bm_tor)|6477|6477|22|0.3%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3470|3470|16|0.4%|0.1%|
[openbl_90d](#openbl_90d)|9833|9833|13|0.1%|0.1%|
[openbl](#openbl)|9833|9833|13|0.1%|0.1%|
[openbl_60d](#openbl_60d)|7718|7718|10|0.1%|0.0%|
[nixspam](#nixspam)|22937|22937|8|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4386|4386|6|0.1%|0.0%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.0%|
[et_block](#et_block)|904|18056697|5|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|3|0.0%|0.0%|
[shunlist](#shunlist)|51|51|3|5.8%|0.0%|
[openbl_7d](#openbl_7d)|984|984|3|0.3%|0.0%|
[et_compromised](#et_compromised)|2401|2401|3|0.1%|0.0%|
[dshield](#dshield)|20|5120|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2329|2329|3|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.0%|
[xroxy](#xroxy)|1931|1931|1|0.0%|0.0%|
[voipbl](#voipbl)|10305|10714|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4670|4670|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1794|1794|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1570|1570|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[openbl_1d](#openbl_1d)|255|255|1|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Fri May 29 15:56:11 UTC 2015.

The ipset `blocklist_de_bots` has **3470** entries, **3470** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22246|22246|3457|15.5%|99.6%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|2409|2.6%|69.4%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|2175|7.0%|62.6%|
[stopforumspam_1d](#stopforumspam_1d)|7243|7243|1494|20.6%|43.0%|
[ri_web_proxies](#ri_web_proxies)|4670|4670|349|7.4%|10.0%|
[xroxy](#xroxy)|1931|1931|252|13.0%|7.2%|
[proxyrss](#proxyrss)|1570|1570|206|13.1%|5.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|161|0.0%|4.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|134|57.2%|3.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|92|0.0%|2.6%|
[ri_connect_proxies](#ri_connect_proxies)|1794|1794|88|4.9%|2.5%|
[php_commenters](#php_commenters)|281|281|60|21.3%|1.7%|
[php_bad](#php_bad)|281|281|60|21.3%|1.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|55|0.0%|1.5%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|54|0.0%|1.5%|
[et_block](#et_block)|904|18056697|54|0.0%|1.5%|
[nixspam](#nixspam)|22937|22937|52|0.2%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|43|0.0%|1.2%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|36|0.5%|1.0%|
[proxz](#proxz)|157|157|28|17.8%|0.8%|
[php_harvesters](#php_harvesters)|257|257|28|10.8%|0.8%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|24|0.0%|0.6%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|23|0.0%|0.6%|
[php_spammers](#php_spammers)|417|417|19|4.5%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|14691|14691|16|0.1%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|12632|12632|16|0.1%|0.4%|
[php_dictionary](#php_dictionary)|433|433|15|3.4%|0.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|4|0.5%|0.1%|
[openbl_90d](#openbl_90d)|9833|9833|2|0.0%|0.0%|
[openbl](#openbl)|9833|9833|2|0.0%|0.0%|
[voipbl](#voipbl)|10305|10714|1|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Fri May 29 15:42:16 UTC 2015.

The ipset `blocklist_de_bruteforce` has **1325** entries, **1325** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22246|22246|1325|5.9%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|12632|12632|1324|10.4%|99.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|110|0.0%|8.3%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|84|0.0%|6.3%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|73|0.2%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|42|0.0%|3.1%|
[stopforumspam_1d](#stopforumspam_1d)|7243|7243|39|0.5%|2.9%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|35|0.5%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|28|0.0%|2.1%|
[et_tor](#et_tor)|6360|6360|20|0.3%|1.5%|
[dm_tor](#dm_tor)|6483|6483|19|0.2%|1.4%|
[bm_tor](#bm_tor)|6477|6477|19|0.2%|1.4%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|19|0.0%|1.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|10|4.2%|0.7%|
[nixspam](#nixspam)|22937|22937|7|0.0%|0.5%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.3%|
[php_commenters](#php_commenters)|281|281|5|1.7%|0.3%|
[php_bad](#php_bad)|281|281|5|1.7%|0.3%|
[openbl_90d](#openbl_90d)|9833|9833|5|0.0%|0.3%|
[openbl](#openbl)|9833|9833|5|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|3|0.0%|0.2%|
[openbl_60d](#openbl_60d)|7718|7718|3|0.0%|0.2%|
[et_block](#et_block)|904|18056697|3|0.0%|0.2%|
[xroxy](#xroxy)|1931|1931|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4670|4670|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1794|1794|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1570|1570|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4386|4386|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2401|2401|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2329|2329|1|0.0%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Fri May 29 15:56:09 UTC 2015.

The ipset `blocklist_de_ftp` has **409** entries, **409** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22246|22246|409|1.8%|100.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|29|0.0%|7.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|25|0.0%|6.1%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|18|0.0%|4.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|12|0.0%|2.9%|
[openbl_90d](#openbl_90d)|9833|9833|10|0.1%|2.4%|
[openbl](#openbl)|9833|9833|10|0.1%|2.4%|
[openbl_60d](#openbl_60d)|7718|7718|9|0.1%|2.2%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|8|0.0%|1.9%|
[nixspam](#nixspam)|22937|22937|6|0.0%|1.4%|
[openbl_30d](#openbl_30d)|4386|4386|4|0.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|3|0.0%|0.7%|
[php_harvesters](#php_harvesters)|257|257|3|1.1%|0.7%|
[openbl_7d](#openbl_7d)|984|984|3|0.3%|0.7%|
[stopforumspam_1d](#stopforumspam_1d)|7243|7243|2|0.0%|0.4%|
[openbl_1d](#openbl_1d)|255|255|2|0.7%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|2|0.8%|0.4%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|1|0.0%|0.2%|
[ciarmy](#ciarmy)|360|360|1|0.2%|0.2%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Fri May 29 15:56:08 UTC 2015.

The ipset `blocklist_de_imap` has **803** entries, **803** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|14691|14691|803|5.4%|100.0%|
[blocklist_de](#blocklist_de)|22246|22246|802|3.6%|99.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|56|0.0%|6.9%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|52|0.0%|6.4%|
[openbl_90d](#openbl_90d)|9833|9833|45|0.4%|5.6%|
[openbl](#openbl)|9833|9833|45|0.4%|5.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|44|0.0%|5.4%|
[openbl_60d](#openbl_60d)|7718|7718|42|0.5%|5.2%|
[openbl_30d](#openbl_30d)|4386|4386|38|0.8%|4.7%|
[openbl_7d](#openbl_7d)|984|984|24|2.4%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|15|0.0%|1.8%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|14|0.0%|1.7%|
[et_block](#et_block)|904|18056697|14|0.0%|1.7%|
[et_compromised](#et_compromised)|2401|2401|10|0.4%|1.2%|
[bruteforceblocker](#bruteforceblocker)|2329|2329|8|0.3%|0.9%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|7|0.1%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|4|0.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.4%|
[openbl_1d](#openbl_1d)|255|255|3|1.1%|0.3%|
[voipbl](#voipbl)|10305|10714|1|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|1|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.1%|
[nixspam](#nixspam)|22937|22937|1|0.0%|0.1%|
[ciarmy](#ciarmy)|360|360|1|0.2%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|1|0.4%|0.1%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Fri May 29 15:56:05 UTC 2015.

The ipset `blocklist_de_mail` has **14691** entries, **14691** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22246|22246|14688|66.0%|99.9%|
[blocklist_de_apache](#blocklist_de_apache)|12632|12632|11059|87.5%|75.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2296|0.0%|15.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1335|0.0%|9.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1162|0.0%|7.9%|
[blocklist_de_imap](#blocklist_de_imap)|803|803|803|100.0%|5.4%|
[nixspam](#nixspam)|22937|22937|514|2.2%|3.4%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|205|0.2%|1.3%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|139|2.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|96|0.3%|0.6%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|75|0.0%|0.5%|
[openbl_90d](#openbl_90d)|9833|9833|58|0.5%|0.3%|
[openbl](#openbl)|9833|9833|58|0.5%|0.3%|
[openbl_60d](#openbl_60d)|7718|7718|54|0.6%|0.3%|
[php_dictionary](#php_dictionary)|433|433|50|11.5%|0.3%|
[openbl_30d](#openbl_30d)|4386|4386|49|1.1%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7243|7243|44|0.6%|0.2%|
[xroxy](#xroxy)|1931|1931|42|2.1%|0.2%|
[php_spammers](#php_spammers)|417|417|37|8.8%|0.2%|
[ri_web_proxies](#ri_web_proxies)|4670|4670|27|0.5%|0.1%|
[openbl_7d](#openbl_7d)|984|984|27|2.7%|0.1%|
[php_commenters](#php_commenters)|281|281|23|8.1%|0.1%|
[php_bad](#php_bad)|281|281|22|7.8%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|19|8.1%|0.1%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|18|0.0%|0.1%|
[et_block](#et_block)|904|18056697|18|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3470|3470|16|0.4%|0.1%|
[et_compromised](#et_compromised)|2401|2401|15|0.6%|0.1%|
[bruteforceblocker](#bruteforceblocker)|2329|2329|13|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|4|1.5%|0.0%|
[voipbl](#voipbl)|10305|10714|3|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|3|0.0%|0.0%|
[openbl_1d](#openbl_1d)|255|255|3|1.1%|0.0%|
[dm_tor](#dm_tor)|6483|6483|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6477|6477|3|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[et_tor](#et_tor)|6360|6360|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1794|1794|1|0.0%|0.0%|
[proxz](#proxz)|157|157|1|0.6%|0.0%|
[proxyrss](#proxyrss)|1570|1570|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[ciarmy](#ciarmy)|360|360|1|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2038|2038|1|0.0%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Fri May 29 15:56:10 UTC 2015.

The ipset `blocklist_de_sip` has **85** entries, **85** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22246|22246|66|0.2%|77.6%|
[voipbl](#voipbl)|10305|10714|28|0.2%|32.9%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|18|0.0%|21.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|16|0.0%|18.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|6|0.0%|7.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4|0.0%|4.7%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|2.3%|
[et_botnet](#et_botnet)|505|505|1|0.1%|1.1%|
[ciarmy](#ciarmy)|360|360|1|0.2%|1.1%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Fri May 29 15:42:05 UTC 2015.

The ipset `blocklist_de_ssh` has **2038** entries, **2038** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22246|22246|2038|9.1%|100.0%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|1198|0.6%|58.7%|
[openbl_90d](#openbl_90d)|9833|9833|1119|11.3%|54.9%|
[openbl](#openbl)|9833|9833|1119|11.3%|54.9%|
[openbl_60d](#openbl_60d)|7718|7718|1077|13.9%|52.8%|
[openbl_30d](#openbl_30d)|4386|4386|1007|22.9%|49.4%|
[bruteforceblocker](#bruteforceblocker)|2329|2329|975|41.8%|47.8%|
[et_compromised](#et_compromised)|2401|2401|931|38.7%|45.6%|
[openbl_7d](#openbl_7d)|984|984|619|62.9%|30.3%|
[openbl_1d](#openbl_1d)|255|255|216|84.7%|10.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|207|0.0%|10.1%|
[dshield](#dshield)|20|5120|161|3.1%|7.8%|
[et_block](#et_block)|904|18056697|117|0.0%|5.7%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|113|0.0%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|104|0.0%|5.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|79|33.7%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|38|0.0%|1.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.5%|
[shunlist](#shunlist)|51|51|7|13.7%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|6|0.0%|0.2%|
[voipbl](#voipbl)|10305|10714|4|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[xroxy](#xroxy)|1931|1931|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7243|7243|1|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.0%|
[nixspam](#nixspam)|22937|22937|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[ciarmy](#ciarmy)|360|360|1|0.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14691|14691|1|0.0%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Fri May 29 15:42:14 UTC 2015.

The ipset `blocklist_de_strongips` has **234** entries, **234** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22246|22246|234|1.0%|100.0%|
[blocklist_de_bots](#blocklist_de_bots)|3470|3470|134|3.8%|57.2%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|132|0.1%|56.4%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|121|0.3%|51.7%|
[stopforumspam_1d](#stopforumspam_1d)|7243|7243|104|1.4%|44.4%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|88|0.0%|37.6%|
[openbl_90d](#openbl_90d)|9833|9833|80|0.8%|34.1%|
[openbl](#openbl)|9833|9833|80|0.8%|34.1%|
[openbl_60d](#openbl_60d)|7718|7718|79|1.0%|33.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|2038|2038|79|3.8%|33.7%|
[openbl_30d](#openbl_30d)|4386|4386|77|1.7%|32.9%|
[openbl_7d](#openbl_7d)|984|984|76|7.7%|32.4%|
[openbl_1d](#openbl_1d)|255|255|40|15.6%|17.0%|
[php_commenters](#php_commenters)|281|281|34|12.0%|14.5%|
[php_bad](#php_bad)|281|281|34|12.0%|14.5%|
[dshield](#dshield)|20|5120|34|0.6%|14.5%|
[blocklist_de_apache](#blocklist_de_apache)|12632|12632|32|0.2%|13.6%|
[et_compromised](#et_compromised)|2401|2401|22|0.9%|9.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|19|0.0%|8.1%|
[blocklist_de_mail](#blocklist_de_mail)|14691|14691|19|0.1%|8.1%|
[bruteforceblocker](#bruteforceblocker)|2329|2329|17|0.7%|7.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1325|1325|10|0.7%|4.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8|0.0%|3.4%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|7|0.0%|2.9%|
[et_block](#et_block)|904|18056697|7|0.0%|2.9%|
[xroxy](#xroxy)|1931|1931|6|0.3%|2.5%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|6|0.0%|2.5%|
[php_spammers](#php_spammers)|417|417|6|1.4%|2.5%|
[ri_web_proxies](#ri_web_proxies)|4670|4670|3|0.0%|1.2%|
[proxyrss](#proxyrss)|1570|1570|3|0.1%|1.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.2%|
[nixspam](#nixspam)|22937|22937|2|0.0%|0.8%|
[blocklist_de_ftp](#blocklist_de_ftp)|409|409|2|0.4%|0.8%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|1|0.0%|0.4%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.4%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|803|803|1|0.1%|0.4%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Fri May 29 15:54:07 UTC 2015.

The ipset `bm_tor` has **6477** entries, **6477** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[dm_tor](#dm_tor)|6483|6483|6391|98.5%|98.6%|
[et_tor](#et_tor)|6360|6360|5677|89.2%|87.6%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|1034|15.1%|15.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|617|0.0%|9.5%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|587|0.6%|9.0%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|454|1.4%|7.0%|
[stopforumspam_1d](#stopforumspam_1d)|7243|7243|328|4.5%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|186|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|176|47.3%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|159|0.0%|2.4%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|44|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[php_bad](#php_bad)|281|281|29|10.3%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|12632|12632|22|0.1%|0.3%|
[blocklist_de](#blocklist_de)|22246|22246|22|0.0%|0.3%|
[openbl_90d](#openbl_90d)|9833|9833|21|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7718|7718|21|0.2%|0.3%|
[openbl](#openbl)|9833|9833|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1325|1325|19|1.4%|0.2%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4670|4670|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|904|18056697|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14691|14691|3|0.0%|0.0%|
[xroxy](#xroxy)|1931|1931|2|0.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1794|1794|2|0.1%|0.0%|
[voipbl](#voipbl)|10305|10714|1|0.0%|0.0%|
[proxz](#proxz)|157|157|1|0.6%|0.0%|
[nixspam](#nixspam)|22937|22937|1|0.0%|0.0%|
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
[bruteforceblocker](#bruteforceblocker)|2329|2329|1|0.0%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD)

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Fri May 29 15:09:22 UTC 2015.

The ipset `bruteforceblocker` has **2329** entries, **2329** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_compromised](#et_compromised)|2401|2401|2250|93.7%|96.6%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|1473|0.8%|63.2%|
[openbl_90d](#openbl_90d)|9833|9833|1411|14.3%|60.5%|
[openbl](#openbl)|9833|9833|1411|14.3%|60.5%|
[openbl_60d](#openbl_60d)|7718|7718|1396|18.0%|59.9%|
[openbl_30d](#openbl_30d)|4386|4386|1333|30.3%|57.2%|
[blocklist_de](#blocklist_de)|22246|22246|990|4.4%|42.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|2038|2038|975|47.8%|41.8%|
[openbl_7d](#openbl_7d)|984|984|513|52.1%|22.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|223|0.0%|9.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|138|0.0%|5.9%|
[openbl_1d](#openbl_1d)|255|255|130|50.9%|5.5%|
[dshield](#dshield)|20|5120|126|2.4%|5.4%|
[et_block](#et_block)|904|18056697|103|0.0%|4.4%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|102|0.0%|4.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|68|0.0%|2.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|17|7.2%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|14691|14691|13|0.0%|0.5%|
[shunlist](#shunlist)|51|51|8|15.6%|0.3%|
[blocklist_de_imap](#blocklist_de_imap)|803|803|8|0.9%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|6|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|3|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12632|12632|3|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7243|7243|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|228|228|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[xroxy](#xroxy)|1931|1931|1|0.0%|0.0%|
[voipbl](#voipbl)|10305|10714|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|1|0.0%|0.0%|
[proxz](#proxz)|157|157|1|0.6%|0.0%|
[proxyrss](#proxyrss)|1570|1570|1|0.0%|0.0%|
[nixspam](#nixspam)|22937|22937|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3656|670639576|1|0.0%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1325|1325|1|0.0%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Fri May 29 13:15:16 UTC 2015.

The ipset `ciarmy` has **360** entries, **360** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|176841|176841|357|0.2%|99.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|63|0.0%|17.5%|
[blocklist_de](#blocklist_de)|22246|22246|31|0.1%|8.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|28|0.0%|7.7%|
[blocklist_de_apache](#blocklist_de_apache)|12632|12632|27|0.2%|7.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|17|0.0%|4.7%|
[voipbl](#voipbl)|10305|10714|4|0.0%|1.1%|
[shunlist](#shunlist)|51|51|2|3.9%|0.5%|
[dshield](#dshield)|20|5120|2|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|1|0.0%|0.2%|
[openbl_90d](#openbl_90d)|9833|9833|1|0.0%|0.2%|
[openbl_7d](#openbl_7d)|984|984|1|0.1%|0.2%|
[openbl_60d](#openbl_60d)|7718|7718|1|0.0%|0.2%|
[openbl_30d](#openbl_30d)|4386|4386|1|0.0%|0.2%|
[openbl](#openbl)|9833|9833|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2038|2038|1|0.0%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|85|85|1|1.1%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|14691|14691|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|803|803|1|0.1%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|409|409|1|0.2%|0.2%|

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
[malc0de](#malc0de)|410|410|9|2.1%|9.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8|0.0%|8.7%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|2.1%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|2|0.0%|2.1%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|1|0.0%|1.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1|0.0%|1.0%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Fri May 29 15:54:04 UTC 2015.

The ipset `dm_tor` has **6483** entries, **6483** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6477|6477|6391|98.6%|98.5%|
[et_tor](#et_tor)|6360|6360|5665|89.0%|87.3%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|1035|15.1%|15.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|610|0.0%|9.4%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|590|0.6%|9.1%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|456|1.4%|7.0%|
[stopforumspam_1d](#stopforumspam_1d)|7243|7243|329|4.5%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|185|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|176|47.3%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|159|0.0%|2.4%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|44|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[php_bad](#php_bad)|281|281|29|10.3%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|12632|12632|22|0.1%|0.3%|
[blocklist_de](#blocklist_de)|22246|22246|22|0.0%|0.3%|
[openbl_90d](#openbl_90d)|9833|9833|21|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7718|7718|21|0.2%|0.3%|
[openbl](#openbl)|9833|9833|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1325|1325|19|1.4%|0.2%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4670|4670|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|904|18056697|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14691|14691|3|0.0%|0.0%|
[xroxy](#xroxy)|1931|1931|2|0.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1794|1794|2|0.1%|0.0%|
[voipbl](#voipbl)|10305|10714|1|0.0%|0.0%|
[proxz](#proxz)|157|157|1|0.6%|0.0%|
[nixspam](#nixspam)|22937|22937|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Fri May 29 14:56:00 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|176841|176841|3588|2.0%|70.0%|
[et_block](#et_block)|904|18056697|768|0.0%|15.0%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|512|0.0%|10.0%|
[openbl_90d](#openbl_90d)|9833|9833|188|1.9%|3.6%|
[openbl](#openbl)|9833|9833|188|1.9%|3.6%|
[openbl_60d](#openbl_60d)|7718|7718|184|2.3%|3.5%|
[openbl_30d](#openbl_30d)|4386|4386|167|3.8%|3.2%|
[blocklist_de](#blocklist_de)|22246|22246|164|0.7%|3.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2038|2038|161|7.8%|3.1%|
[openbl_7d](#openbl_7d)|984|984|127|12.9%|2.4%|
[bruteforceblocker](#bruteforceblocker)|2329|2329|126|5.4%|2.4%|
[et_compromised](#et_compromised)|2401|2401|120|4.9%|2.3%|
[openbl_1d](#openbl_1d)|255|255|52|20.3%|1.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|34|14.5%|0.6%|
[nixspam](#nixspam)|22937|22937|5|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12632|12632|3|0.0%|0.0%|
[malc0de](#malc0de)|410|410|2|0.4%|0.0%|
[ciarmy](#ciarmy)|360|360|2|0.5%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|1|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7243|7243|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|1|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1|0.0%|0.0%|
[et_tor](#et_tor)|6360|6360|1|0.0%|0.0%|

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
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|2133265|0.2%|11.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|195924|0.1%|1.0%|
[fullbogons](#fullbogons)|3656|670639576|20480|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|5013|2.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1038|0.3%|0.0%|
[dshield](#dshield)|20|5120|768|15.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|744|0.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|517|0.1%|0.0%|
[openbl_90d](#openbl_90d)|9833|9833|451|4.5%|0.0%|
[openbl](#openbl)|9833|9833|451|4.5%|0.0%|
[nixspam](#nixspam)|22937|22937|289|1.2%|0.0%|
[zeus](#zeus)|266|266|262|98.4%|0.0%|
[openbl_60d](#openbl_60d)|7718|7718|242|3.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|229|3.3%|0.0%|
[zeus_badips](#zeus_badips)|228|228|226|99.1%|0.0%|
[openbl_30d](#openbl_30d)|4386|4386|209|4.7%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|205|0.6%|0.0%|
[blocklist_de](#blocklist_de)|22246|22246|193|0.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2038|2038|117|5.7%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2329|2329|103|4.4%|0.0%|
[et_compromised](#et_compromised)|2401|2401|98|4.0%|0.0%|
[openbl_7d](#openbl_7d)|984|984|85|8.6%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7243|7243|54|0.7%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3470|3470|54|1.5%|0.0%|
[openbl_1d](#openbl_1d)|255|255|31|12.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|28|2.1%|0.0%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.0%|
[php_bad](#php_bad)|281|281|24|8.5%|0.0%|
[voipbl](#voipbl)|10305|10714|19|0.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14691|14691|18|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|803|803|14|1.7%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|7|2.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12632|12632|5|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[sslbl](#sslbl)|347|347|3|0.8%|0.0%|
[et_tor](#et_tor)|6360|6360|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6483|6483|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6477|6477|3|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1325|1325|3|0.2%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[malc0de](#malc0de)|410|410|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[et_botnet](#et_botnet)|505|505|1|0.1%|0.0%|

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
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|40|0.0%|7.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|21|0.0%|4.1%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|3|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[et_block](#et_block)|904|18056697|1|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|85|85|1|1.1%|0.1%|

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
[bruteforceblocker](#bruteforceblocker)|2329|2329|2250|96.6%|93.7%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|1505|0.8%|62.6%|
[openbl_90d](#openbl_90d)|9833|9833|1432|14.5%|59.6%|
[openbl](#openbl)|9833|9833|1432|14.5%|59.6%|
[openbl_60d](#openbl_60d)|7718|7718|1417|18.3%|59.0%|
[openbl_30d](#openbl_30d)|4386|4386|1343|30.6%|55.9%|
[blocklist_de](#blocklist_de)|22246|22246|948|4.2%|39.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|2038|2038|931|45.6%|38.7%|
[openbl_7d](#openbl_7d)|984|984|500|50.8%|20.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|230|0.0%|9.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|148|0.0%|6.1%|
[openbl_1d](#openbl_1d)|255|255|120|47.0%|4.9%|
[dshield](#dshield)|20|5120|120|2.3%|4.9%|
[et_block](#et_block)|904|18056697|98|0.0%|4.0%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|97|0.0%|4.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|73|0.0%|3.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|22|9.4%|0.9%|
[blocklist_de_mail](#blocklist_de_mail)|14691|14691|15|0.1%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|803|803|10|1.2%|0.4%|
[shunlist](#shunlist)|51|51|8|15.6%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|6|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|3|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12632|12632|3|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7243|7243|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|228|228|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[xroxy](#xroxy)|1931|1931|1|0.0%|0.0%|
[voipbl](#voipbl)|10305|10714|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|1|0.0%|0.0%|
[proxz](#proxz)|157|157|1|0.6%|0.0%|
[proxyrss](#proxyrss)|1570|1570|1|0.0%|0.0%|
[nixspam](#nixspam)|22937|22937|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1325|1325|1|0.0%|0.0%|

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
[bm_tor](#bm_tor)|6477|6477|5677|87.6%|89.2%|
[dm_tor](#dm_tor)|6483|6483|5665|87.3%|89.0%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|1068|15.6%|16.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|607|0.0%|9.5%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|601|0.6%|9.4%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|465|1.5%|7.3%|
[stopforumspam_1d](#stopforumspam_1d)|7243|7243|332|4.5%|5.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|182|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|178|47.8%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|166|0.0%|2.6%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|46|0.0%|0.7%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[php_bad](#php_bad)|281|281|29|10.3%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|12632|12632|22|0.1%|0.3%|
[blocklist_de](#blocklist_de)|22246|22246|22|0.0%|0.3%|
[openbl_90d](#openbl_90d)|9833|9833|21|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7718|7718|21|0.2%|0.3%|
[openbl](#openbl)|9833|9833|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1325|1325|20|1.5%|0.3%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4670|4670|5|0.1%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|904|18056697|3|0.0%|0.0%|
[xroxy](#xroxy)|1931|1931|2|0.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1794|1794|2|0.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14691|14691|2|0.0%|0.0%|
[voipbl](#voipbl)|10305|10714|1|0.0%|0.0%|
[proxz](#proxz)|157|157|1|0.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Fri May 29 15:54:20 UTC 2015.

The ipset `feodo` has **68** entries, **68** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[snort_ipfilter](#snort_ipfilter)|6827|6827|53|0.7%|77.9%|
[sslbl](#sslbl)|347|347|25|7.2%|36.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|4|0.0%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|3|0.0%|4.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|4.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|1.4%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|1|0.0%|1.4%|

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
[et_block](#et_block)|904|18056697|20480|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|890|0.2%|0.0%|
[voipbl](#voipbl)|10305|10714|319|2.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|33|2.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|9|0.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2329|2329|1|0.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|176841|176841|14|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.0%|
[nixspam](#nixspam)|22937|22937|7|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|6|0.0%|0.0%|
[et_block](#et_block)|904|18056697|6|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[xroxy](#xroxy)|1931|1931|3|0.1%|0.0%|
[voipbl](#voipbl)|10305|10714|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14691|14691|2|0.0%|0.0%|
[blocklist_de](#blocklist_de)|22246|22246|2|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7243|7243|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4670|4670|1|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

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
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|904796|0.1%|9.8%|
[fullbogons](#fullbogons)|3656|670639576|565248|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|145472|0.1%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1036|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|742|0.8%|0.0%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|518|0.2%|0.0%|
[nixspam](#nixspam)|22937|22937|289|1.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|194|0.6%|0.0%|
[blocklist_de](#blocklist_de)|22246|22246|73|0.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3470|3470|55|1.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7243|7243|42|0.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|27|2.1%|0.0%|
[openbl_90d](#openbl_90d)|9833|9833|20|0.2%|0.0%|
[openbl](#openbl)|9833|9833|20|0.2%|0.0%|
[openbl_60d](#openbl_60d)|7718|7718|19|0.2%|0.0%|
[openbl_30d](#openbl_30d)|4386|4386|14|0.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|11|0.1%|0.0%|
[openbl_7d](#openbl_7d)|984|984|11|1.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2038|2038|11|0.5%|0.0%|
[zeus_badips](#zeus_badips)|228|228|10|4.3%|0.0%|
[zeus](#zeus)|266|266|10|3.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14691|14691|6|0.0%|0.0%|
[openbl_1d](#openbl_1d)|255|255|5|1.9%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2329|2329|5|0.2%|0.0%|
[et_compromised](#et_compromised)|2401|2401|4|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|803|803|4|0.4%|0.0%|
[et_tor](#et_tor)|6360|6360|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6483|6483|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6477|6477|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|3|1.2%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12632|12632|2|0.0%|0.0%|
[voipbl](#voipbl)|10305|10714|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.0%|
[php_bad](#php_bad)|281|281|1|0.3%|0.0%|
[et_botnet](#et_botnet)|505|505|1|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1325|1325|1|0.0%|0.0%|

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
[et_block](#et_block)|904|18056697|2133265|11.8%|0.2%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|2133002|11.9%|0.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1354348|0.9%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904796|9.8%|0.1%|
[fullbogons](#fullbogons)|3656|670639576|234871|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|33155|7.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|13248|3.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|4720|2.6%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|1511|1.6%|0.0%|
[blocklist_de](#blocklist_de)|22246|22246|1473|6.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14691|14691|1335|9.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12632|12632|1323|10.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|576|1.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|406|0.8%|0.0%|
[nixspam](#nixspam)|22937|22937|306|1.3%|0.0%|
[voipbl](#voipbl)|10305|10714|295|2.7%|0.0%|
[openbl_90d](#openbl_90d)|9833|9833|218|2.2%|0.0%|
[openbl](#openbl)|9833|9833|218|2.2%|0.0%|
[openbl_60d](#openbl_60d)|7718|7718|180|2.3%|0.0%|
[et_tor](#et_tor)|6360|6360|166|2.6%|0.0%|
[dm_tor](#dm_tor)|6483|6483|159|2.4%|0.0%|
[bm_tor](#bm_tor)|6477|6477|159|2.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7243|7243|151|2.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4670|4670|107|2.2%|0.0%|
[openbl_30d](#openbl_30d)|4386|4386|100|2.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|97|6.6%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|78|1.1%|0.0%|
[et_compromised](#et_compromised)|2401|2401|73|3.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2329|2329|68|2.9%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|66|5.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1794|1794|63|3.5%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|58|8.6%|0.0%|
[xroxy](#xroxy)|1931|1931|52|2.6%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3470|3470|43|1.2%|0.0%|
[et_botnet](#et_botnet)|505|505|40|7.9%|0.0%|
[proxyrss](#proxyrss)|1570|1570|38|2.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2038|2038|38|1.8%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1325|1325|28|2.1%|0.0%|
[openbl_7d](#openbl_7d)|984|984|17|1.7%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|17|4.5%|0.0%|
[ciarmy](#ciarmy)|360|360|17|4.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|803|803|15|1.8%|0.0%|
[malc0de](#malc0de)|410|410|12|2.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|409|409|12|2.9%|0.0%|
[php_dictionary](#php_dictionary)|433|433|9|2.0%|0.0%|
[zeus](#zeus)|266|266|8|3.0%|0.0%|
[proxz](#proxz)|157|157|7|4.4%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.0%|
[php_commenters](#php_commenters)|281|281|5|1.7%|0.0%|
[php_bad](#php_bad)|281|281|5|1.7%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[zeus_badips](#zeus_badips)|228|228|4|1.7%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|85|85|4|4.7%|0.0%|
[sslbl](#sslbl)|347|347|3|0.8%|0.0%|
[feodo](#feodo)|68|68|3|4.4%|0.0%|
[openbl_1d](#openbl_1d)|255|255|2|0.7%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
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
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|16300309|2.1%|4.6%|
[et_block](#et_block)|904|18056697|8401954|46.5%|2.4%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|8401434|46.8%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2830140|2.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2526625|27.5%|0.7%|
[fullbogons](#fullbogons)|3656|670639576|248319|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|33368|7.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|7875|4.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|7733|2.2%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|2445|2.6%|0.0%|
[blocklist_de](#blocklist_de)|22246|22246|1445|6.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14691|14691|1162|7.9%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12632|12632|1079|8.5%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|904|2.9%|0.0%|
[nixspam](#nixspam)|22937|22937|580|2.5%|0.0%|
[openbl_90d](#openbl_90d)|9833|9833|505|5.1%|0.0%|
[openbl](#openbl)|9833|9833|505|5.1%|0.0%|
[voipbl](#voipbl)|10305|10714|429|4.0%|0.0%|
[openbl_60d](#openbl_60d)|7718|7718|359|4.6%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7243|7243|242|3.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|230|0.4%|0.0%|
[openbl_30d](#openbl_30d)|4386|4386|221|5.0%|0.0%|
[bm_tor](#bm_tor)|6477|6477|186|2.8%|0.0%|
[dm_tor](#dm_tor)|6483|6483|185|2.8%|0.0%|
[et_tor](#et_tor)|6360|6360|182|2.8%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4670|4670|164|3.5%|0.0%|
[et_compromised](#et_compromised)|2401|2401|148|6.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2329|2329|138|5.9%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2038|2038|104|5.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|103|1.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3470|3470|92|2.6%|0.0%|
[xroxy](#xroxy)|1931|1931|89|4.6%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1794|1794|76|4.2%|0.0%|
[proxyrss](#proxyrss)|1570|1570|72|4.5%|0.0%|
[openbl_7d](#openbl_7d)|984|984|51|5.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|45|3.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|803|803|44|5.4%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1325|1325|42|3.1%|0.0%|
[php_spammers](#php_spammers)|417|417|31|7.4%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|409|409|29|7.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|28|4.1%|0.0%|
[ciarmy](#ciarmy)|360|360|28|7.7%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|26|2.0%|0.0%|
[malc0de](#malc0de)|410|410|26|6.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|21|5.6%|0.0%|
[et_botnet](#et_botnet)|505|505|21|4.1%|0.0%|
[php_dictionary](#php_dictionary)|433|433|10|2.3%|0.0%|
[openbl_1d](#openbl_1d)|255|255|10|3.9%|0.0%|
[zeus](#zeus)|266|266|9|3.3%|0.0%|
[php_commenters](#php_commenters)|281|281|9|3.2%|0.0%|
[php_bad](#php_bad)|281|281|9|3.2%|0.0%|
[zeus_badips](#zeus_badips)|228|228|8|3.5%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|91|91|8|8.7%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|8|3.4%|0.0%|
[proxz](#proxz)|157|157|7|4.4%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[sslbl](#sslbl)|347|347|6|1.7%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|85|85|6|7.0%|0.0%|
[shunlist](#shunlist)|51|51|3|5.8%|0.0%|
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
[et_block](#et_block)|904|18056697|195924|1.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|195904|1.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|15168|8.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|9231|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|6079|6.5%|0.0%|
[blocklist_de](#blocklist_de)|22246|22246|2833|12.7%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14691|14691|2296|15.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12632|12632|2201|17.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|2103|6.7%|0.0%|
[nixspam](#nixspam)|22937|22937|1673|7.2%|0.0%|
[voipbl](#voipbl)|10305|10714|1586|14.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1172|2.4%|0.0%|
[openbl_90d](#openbl_90d)|9833|9833|947|9.6%|0.0%|
[openbl](#openbl)|9833|9833|947|9.6%|0.0%|
[openbl_60d](#openbl_60d)|7718|7718|721|9.3%|0.0%|
[bm_tor](#bm_tor)|6477|6477|617|9.5%|0.0%|
[dm_tor](#dm_tor)|6483|6483|610|9.4%|0.0%|
[et_tor](#et_tor)|6360|6360|607|9.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7243|7243|446|6.1%|0.0%|
[openbl_30d](#openbl_30d)|4386|4386|438|9.9%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|231|3.3%|0.0%|
[et_compromised](#et_compromised)|2401|2401|230|9.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2329|2329|223|9.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2038|2038|207|10.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3470|3470|161|4.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|146|11.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4670|4670|144|3.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|125|33.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|110|7.5%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1325|1325|110|8.3%|0.0%|
[openbl_7d](#openbl_7d)|984|984|97|9.8%|0.0%|
[xroxy](#xroxy)|1931|1931|76|3.9%|0.0%|
[malc0de](#malc0de)|410|410|76|18.5%|0.0%|
[et_botnet](#et_botnet)|505|505|74|14.6%|0.0%|
[ciarmy](#ciarmy)|360|360|63|17.5%|0.0%|
[proxyrss](#proxyrss)|1570|1570|58|3.6%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|803|803|56|6.9%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|51|7.5%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1794|1794|42|2.3%|0.0%|
[php_spammers](#php_spammers)|417|417|26|6.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|409|409|25|6.1%|0.0%|
[php_dictionary](#php_dictionary)|433|433|24|5.5%|0.0%|
[sslbl](#sslbl)|347|347|23|6.6%|0.0%|
[proxz](#proxz)|157|157|23|14.6%|0.0%|
[zeus](#zeus)|266|266|19|7.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|19|8.1%|0.0%|
[openbl_1d](#openbl_1d)|255|255|17|6.6%|0.0%|
[php_bad](#php_bad)|281|281|16|5.6%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|85|85|16|18.8%|0.0%|
[php_harvesters](#php_harvesters)|257|257|15|5.8%|0.0%|
[php_commenters](#php_commenters)|281|281|15|5.3%|0.0%|
[zeus_badips](#zeus_badips)|228|228|14|6.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|91|91|14|15.3%|0.0%|
[shunlist](#shunlist)|51|51|5|9.8%|0.0%|
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
[xroxy](#xroxy)|1931|1931|12|0.6%|1.7%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|11|0.0%|1.6%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|10|0.0%|1.4%|
[ri_web_proxies](#ri_web_proxies)|4670|4670|10|0.2%|1.4%|
[stopforumspam_1d](#stopforumspam_1d)|7243|7243|6|0.0%|0.8%|
[ri_connect_proxies](#ri_connect_proxies)|1794|1794|6|0.3%|0.8%|
[proxyrss](#proxyrss)|1570|1570|6|0.3%|0.8%|
[blocklist_de_bots](#blocklist_de_bots)|3470|3470|4|0.1%|0.5%|
[blocklist_de](#blocklist_de)|22246|22246|4|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|2|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.2%|
[et_block](#et_block)|904|18056697|2|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|1|0.0%|0.1%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.1%|
[nixspam](#nixspam)|22937|22937|1|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|1|0.0%|0.1%|

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
[et_block](#et_block)|904|18056697|1038|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|1037|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1036|0.0%|0.3%|
[fullbogons](#fullbogons)|3656|670639576|890|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|289|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|41|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|25|1.9%|0.0%|
[et_tor](#et_tor)|6360|6360|21|0.3%|0.0%|
[dm_tor](#dm_tor)|6483|6483|21|0.3%|0.0%|
[bm_tor](#bm_tor)|6477|6477|21|0.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|19|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|19|1.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|15|0.2%|0.0%|
[nixspam](#nixspam)|22937|22937|14|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7243|7243|10|0.1%|0.0%|
[openbl_90d](#openbl_90d)|9833|9833|6|0.0%|0.0%|
[openbl](#openbl)|9833|9833|6|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7718|7718|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|5|1.3%|0.0%|
[voipbl](#voipbl)|10305|10714|4|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4670|4670|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4386|4386|4|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[malc0de](#malc0de)|410|410|3|0.7%|0.0%|
[blocklist_de](#blocklist_de)|22246|22246|3|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|91|91|2|2.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|85|85|2|2.3%|0.0%|
[zeus_badips](#zeus_badips)|228|228|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[xroxy](#xroxy)|1931|1931|1|0.0%|0.0%|
[sslbl](#sslbl)|347|347|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|
[openbl_7d](#openbl_7d)|984|984|1|0.1%|0.0%|
[feodo](#feodo)|68|68|1|1.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2329|2329|1|0.0%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2038|2038|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14691|14691|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3470|3470|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12632|12632|1|0.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|176841|176841|8|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|6|0.0%|0.4%|
[et_block](#et_block)|904|18056697|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|3|0.2%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|2|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|2|0.0%|0.1%|
[openbl_90d](#openbl_90d)|9833|9833|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7718|7718|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|4386|4386|2|0.0%|0.1%|
[openbl](#openbl)|9833|9833|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.1%|
[et_compromised](#et_compromised)|2401|2401|2|0.0%|0.1%|
[bruteforceblocker](#bruteforceblocker)|2329|2329|2|0.0%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|2038|2038|2|0.0%|0.1%|
[blocklist_de](#blocklist_de)|22246|22246|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7243|7243|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4670|4670|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|984|984|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_tor](#et_tor)|6360|6360|1|0.0%|0.0%|
[et_botnet](#et_botnet)|505|505|1|0.1%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6483|6483|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6477|6477|1|0.0%|0.0%|

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
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|26|0.0%|6.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|12|0.0%|2.9%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|10|0.0%|2.4%|
[cleanmx_viruses](#cleanmx_viruses)|91|91|9|9.8%|2.1%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|4|0.3%|0.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|2|0.0%|0.4%|
[et_block](#et_block)|904|18056697|2|0.0%|0.4%|
[dshield](#dshield)|20|5120|2|0.0%|0.4%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|1|0.0%|0.2%|

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
[et_block](#et_block)|904|18056697|28|0.0%|2.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.1%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|26|0.3%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|26|0.0%|2.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|25|0.0%|1.9%|
[fullbogons](#fullbogons)|3656|670639576|9|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|7|0.0%|0.5%|
[malc0de](#malc0de)|410|410|4|0.9%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7243|7243|2|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|1|0.0%|0.0%|
[et_botnet](#et_botnet)|505|505|1|0.1%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|91|91|1|1.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3470|3470|1|0.0%|0.0%|
[blocklist_de](#blocklist_de)|22246|22246|1|0.0%|0.0%|

## maxmind_proxy_fraud

[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.

Source is downloaded from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list).

The last time downloaded was found to be dated: Fri May 29 12:09:26 UTC 2015.

The ipset `maxmind_proxy_fraud` has **372** entries, **372** unique IPs.

The following table shows the overlaps of `maxmind_proxy_fraud` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `maxmind_proxy_fraud`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `maxmind_proxy_fraud`.
- ` this % ` is the percentage **of this ipset (`maxmind_proxy_fraud`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|237|0.2%|63.7%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|200|0.6%|53.7%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|184|2.6%|49.4%|
[et_tor](#et_tor)|6360|6360|178|2.7%|47.8%|
[dm_tor](#dm_tor)|6483|6483|176|2.7%|47.3%|
[bm_tor](#bm_tor)|6477|6477|176|2.7%|47.3%|
[stopforumspam_1d](#stopforumspam_1d)|7243|7243|167|2.3%|44.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|125|0.0%|33.6%|
[php_commenters](#php_commenters)|281|281|28|9.9%|7.5%|
[php_bad](#php_bad)|281|281|28|9.9%|7.5%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|23|0.0%|6.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|21|0.0%|5.6%|
[openbl_90d](#openbl_90d)|9833|9833|18|0.1%|4.8%|
[openbl_60d](#openbl_60d)|7718|7718|18|0.2%|4.8%|
[openbl](#openbl)|9833|9833|18|0.1%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|17|0.0%|4.5%|
[php_harvesters](#php_harvesters)|257|257|6|2.3%|1.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|1.3%|
[ri_web_proxies](#ri_web_proxies)|4670|4670|4|0.0%|1.0%|
[php_spammers](#php_spammers)|417|417|4|0.9%|1.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|1.0%|
[blocklist_de](#blocklist_de)|22246|22246|3|0.0%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|14691|14691|2|0.0%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|12632|12632|2|0.0%|0.5%|
[xroxy](#xroxy)|1931|1931|1|0.0%|0.2%|
[voipbl](#voipbl)|10305|10714|1|0.0%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|1794|1794|1|0.0%|0.2%|
[nixspam](#nixspam)|22937|22937|1|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1325|1325|1|0.0%|0.2%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Fri May 29 16:00:01 UTC 2015.

The ipset `nixspam` has **22937** entries, **22937** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1673|0.0%|7.2%|
[blocklist_de](#blocklist_de)|22246|22246|585|2.6%|2.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|580|0.0%|2.5%|
[blocklist_de_mail](#blocklist_de_mail)|14691|14691|514|3.4%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|306|0.0%|1.3%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|289|0.0%|1.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|289|0.0%|1.2%|
[et_block](#et_block)|904|18056697|289|0.0%|1.2%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|219|0.2%|0.9%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|202|2.9%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|132|0.4%|0.5%|
[php_dictionary](#php_dictionary)|433|433|97|22.4%|0.4%|
[ri_web_proxies](#ri_web_proxies)|4670|4670|81|1.7%|0.3%|
[xroxy](#xroxy)|1931|1931|79|4.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7243|7243|72|0.9%|0.3%|
[php_spammers](#php_spammers)|417|417|70|16.7%|0.3%|
[blocklist_de_bots](#blocklist_de_bots)|3470|3470|52|1.4%|0.2%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|30|0.0%|0.1%|
[proxyrss](#proxyrss)|1570|1570|15|0.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|14|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1794|1794|13|0.7%|0.0%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.0%|
[php_bad](#php_bad)|281|281|8|2.8%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12632|12632|8|0.0%|0.0%|
[openbl_90d](#openbl_90d)|9833|9833|7|0.0%|0.0%|
[openbl](#openbl)|9833|9833|7|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|7|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1325|1325|7|0.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|409|409|6|1.4%|0.0%|
[proxz](#proxz)|157|157|5|3.1%|0.0%|
[php_harvesters](#php_harvesters)|257|257|5|1.9%|0.0%|
[openbl_60d](#openbl_60d)|7718|7718|5|0.0%|0.0%|
[dshield](#dshield)|20|5120|5|0.0%|0.0%|
[voipbl](#voipbl)|10305|10714|2|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|2|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|2|0.8%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[openbl_30d](#openbl_30d)|4386|4386|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[et_compromised](#et_compromised)|2401|2401|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6483|6483|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2329|2329|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6477|6477|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2038|2038|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|803|803|1|0.1%|0.0%|

## openbl

[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**

Source is downloaded from [this link](http://www.openbl.org/lists/base.txt).

The last time downloaded was found to be dated: Fri May 29 15:32:00 UTC 2015.

The ipset `openbl` has **9833** entries, **9833** unique IPs.

The following table shows the overlaps of `openbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl`.
- ` this % ` is the percentage **of this ipset (`openbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9833|9833|9833|100.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|9811|5.5%|99.7%|
[openbl_60d](#openbl_60d)|7718|7718|7718|100.0%|78.4%|
[openbl_30d](#openbl_30d)|4386|4386|4386|100.0%|44.6%|
[et_compromised](#et_compromised)|2401|2401|1432|59.6%|14.5%|
[bruteforceblocker](#bruteforceblocker)|2329|2329|1411|60.5%|14.3%|
[blocklist_de](#blocklist_de)|22246|22246|1201|5.3%|12.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2038|2038|1119|54.9%|11.3%|
[openbl_7d](#openbl_7d)|984|984|984|100.0%|10.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|947|0.0%|9.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|505|0.0%|5.1%|
[et_block](#et_block)|904|18056697|451|0.0%|4.5%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|448|0.0%|4.5%|
[openbl_1d](#openbl_1d)|255|255|255|100.0%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|218|0.0%|2.2%|
[dshield](#dshield)|20|5120|188|3.6%|1.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|80|34.1%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|63|0.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|14691|14691|58|0.3%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|803|803|45|5.6%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|33|0.1%|0.3%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|27|0.3%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7243|7243|22|0.3%|0.2%|
[et_tor](#et_tor)|6360|6360|21|0.3%|0.2%|
[dm_tor](#dm_tor)|6483|6483|21|0.3%|0.2%|
[bm_tor](#bm_tor)|6477|6477|21|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|20|0.0%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|14|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12632|12632|13|0.1%|0.1%|
[voipbl](#voipbl)|10305|10714|12|0.1%|0.1%|
[shunlist](#shunlist)|51|51|10|19.6%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|409|409|10|2.4%|0.1%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.0%|
[php_bad](#php_bad)|281|281|8|2.8%|0.0%|
[nixspam](#nixspam)|22937|22937|7|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|6|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|5|1.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1325|1325|5|0.3%|0.0%|
[zeus](#zeus)|266|266|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3470|3470|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|228|228|1|0.4%|0.0%|
[sslbl](#sslbl)|347|347|1|0.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4670|4670|1|0.0%|0.0%|
[ciarmy](#ciarmy)|360|360|1|0.2%|0.0%|

## openbl_1d

[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_1days.txt).

The last time downloaded was found to be dated: Fri May 29 14:07:00 UTC 2015.

The ipset `openbl_1d` has **255** entries, **255** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9833|9833|255|2.5%|100.0%|
[openbl_7d](#openbl_7d)|984|984|255|25.9%|100.0%|
[openbl_60d](#openbl_60d)|7718|7718|255|3.3%|100.0%|
[openbl_30d](#openbl_30d)|4386|4386|255|5.8%|100.0%|
[openbl](#openbl)|9833|9833|255|2.5%|100.0%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|254|0.1%|99.6%|
[blocklist_de](#blocklist_de)|22246|22246|222|0.9%|87.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2038|2038|216|10.5%|84.7%|
[bruteforceblocker](#bruteforceblocker)|2329|2329|130|5.5%|50.9%|
[et_compromised](#et_compromised)|2401|2401|120|4.9%|47.0%|
[dshield](#dshield)|20|5120|52|1.0%|20.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|40|17.0%|15.6%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|31|0.0%|12.1%|
[et_block](#et_block)|904|18056697|31|0.0%|12.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|17|0.0%|6.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|10|0.0%|3.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|1.9%|
[blocklist_de_mail](#blocklist_de_mail)|14691|14691|3|0.0%|1.1%|
[blocklist_de_imap](#blocklist_de_imap)|803|803|3|0.3%|1.1%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|2|0.0%|0.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|2|0.0%|0.7%|
[blocklist_de_ftp](#blocklist_de_ftp)|409|409|2|0.4%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|12632|12632|1|0.0%|0.3%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt).

The last time downloaded was found to be dated: Fri May 29 15:32:00 UTC 2015.

The ipset `openbl_30d` has **4386** entries, **4386** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9833|9833|4386|44.6%|100.0%|
[openbl_60d](#openbl_60d)|7718|7718|4386|56.8%|100.0%|
[openbl](#openbl)|9833|9833|4386|44.6%|100.0%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|4375|2.4%|99.7%|
[et_compromised](#et_compromised)|2401|2401|1343|55.9%|30.6%|
[bruteforceblocker](#bruteforceblocker)|2329|2329|1333|57.2%|30.3%|
[blocklist_de](#blocklist_de)|22246|22246|1065|4.7%|24.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2038|2038|1007|49.4%|22.9%|
[openbl_7d](#openbl_7d)|984|984|984|100.0%|22.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|438|0.0%|9.9%|
[openbl_1d](#openbl_1d)|255|255|255|100.0%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|221|0.0%|5.0%|
[et_block](#et_block)|904|18056697|209|0.0%|4.7%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|207|0.0%|4.7%|
[dshield](#dshield)|20|5120|167|3.2%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|100|0.0%|2.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|77|32.9%|1.7%|
[blocklist_de_mail](#blocklist_de_mail)|14691|14691|49|0.3%|1.1%|
[blocklist_de_imap](#blocklist_de_imap)|803|803|38|4.7%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|15|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|14|0.0%|0.3%|
[shunlist](#shunlist)|51|51|9|17.6%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|12632|12632|6|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|5|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|5|0.0%|0.1%|
[voipbl](#voipbl)|10305|10714|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|409|409|4|0.9%|0.0%|
[zeus](#zeus)|266|266|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|228|228|1|0.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7243|7243|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[nixspam](#nixspam)|22937|22937|1|0.0%|0.0%|
[ciarmy](#ciarmy)|360|360|1|0.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1325|1325|1|0.0%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt).

The last time downloaded was found to be dated: Fri May 29 15:32:00 UTC 2015.

The ipset `openbl_60d` has **7718** entries, **7718** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9833|9833|7718|78.4%|100.0%|
[openbl](#openbl)|9833|9833|7718|78.4%|100.0%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|7699|4.3%|99.7%|
[openbl_30d](#openbl_30d)|4386|4386|4386|100.0%|56.8%|
[et_compromised](#et_compromised)|2401|2401|1417|59.0%|18.3%|
[bruteforceblocker](#bruteforceblocker)|2329|2329|1396|59.9%|18.0%|
[blocklist_de](#blocklist_de)|22246|22246|1149|5.1%|14.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|2038|2038|1077|52.8%|13.9%|
[openbl_7d](#openbl_7d)|984|984|984|100.0%|12.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|721|0.0%|9.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|359|0.0%|4.6%|
[openbl_1d](#openbl_1d)|255|255|255|100.0%|3.3%|
[et_block](#et_block)|904|18056697|242|0.0%|3.1%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|240|0.0%|3.1%|
[dshield](#dshield)|20|5120|184|3.5%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|180|0.0%|2.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|79|33.7%|1.0%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|56|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|14691|14691|54|0.3%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|803|803|42|5.2%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|31|0.1%|0.4%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|27|0.3%|0.3%|
[et_tor](#et_tor)|6360|6360|21|0.3%|0.2%|
[dm_tor](#dm_tor)|6483|6483|21|0.3%|0.2%|
[bm_tor](#bm_tor)|6477|6477|21|0.3%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7243|7243|20|0.2%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|19|0.0%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.2%|
[shunlist](#shunlist)|51|51|10|19.6%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12632|12632|10|0.0%|0.1%|
[voipbl](#voipbl)|10305|10714|9|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|409|409|9|2.2%|0.1%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.1%|
[php_bad](#php_bad)|281|281|8|2.8%|0.1%|
[php_harvesters](#php_harvesters)|257|257|5|1.9%|0.0%|
[nixspam](#nixspam)|22937|22937|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1325|1325|3|0.2%|0.0%|
[zeus](#zeus)|266|266|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|228|228|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|360|360|1|0.2%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt).

The last time downloaded was found to be dated: Fri May 29 15:32:00 UTC 2015.

The ipset `openbl_7d` has **984** entries, **984** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9833|9833|984|10.0%|100.0%|
[openbl_60d](#openbl_60d)|7718|7718|984|12.7%|100.0%|
[openbl_30d](#openbl_30d)|4386|4386|984|22.4%|100.0%|
[openbl](#openbl)|9833|9833|984|10.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|978|0.5%|99.3%|
[blocklist_de](#blocklist_de)|22246|22246|651|2.9%|66.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|2038|2038|619|30.3%|62.9%|
[bruteforceblocker](#bruteforceblocker)|2329|2329|513|22.0%|52.1%|
[et_compromised](#et_compromised)|2401|2401|500|20.8%|50.8%|
[openbl_1d](#openbl_1d)|255|255|255|100.0%|25.9%|
[dshield](#dshield)|20|5120|127|2.4%|12.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|97|0.0%|9.8%|
[et_block](#et_block)|904|18056697|85|0.0%|8.6%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|84|0.0%|8.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|76|32.4%|7.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|51|0.0%|5.1%|
[blocklist_de_mail](#blocklist_de_mail)|14691|14691|27|0.1%|2.7%|
[blocklist_de_imap](#blocklist_de_imap)|803|803|24|2.9%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|17|0.0%|1.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|1.1%|
[shunlist](#shunlist)|51|51|5|9.8%|0.5%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|4|0.0%|0.4%|
[blocklist_de_ftp](#blocklist_de_ftp)|409|409|3|0.7%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|12632|12632|3|0.0%|0.3%|
[voipbl](#voipbl)|10305|10714|2|0.0%|0.2%|
[zeus](#zeus)|266|266|1|0.3%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.1%|
[ciarmy](#ciarmy)|360|360|1|0.2%|0.1%|

## openbl_90d

[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_90days.txt).

The last time downloaded was found to be dated: Fri May 29 15:32:00 UTC 2015.

The ipset `openbl_90d` has **9833** entries, **9833** unique IPs.

The following table shows the overlaps of `openbl_90d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_90d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_90d`.
- ` this % ` is the percentage **of this ipset (`openbl_90d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl](#openbl)|9833|9833|9833|100.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|9811|5.5%|99.7%|
[openbl_60d](#openbl_60d)|7718|7718|7718|100.0%|78.4%|
[openbl_30d](#openbl_30d)|4386|4386|4386|100.0%|44.6%|
[et_compromised](#et_compromised)|2401|2401|1432|59.6%|14.5%|
[bruteforceblocker](#bruteforceblocker)|2329|2329|1411|60.5%|14.3%|
[blocklist_de](#blocklist_de)|22246|22246|1201|5.3%|12.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2038|2038|1119|54.9%|11.3%|
[openbl_7d](#openbl_7d)|984|984|984|100.0%|10.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|947|0.0%|9.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|505|0.0%|5.1%|
[et_block](#et_block)|904|18056697|451|0.0%|4.5%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|448|0.0%|4.5%|
[openbl_1d](#openbl_1d)|255|255|255|100.0%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|218|0.0%|2.2%|
[dshield](#dshield)|20|5120|188|3.6%|1.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|80|34.1%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|63|0.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|14691|14691|58|0.3%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|803|803|45|5.6%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|33|0.1%|0.3%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|27|0.3%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7243|7243|22|0.3%|0.2%|
[et_tor](#et_tor)|6360|6360|21|0.3%|0.2%|
[dm_tor](#dm_tor)|6483|6483|21|0.3%|0.2%|
[bm_tor](#bm_tor)|6477|6477|21|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|20|0.0%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|14|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12632|12632|13|0.1%|0.1%|
[voipbl](#voipbl)|10305|10714|12|0.1%|0.1%|
[shunlist](#shunlist)|51|51|10|19.6%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|409|409|10|2.4%|0.1%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.0%|
[php_bad](#php_bad)|281|281|8|2.8%|0.0%|
[nixspam](#nixspam)|22937|22937|7|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|6|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|5|1.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1325|1325|5|0.3%|0.0%|
[zeus](#zeus)|266|266|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3470|3470|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|228|228|1|0.4%|0.0%|
[sslbl](#sslbl)|347|347|1|0.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4670|4670|1|0.0%|0.0%|
[ciarmy](#ciarmy)|360|360|1|0.2%|0.0%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Fri May 29 15:54:17 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
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
[stopforumspam_1d](#stopforumspam_1d)|7243|7243|112|1.5%|39.8%|
[blocklist_de](#blocklist_de)|22246|22246|74|0.3%|26.3%|
[blocklist_de_bots](#blocklist_de_bots)|3470|3470|60|1.7%|21.3%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|41|0.6%|14.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|34|14.5%|12.0%|
[php_spammers](#php_spammers)|417|417|32|7.6%|11.3%|
[et_tor](#et_tor)|6360|6360|29|0.4%|10.3%|
[dm_tor](#dm_tor)|6483|6483|29|0.4%|10.3%|
[bm_tor](#bm_tor)|6477|6477|29|0.4%|10.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|28|7.5%|9.9%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|24|0.0%|8.5%|
[et_block](#et_block)|904|18056697|24|0.0%|8.5%|
[php_dictionary](#php_dictionary)|433|433|22|5.0%|7.8%|
[blocklist_de_mail](#blocklist_de_mail)|14691|14691|22|0.1%|7.8%|
[blocklist_de_apache](#blocklist_de_apache)|12632|12632|22|0.1%|7.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|16|0.0%|5.6%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|12|0.0%|4.2%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.2%|
[ri_web_proxies](#ri_web_proxies)|4670|4670|8|0.1%|2.8%|
[openbl_90d](#openbl_90d)|9833|9833|8|0.0%|2.8%|
[openbl_60d](#openbl_60d)|7718|7718|8|0.1%|2.8%|
[openbl](#openbl)|9833|9833|8|0.0%|2.8%|
[nixspam](#nixspam)|22937|22937|8|0.0%|2.8%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|7|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|1.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1325|1325|5|0.3%|1.7%|
[xroxy](#xroxy)|1931|1931|3|0.1%|1.0%|
[zeus_badips](#zeus_badips)|228|228|1|0.4%|0.3%|
[zeus](#zeus)|266|266|1|0.3%|0.3%|
[proxz](#proxz)|157|157|1|0.6%|0.3%|
[proxyrss](#proxyrss)|1570|1570|1|0.0%|0.3%|
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
[stopforumspam_1d](#stopforumspam_1d)|7243|7243|112|1.5%|39.8%|
[blocklist_de](#blocklist_de)|22246|22246|75|0.3%|26.6%|
[blocklist_de_bots](#blocklist_de_bots)|3470|3470|60|1.7%|21.3%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|42|0.6%|14.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|34|14.5%|12.0%|
[php_spammers](#php_spammers)|417|417|32|7.6%|11.3%|
[et_tor](#et_tor)|6360|6360|29|0.4%|10.3%|
[dm_tor](#dm_tor)|6483|6483|29|0.4%|10.3%|
[bm_tor](#bm_tor)|6477|6477|29|0.4%|10.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|28|7.5%|9.9%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|24|0.0%|8.5%|
[et_block](#et_block)|904|18056697|24|0.0%|8.5%|
[blocklist_de_mail](#blocklist_de_mail)|14691|14691|23|0.1%|8.1%|
[php_dictionary](#php_dictionary)|433|433|22|5.0%|7.8%|
[blocklist_de_apache](#blocklist_de_apache)|12632|12632|22|0.1%|7.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|5.3%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|12|0.0%|4.2%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.2%|
[ri_web_proxies](#ri_web_proxies)|4670|4670|8|0.1%|2.8%|
[openbl_90d](#openbl_90d)|9833|9833|8|0.0%|2.8%|
[openbl_60d](#openbl_60d)|7718|7718|8|0.1%|2.8%|
[openbl](#openbl)|9833|9833|8|0.0%|2.8%|
[nixspam](#nixspam)|22937|22937|8|0.0%|2.8%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|7|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|1.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1325|1325|5|0.3%|1.7%|
[xroxy](#xroxy)|1931|1931|3|0.1%|1.0%|
[zeus_badips](#zeus_badips)|228|228|1|0.4%|0.3%|
[zeus](#zeus)|266|266|1|0.3%|0.3%|
[proxz](#proxz)|157|157|1|0.6%|0.3%|
[proxyrss](#proxyrss)|1570|1570|1|0.0%|0.3%|
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
[nixspam](#nixspam)|22937|22937|97|0.4%|22.4%|
[php_spammers](#php_spammers)|417|417|84|20.1%|19.3%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|77|0.0%|17.7%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|75|1.0%|17.3%|
[blocklist_de](#blocklist_de)|22246|22246|65|0.2%|15.0%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|59|0.1%|13.6%|
[blocklist_de_mail](#blocklist_de_mail)|14691|14691|50|0.3%|11.5%|
[stopforumspam_1d](#stopforumspam_1d)|7243|7243|25|0.3%|5.7%|
[ri_web_proxies](#ri_web_proxies)|4670|4670|25|0.5%|5.7%|
[xroxy](#xroxy)|1931|1931|24|1.2%|5.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|24|0.0%|5.5%|
[php_commenters](#php_commenters)|281|281|22|7.8%|5.0%|
[php_bad](#php_bad)|281|281|22|7.8%|5.0%|
[blocklist_de_bots](#blocklist_de_bots)|3470|3470|15|0.4%|3.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|10|0.0%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|9|0.0%|2.0%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|7|0.0%|1.6%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|4|0.0%|0.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.9%|
[et_tor](#et_tor)|6360|6360|4|0.0%|0.9%|
[et_block](#et_block)|904|18056697|4|0.0%|0.9%|
[dm_tor](#dm_tor)|6483|6483|4|0.0%|0.9%|
[bm_tor](#bm_tor)|6477|6477|4|0.0%|0.9%|
[ri_connect_proxies](#ri_connect_proxies)|1794|1794|3|0.1%|0.6%|
[proxz](#proxz)|157|157|2|1.2%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.4%|
[proxyrss](#proxyrss)|1570|1570|1|0.0%|0.2%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.2%|
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
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|62|0.0%|24.1%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|50|0.1%|19.4%|
[blocklist_de](#blocklist_de)|22246|22246|35|0.1%|13.6%|
[stopforumspam_1d](#stopforumspam_1d)|7243|7243|32|0.4%|12.4%|
[blocklist_de_bots](#blocklist_de_bots)|3470|3470|28|0.8%|10.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|5.8%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|9|0.1%|3.5%|
[php_commenters](#php_commenters)|281|281|9|3.2%|3.5%|
[php_bad](#php_bad)|281|281|9|3.2%|3.5%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|9|0.0%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|7|0.0%|2.7%|
[et_tor](#et_tor)|6360|6360|7|0.1%|2.7%|
[dm_tor](#dm_tor)|6483|6483|7|0.1%|2.7%|
[bm_tor](#bm_tor)|6477|6477|7|0.1%|2.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|6|1.6%|2.3%|
[openbl_90d](#openbl_90d)|9833|9833|5|0.0%|1.9%|
[openbl_60d](#openbl_60d)|7718|7718|5|0.0%|1.9%|
[openbl](#openbl)|9833|9833|5|0.0%|1.9%|
[nixspam](#nixspam)|22937|22937|5|0.0%|1.9%|
[blocklist_de_mail](#blocklist_de_mail)|14691|14691|4|0.0%|1.5%|
[blocklist_de_ftp](#blocklist_de_ftp)|409|409|3|0.7%|1.1%|
[xroxy](#xroxy)|1931|1931|2|0.1%|0.7%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.7%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|1|0.0%|0.3%|
[ri_web_proxies](#ri_web_proxies)|4670|4670|1|0.0%|0.3%|
[proxyrss](#proxyrss)|1570|1570|1|0.0%|0.3%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.3%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|
[fullbogons](#fullbogons)|3656|670639576|1|0.0%|0.3%|
[et_block](#et_block)|904|18056697|1|0.0%|0.3%|
[bogons](#bogons)|13|592708608|1|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|1|0.4%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|12632|12632|1|0.0%|0.3%|

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
[nixspam](#nixspam)|22937|22937|70|0.3%|16.7%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|65|0.2%|15.5%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|63|0.9%|15.1%|
[blocklist_de](#blocklist_de)|22246|22246|63|0.2%|15.1%|
[blocklist_de_mail](#blocklist_de_mail)|14691|14691|37|0.2%|8.8%|
[php_commenters](#php_commenters)|281|281|32|11.3%|7.6%|
[php_bad](#php_bad)|281|281|32|11.3%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|31|0.0%|7.4%|
[stopforumspam_1d](#stopforumspam_1d)|7243|7243|30|0.4%|7.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|26|0.0%|6.2%|
[ri_web_proxies](#ri_web_proxies)|4670|4670|20|0.4%|4.7%|
[blocklist_de_bots](#blocklist_de_bots)|3470|3470|19|0.5%|4.5%|
[xroxy](#xroxy)|1931|1931|18|0.9%|4.3%|
[et_tor](#et_tor)|6360|6360|6|0.0%|1.4%|
[dm_tor](#dm_tor)|6483|6483|6|0.0%|1.4%|
[bm_tor](#bm_tor)|6477|6477|6|0.0%|1.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|6|2.5%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|1.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1325|1325|5|0.3%|1.1%|
[blocklist_de_apache](#blocklist_de_apache)|12632|12632|5|0.0%|1.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.9%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|3|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|2|0.0%|0.4%|
[ri_connect_proxies](#ri_connect_proxies)|1794|1794|2|0.1%|0.4%|
[proxz](#proxz)|157|157|2|1.2%|0.4%|
[proxyrss](#proxyrss)|1570|1570|2|0.1%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[et_block](#et_block)|904|18056697|2|0.0%|0.4%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|2038|2038|1|0.0%|0.2%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Fri May 29 13:31:26 UTC 2015.

The ipset `proxyrss` has **1570** entries, **1570** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|807|0.8%|51.4%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|685|2.2%|43.6%|
[ri_web_proxies](#ri_web_proxies)|4670|4670|653|13.9%|41.5%|
[xroxy](#xroxy)|1931|1931|624|32.3%|39.7%|
[stopforumspam_1d](#stopforumspam_1d)|7243|7243|401|5.5%|25.5%|
[ri_connect_proxies](#ri_connect_proxies)|1794|1794|234|13.0%|14.9%|
[blocklist_de](#blocklist_de)|22246|22246|208|0.9%|13.2%|
[blocklist_de_bots](#blocklist_de_bots)|3470|3470|206|5.9%|13.1%|
[proxz](#proxz)|157|157|88|56.0%|5.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|72|0.0%|4.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|58|0.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|38|0.0%|2.4%|
[nixspam](#nixspam)|22937|22937|15|0.0%|0.9%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.3%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|5|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|3|1.2%|0.1%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.1%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|2|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.0%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.0%|
[php_bad](#php_bad)|281|281|1|0.3%|0.0%|
[et_compromised](#et_compromised)|2401|2401|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2329|2329|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14691|14691|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1325|1325|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12632|12632|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Fri May 29 13:31:31 UTC 2015.

The ipset `proxz` has **157** entries, **157** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[xroxy](#xroxy)|1931|1931|110|5.6%|70.0%|
[proxyrss](#proxyrss)|1570|1570|88|5.6%|56.0%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|85|0.0%|54.1%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|79|0.2%|50.3%|
[ri_web_proxies](#ri_web_proxies)|4670|4670|60|1.2%|38.2%|
[stopforumspam_1d](#stopforumspam_1d)|7243|7243|46|0.6%|29.2%|
[blocklist_de](#blocklist_de)|22246|22246|29|0.1%|18.4%|
[blocklist_de_bots](#blocklist_de_bots)|3470|3470|28|0.8%|17.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|23|0.0%|14.6%|
[ri_connect_proxies](#ri_connect_proxies)|1794|1794|17|0.9%|10.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7|0.0%|4.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|7|0.0%|4.4%|
[nixspam](#nixspam)|22937|22937|5|0.0%|3.1%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|3|0.0%|1.9%|
[php_spammers](#php_spammers)|417|417|2|0.4%|1.2%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|1.2%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.6%|
[php_bad](#php_bad)|281|281|1|0.3%|0.6%|
[et_tor](#et_tor)|6360|6360|1|0.0%|0.6%|
[et_compromised](#et_compromised)|2401|2401|1|0.0%|0.6%|
[dm_tor](#dm_tor)|6483|6483|1|0.0%|0.6%|
[bruteforceblocker](#bruteforceblocker)|2329|2329|1|0.0%|0.6%|
[bm_tor](#bm_tor)|6477|6477|1|0.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|14691|14691|1|0.0%|0.6%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|1|0.0%|0.6%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Fri May 29 14:28:44 UTC 2015.

The ipset `ri_connect_proxies` has **1794** entries, **1794** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|1061|1.1%|59.1%|
[ri_web_proxies](#ri_web_proxies)|4670|4670|721|15.4%|40.1%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|718|2.3%|40.0%|
[xroxy](#xroxy)|1931|1931|286|14.8%|15.9%|
[proxyrss](#proxyrss)|1570|1570|234|14.9%|13.0%|
[stopforumspam_1d](#stopforumspam_1d)|7243|7243|151|2.0%|8.4%|
[blocklist_de](#blocklist_de)|22246|22246|90|0.4%|5.0%|
[blocklist_de_bots](#blocklist_de_bots)|3470|3470|88|2.5%|4.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|76|0.0%|4.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|63|0.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|42|0.0%|2.3%|
[proxz](#proxz)|157|157|17|10.8%|0.9%|
[nixspam](#nixspam)|22937|22937|13|0.0%|0.7%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|7|0.1%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.3%|
[php_dictionary](#php_dictionary)|433|433|3|0.6%|0.1%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.1%|
[et_tor](#et_tor)|6360|6360|2|0.0%|0.1%|
[dm_tor](#dm_tor)|6483|6483|2|0.0%|0.1%|
[bm_tor](#bm_tor)|6477|6477|2|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|2|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14691|14691|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1325|1325|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12632|12632|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Fri May 29 14:28:32 UTC 2015.

The ipset `ri_web_proxies` has **4670** entries, **4670** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|2327|2.5%|49.8%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|1695|5.4%|36.2%|
[xroxy](#xroxy)|1931|1931|740|38.3%|15.8%|
[ri_connect_proxies](#ri_connect_proxies)|1794|1794|721|40.1%|15.4%|
[proxyrss](#proxyrss)|1570|1570|653|41.5%|13.9%|
[stopforumspam_1d](#stopforumspam_1d)|7243|7243|529|7.3%|11.3%|
[blocklist_de](#blocklist_de)|22246|22246|376|1.6%|8.0%|
[blocklist_de_bots](#blocklist_de_bots)|3470|3470|349|10.0%|7.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|164|0.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|144|0.0%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|107|0.0%|2.2%|
[nixspam](#nixspam)|22937|22937|81|0.3%|1.7%|
[proxz](#proxz)|157|157|60|38.2%|1.2%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|50|0.7%|1.0%|
[blocklist_de_mail](#blocklist_de_mail)|14691|14691|27|0.1%|0.5%|
[php_dictionary](#php_dictionary)|433|433|25|5.7%|0.5%|
[php_spammers](#php_spammers)|417|417|20|4.7%|0.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|10|1.4%|0.2%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.1%|
[php_bad](#php_bad)|281|281|8|2.8%|0.1%|
[et_tor](#et_tor)|6360|6360|5|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6483|6483|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6477|6477|4|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|3|1.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[openbl_90d](#openbl_90d)|9833|9833|1|0.0%|0.0%|
[openbl](#openbl)|9833|9833|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1325|1325|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12632|12632|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Fri May 29 14:30:08 UTC 2015.

The ipset `shunlist` has **51** entries, **51** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|176841|176841|51|0.0%|100.0%|
[openbl_90d](#openbl_90d)|9833|9833|10|0.1%|19.6%|
[openbl_60d](#openbl_60d)|7718|7718|10|0.1%|19.6%|
[openbl](#openbl)|9833|9833|10|0.1%|19.6%|
[blocklist_de](#blocklist_de)|22246|22246|10|0.0%|19.6%|
[openbl_30d](#openbl_30d)|4386|4386|9|0.2%|17.6%|
[et_compromised](#et_compromised)|2401|2401|8|0.3%|15.6%|
[bruteforceblocker](#bruteforceblocker)|2329|2329|8|0.3%|15.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|2038|2038|7|0.3%|13.7%|
[openbl_7d](#openbl_7d)|984|984|5|0.5%|9.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|5|0.0%|9.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|3|0.0%|5.8%|
[blocklist_de_apache](#blocklist_de_apache)|12632|12632|3|0.0%|5.8%|
[voipbl](#voipbl)|10305|10714|2|0.0%|3.9%|
[ciarmy](#ciarmy)|360|360|2|0.5%|3.9%|

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
[et_tor](#et_tor)|6360|6360|1068|16.7%|15.6%|
[dm_tor](#dm_tor)|6483|6483|1035|15.9%|15.1%|
[bm_tor](#bm_tor)|6477|6477|1034|15.9%|15.1%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|766|0.8%|11.2%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|575|1.8%|8.4%|
[stopforumspam_1d](#stopforumspam_1d)|7243|7243|378|5.2%|5.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|231|0.0%|3.3%|
[et_block](#et_block)|904|18056697|229|0.0%|3.3%|
[zeus](#zeus)|266|266|226|84.9%|3.3%|
[blocklist_de](#blocklist_de)|22246|22246|214|0.9%|3.1%|
[nixspam](#nixspam)|22937|22937|202|0.8%|2.9%|
[zeus_badips](#zeus_badips)|228|228|199|87.2%|2.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|184|49.4%|2.6%|
[blocklist_de_mail](#blocklist_de_mail)|14691|14691|139|0.9%|2.0%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|120|0.0%|1.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|103|0.0%|1.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|78|0.0%|1.1%|
[php_dictionary](#php_dictionary)|433|433|75|17.3%|1.0%|
[php_spammers](#php_spammers)|417|417|63|15.1%|0.9%|
[xroxy](#xroxy)|1931|1931|54|2.7%|0.7%|
[feodo](#feodo)|68|68|53|77.9%|0.7%|
[ri_web_proxies](#ri_web_proxies)|4670|4670|50|1.0%|0.7%|
[php_commenters](#php_commenters)|281|281|42|14.9%|0.6%|
[php_bad](#php_bad)|281|281|41|14.5%|0.6%|
[blocklist_de_apache](#blocklist_de_apache)|12632|12632|38|0.3%|0.5%|
[blocklist_de_bots](#blocklist_de_bots)|3470|3470|36|1.0%|0.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1325|1325|35|2.6%|0.5%|
[openbl_90d](#openbl_90d)|9833|9833|27|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7718|7718|27|0.3%|0.3%|
[openbl](#openbl)|9833|9833|27|0.2%|0.3%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|26|2.0%|0.3%|
[sslbl](#sslbl)|347|347|21|6.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|18|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|15|0.0%|0.2%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|0.1%|
[ri_connect_proxies](#ri_connect_proxies)|1794|1794|7|0.3%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|803|803|7|0.8%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|6|0.0%|0.0%|
[proxyrss](#proxyrss)|1570|1570|5|0.3%|0.0%|
[openbl_30d](#openbl_30d)|4386|4386|5|0.1%|0.0%|
[openbl_7d](#openbl_7d)|984|984|4|0.4%|0.0%|
[proxz](#proxz)|157|157|3|1.9%|0.0%|
[openbl_1d](#openbl_1d)|255|255|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2038|2038|2|0.0%|0.0%|
[malc0de](#malc0de)|410|410|1|0.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2401|2401|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2329|2329|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|1|0.4%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|409|409|1|0.2%|0.0%|

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
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|2133002|0.2%|11.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|195904|0.1%|1.0%|
[fullbogons](#fullbogons)|3656|670639576|20480|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|1625|0.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|741|0.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|512|0.1%|0.0%|
[dshield](#dshield)|20|5120|512|10.0%|0.0%|
[openbl_90d](#openbl_90d)|9833|9833|448|4.5%|0.0%|
[openbl](#openbl)|9833|9833|448|4.5%|0.0%|
[nixspam](#nixspam)|22937|22937|289|1.2%|0.0%|
[openbl_60d](#openbl_60d)|7718|7718|240|3.1%|0.0%|
[openbl_30d](#openbl_30d)|4386|4386|207|4.7%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|204|0.6%|0.0%|
[blocklist_de](#blocklist_de)|22246|22246|187|0.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2038|2038|113|5.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2329|2329|102|4.3%|0.0%|
[et_compromised](#et_compromised)|2401|2401|97|4.0%|0.0%|
[openbl_7d](#openbl_7d)|984|984|84|8.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3470|3470|54|1.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7243|7243|53|0.7%|0.0%|
[openbl_1d](#openbl_1d)|255|255|31|12.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|29|2.2%|0.0%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.0%|
[php_bad](#php_bad)|281|281|24|8.5%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|18|0.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14691|14691|18|0.1%|0.0%|
[zeus_badips](#zeus_badips)|228|228|16|7.0%|0.0%|
[zeus](#zeus)|266|266|16|6.0%|0.0%|
[voipbl](#voipbl)|10305|10714|14|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|803|803|14|1.7%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|7|2.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[sslbl](#sslbl)|347|347|3|0.8%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1325|1325|3|0.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12632|12632|3|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[malc0de](#malc0de)|410|410|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6360|6360|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6483|6483|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6477|6477|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
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
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|270785|0.1%|64.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|33368|0.0%|7.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|33155|0.0%|7.8%|
[et_block](#et_block)|904|18056697|517|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|512|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|106|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|42|0.1%|0.0%|
[blocklist_de](#blocklist_de)|22246|22246|28|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3470|3470|24|0.6%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7243|7243|16|0.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|15|0.0%|0.0%|
[openbl_90d](#openbl_90d)|9833|9833|14|0.1%|0.0%|
[openbl](#openbl)|9833|9833|14|0.1%|0.0%|
[php_commenters](#php_commenters)|281|281|7|2.4%|0.0%|
[php_bad](#php_bad)|281|281|7|2.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|6|2.5%|0.0%|
[zeus_badips](#zeus_badips)|228|228|5|2.1%|0.0%|
[zeus](#zeus)|266|266|5|1.8%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14691|14691|3|0.0%|0.0%|
[nixspam](#nixspam)|22937|22937|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[openbl_60d](#openbl_60d)|7718|7718|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|4386|4386|1|0.0%|0.0%|
[malc0de](#malc0de)|410|410|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|803|803|1|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12632|12632|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Fri May 29 15:45:06 UTC 2015.

The ipset `sslbl` has **347** entries, **347** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[feodo](#feodo)|68|68|25|36.7%|7.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|23|0.0%|6.6%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|21|0.3%|6.0%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|7|0.0%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|6|0.0%|1.7%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|3|0.0%|0.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|0.8%|
[et_block](#et_block)|904|18056697|3|0.0%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|1|0.0%|0.2%|
[openbl_90d](#openbl_90d)|9833|9833|1|0.0%|0.2%|
[openbl](#openbl)|9833|9833|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Fri May 29 16:00:01 UTC 2015.

The ipset `stopforumspam_1d` has **7243** entries, **7243** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|5351|5.7%|73.8%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|5214|16.8%|71.9%|
[blocklist_de](#blocklist_de)|22246|22246|1574|7.0%|21.7%|
[blocklist_de_bots](#blocklist_de_bots)|3470|3470|1494|43.0%|20.6%|
[ri_web_proxies](#ri_web_proxies)|4670|4670|529|11.3%|7.3%|
[xroxy](#xroxy)|1931|1931|465|24.0%|6.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|446|0.0%|6.1%|
[proxyrss](#proxyrss)|1570|1570|401|25.5%|5.5%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|378|5.5%|5.2%|
[et_tor](#et_tor)|6360|6360|332|5.2%|4.5%|
[dm_tor](#dm_tor)|6483|6483|329|5.0%|4.5%|
[bm_tor](#bm_tor)|6477|6477|328|5.0%|4.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|242|0.0%|3.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|167|44.8%|2.3%|
[ri_connect_proxies](#ri_connect_proxies)|1794|1794|151|8.4%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|151|0.0%|2.0%|
[php_commenters](#php_commenters)|281|281|112|39.8%|1.5%|
[php_bad](#php_bad)|281|281|112|39.8%|1.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|104|44.4%|1.4%|
[blocklist_de_apache](#blocklist_de_apache)|12632|12632|79|0.6%|1.0%|
[nixspam](#nixspam)|22937|22937|72|0.3%|0.9%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|60|0.0%|0.8%|
[et_block](#et_block)|904|18056697|54|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|53|0.0%|0.7%|
[proxz](#proxz)|157|157|46|29.2%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|14691|14691|44|0.2%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|42|0.0%|0.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1325|1325|39|2.9%|0.5%|
[php_harvesters](#php_harvesters)|257|257|32|12.4%|0.4%|
[php_spammers](#php_spammers)|417|417|30|7.1%|0.4%|
[php_dictionary](#php_dictionary)|433|433|25|5.7%|0.3%|
[openbl_90d](#openbl_90d)|9833|9833|22|0.2%|0.3%|
[openbl](#openbl)|9833|9833|22|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7718|7718|20|0.2%|0.2%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|16|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|10|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.0%|
[voipbl](#voipbl)|10305|10714|3|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|2|0.1%|0.0%|
[et_compromised](#et_compromised)|2401|2401|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2329|2329|2|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|409|409|2|0.4%|0.0%|
[openbl_30d](#openbl_30d)|4386|4386|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2038|2038|1|0.0%|0.0%|

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
[stopforumspam_1d](#stopforumspam_1d)|7243|7243|5351|73.8%|5.7%|
[blocklist_de](#blocklist_de)|22246|22246|2722|12.2%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2445|0.0%|2.6%|
[blocklist_de_bots](#blocklist_de_bots)|3470|3470|2409|69.4%|2.6%|
[ri_web_proxies](#ri_web_proxies)|4670|4670|2327|49.8%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1511|0.0%|1.6%|
[xroxy](#xroxy)|1931|1931|1073|55.5%|1.1%|
[ri_connect_proxies](#ri_connect_proxies)|1794|1794|1061|59.1%|1.1%|
[proxyrss](#proxyrss)|1570|1570|807|51.4%|0.8%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|766|11.2%|0.8%|
[et_block](#et_block)|904|18056697|744|0.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|742|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|741|0.0%|0.8%|
[et_tor](#et_tor)|6360|6360|601|9.4%|0.6%|
[dm_tor](#dm_tor)|6483|6483|590|9.1%|0.6%|
[bm_tor](#bm_tor)|6477|6477|587|9.0%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|237|63.7%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|12632|12632|227|1.7%|0.2%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|221|0.1%|0.2%|
[nixspam](#nixspam)|22937|22937|219|0.9%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|14691|14691|205|1.3%|0.2%|
[php_commenters](#php_commenters)|281|281|203|72.2%|0.2%|
[php_bad](#php_bad)|281|281|202|71.8%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|132|56.4%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|106|0.0%|0.1%|
[php_spammers](#php_spammers)|417|417|97|23.2%|0.1%|
[proxz](#proxz)|157|157|85|54.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1325|1325|84|6.3%|0.0%|
[php_dictionary](#php_dictionary)|433|433|77|17.7%|0.0%|
[openbl_90d](#openbl_90d)|9833|9833|63|0.6%|0.0%|
[openbl](#openbl)|9833|9833|63|0.6%|0.0%|
[php_harvesters](#php_harvesters)|257|257|62|24.1%|0.0%|
[openbl_60d](#openbl_60d)|7718|7718|56|0.7%|0.0%|
[voipbl](#voipbl)|10305|10714|41|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|41|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|22|3.2%|0.0%|
[openbl_30d](#openbl_30d)|4386|4386|15|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|15|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|409|409|8|1.9%|0.0%|
[et_compromised](#et_compromised)|2401|2401|6|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2329|2329|6|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2038|2038|6|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|803|803|4|0.4%|0.0%|
[zeus_badips](#zeus_badips)|228|228|3|1.3%|0.0%|
[zeus](#zeus)|266|266|3|1.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|2|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3656|670639576|2|0.0%|0.0%|
[sslbl](#sslbl)|347|347|1|0.2%|0.0%|
[openbl_7d](#openbl_7d)|984|984|1|0.1%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|360|360|1|0.2%|0.0%|
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
[stopforumspam_1d](#stopforumspam_1d)|7243|7243|5214|71.9%|16.8%|
[blocklist_de](#blocklist_de)|22246|22246|2356|10.5%|7.6%|
[blocklist_de_bots](#blocklist_de_bots)|3470|3470|2175|62.6%|7.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2103|0.0%|6.7%|
[ri_web_proxies](#ri_web_proxies)|4670|4670|1695|36.2%|5.4%|
[xroxy](#xroxy)|1931|1931|923|47.7%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|904|0.0%|2.9%|
[ri_connect_proxies](#ri_connect_proxies)|1794|1794|718|40.0%|2.3%|
[proxyrss](#proxyrss)|1570|1570|685|43.6%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|576|0.0%|1.8%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|575|8.4%|1.8%|
[et_tor](#et_tor)|6360|6360|465|7.3%|1.5%|
[dm_tor](#dm_tor)|6483|6483|456|7.0%|1.4%|
[bm_tor](#bm_tor)|6477|6477|454|7.0%|1.4%|
[et_block](#et_block)|904|18056697|205|0.0%|0.6%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|204|0.0%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|200|53.7%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|194|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|189|67.2%|0.6%|
[php_bad](#php_bad)|281|281|188|66.9%|0.6%|
[blocklist_de_apache](#blocklist_de_apache)|12632|12632|136|1.0%|0.4%|
[nixspam](#nixspam)|22937|22937|132|0.5%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|121|51.7%|0.3%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|115|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|14691|14691|96|0.6%|0.3%|
[proxz](#proxz)|157|157|79|50.3%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1325|1325|73|5.5%|0.2%|
[php_spammers](#php_spammers)|417|417|65|15.5%|0.2%|
[php_dictionary](#php_dictionary)|433|433|59|13.6%|0.1%|
[php_harvesters](#php_harvesters)|257|257|50|19.4%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|42|0.0%|0.1%|
[openbl_90d](#openbl_90d)|9833|9833|33|0.3%|0.1%|
[openbl](#openbl)|9833|9833|33|0.3%|0.1%|
[openbl_60d](#openbl_60d)|7718|7718|31|0.4%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|19|0.0%|0.0%|
[voipbl](#voipbl)|10305|10714|10|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|10|1.4%|0.0%|
[openbl_30d](#openbl_30d)|4386|4386|5|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|5|0.0%|0.0%|
[et_compromised](#et_compromised)|2401|2401|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2329|2329|3|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|409|409|3|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2038|2038|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|228|228|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|803|803|1|0.1%|0.0%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Fri May 29 14:36:24 UTC 2015.

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
[alienvault_reputation](#alienvault_reputation)|176841|176841|205|0.1%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|41|0.0%|0.3%|
[blocklist_de](#blocklist_de)|22246|22246|37|0.1%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|85|85|28|32.9%|0.2%|
[et_block](#et_block)|904|18056697|19|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|14|0.0%|0.1%|
[openbl_90d](#openbl_90d)|9833|9833|12|0.1%|0.1%|
[openbl](#openbl)|9833|9833|12|0.1%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|10|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7718|7718|9|0.1%|0.0%|
[openbl_30d](#openbl_30d)|4386|4386|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[ciarmy](#ciarmy)|360|360|4|1.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2038|2038|4|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7243|7243|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14691|14691|3|0.0%|0.0%|
[shunlist](#shunlist)|51|51|2|3.9%|0.0%|
[openbl_7d](#openbl_7d)|984|984|2|0.2%|0.0%|
[nixspam](#nixspam)|22937|22937|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[et_tor](#et_tor)|6360|6360|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2401|2401|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6483|6483|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2329|2329|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6477|6477|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|803|803|1|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3470|3470|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12632|12632|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Fri May 29 15:33:02 UTC 2015.

The ipset `xroxy` has **1931** entries, **1931** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|1073|1.1%|55.5%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|923|2.9%|47.7%|
[ri_web_proxies](#ri_web_proxies)|4670|4670|740|15.8%|38.3%|
[proxyrss](#proxyrss)|1570|1570|624|39.7%|32.3%|
[stopforumspam_1d](#stopforumspam_1d)|7243|7243|465|6.4%|24.0%|
[blocklist_de](#blocklist_de)|22246|22246|297|1.3%|15.3%|
[ri_connect_proxies](#ri_connect_proxies)|1794|1794|286|15.9%|14.8%|
[blocklist_de_bots](#blocklist_de_bots)|3470|3470|252|7.2%|13.0%|
[proxz](#proxz)|157|157|110|70.0%|5.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|89|0.0%|4.6%|
[nixspam](#nixspam)|22937|22937|79|0.3%|4.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|76|0.0%|3.9%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|54|0.7%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|52|0.0%|2.6%|
[blocklist_de_mail](#blocklist_de_mail)|14691|14691|42|0.2%|2.1%|
[php_dictionary](#php_dictionary)|433|433|24|5.5%|1.2%|
[php_spammers](#php_spammers)|417|417|18|4.3%|0.9%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|12|1.7%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|234|234|6|2.5%|0.3%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|4|0.0%|0.2%|
[php_commenters](#php_commenters)|281|281|3|1.0%|0.1%|
[php_bad](#php_bad)|281|281|3|1.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.1%|
[et_tor](#et_tor)|6360|6360|2|0.0%|0.1%|
[dm_tor](#dm_tor)|6483|6483|2|0.0%|0.1%|
[bm_tor](#bm_tor)|6477|6477|2|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2401|2401|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2329|2329|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|2038|2038|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1325|1325|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12632|12632|1|0.0%|0.0%|

## zeus

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist).

The last time downloaded was found to be dated: Fri May 29 12:33:38 UTC 2015.

The ipset `zeus` has **266** entries, **266** unique IPs.

The following table shows the overlaps of `zeus` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus`.
- ` this % ` is the percentage **of this ipset (`zeus`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|904|18056697|262|0.0%|98.4%|
[zeus_badips](#zeus_badips)|228|228|228|100.0%|85.7%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|226|3.3%|84.9%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|68|0.0%|25.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|19|0.0%|7.1%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|16|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|8|0.0%|3.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|5|0.0%|1.8%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|3|0.0%|1.1%|
[openbl_90d](#openbl_90d)|9833|9833|2|0.0%|0.7%|
[openbl_60d](#openbl_60d)|7718|7718|2|0.0%|0.7%|
[openbl_30d](#openbl_30d)|4386|4386|2|0.0%|0.7%|
[openbl](#openbl)|9833|9833|2|0.0%|0.7%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|1|0.0%|0.3%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.3%|
[php_bad](#php_bad)|281|281|1|0.3%|0.3%|
[openbl_7d](#openbl_7d)|984|984|1|0.1%|0.3%|
[nixspam](#nixspam)|22937|22937|1|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|
[et_compromised](#et_compromised)|2401|2401|1|0.0%|0.3%|
[bruteforceblocker](#bruteforceblocker)|2329|2329|1|0.0%|0.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|2038|2038|1|0.0%|0.3%|
[blocklist_de](#blocklist_de)|22246|22246|1|0.0%|0.3%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Fri May 29 15:54:15 UTC 2015.

The ipset `zeus_badips` has **228** entries, **228** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|266|266|228|85.7%|100.0%|
[et_block](#et_block)|904|18056697|226|0.0%|99.1%|
[snort_ipfilter](#snort_ipfilter)|6827|6827|199|2.9%|87.2%|
[alienvault_reputation](#alienvault_reputation)|176841|176841|36|0.0%|15.7%|
[spamhaus_drop](#spamhaus_drop)|639|17921280|16|0.0%|7.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14|0.0%|6.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8|0.0%|3.5%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|5|0.0%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4|0.0%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|92405|92405|3|0.0%|1.3%|
[stopforumspam_7d](#stopforumspam_7d)|30975|30975|1|0.0%|0.4%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.4%|
[php_bad](#php_bad)|281|281|1|0.3%|0.4%|
[openbl_90d](#openbl_90d)|9833|9833|1|0.0%|0.4%|
[openbl_60d](#openbl_60d)|7718|7718|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|4386|4386|1|0.0%|0.4%|
[openbl](#openbl)|9833|9833|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.4%|
[et_compromised](#et_compromised)|2401|2401|1|0.0%|0.4%|
[bruteforceblocker](#bruteforceblocker)|2329|2329|1|0.0%|0.4%|
