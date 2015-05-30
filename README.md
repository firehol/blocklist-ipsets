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

As time passes and the internet matures in our life, cyber crime is becoming increasingly sophisticated. Although there many tools (detection of malware, viruses, intrusion detection and prevension systems, etc) to help us isolate the budguys, there are now a lot more than just such attacks.

What is more interesting is that the fraudsters or attackers in many cases are not going to do a direct damage to you or your systems. They will use you and your systems to gain something else, possibly not related or indirectly related to your business. Nowdays the attacks cannot be identified easily. They are distributed and come to our systems from a vast amount of IPs around the world.

To get an idea, check for example the [XRumer](http://en.wikipedia.org/wiki/XRumer) software. This thing mimics human behaviour to post ads, it creates email accounts, responds to emails it receives, bypasses captchas, it goes gently to stay unoticed, etc.

To increase our effectiveness we need to complement our security solutions with our shared knowledge, our shared experience in this fight.

Hopefully, there are many teams out there that do their best to identify the attacks and pinpoint the attackers. These teams release blocklists. Blocklists of IPs (for use in firewalls), domains & URLs
(for use in proxies), etc.

What we are interested here is IPs.

Using IP blocklists at the internet side of your firewall is a key component of internet security. These lists share key knowledge between us, allowing us to learn from each other and effectively isolate fraudsters and attackers from our services.

I decided to upload these lists to a github repo because:

1. They are freely available on the internet. The intention of their creators is to help internet security.
 Keep in mind though that a few of these lists may have special licences attached. Before using them, please check their source site for any information regarding proper use.

2. Github provides (via `git pull`) a unified way of updating all the lists together.
 Pulling this repo regularly on your machines, you will update all the IP lists at once.

3. Github also provides a unified version control. Using it we can have a history of what each list has done, which IPs or subnets were added and which were removed.

## DNSBLs

Check also another tool included in FireHOL v3+, called `dnsbl-ipset.sh`.

This tool is capable of creating an ipset based on your traffic by looking up information on DNSBLs and scoring it according to your preferences.

More information [here](https://github.com/ktsaou/firehol/wiki/dnsbl-ipset.sh).


---

# Using these ipsets

Please be very careful what you choose to use and how you use it. If you blacklist traffic using these lists you may end up blocking your users, your customers, even yourself (!) from accessing your services.

1. Go to to the site of each list and read how each list is maintained. You are going to trust these guys for doing their job right.

2. Most sites have either a donation system or commercial lists of higher quality. Try to support them. 

3. I have included the TOR network in these lists (`bm_tor`, `dm_tor`, `et_tor`). The TOR network is not necessarily bad and you should not block it if you want to allow your users be anonymous. I have included it because for certain cases, allowing an anonymity network might be a risky thing (such as eCommerce).

4. Apply any blacklist at the internet side of your firewall. Be very carefull. The `bogons` and `fullbogons` lists contain private, unroutable IPs that should not be routed on the internet. If you apply such a blocklist on your DMZ or LAN side, you will be blocked out of your firewall.

5. Always have a whitelist too, containing the IP addresses or subnets you trust. Try to build the rules in such a way that if an IP is in the whitelist, it should not be blocked by these blocklists.


## Which ones to use


### Level 1 - Basic

These are the ones I install on all my firewalls. **Level 1** provides basic security against the most well known attackers, with the minimum of false positives.

1. **Abuse.ch** lists `feodo`, `palevo`, `sslbl`, `zeus`, `zeus_badips`
   
   These folks are doing a great job tracking crimeware. Their blocklists are very focused.
   Keep in mind `zeus` may include some false positives. You can use `zeus_badips` instead.

2. **DShield.org** list `dshield`

   It contains the top 20 attacking class C (/24) subnets, over the last three days.

3. **Spamhaus.org** lists `spamhaus_drop`, `spamhaus_edrop`
   
   DROP (Don't Route Or Peer) and EDROP are advisory "drop all traffic" lists, consisting of netblocks that are "hijacked" or leased by professional spam or cyber-crime operations (used for dissemination of malware, trojan downloaders, botnet controllers).
   According to Spamhaus.org:

   > When implemented at a network or ISP's 'core routers', DROP and EDROP will help protect the network's users from spamming, scanning, harvesting, DNS-hijacking and DDoS attacks originating on rogue netblocks.
   > 
   > Spamhaus strongly encourages the use of DROP and EDROP by tier-1s and backbones.

 Spamhaus is very responsive to adapt these lists when a network owner updates them that the issue has been solved (I had one such incident with one of my users).

4. **Team-Cymru.org** list `bogons` or `fullbogons`

   These are lists of IPs that should not be routed on the internet. No one should be using them.
   Be very careful to apply either of the two on the internet side of your network.

### Level 2 - Essentials

**Level 2** provide protection against current brute force attacks. This level may have a small percentage of false positives, mainly due to dynamic IPs being re-used by other users.

1. **OpenBL.org** lists `openbl*`
   
   The team of OpenBL tracks brute force attacks on their hosts. They have a very short list for hosts, under their own control, collecting this information, to eliminate false positives.
   They suggest to use the default blacklist which has a retention policy of 90 days (`openbl`), but they also provide lists with different retention policies (from 1 day to 1 year).
   Their goal is to report abuse to the responsible provider so that the infection is disabled.

2. **Blocklist.de** lists `blocklist_de*`
   
   Is a network of users reporting abuse mainly using `fail2ban`. They eliminate false positives using other lists available. Since they collect information from their users, their lists may be subject to poisoning, or false positives.
   However, they only include individual IPs (no subnets) which have attacked their users the last 48 hours and their list contains 20.000 to 40.000 IPs (which is small enough considering the size of the internet).
   Like `openbl`, their goal is to report abuse back, so that the infection is disabled.
   They also provide their blocklist per type of attack (mail, web, etc).

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

The following list was automatically generated on Sat May 30 15:28:23 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|174737 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|21351 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|12566 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|3325 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|1235 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|312 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|726 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|14356 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|91 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|1784 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|193 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6479 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD)|ipv4 hash:ip|2253 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|355 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|259 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6476 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|986 subnets, 18056524 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botcc](#et_botcc)|[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)|ipv4 hash:ip|501 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net](http://www.emergingthreats.net/) compromised hosts (seems to be a derivate of other lists)|ipv4 hash:ip|2367 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6470 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[feodo](#feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|71 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
[fullbogons](#fullbogons)|[Team-Cymru.org](http://www.team-cymru.org) IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user - **excellent list - use it only your internet interface**|ipv4 hash:net|3642 subnets, 670590424 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt)
[geolite2_country](https://github.com/ktsaou/blocklist-ipsets/tree/master/geolite2_country)|[MaxMind GeoLite2](http://dev.maxmind.com/geoip/geoip2/geolite2/) databases are free IP geolocation databases comparable to, but less accurate than, MaxMind’s GeoIP2 databases. They include IPs per country, IPs per continent, IPs used by anonymous services (VPNs, Proxies, etc) and Satellite Providers.|ipv4 hash:net|All the world|updated every 7 days  from [this link](http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country-CSV.zip)
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) IPs that have been reported for bad deeds in p2p|ipv4 hash:ip|48134 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=cwworuawihqvocglcoss&fileformat=p2p&archiveformat=gz)
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) hijacked IP-Blocks Hijacked IP space are IP blocks that are being used without permission|ipv4 hash:net|535 subnets, 9177856 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=usrcshglbiilevmyfhse&fileformat=p2p&archiveformat=gz)
[ib_bluetack_level1](#ib_bluetack_level1)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Level 1 (for use in p2p): Companies or organizations who are clearly involved with trying to stop filesharing (e.g. Baytsp, MediaDefender, Mediasentry a.o.). Companies which anti-p2p activity has been seen from. Companies that produce or have a strong financial interest in copyrighted material (e.g. music, movie, software industries a.o.). Government ranges or companies that have a strong financial interest in doing work for governments. Legal industry ranges. IPs or ranges of ISPs from which anti-p2p activity has been observed. Basically this list will block all kinds of internet connections that most people would rather not have during their internet travels.|ipv4 hash:net|218309 subnets, 764987411 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz)
[ib_bluetack_level2](#ib_bluetack_level2)|[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 2 (for use in p2p). General corporate ranges. Ranges used by labs or researchers. Proxies.|ipv4 hash:net|72774 subnets, 348707599 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw&fileformat=p2p&archiveformat=gz)
[ib_bluetack_level3](#ib_bluetack_level3)|[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 3 (for use in p2p). Many portal-type websites. ISP ranges that may be dodgy for some reason. Ranges that belong to an individual, but which have not been determined to be used by a particular company. Ranges for things that are unusual in some way. The L3 list is aka the paranoid list.|ipv4 hash:net|17802 subnets, 139104824 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh&fileformat=p2p&archiveformat=gz)
[ib_bluetack_proxies](#ib_bluetack_proxies)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Open Proxies IPs list (without TOR)|ipv4 hash:ip|673 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=xoebmbyexwuiogmbyprb&fileformat=p2p&archiveformat=gz)
[ib_bluetack_spyware](#ib_bluetack_spyware)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) known malicious SPYWARE and ADWARE IP Address ranges|ipv4 hash:net|3274 subnets, 339192 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=llvtlsjyoyiczbkjsxpf&fileformat=p2p&archiveformat=gz)
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) web server hack and exploit attempts|ipv4 hash:ip|1460 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=ghlzqtqxnzctvvajwwag&fileformat=p2p&archiveformat=gz)
[malc0de](#malc0de)|[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days|ipv4 hash:ip|407 unique IPs|updated every 1 day  from [this link](http://malc0de.com/bl/IP_Blacklist.txt)
[malwaredomainlist](#malwaredomainlist)|[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses|ipv4 hash:ip|1282 unique IPs|updated every 12 hours  from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt)
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.|ipv4 hash:ip|372 unique IPs|updated every 4 hours  from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list)
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|22222 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
[openbl](#openbl)|[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**|ipv4 hash:ip|9797 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base.txt)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|220 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|3339 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7680 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|949 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
[openbl_90d](#openbl_90d)|[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|9797 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_90days.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
[php_bad](#php_bad)|[projecthoneypot.org](http://www.projecthoneypot.org/) bad web hosts (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|281 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=b&rss=1)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|281 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|433 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|257 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|417 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1476 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|247 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1859 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|4892 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1188 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|2000 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|640 subnets, 17925376 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|55 subnets, 421120 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|349 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|6827 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|92359 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|30993 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10327 subnets, 10736 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1963 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|263 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|229 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Sat May 30 10:00:35 UTC 2015.

The ipset `alienvault_reputation` has **174737** entries, **174737** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14896|0.0%|8.5%|
[openbl_90d](#openbl_90d)|9797|9797|9772|99.7%|5.5%|
[openbl](#openbl)|9797|9797|9772|99.7%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8388|0.0%|4.8%|
[openbl_60d](#openbl_60d)|7680|7680|7658|99.7%|4.3%|
[et_block](#et_block)|986|18056524|6044|0.0%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4710|0.0%|2.6%|
[openbl_30d](#openbl_30d)|3339|3339|3325|99.5%|1.9%|
[dshield](#dshield)|20|5120|3075|60.0%|1.7%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|1626|0.0%|0.9%|
[et_compromised](#et_compromised)|2367|2367|1533|64.7%|0.8%|
[bruteforceblocker](#bruteforceblocker)|2253|2253|1468|65.1%|0.8%|
[blocklist_de](#blocklist_de)|21351|21351|1255|5.8%|0.7%|
[shunlist](#shunlist)|1188|1188|1185|99.7%|0.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|1784|1784|1004|56.2%|0.5%|
[openbl_7d](#openbl_7d)|949|949|941|99.1%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|519|0.0%|0.2%|
[ciarmy](#ciarmy)|355|355|336|94.6%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|289|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|226|0.2%|0.1%|
[openbl_1d](#openbl_1d)|220|220|214|97.2%|0.1%|
[voipbl](#voipbl)|10327|10736|209|1.9%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12566|12566|121|0.9%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|114|0.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|2000|2000|110|5.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14356|14356|81|0.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|726|726|67|9.2%|0.0%|
[zeus](#zeus)|263|263|64|24.3%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6827|6827|57|0.8%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|193|193|57|29.5%|0.0%|
[et_tor](#et_tor)|6470|6470|48|0.7%|0.0%|
[dm_tor](#dm_tor)|6476|6476|48|0.7%|0.0%|
[bm_tor](#bm_tor)|6479|6479|48|0.7%|0.0%|
[nixspam](#nixspam)|22222|22222|38|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|37|16.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3325|3325|27|0.8%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|25|6.7%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|91|91|19|20.8%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1235|1235|17|1.3%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|15|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|312|312|13|4.1%|0.0%|
[php_commenters](#php_commenters)|281|281|12|4.2%|0.0%|
[php_bad](#php_bad)|281|281|12|4.2%|0.0%|
[sslbl](#sslbl)|349|349|11|3.1%|0.0%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|0.0%|
[malc0de](#malc0de)|407|407|9|2.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|8|0.5%|0.0%|
[php_dictionary](#php_dictionary)|433|433|7|1.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|7|0.5%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|259|259|6|2.3%|0.0%|
[xroxy](#xroxy)|1963|1963|5|0.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4892|4892|3|0.0%|0.0%|
[proxyrss](#proxyrss)|1476|1476|3|0.2%|0.0%|
[php_spammers](#php_spammers)|417|417|3|0.7%|0.0%|
[et_botcc](#et_botcc)|501|501|3|0.5%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1859|1859|2|0.1%|0.0%|
[proxz](#proxz)|247|247|2|0.8%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[feodo](#feodo)|71|71|1|1.4%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Sat May 30 15:14:03 UTC 2015.

The ipset `blocklist_de` has **21351** entries, **21351** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|14356|14356|14356|100.0%|67.2%|
[blocklist_de_apache](#blocklist_de_apache)|12566|12566|12566|100.0%|58.8%|
[blocklist_de_bots](#blocklist_de_bots)|3325|3325|3325|100.0%|15.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2811|0.0%|13.1%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|2559|2.7%|11.9%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|2235|7.2%|10.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|1784|1784|1781|99.8%|8.3%|
[stopforumspam_1d](#stopforumspam_1d)|6827|6827|1536|22.4%|7.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1468|0.0%|6.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1441|0.0%|6.7%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|1255|0.7%|5.8%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1235|1235|1235|100.0%|5.7%|
[openbl_90d](#openbl_90d)|9797|9797|993|10.1%|4.6%|
[openbl](#openbl)|9797|9797|993|10.1%|4.6%|
[openbl_60d](#openbl_60d)|7680|7680|946|12.3%|4.4%|
[openbl_30d](#openbl_30d)|3339|3339|870|26.0%|4.0%|
[bruteforceblocker](#bruteforceblocker)|2253|2253|782|34.7%|3.6%|
[et_compromised](#et_compromised)|2367|2367|751|31.7%|3.5%|
[blocklist_de_imap](#blocklist_de_imap)|726|726|726|100.0%|3.4%|
[openbl_7d](#openbl_7d)|949|949|563|59.3%|2.6%|
[nixspam](#nixspam)|22222|22222|518|2.3%|2.4%|
[shunlist](#shunlist)|1188|1188|465|39.1%|2.1%|
[ri_web_proxies](#ri_web_proxies)|4892|4892|384|7.8%|1.7%|
[blocklist_de_ftp](#blocklist_de_ftp)|312|312|312|100.0%|1.4%|
[xroxy](#xroxy)|1963|1963|289|14.7%|1.3%|
[proxyrss](#proxyrss)|1476|1476|248|16.8%|1.1%|
[openbl_1d](#openbl_1d)|220|220|201|91.3%|0.9%|
[et_block](#et_block)|986|18056524|198|0.0%|0.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|193|193|193|100.0%|0.9%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|186|0.0%|0.8%|
[dshield](#dshield)|20|5120|127|2.4%|0.5%|
[ri_connect_proxies](#ri_connect_proxies)|1859|1859|79|4.2%|0.3%|
[proxz](#proxz)|247|247|72|29.1%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|91|91|72|79.1%|0.3%|
[php_commenters](#php_commenters)|281|281|65|23.1%|0.3%|
[php_bad](#php_bad)|281|281|65|23.1%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|65|0.0%|0.3%|
[php_dictionary](#php_dictionary)|433|433|58|13.3%|0.2%|
[php_spammers](#php_spammers)|417|417|54|12.9%|0.2%|
[ciarmy](#ciarmy)|355|355|45|12.6%|0.2%|
[voipbl](#voipbl)|10327|10736|41|0.3%|0.1%|
[php_harvesters](#php_harvesters)|257|257|27|10.5%|0.1%|
[snort_ipfilter](#snort_ipfilter)|2000|2000|25|1.2%|0.1%|
[dm_tor](#dm_tor)|6476|6476|17|0.2%|0.0%|
[bm_tor](#bm_tor)|6479|6479|17|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|16|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|16|0.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|5|0.7%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|3|0.8%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|259|259|3|1.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[zeus](#zeus)|263|263|1|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Sat May 30 14:56:05 UTC 2015.

The ipset `blocklist_de_apache` has **12566** entries, **12566** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|21351|21351|12566|58.8%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|14356|14356|11059|77.0%|88.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2197|0.0%|17.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1312|0.0%|10.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1235|1235|1235|100.0%|9.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1067|0.0%|8.4%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|215|0.2%|1.7%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|130|0.4%|1.0%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|121|0.0%|0.9%|
[stopforumspam_1d](#stopforumspam_1d)|6827|6827|83|1.2%|0.6%|
[ciarmy](#ciarmy)|355|355|41|11.5%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|193|193|35|18.1%|0.2%|
[shunlist](#shunlist)|1188|1188|31|2.6%|0.2%|
[php_commenters](#php_commenters)|281|281|26|9.2%|0.2%|
[php_bad](#php_bad)|281|281|26|9.2%|0.2%|
[snort_ipfilter](#snort_ipfilter)|2000|2000|22|1.1%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3325|3325|18|0.5%|0.1%|
[et_tor](#et_tor)|6470|6470|16|0.2%|0.1%|
[dm_tor](#dm_tor)|6476|6476|16|0.2%|0.1%|
[bm_tor](#bm_tor)|6479|6479|16|0.2%|0.1%|
[openbl_90d](#openbl_90d)|9797|9797|12|0.1%|0.0%|
[openbl](#openbl)|9797|9797|12|0.1%|0.0%|
[openbl_60d](#openbl_60d)|7680|7680|10|0.1%|0.0%|
[nixspam](#nixspam)|22222|22222|7|0.0%|0.0%|
[et_block](#et_block)|986|18056524|7|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3339|3339|6|0.1%|0.0%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|3|0.0%|0.0%|
[openbl_7d](#openbl_7d)|949|949|3|0.3%|0.0%|
[et_compromised](#et_compromised)|2367|2367|3|0.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|259|259|3|1.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2253|2253|3|0.1%|0.0%|
[voipbl](#voipbl)|10327|10736|2|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[zeus](#zeus)|263|263|1|0.3%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Sat May 30 15:10:08 UTC 2015.

The ipset `blocklist_de_bots` has **3325** entries, **3325** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|21351|21351|3325|15.5%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|2247|2.4%|67.5%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|2053|6.6%|61.7%|
[stopforumspam_1d](#stopforumspam_1d)|6827|6827|1452|21.2%|43.6%|
[ri_web_proxies](#ri_web_proxies)|4892|4892|350|7.1%|10.5%|
[proxyrss](#proxyrss)|1476|1476|246|16.6%|7.3%|
[xroxy](#xroxy)|1963|1963|245|12.4%|7.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|176|0.0%|5.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|142|0.0%|4.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|193|193|124|64.2%|3.7%|
[ri_connect_proxies](#ri_connect_proxies)|1859|1859|76|4.0%|2.2%|
[proxz](#proxz)|247|247|62|25.1%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|59|0.0%|1.7%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|52|0.0%|1.5%|
[et_block](#et_block)|986|18056524|52|0.0%|1.5%|
[php_commenters](#php_commenters)|281|281|50|17.7%|1.5%|
[php_bad](#php_bad)|281|281|50|17.7%|1.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|50|0.0%|1.5%|
[nixspam](#nixspam)|22222|22222|38|0.1%|1.1%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|27|0.0%|0.8%|
[php_harvesters](#php_harvesters)|257|257|22|8.5%|0.6%|
[blocklist_de_apache](#blocklist_de_apache)|12566|12566|18|0.1%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|14356|14356|17|0.1%|0.5%|
[php_spammers](#php_spammers)|417|417|13|3.1%|0.3%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|12|0.0%|0.3%|
[php_dictionary](#php_dictionary)|433|433|10|2.3%|0.3%|
[dshield](#dshield)|20|5120|9|0.1%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|4|0.5%|0.1%|
[openbl_90d](#openbl_90d)|9797|9797|3|0.0%|0.0%|
[openbl](#openbl)|9797|9797|3|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7680|7680|2|0.0%|0.0%|
[voipbl](#voipbl)|10327|10736|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6476|6476|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2253|2253|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6479|6479|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Sat May 30 15:10:10 UTC 2015.

The ipset `blocklist_de_bruteforce` has **1235** entries, **1235** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_apache](#blocklist_de_apache)|12566|12566|1235|9.8%|100.0%|
[blocklist_de](#blocklist_de)|21351|21351|1235|5.7%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|100|0.0%|8.0%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|60|0.0%|4.8%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|53|0.1%|4.2%|
[stopforumspam_1d](#stopforumspam_1d)|6827|6827|31|0.4%|2.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|30|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|24|0.0%|1.9%|
[snort_ipfilter](#snort_ipfilter)|2000|2000|19|0.9%|1.5%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|17|0.0%|1.3%|
[et_tor](#et_tor)|6470|6470|13|0.2%|1.0%|
[dm_tor](#dm_tor)|6476|6476|13|0.2%|1.0%|
[bm_tor](#bm_tor)|6479|6479|13|0.2%|1.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|193|193|10|5.1%|0.8%|
[nixspam](#nixspam)|22222|22222|7|0.0%|0.5%|
[php_commenters](#php_commenters)|281|281|6|2.1%|0.4%|
[php_bad](#php_bad)|281|281|6|2.1%|0.4%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.4%|
[et_block](#et_block)|986|18056524|4|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|3|0.0%|0.2%|
[openbl_90d](#openbl_90d)|9797|9797|3|0.0%|0.2%|
[openbl](#openbl)|9797|9797|3|0.0%|0.2%|
[cleanmx_viruses](#cleanmx_viruses)|259|259|3|1.1%|0.2%|
[shunlist](#shunlist)|1188|1188|2|0.1%|0.1%|
[zeus](#zeus)|263|263|1|0.3%|0.0%|
[voipbl](#voipbl)|10327|10736|1|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7680|7680|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Sat May 30 15:14:07 UTC 2015.

The ipset `blocklist_de_ftp` has **312** entries, **312** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|21351|21351|312|1.4%|100.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|24|0.0%|7.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|17|0.0%|5.4%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|13|0.0%|4.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|12|0.0%|3.8%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|11|0.0%|3.5%|
[openbl_90d](#openbl_90d)|9797|9797|7|0.0%|2.2%|
[openbl](#openbl)|9797|9797|7|0.0%|2.2%|
[openbl_60d](#openbl_60d)|7680|7680|5|0.0%|1.6%|
[php_harvesters](#php_harvesters)|257|257|4|1.5%|1.2%|
[nixspam](#nixspam)|22222|22222|4|0.0%|1.2%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|3|0.0%|0.9%|
[openbl_7d](#openbl_7d)|949|949|2|0.2%|0.6%|
[openbl_30d](#openbl_30d)|3339|3339|2|0.0%|0.6%|
[dshield](#dshield)|20|5120|2|0.0%|0.6%|
[stopforumspam_1d](#stopforumspam_1d)|6827|6827|1|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|1|0.0%|0.3%|
[shunlist](#shunlist)|1188|1188|1|0.0%|0.3%|
[openbl_1d](#openbl_1d)|220|220|1|0.4%|0.3%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.3%|
[et_block](#et_block)|986|18056524|1|0.0%|0.3%|
[ciarmy](#ciarmy)|355|355|1|0.2%|0.3%|
[bruteforceblocker](#bruteforceblocker)|2253|2253|1|0.0%|0.3%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Sat May 30 15:10:07 UTC 2015.

The ipset `blocklist_de_imap` has **726** entries, **726** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|21351|21351|726|3.4%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|14356|14356|725|5.0%|99.8%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|67|0.0%|9.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|65|0.0%|8.9%|
[openbl_90d](#openbl_90d)|9797|9797|52|0.5%|7.1%|
[openbl](#openbl)|9797|9797|52|0.5%|7.1%|
[openbl_60d](#openbl_60d)|7680|7680|49|0.6%|6.7%|
[openbl_30d](#openbl_30d)|3339|3339|44|1.3%|6.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|37|0.0%|5.0%|
[openbl_7d](#openbl_7d)|949|949|30|3.1%|4.1%|
[et_compromised](#et_compromised)|2367|2367|18|0.7%|2.4%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|16|0.0%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|16|0.0%|2.2%|
[et_block](#et_block)|986|18056524|16|0.0%|2.2%|
[bruteforceblocker](#bruteforceblocker)|2253|2253|15|0.6%|2.0%|
[shunlist](#shunlist)|1188|1188|5|0.4%|0.6%|
[openbl_1d](#openbl_1d)|220|220|5|2.2%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|2|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|1|0.0%|0.1%|
[nixspam](#nixspam)|22222|22222|1|0.0%|0.1%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Sat May 30 15:14:04 UTC 2015.

The ipset `blocklist_de_mail` has **14356** entries, **14356** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|21351|21351|14356|67.2%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|12566|12566|11059|88.0%|77.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2279|0.0%|15.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1327|0.0%|9.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1138|0.0%|7.9%|
[blocklist_de_imap](#blocklist_de_imap)|726|726|725|99.8%|5.0%|
[nixspam](#nixspam)|22222|22222|468|2.1%|3.2%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|218|0.2%|1.5%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|113|0.3%|0.7%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|81|0.0%|0.5%|
[openbl_90d](#openbl_90d)|9797|9797|60|0.6%|0.4%|
[openbl](#openbl)|9797|9797|60|0.6%|0.4%|
[openbl_60d](#openbl_60d)|7680|7680|56|0.7%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6827|6827|52|0.7%|0.3%|
[openbl_30d](#openbl_30d)|3339|3339|50|1.4%|0.3%|
[php_dictionary](#php_dictionary)|433|433|48|11.0%|0.3%|
[xroxy](#xroxy)|1963|1963|43|2.1%|0.2%|
[php_spammers](#php_spammers)|417|417|35|8.3%|0.2%|
[ri_web_proxies](#ri_web_proxies)|4892|4892|34|0.6%|0.2%|
[openbl_7d](#openbl_7d)|949|949|32|3.3%|0.2%|
[et_block](#et_block)|986|18056524|22|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|21|0.0%|0.1%|
[php_commenters](#php_commenters)|281|281|19|6.7%|0.1%|
[php_bad](#php_bad)|281|281|19|6.7%|0.1%|
[et_compromised](#et_compromised)|2367|2367|19|0.8%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|193|193|18|9.3%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3325|3325|17|0.5%|0.1%|
[bruteforceblocker](#bruteforceblocker)|2253|2253|16|0.7%|0.1%|
[proxz](#proxz)|247|247|9|3.6%|0.0%|
[openbl_1d](#openbl_1d)|220|220|6|2.7%|0.0%|
[snort_ipfilter](#snort_ipfilter)|2000|2000|5|0.2%|0.0%|
[shunlist](#shunlist)|1188|1188|5|0.4%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.0%|
[voipbl](#voipbl)|10327|10736|3|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1859|1859|3|0.1%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6476|6476|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6479|6479|3|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Sat May 30 15:14:07 UTC 2015.

The ipset `blocklist_de_sip` has **91** entries, **91** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|21351|21351|72|0.3%|79.1%|
[voipbl](#voipbl)|10327|10736|32|0.2%|35.1%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|19|0.0%|20.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|18|0.0%|19.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8|0.0%|8.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|5.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|2.1%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|1|0.0%|1.0%|
[shunlist](#shunlist)|1188|1188|1|0.0%|1.0%|
[et_botcc](#et_botcc)|501|501|1|0.1%|1.0%|
[et_block](#et_block)|986|18056524|1|0.0%|1.0%|
[ciarmy](#ciarmy)|355|355|1|0.2%|1.0%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Sat May 30 14:56:03 UTC 2015.

The ipset `blocklist_de_ssh` has **1784** entries, **1784** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|21351|21351|1781|8.3%|99.8%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|1004|0.5%|56.2%|
[openbl_90d](#openbl_90d)|9797|9797|910|9.2%|51.0%|
[openbl](#openbl)|9797|9797|910|9.2%|51.0%|
[openbl_60d](#openbl_60d)|7680|7680|871|11.3%|48.8%|
[openbl_30d](#openbl_30d)|3339|3339|810|24.2%|45.4%|
[bruteforceblocker](#bruteforceblocker)|2253|2253|759|33.6%|42.5%|
[et_compromised](#et_compromised)|2367|2367|725|30.6%|40.6%|
[openbl_7d](#openbl_7d)|949|949|525|55.3%|29.4%|
[shunlist](#shunlist)|1188|1188|425|35.7%|23.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|199|0.0%|11.1%|
[openbl_1d](#openbl_1d)|220|220|194|88.1%|10.8%|
[et_block](#et_block)|986|18056524|115|0.0%|6.4%|
[dshield](#dshield)|20|5120|114|2.2%|6.3%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|108|0.0%|6.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|90|0.0%|5.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|193|193|48|24.8%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|34|0.0%|1.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|9|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|5|0.0%|0.2%|
[voipbl](#voipbl)|10327|10736|3|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|3|0.0%|0.1%|
[ciarmy](#ciarmy)|355|355|2|0.5%|0.1%|
[xroxy](#xroxy)|1963|1963|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|2000|2000|1|0.0%|0.0%|
[proxz](#proxz)|247|247|1|0.4%|0.0%|
[proxyrss](#proxyrss)|1476|1476|1|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.0%|
[nixspam](#nixspam)|22222|22222|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Sat May 30 15:10:10 UTC 2015.

The ipset `blocklist_de_strongips` has **193** entries, **193** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|21351|21351|193|0.9%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|130|0.1%|67.3%|
[blocklist_de_bots](#blocklist_de_bots)|3325|3325|124|3.7%|64.2%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|119|0.3%|61.6%|
[stopforumspam_1d](#stopforumspam_1d)|6827|6827|97|1.4%|50.2%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|57|0.0%|29.5%|
[openbl_90d](#openbl_90d)|9797|9797|49|0.5%|25.3%|
[openbl](#openbl)|9797|9797|49|0.5%|25.3%|
[openbl_60d](#openbl_60d)|7680|7680|48|0.6%|24.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|1784|1784|48|2.6%|24.8%|
[openbl_30d](#openbl_30d)|3339|3339|46|1.3%|23.8%|
[openbl_7d](#openbl_7d)|949|949|45|4.7%|23.3%|
[shunlist](#shunlist)|1188|1188|42|3.5%|21.7%|
[openbl_1d](#openbl_1d)|220|220|42|19.0%|21.7%|
[blocklist_de_apache](#blocklist_de_apache)|12566|12566|35|0.2%|18.1%|
[php_commenters](#php_commenters)|281|281|33|11.7%|17.0%|
[php_bad](#php_bad)|281|281|33|11.7%|17.0%|
[blocklist_de_mail](#blocklist_de_mail)|14356|14356|18|0.1%|9.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|16|0.0%|8.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1235|1235|10|0.8%|5.1%|
[dshield](#dshield)|20|5120|8|0.1%|4.1%|
[xroxy](#xroxy)|1963|1963|6|0.3%|3.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|6|0.0%|3.1%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|6|0.0%|3.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|6|0.0%|3.1%|
[et_block](#et_block)|986|18056524|6|0.0%|3.1%|
[php_spammers](#php_spammers)|417|417|4|0.9%|2.0%|
[ri_web_proxies](#ri_web_proxies)|4892|4892|3|0.0%|1.5%|
[nixspam](#nixspam)|22222|22222|3|0.0%|1.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.5%|
[proxz](#proxz)|247|247|2|0.8%|1.0%|
[proxyrss](#proxyrss)|1476|1476|2|0.1%|1.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|1.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|1.0%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Sat May 30 15:00:11 UTC 2015.

The ipset `bm_tor` has **6479** entries, **6479** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[dm_tor](#dm_tor)|6476|6476|6476|100.0%|99.9%|
[et_tor](#et_tor)|6470|6470|5689|87.9%|87.8%|
[snort_ipfilter](#snort_ipfilter)|2000|2000|993|49.6%|15.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|614|0.0%|9.4%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|582|0.6%|8.9%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|464|1.4%|7.1%|
[stopforumspam_1d](#stopforumspam_1d)|6827|6827|330|4.8%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|183|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|169|45.4%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|157|0.0%|2.4%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|48|0.0%|0.7%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[php_bad](#php_bad)|281|281|29|10.3%|0.4%|
[openbl_90d](#openbl_90d)|9797|9797|21|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7680|7680|21|0.2%|0.3%|
[openbl](#openbl)|9797|9797|21|0.2%|0.3%|
[blocklist_de](#blocklist_de)|21351|21351|17|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|12566|12566|16|0.1%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1235|1235|13|1.0%|0.2%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[php_harvesters](#php_harvesters)|257|257|6|2.3%|0.0%|
[nixspam](#nixspam)|22222|22222|6|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4892|4892|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|3|0.6%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|986|18056524|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14356|14356|3|0.0%|0.0%|
[xroxy](#xroxy)|1963|1963|2|0.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1859|1859|2|0.1%|0.0%|
[proxyrss](#proxyrss)|1476|1476|2|0.1%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[voipbl](#voipbl)|10327|10736|1|0.0%|0.0%|
[shunlist](#shunlist)|1188|1188|1|0.0%|0.0%|
[proxz](#proxz)|247|247|1|0.4%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3325|3325|1|0.0%|0.0%|

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
[fullbogons](#fullbogons)|3642|670590424|592708608|88.3%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|4194304|3.0%|0.7%|
[voipbl](#voipbl)|10327|10736|319|2.9%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2253|2253|1|0.0%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD)

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Sat May 30 13:18:26 UTC 2015.

The ipset `bruteforceblocker` has **2253** entries, **2253** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_compromised](#et_compromised)|2367|2367|2199|92.9%|97.6%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|1468|0.8%|65.1%|
[openbl_90d](#openbl_90d)|9797|9797|1378|14.0%|61.1%|
[openbl](#openbl)|9797|9797|1378|14.0%|61.1%|
[openbl_60d](#openbl_60d)|7680|7680|1363|17.7%|60.4%|
[openbl_30d](#openbl_30d)|3339|3339|1299|38.9%|57.6%|
[blocklist_de](#blocklist_de)|21351|21351|782|3.6%|34.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|1784|1784|759|42.5%|33.6%|
[openbl_7d](#openbl_7d)|949|949|506|53.3%|22.4%|
[shunlist](#shunlist)|1188|1188|498|41.9%|22.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|218|0.0%|9.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|130|0.0%|5.7%|
[dshield](#dshield)|20|5120|121|2.3%|5.3%|
[openbl_1d](#openbl_1d)|220|220|118|53.6%|5.2%|
[et_block](#et_block)|986|18056524|103|0.0%|4.5%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|102|0.0%|4.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|65|0.0%|2.8%|
[blocklist_de_mail](#blocklist_de_mail)|14356|14356|16|0.1%|0.7%|
[blocklist_de_imap](#blocklist_de_imap)|726|726|15|2.0%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|6|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|3|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12566|12566|3|0.0%|0.1%|
[proxz](#proxz)|247|247|2|0.8%|0.0%|
[proxyrss](#proxyrss)|1476|1476|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|263|263|1|0.3%|0.0%|
[xroxy](#xroxy)|1963|1963|1|0.0%|0.0%|
[voipbl](#voipbl)|10327|10736|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6827|6827|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|2000|2000|1|0.0%|0.0%|
[nixspam](#nixspam)|22222|22222|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3642|670590424|1|0.0%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|312|312|1|0.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3325|3325|1|0.0%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Sat May 30 13:15:15 UTC 2015.

The ipset `ciarmy` has **355** entries, **355** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|174737|174737|336|0.1%|94.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|58|0.0%|16.3%|
[blocklist_de](#blocklist_de)|21351|21351|45|0.2%|12.6%|
[blocklist_de_apache](#blocklist_de_apache)|12566|12566|41|0.3%|11.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|22|0.0%|6.1%|
[shunlist](#shunlist)|1188|1188|21|1.7%|5.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|11|0.0%|3.0%|
[dshield](#dshield)|20|5120|3|0.0%|0.8%|
[voipbl](#voipbl)|10327|10736|2|0.0%|0.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|1784|1784|2|0.1%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|1|0.0%|0.2%|
[openbl_90d](#openbl_90d)|9797|9797|1|0.0%|0.2%|
[openbl_7d](#openbl_7d)|949|949|1|0.1%|0.2%|
[openbl_60d](#openbl_60d)|7680|7680|1|0.0%|0.2%|
[openbl_30d](#openbl_30d)|3339|3339|1|0.0%|0.2%|
[openbl](#openbl)|9797|9797|1|0.0%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|91|91|1|1.0%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|312|312|1|0.3%|0.2%|

## cleanmx_viruses

[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses

Source is downloaded from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive).

The last time downloaded was found to be dated: Sat May 30 05:18:48 UTC 2015.

The ipset `cleanmx_viruses` has **259** entries, **259** unique IPs.

The following table shows the overlaps of `cleanmx_viruses` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `cleanmx_viruses`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `cleanmx_viruses`.
- ` this % ` is the percentage **of this ipset (`cleanmx_viruses`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|38|0.0%|14.6%|
[malc0de](#malc0de)|407|407|28|6.8%|10.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|10|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|6|0.0%|2.3%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|6|0.0%|2.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1235|1235|3|0.2%|1.1%|
[blocklist_de_apache](#blocklist_de_apache)|12566|12566|3|0.0%|1.1%|
[blocklist_de](#blocklist_de)|21351|21351|3|0.0%|1.1%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.3%|
[zeus](#zeus)|263|263|1|0.3%|0.3%|
[snort_ipfilter](#snort_ipfilter)|2000|2000|1|0.0%|0.3%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|1|0.0%|0.3%|
[et_block](#et_block)|986|18056524|1|0.0%|0.3%|
[dshield](#dshield)|20|5120|1|0.0%|0.3%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Sat May 30 15:00:08 UTC 2015.

The ipset `dm_tor` has **6476** entries, **6476** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6479|6479|6476|99.9%|100.0%|
[et_tor](#et_tor)|6470|6470|5686|87.8%|87.8%|
[snort_ipfilter](#snort_ipfilter)|2000|2000|993|49.6%|15.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|614|0.0%|9.4%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|582|0.6%|8.9%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|464|1.4%|7.1%|
[stopforumspam_1d](#stopforumspam_1d)|6827|6827|330|4.8%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|183|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|169|45.4%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|157|0.0%|2.4%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|48|0.0%|0.7%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[php_bad](#php_bad)|281|281|29|10.3%|0.4%|
[openbl_90d](#openbl_90d)|9797|9797|21|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7680|7680|21|0.2%|0.3%|
[openbl](#openbl)|9797|9797|21|0.2%|0.3%|
[blocklist_de](#blocklist_de)|21351|21351|17|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|12566|12566|16|0.1%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1235|1235|13|1.0%|0.2%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[php_harvesters](#php_harvesters)|257|257|6|2.3%|0.0%|
[nixspam](#nixspam)|22222|22222|6|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4892|4892|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|3|0.6%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|986|18056524|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14356|14356|3|0.0%|0.0%|
[xroxy](#xroxy)|1963|1963|2|0.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1859|1859|2|0.1%|0.0%|
[proxyrss](#proxyrss)|1476|1476|2|0.1%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[voipbl](#voipbl)|10327|10736|1|0.0%|0.0%|
[shunlist](#shunlist)|1188|1188|1|0.0%|0.0%|
[proxz](#proxz)|247|247|1|0.4%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3325|3325|1|0.0%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Sat May 30 14:56:01 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|174737|174737|3075|1.7%|60.0%|
[et_block](#et_block)|986|18056524|768|0.0%|15.0%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|512|0.0%|10.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|256|0.0%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|256|0.0%|5.0%|
[openbl_90d](#openbl_90d)|9797|9797|164|1.6%|3.2%|
[openbl](#openbl)|9797|9797|164|1.6%|3.2%|
[openbl_60d](#openbl_60d)|7680|7680|163|2.1%|3.1%|
[openbl_30d](#openbl_30d)|3339|3339|147|4.4%|2.8%|
[shunlist](#shunlist)|1188|1188|129|10.8%|2.5%|
[blocklist_de](#blocklist_de)|21351|21351|127|0.5%|2.4%|
[et_compromised](#et_compromised)|2367|2367|121|5.1%|2.3%|
[bruteforceblocker](#bruteforceblocker)|2253|2253|121|5.3%|2.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|1784|1784|114|6.3%|2.2%|
[openbl_7d](#openbl_7d)|949|949|101|10.6%|1.9%|
[openbl_1d](#openbl_1d)|220|220|17|7.7%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|16|0.0%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|13|0.0%|0.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|11|0.0%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3325|3325|9|0.2%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6827|6827|8|0.1%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|193|193|8|4.1%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[ciarmy](#ciarmy)|355|355|3|0.8%|0.0%|
[malc0de](#malc0de)|407|407|2|0.4%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6476|6476|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6479|6479|2|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|312|312|2|0.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12566|12566|2|0.0%|0.0%|
[nixspam](#nixspam)|22222|22222|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|259|259|1|0.3%|0.0%|

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
[spamhaus_drop](#spamhaus_drop)|640|17925376|17920256|99.9%|99.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8402471|2.4%|46.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7211008|78.5%|39.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|2133460|0.2%|11.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|196184|0.1%|1.0%|
[fullbogons](#fullbogons)|3642|670590424|20480|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|6044|3.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1040|0.3%|0.0%|
[dshield](#dshield)|20|5120|768|15.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|746|0.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|517|0.1%|0.0%|
[openbl_90d](#openbl_90d)|9797|9797|454|4.6%|0.0%|
[openbl](#openbl)|9797|9797|454|4.6%|0.0%|
[snort_ipfilter](#snort_ipfilter)|2000|2000|290|14.5%|0.0%|
[zeus](#zeus)|263|263|259|98.4%|0.0%|
[openbl_60d](#openbl_60d)|7680|7680|241|3.1%|0.0%|
[nixspam](#nixspam)|22222|22222|234|1.0%|0.0%|
[zeus_badips](#zeus_badips)|229|229|228|99.5%|0.0%|
[openbl_30d](#openbl_30d)|3339|3339|209|6.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|208|0.6%|0.0%|
[blocklist_de](#blocklist_de)|21351|21351|198|0.9%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1784|1784|115|6.4%|0.0%|
[shunlist](#shunlist)|1188|1188|110|9.2%|0.0%|
[et_compromised](#et_compromised)|2367|2367|103|4.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2253|2253|103|4.5%|0.0%|
[openbl_7d](#openbl_7d)|949|949|85|8.9%|0.0%|
[feodo](#feodo)|71|71|67|94.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3325|3325|52|1.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6827|6827|40|0.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|28|2.1%|0.0%|
[sslbl](#sslbl)|349|349|27|7.7%|0.0%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.0%|
[php_bad](#php_bad)|281|281|24|8.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14356|14356|22|0.1%|0.0%|
[openbl_1d](#openbl_1d)|220|220|18|8.1%|0.0%|
[voipbl](#voipbl)|10327|10736|17|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|726|726|16|2.2%|0.0%|
[palevo](#palevo)|13|13|13|100.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|7|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12566|12566|7|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|193|193|6|3.1%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1235|1235|4|0.3%|0.0%|
[malc0de](#malc0de)|407|407|3|0.7%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6476|6476|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6479|6479|3|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[et_botcc](#et_botcc)|501|501|1|0.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|259|259|1|0.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|91|91|1|1.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|312|312|1|0.3%|0.0%|

## et_botcc

[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)

Source is downloaded from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules).

The last time downloaded was found to be dated: Fri May 29 04:30:01 UTC 2015.

The ipset `et_botcc` has **501** entries, **501** unique IPs.

The following table shows the overlaps of `et_botcc` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_botcc`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_botcc`.
- ` this % ` is the percentage **of this ipset (`et_botcc`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|74|0.0%|14.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|40|0.0%|7.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|21|0.0%|4.1%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|3|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[et_block](#et_block)|986|18056524|1|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|91|91|1|1.0%|0.1%|

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
[bruteforceblocker](#bruteforceblocker)|2253|2253|2199|97.6%|92.9%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|1533|0.8%|64.7%|
[openbl_90d](#openbl_90d)|9797|9797|1434|14.6%|60.5%|
[openbl](#openbl)|9797|9797|1434|14.6%|60.5%|
[openbl_60d](#openbl_60d)|7680|7680|1419|18.4%|59.9%|
[openbl_30d](#openbl_30d)|3339|3339|1337|40.0%|56.4%|
[blocklist_de](#blocklist_de)|21351|21351|751|3.5%|31.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|1784|1784|725|40.6%|30.6%|
[openbl_7d](#openbl_7d)|949|949|504|53.1%|21.2%|
[shunlist](#shunlist)|1188|1188|498|41.9%|21.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|227|0.0%|9.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|140|0.0%|5.9%|
[dshield](#dshield)|20|5120|121|2.3%|5.1%|
[openbl_1d](#openbl_1d)|220|220|115|52.2%|4.8%|
[et_block](#et_block)|986|18056524|103|0.0%|4.3%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|102|0.0%|4.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|70|0.0%|2.9%|
[blocklist_de_mail](#blocklist_de_mail)|14356|14356|19|0.1%|0.8%|
[blocklist_de_imap](#blocklist_de_imap)|726|726|18|2.4%|0.7%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|6|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|3|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12566|12566|3|0.0%|0.1%|
[proxz](#proxz)|247|247|2|0.8%|0.0%|
[proxyrss](#proxyrss)|1476|1476|2|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|263|263|1|0.3%|0.0%|
[xroxy](#xroxy)|1963|1963|1|0.0%|0.0%|
[voipbl](#voipbl)|10327|10736|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6827|6827|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|2000|2000|1|0.0%|0.0%|
[nixspam](#nixspam)|22222|22222|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|312|312|1|0.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3325|3325|1|0.0%|0.0%|

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
[bm_tor](#bm_tor)|6479|6479|5689|87.8%|87.9%|
[dm_tor](#dm_tor)|6476|6476|5686|87.8%|87.8%|
[snort_ipfilter](#snort_ipfilter)|2000|2000|1071|53.5%|16.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|619|0.0%|9.5%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|614|0.6%|9.4%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|485|1.5%|7.4%|
[stopforumspam_1d](#stopforumspam_1d)|6827|6827|335|4.9%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|184|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|179|48.1%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|163|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|48|0.0%|0.7%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[php_bad](#php_bad)|281|281|29|10.3%|0.4%|
[openbl_90d](#openbl_90d)|9797|9797|21|0.2%|0.3%|
[openbl_60d](#openbl_60d)|7680|7680|21|0.2%|0.3%|
[openbl](#openbl)|9797|9797|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|12566|12566|16|0.1%|0.2%|
[blocklist_de](#blocklist_de)|21351|21351|16|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1235|1235|13|1.0%|0.2%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[nixspam](#nixspam)|22222|22222|5|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4892|4892|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|986|18056524|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14356|14356|3|0.0%|0.0%|
[xroxy](#xroxy)|1963|1963|2|0.1%|0.0%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1859|1859|2|0.1%|0.0%|
[proxyrss](#proxyrss)|1476|1476|2|0.1%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[voipbl](#voipbl)|10327|10736|1|0.0%|0.0%|
[shunlist](#shunlist)|1188|1188|1|0.0%|0.0%|
[proxz](#proxz)|247|247|1|0.4%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Sat May 30 15:00:24 UTC 2015.

The ipset `feodo` has **71** entries, **71** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|986|18056524|67|0.0%|94.3%|
[snort_ipfilter](#snort_ipfilter)|2000|2000|53|2.6%|74.6%|
[sslbl](#sslbl)|349|349|26|7.4%|36.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|6|0.0%|8.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|3|0.0%|4.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|4.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|1.4%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|1|0.0%|1.4%|

## fullbogons

[Team-Cymru.org](http://www.team-cymru.org) IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user - **excellent list - use it only your internet interface**

Source is downloaded from [this link](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt).

The last time downloaded was found to be dated: Sat May 30 09:35:11 UTC 2015.

The ipset `fullbogons` has **3642** entries, **670590424** unique IPs.

The following table shows the overlaps of `fullbogons` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `fullbogons`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `fullbogons`.
- ` this % ` is the percentage **of this ipset (`fullbogons`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bogons](#bogons)|13|592708608|592708608|100.0%|88.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|4233775|3.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|565248|6.1%|0.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|248319|0.0%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|234359|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|20480|0.1%|0.0%|
[et_block](#et_block)|986|18056524|20480|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|890|0.2%|0.0%|
[voipbl](#voipbl)|10327|10736|319|2.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|33|2.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|9|0.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2253|2253|1|0.0%|0.0%|

## ib_bluetack_badpeers

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) IPs that have been reported for bad deeds in p2p

Source is downloaded from [this link](http://list.iblocklist.com/?list=cwworuawihqvocglcoss&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sat May 30 03:40:49 UTC 2015.

The ipset `ib_bluetack_badpeers` has **48134** entries, **48134** unique IPs.

The following table shows the overlaps of `ib_bluetack_badpeers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_badpeers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_badpeers`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_badpeers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1172|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|406|0.0%|0.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|230|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|15|0.0%|0.0%|
[fullbogons](#fullbogons)|3642|670590424|14|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|14|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.0%|
[nixspam](#nixspam)|22222|22222|8|0.0%|0.0%|
[et_block](#et_block)|986|18056524|7|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|6|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[dshield](#dshield)|20|5120|4|0.0%|0.0%|
[xroxy](#xroxy)|1963|1963|3|0.1%|0.0%|
[voipbl](#voipbl)|10327|10736|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[blocklist_de](#blocklist_de)|21351|21351|2|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6827|6827|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4892|4892|1|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14356|14356|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3325|3325|1|0.0%|0.0%|

## ib_bluetack_hijacked

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) hijacked IP-Blocks Hijacked IP space are IP blocks that are being used without permission

Source is downloaded from [this link](http://list.iblocklist.com/?list=usrcshglbiilevmyfhse&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sat May 30 04:10:07 UTC 2015.

The ipset `ib_bluetack_hijacked` has **535** entries, **9177856** unique IPs.

The following table shows the overlaps of `ib_bluetack_hijacked` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_hijacked`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_hijacked`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_hijacked`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|986|18056524|7211008|39.9%|78.5%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|7079936|39.4%|77.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2526625|0.7%|27.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|904796|0.1%|9.8%|
[fullbogons](#fullbogons)|3642|670590424|565248|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|145472|0.1%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1036|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|748|0.8%|0.0%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|519|0.2%|0.0%|
[nixspam](#nixspam)|22222|22222|233|1.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|196|0.6%|0.0%|
[blocklist_de](#blocklist_de)|21351|21351|65|0.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3325|3325|50|1.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|27|2.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6827|6827|23|0.3%|0.0%|
[openbl_90d](#openbl_90d)|9797|9797|20|0.2%|0.0%|
[openbl](#openbl)|9797|9797|20|0.2%|0.0%|
[openbl_60d](#openbl_60d)|7680|7680|19|0.2%|0.0%|
[openbl_30d](#openbl_30d)|3339|3339|14|0.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|2000|2000|11|0.5%|0.0%|
[openbl_7d](#openbl_7d)|949|949|11|1.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|10|4.3%|0.0%|
[zeus](#zeus)|263|263|10|3.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1784|1784|9|0.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[et_compromised](#et_compromised)|2367|2367|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2253|2253|5|0.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14356|14356|5|0.0%|0.0%|
[shunlist](#shunlist)|1188|1188|4|0.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|726|726|4|0.5%|0.0%|
[openbl_1d](#openbl_1d)|220|220|3|1.3%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6476|6476|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6479|6479|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|193|193|3|1.5%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[voipbl](#voipbl)|10327|10736|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.0%|
[php_bad](#php_bad)|281|281|1|0.3%|0.0%|
[et_botcc](#et_botcc)|501|501|1|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1235|1235|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12566|12566|1|0.0%|0.0%|

## ib_bluetack_level1

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Level 1 (for use in p2p): Companies or organizations who are clearly involved with trying to stop filesharing (e.g. Baytsp, MediaDefender, Mediasentry a.o.). Companies which anti-p2p activity has been seen from. Companies that produce or have a strong financial interest in copyrighted material (e.g. music, movie, software industries a.o.). Government ranges or companies that have a strong financial interest in doing work for governments. Legal industry ranges. IPs or ranges of ISPs from which anti-p2p activity has been observed. Basically this list will block all kinds of internet connections that most people would rather not have during their internet travels.

Source is downloaded from [this link](http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sat May 30 09:51:02 UTC 2015.

The ipset `ib_bluetack_level1` has **218309** entries, **764987411** unique IPs.

The following table shows the overlaps of `ib_bluetack_level1` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level1`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level1`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level1`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|16300309|4.6%|2.1%|
[et_block](#et_block)|986|18056524|2133460|11.8%|0.2%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|2133002|11.8%|0.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1354348|0.9%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904796|9.8%|0.1%|
[fullbogons](#fullbogons)|3642|670590424|234359|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|33155|7.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|13248|3.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|4710|2.6%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|1522|1.6%|0.0%|
[blocklist_de](#blocklist_de)|21351|21351|1468|6.8%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14356|14356|1327|9.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12566|12566|1312|10.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|563|1.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|406|0.8%|0.0%|
[voipbl](#voipbl)|10327|10736|295|2.7%|0.0%|
[nixspam](#nixspam)|22222|22222|281|1.2%|0.0%|
[openbl_90d](#openbl_90d)|9797|9797|216|2.2%|0.0%|
[openbl](#openbl)|9797|9797|216|2.2%|0.0%|
[openbl_60d](#openbl_60d)|7680|7680|177|2.3%|0.0%|
[et_tor](#et_tor)|6470|6470|163|2.5%|0.0%|
[dm_tor](#dm_tor)|6476|6476|157|2.4%|0.0%|
[bm_tor](#bm_tor)|6479|6479|157|2.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6827|6827|135|1.9%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4892|4892|110|2.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|97|6.6%|0.0%|
[openbl_30d](#openbl_30d)|3339|3339|71|2.1%|0.0%|
[et_compromised](#et_compromised)|2367|2367|70|2.9%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|66|5.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2253|2253|65|2.8%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1859|1859|64|3.4%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3325|3325|59|1.7%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|58|8.6%|0.0%|
[xroxy](#xroxy)|1963|1963|54|2.7%|0.0%|
[snort_ipfilter](#snort_ipfilter)|2000|2000|49|2.4%|0.0%|
[et_botcc](#et_botcc)|501|501|40|7.9%|0.0%|
[proxyrss](#proxyrss)|1476|1476|37|2.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1784|1784|34|1.9%|0.0%|
[shunlist](#shunlist)|1188|1188|24|2.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1235|1235|24|1.9%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|17|4.5%|0.0%|
[openbl_7d](#openbl_7d)|949|949|16|1.6%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|726|726|16|2.2%|0.0%|
[proxz](#proxz)|247|247|13|5.2%|0.0%|
[malc0de](#malc0de)|407|407|12|2.9%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|312|312|12|3.8%|0.0%|
[dshield](#dshield)|20|5120|11|0.2%|0.0%|
[ciarmy](#ciarmy)|355|355|11|3.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|9|2.0%|0.0%|
[zeus](#zeus)|263|263|7|2.6%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|259|259|6|2.3%|0.0%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.0%|
[php_commenters](#php_commenters)|281|281|5|1.7%|0.0%|
[php_bad](#php_bad)|281|281|5|1.7%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|91|91|5|5.4%|0.0%|
[zeus_badips](#zeus_badips)|229|229|4|1.7%|0.0%|
[openbl_1d](#openbl_1d)|220|220|4|1.8%|0.0%|
[sslbl](#sslbl)|349|349|3|0.8%|0.0%|
[feodo](#feodo)|71|71|3|4.2%|0.0%|

## ib_bluetack_level2

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 2 (for use in p2p). General corporate ranges. Ranges used by labs or researchers. Proxies.

Source is downloaded from [this link](http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sat May 30 04:11:22 UTC 2015.

The ipset `ib_bluetack_level2` has **72774** entries, **348707599** unique IPs.

The following table shows the overlaps of `ib_bluetack_level2` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level2`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level2`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level2`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|16300309|2.1%|4.6%|
[et_block](#et_block)|986|18056524|8402471|46.5%|2.4%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|8401434|46.8%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2830140|2.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2526625|27.5%|0.7%|
[fullbogons](#fullbogons)|3642|670590424|248319|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|33368|7.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|8388|4.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|7733|2.2%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|2449|2.6%|0.0%|
[blocklist_de](#blocklist_de)|21351|21351|1441|6.7%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14356|14356|1138|7.9%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12566|12566|1067|8.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|919|2.9%|0.0%|
[nixspam](#nixspam)|22222|22222|561|2.5%|0.0%|
[openbl_90d](#openbl_90d)|9797|9797|501|5.1%|0.0%|
[openbl](#openbl)|9797|9797|501|5.1%|0.0%|
[voipbl](#voipbl)|10327|10736|429|3.9%|0.0%|
[openbl_60d](#openbl_60d)|7680|7680|358|4.6%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6827|6827|241|3.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|230|0.4%|0.0%|
[et_tor](#et_tor)|6470|6470|184|2.8%|0.0%|
[dm_tor](#dm_tor)|6476|6476|183|2.8%|0.0%|
[bm_tor](#bm_tor)|6479|6479|183|2.8%|0.0%|
[openbl_30d](#openbl_30d)|3339|3339|180|5.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4892|4892|166|3.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3325|3325|142|4.2%|0.0%|
[et_compromised](#et_compromised)|2367|2367|140|5.9%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2253|2253|130|5.7%|0.0%|
[xroxy](#xroxy)|1963|1963|93|4.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1784|1784|90|5.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1859|1859|77|4.1%|0.0%|
[shunlist](#shunlist)|1188|1188|72|6.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|2000|2000|67|3.3%|0.0%|
[proxyrss](#proxyrss)|1476|1476|64|4.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|45|3.0%|0.0%|
[openbl_7d](#openbl_7d)|949|949|41|4.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|726|726|37|5.0%|0.0%|
[php_spammers](#php_spammers)|417|417|31|7.4%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1235|1235|30|2.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|28|4.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|26|2.0%|0.0%|
[malc0de](#malc0de)|407|407|25|6.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|312|312|24|7.6%|0.0%|
[ciarmy](#ciarmy)|355|355|22|6.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|21|5.6%|0.0%|
[et_botcc](#et_botcc)|501|501|21|4.1%|0.0%|
[proxz](#proxz)|247|247|10|4.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|10|2.3%|0.0%|
[openbl_1d](#openbl_1d)|220|220|10|4.5%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|259|259|10|3.8%|0.0%|
[zeus](#zeus)|263|263|9|3.4%|0.0%|
[php_commenters](#php_commenters)|281|281|9|3.2%|0.0%|
[php_bad](#php_bad)|281|281|9|3.2%|0.0%|
[zeus_badips](#zeus_badips)|229|229|8|3.4%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|91|91|8|8.7%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[sslbl](#sslbl)|349|349|6|1.7%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|193|193|6|3.1%|0.0%|
[feodo](#feodo)|71|71|3|4.2%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|

## ib_bluetack_level3

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 3 (for use in p2p). Many portal-type websites. ISP ranges that may be dodgy for some reason. Ranges that belong to an individual, but which have not been determined to be used by a particular company. Ranges for things that are unusual in some way. The L3 list is aka the paranoid list.

Source is downloaded from [this link](http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sat May 30 04:11:05 UTC 2015.

The ipset `ib_bluetack_level3` has **17802** entries, **139104824** unique IPs.

The following table shows the overlaps of `ib_bluetack_level3` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level3`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level3`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level3`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[fullbogons](#fullbogons)|3642|670590424|4233775|0.6%|3.0%|
[bogons](#bogons)|13|592708608|4194304|0.7%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2830140|0.8%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1354348|0.1%|0.9%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|270785|64.3%|0.1%|
[et_block](#et_block)|986|18056524|196184|1.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|195904|1.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|14896|8.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|9231|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|5991|6.4%|0.0%|
[blocklist_de](#blocklist_de)|21351|21351|2811|13.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14356|14356|2279|15.8%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12566|12566|2197|17.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|2081|6.7%|0.0%|
[nixspam](#nixspam)|22222|22222|1633|7.3%|0.0%|
[voipbl](#voipbl)|10327|10736|1588|14.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1172|2.4%|0.0%|
[openbl_90d](#openbl_90d)|9797|9797|944|9.6%|0.0%|
[openbl](#openbl)|9797|9797|944|9.6%|0.0%|
[openbl_60d](#openbl_60d)|7680|7680|722|9.4%|0.0%|
[et_tor](#et_tor)|6470|6470|619|9.5%|0.0%|
[dm_tor](#dm_tor)|6476|6476|614|9.4%|0.0%|
[bm_tor](#bm_tor)|6479|6479|614|9.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6827|6827|441|6.4%|0.0%|
[openbl_30d](#openbl_30d)|3339|3339|289|8.6%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[et_compromised](#et_compromised)|2367|2367|227|9.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2253|2253|218|9.6%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1784|1784|199|11.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3325|3325|176|5.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|2000|2000|164|8.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4892|4892|150|3.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|146|11.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|125|33.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|110|7.5%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1235|1235|100|8.0%|0.0%|
[openbl_7d](#openbl_7d)|949|949|94|9.9%|0.0%|
[shunlist](#shunlist)|1188|1188|89|7.4%|0.0%|
[xroxy](#xroxy)|1963|1963|79|4.0%|0.0%|
[malc0de](#malc0de)|407|407|74|18.1%|0.0%|
[et_botcc](#et_botcc)|501|501|74|14.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|726|726|65|8.9%|0.0%|
[proxyrss](#proxyrss)|1476|1476|63|4.2%|0.0%|
[ciarmy](#ciarmy)|355|355|58|16.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|51|7.5%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1859|1859|43|2.3%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|259|259|38|14.6%|0.0%|
[proxz](#proxz)|247|247|31|12.5%|0.0%|
[php_spammers](#php_spammers)|417|417|26|6.2%|0.0%|
[php_dictionary](#php_dictionary)|433|433|24|5.5%|0.0%|
[sslbl](#sslbl)|349|349|23|6.5%|0.0%|
[zeus](#zeus)|263|263|19|7.2%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|91|91|18|19.7%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|312|312|17|5.4%|0.0%|
[php_bad](#php_bad)|281|281|16|5.6%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|193|193|16|8.2%|0.0%|
[php_harvesters](#php_harvesters)|257|257|15|5.8%|0.0%|
[php_commenters](#php_commenters)|281|281|15|5.3%|0.0%|
[openbl_1d](#openbl_1d)|220|220|15|6.8%|0.0%|
[zeus_badips](#zeus_badips)|229|229|14|6.1%|0.0%|
[feodo](#feodo)|71|71|6|8.4%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|

## ib_bluetack_proxies

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Open Proxies IPs list (without TOR)

Source is downloaded from [this link](http://list.iblocklist.com/?list=xoebmbyexwuiogmbyprb&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sat May 30 04:10:23 UTC 2015.

The ipset `ib_bluetack_proxies` has **673** entries, **673** unique IPs.

The following table shows the overlaps of `ib_bluetack_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_proxies`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|58|0.0%|8.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|51|0.0%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|28|0.0%|4.1%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|22|0.0%|3.2%|
[xroxy](#xroxy)|1963|1963|13|0.6%|1.9%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|11|0.0%|1.6%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|11|0.0%|1.6%|
[ri_web_proxies](#ri_web_proxies)|4892|4892|10|0.2%|1.4%|
[proxyrss](#proxyrss)|1476|1476|7|0.4%|1.0%|
[ri_connect_proxies](#ri_connect_proxies)|1859|1859|6|0.3%|0.8%|
[blocklist_de](#blocklist_de)|21351|21351|5|0.0%|0.7%|
[blocklist_de_bots](#blocklist_de_bots)|3325|3325|4|0.1%|0.5%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|2|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.2%|
[et_block](#et_block)|986|18056524|2|0.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6827|6827|1|0.0%|0.1%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.1%|
[nixspam](#nixspam)|22222|22222|1|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|14356|14356|1|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|1|0.0%|0.1%|

## ib_bluetack_spyware

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) known malicious SPYWARE and ADWARE IP Address ranges

Source is downloaded from [this link](http://list.iblocklist.com/?list=llvtlsjyoyiczbkjsxpf&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sat May 30 03:40:09 UTC 2015.

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
[spamhaus_drop](#spamhaus_drop)|640|17925376|1037|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1036|0.0%|0.3%|
[fullbogons](#fullbogons)|3642|670590424|890|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|289|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|42|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|25|1.9%|0.0%|
[et_tor](#et_tor)|6470|6470|21|0.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|19|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|19|1.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|2000|2000|14|0.7%|0.0%|
[nixspam](#nixspam)|22222|22222|12|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6827|6827|10|0.1%|0.0%|
[openbl_90d](#openbl_90d)|9797|9797|6|0.0%|0.0%|
[openbl](#openbl)|9797|9797|6|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7680|7680|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|5|1.3%|0.0%|
[voipbl](#voipbl)|10327|10736|4|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4892|4892|4|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6476|6476|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6479|6479|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3339|3339|3|0.0%|0.0%|
[malc0de](#malc0de)|407|407|3|0.7%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|91|91|2|2.1%|0.0%|
[blocklist_de](#blocklist_de)|21351|21351|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|263|263|1|0.3%|0.0%|
[xroxy](#xroxy)|1963|1963|1|0.0%|0.0%|
[sslbl](#sslbl)|349|349|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[shunlist](#shunlist)|1188|1188|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|
[openbl_7d](#openbl_7d)|949|949|1|0.1%|0.0%|
[feodo](#feodo)|71|71|1|1.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2253|2253|1|0.0%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1784|1784|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14356|14356|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12566|12566|1|0.0%|0.0%|

## ib_bluetack_webexploit

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) web server hack and exploit attempts

Source is downloaded from [this link](http://list.iblocklist.com/?list=ghlzqtqxnzctvvajwwag&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sat May 30 03:40:10 UTC 2015.

The ipset `ib_bluetack_webexploit` has **1460** entries, **1460** unique IPs.

The following table shows the overlaps of `ib_bluetack_webexploit` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_webexploit`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_webexploit`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_webexploit`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|110|0.0%|7.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|97|0.0%|6.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|45|0.0%|3.0%|
[fullbogons](#fullbogons)|3642|670590424|33|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|19|0.0%|1.3%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|8|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|6|0.0%|0.4%|
[et_block](#et_block)|986|18056524|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|3|0.2%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|2|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|2|0.0%|0.1%|
[openbl_90d](#openbl_90d)|9797|9797|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7680|7680|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|3339|3339|2|0.0%|0.1%|
[openbl](#openbl)|9797|9797|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.1%|
[et_compromised](#et_compromised)|2367|2367|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6827|6827|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|2000|2000|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4892|4892|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|949|949|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[et_botcc](#et_botcc)|501|501|1|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2253|2253|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1784|1784|1|0.0%|0.0%|
[blocklist_de](#blocklist_de)|21351|21351|1|0.0%|0.0%|

## malc0de

[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days

Source is downloaded from [this link](http://malc0de.com/bl/IP_Blacklist.txt).

The last time downloaded was found to be dated: Sat May 30 13:17:03 UTC 2015.

The ipset `malc0de` has **407** entries, **407** unique IPs.

The following table shows the overlaps of `malc0de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `malc0de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `malc0de`.
- ` this % ` is the percentage **of this ipset (`malc0de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|74|0.0%|18.1%|
[cleanmx_viruses](#cleanmx_viruses)|259|259|28|10.8%|6.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|25|0.0%|6.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|12|0.0%|2.9%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|9|0.0%|2.2%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|4|0.3%|0.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.7%|
[et_block](#et_block)|986|18056524|3|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|2|0.0%|0.4%|
[dshield](#dshield)|20|5120|2|0.0%|0.4%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.2%|

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
[spamhaus_drop](#spamhaus_drop)|640|17925376|29|0.0%|2.2%|
[et_block](#et_block)|986|18056524|28|0.0%|2.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|26|0.0%|2.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|25|0.0%|1.9%|
[snort_ipfilter](#snort_ipfilter)|2000|2000|23|1.1%|1.7%|
[fullbogons](#fullbogons)|3642|670590424|9|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|7|0.0%|0.5%|
[malc0de](#malc0de)|407|407|4|0.9%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|3|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6827|6827|1|0.0%|0.0%|
[nixspam](#nixspam)|22222|22222|1|0.0%|0.0%|
[et_botcc](#et_botcc)|501|501|1|0.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|259|259|1|0.3%|0.0%|

## maxmind_proxy_fraud

[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.

Source is downloaded from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list).

The last time downloaded was found to be dated: Sat May 30 13:00:03 UTC 2015.

The ipset `maxmind_proxy_fraud` has **372** entries, **372** unique IPs.

The following table shows the overlaps of `maxmind_proxy_fraud` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `maxmind_proxy_fraud`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `maxmind_proxy_fraud`.
- ` this % ` is the percentage **of this ipset (`maxmind_proxy_fraud`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|237|0.2%|63.7%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|200|0.6%|53.7%|
[snort_ipfilter](#snort_ipfilter)|2000|2000|183|9.1%|49.1%|
[et_tor](#et_tor)|6470|6470|179|2.7%|48.1%|
[dm_tor](#dm_tor)|6476|6476|169|2.6%|45.4%|
[bm_tor](#bm_tor)|6479|6479|169|2.6%|45.4%|
[stopforumspam_1d](#stopforumspam_1d)|6827|6827|167|2.4%|44.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|125|0.0%|33.6%|
[php_commenters](#php_commenters)|281|281|28|9.9%|7.5%|
[php_bad](#php_bad)|281|281|28|9.9%|7.5%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|25|0.0%|6.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|21|0.0%|5.6%|
[openbl_90d](#openbl_90d)|9797|9797|18|0.1%|4.8%|
[openbl_60d](#openbl_60d)|7680|7680|18|0.2%|4.8%|
[openbl](#openbl)|9797|9797|18|0.1%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|17|0.0%|4.5%|
[php_harvesters](#php_harvesters)|257|257|6|2.3%|1.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|1.3%|
[ri_web_proxies](#ri_web_proxies)|4892|4892|4|0.0%|1.0%|
[php_spammers](#php_spammers)|417|417|4|0.9%|1.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|1.0%|
[blocklist_de](#blocklist_de)|21351|21351|3|0.0%|0.8%|
[shunlist](#shunlist)|1188|1188|2|0.1%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|12566|12566|2|0.0%|0.5%|
[xroxy](#xroxy)|1963|1963|1|0.0%|0.2%|
[voipbl](#voipbl)|10327|10736|1|0.0%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|1859|1859|1|0.0%|0.2%|
[nixspam](#nixspam)|22222|22222|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|14356|14356|1|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1235|1235|1|0.0%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3325|3325|1|0.0%|0.2%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Sat May 30 15:15:02 UTC 2015.

The ipset `nixspam` has **22222** entries, **22222** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1633|0.0%|7.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|561|0.0%|2.5%|
[blocklist_de](#blocklist_de)|21351|21351|518|2.4%|2.3%|
[blocklist_de_mail](#blocklist_de_mail)|14356|14356|468|3.2%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|281|0.0%|1.2%|
[et_block](#et_block)|986|18056524|234|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|233|0.0%|1.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|233|0.0%|1.0%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|221|0.2%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|133|0.4%|0.5%|
[php_dictionary](#php_dictionary)|433|433|81|18.7%|0.3%|
[ri_web_proxies](#ri_web_proxies)|4892|4892|79|1.6%|0.3%|
[xroxy](#xroxy)|1963|1963|70|3.5%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6827|6827|66|0.9%|0.2%|
[php_spammers](#php_spammers)|417|417|66|15.8%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3325|3325|38|1.1%|0.1%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|38|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|12|0.0%|0.0%|
[proxz](#proxz)|247|247|11|4.4%|0.0%|
[openbl_90d](#openbl_90d)|9797|9797|10|0.1%|0.0%|
[openbl_60d](#openbl_60d)|7680|7680|10|0.1%|0.0%|
[openbl](#openbl)|9797|9797|10|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|2000|2000|8|0.4%|0.0%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.0%|
[php_bad](#php_bad)|281|281|8|2.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|8|0.0%|0.0%|
[proxyrss](#proxyrss)|1476|1476|7|0.4%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1235|1235|7|0.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12566|12566|7|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1859|1859|6|0.3%|0.0%|
[dm_tor](#dm_tor)|6476|6476|6|0.0%|0.0%|
[bm_tor](#bm_tor)|6479|6479|6|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|5|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|4|1.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|312|312|4|1.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|193|193|3|1.5%|0.0%|
[voipbl](#voipbl)|10327|10736|2|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3339|3339|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|263|263|1|0.3%|0.0%|
[shunlist](#shunlist)|1188|1188|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2253|2253|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1784|1784|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|726|726|1|0.1%|0.0%|

## openbl

[OpenBL.org](http://www.openbl.org/) default blacklist (currently it is the same with 90 days). OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications - **excellent list**

Source is downloaded from [this link](http://www.openbl.org/lists/base.txt).

The last time downloaded was found to be dated: Sat May 30 11:32:00 UTC 2015.

The ipset `openbl` has **9797** entries, **9797** unique IPs.

The following table shows the overlaps of `openbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl`.
- ` this % ` is the percentage **of this ipset (`openbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9797|9797|9797|100.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|9772|5.5%|99.7%|
[openbl_60d](#openbl_60d)|7680|7680|7680|100.0%|78.3%|
[openbl_30d](#openbl_30d)|3339|3339|3339|100.0%|34.0%|
[et_compromised](#et_compromised)|2367|2367|1434|60.5%|14.6%|
[bruteforceblocker](#bruteforceblocker)|2253|2253|1378|61.1%|14.0%|
[blocklist_de](#blocklist_de)|21351|21351|993|4.6%|10.1%|
[openbl_7d](#openbl_7d)|949|949|949|100.0%|9.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|944|0.0%|9.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|1784|1784|910|51.0%|9.2%|
[shunlist](#shunlist)|1188|1188|604|50.8%|6.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|501|0.0%|5.1%|
[et_block](#et_block)|986|18056524|454|0.0%|4.6%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|449|0.0%|4.5%|
[openbl_1d](#openbl_1d)|220|220|216|98.1%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|216|0.0%|2.2%|
[dshield](#dshield)|20|5120|164|3.2%|1.6%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|63|0.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|14356|14356|60|0.4%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|726|726|52|7.1%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|193|193|49|25.3%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|29|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|2000|2000|24|1.2%|0.2%|
[et_tor](#et_tor)|6470|6470|21|0.3%|0.2%|
[dm_tor](#dm_tor)|6476|6476|21|0.3%|0.2%|
[bm_tor](#bm_tor)|6479|6479|21|0.3%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6827|6827|20|0.2%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|20|0.0%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|14|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12566|12566|12|0.0%|0.1%|
[voipbl](#voipbl)|10327|10736|11|0.1%|0.1%|
[nixspam](#nixspam)|22222|22222|10|0.0%|0.1%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.0%|
[php_bad](#php_bad)|281|281|8|2.8%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|312|312|7|2.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|6|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|5|1.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1235|1235|3|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3325|3325|3|0.0%|0.0%|
[zeus](#zeus)|263|263|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[xroxy](#xroxy)|1963|1963|1|0.0%|0.0%|
[sslbl](#sslbl)|349|349|1|0.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4892|4892|1|0.0%|0.0%|
[ciarmy](#ciarmy)|355|355|1|0.2%|0.0%|

## openbl_1d

[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_1days.txt).

The last time downloaded was found to be dated: Sat May 30 14:07:00 UTC 2015.

The ipset `openbl_1d` has **220** entries, **220** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9797|9797|216|2.2%|98.1%|
[openbl](#openbl)|9797|9797|216|2.2%|98.1%|
[openbl_60d](#openbl_60d)|7680|7680|215|2.7%|97.7%|
[openbl_30d](#openbl_30d)|3339|3339|215|6.4%|97.7%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|214|0.1%|97.2%|
[openbl_7d](#openbl_7d)|949|949|213|22.4%|96.8%|
[blocklist_de](#blocklist_de)|21351|21351|201|0.9%|91.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|1784|1784|194|10.8%|88.1%|
[shunlist](#shunlist)|1188|1188|125|10.5%|56.8%|
[bruteforceblocker](#bruteforceblocker)|2253|2253|118|5.2%|53.6%|
[et_compromised](#et_compromised)|2367|2367|115|4.8%|52.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|193|193|42|21.7%|19.0%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|18|0.0%|8.1%|
[et_block](#et_block)|986|18056524|18|0.0%|8.1%|
[dshield](#dshield)|20|5120|17|0.3%|7.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|6.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|10|0.0%|4.5%|
[blocklist_de_mail](#blocklist_de_mail)|14356|14356|6|0.0%|2.7%|
[blocklist_de_imap](#blocklist_de_imap)|726|726|5|0.6%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4|0.0%|1.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.3%|
[blocklist_de_ftp](#blocklist_de_ftp)|312|312|1|0.3%|0.4%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt).

The last time downloaded was found to be dated: Sat May 30 11:32:00 UTC 2015.

The ipset `openbl_30d` has **3339** entries, **3339** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9797|9797|3339|34.0%|100.0%|
[openbl_60d](#openbl_60d)|7680|7680|3339|43.4%|100.0%|
[openbl](#openbl)|9797|9797|3339|34.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|3325|1.9%|99.5%|
[et_compromised](#et_compromised)|2367|2367|1337|56.4%|40.0%|
[bruteforceblocker](#bruteforceblocker)|2253|2253|1299|57.6%|38.9%|
[openbl_7d](#openbl_7d)|949|949|949|100.0%|28.4%|
[blocklist_de](#blocklist_de)|21351|21351|870|4.0%|26.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1784|1784|810|45.4%|24.2%|
[shunlist](#shunlist)|1188|1188|579|48.7%|17.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|289|0.0%|8.6%|
[openbl_1d](#openbl_1d)|220|220|215|97.7%|6.4%|
[et_block](#et_block)|986|18056524|209|0.0%|6.2%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|205|0.0%|6.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|180|0.0%|5.3%|
[dshield](#dshield)|20|5120|147|2.8%|4.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|71|0.0%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|14356|14356|50|0.3%|1.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|193|193|46|23.8%|1.3%|
[blocklist_de_imap](#blocklist_de_imap)|726|726|44|6.0%|1.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|14|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|6|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12566|12566|6|0.0%|0.1%|
[voipbl](#voipbl)|10327|10736|4|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|3|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.0%|
[zeus](#zeus)|263|263|2|0.7%|0.0%|
[snort_ipfilter](#snort_ipfilter)|2000|2000|2|0.1%|0.0%|
[nixspam](#nixspam)|22222|22222|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|312|312|2|0.6%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6827|6827|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|355|355|1|0.2%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt).

The last time downloaded was found to be dated: Sat May 30 11:32:00 UTC 2015.

The ipset `openbl_60d` has **7680** entries, **7680** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9797|9797|7680|78.3%|100.0%|
[openbl](#openbl)|9797|9797|7680|78.3%|100.0%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|7658|4.3%|99.7%|
[openbl_30d](#openbl_30d)|3339|3339|3339|100.0%|43.4%|
[et_compromised](#et_compromised)|2367|2367|1419|59.9%|18.4%|
[bruteforceblocker](#bruteforceblocker)|2253|2253|1363|60.4%|17.7%|
[openbl_7d](#openbl_7d)|949|949|949|100.0%|12.3%|
[blocklist_de](#blocklist_de)|21351|21351|946|4.4%|12.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|1784|1784|871|48.8%|11.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|722|0.0%|9.4%|
[shunlist](#shunlist)|1188|1188|595|50.0%|7.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|358|0.0%|4.6%|
[et_block](#et_block)|986|18056524|241|0.0%|3.1%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|237|0.0%|3.0%|
[openbl_1d](#openbl_1d)|220|220|215|97.7%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|177|0.0%|2.3%|
[dshield](#dshield)|20|5120|163|3.1%|2.1%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|56|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|14356|14356|56|0.3%|0.7%|
[blocklist_de_imap](#blocklist_de_imap)|726|726|49|6.7%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|193|193|48|24.8%|0.6%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|27|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|2000|2000|24|1.2%|0.3%|
[et_tor](#et_tor)|6470|6470|21|0.3%|0.2%|
[dm_tor](#dm_tor)|6476|6476|21|0.3%|0.2%|
[bm_tor](#bm_tor)|6479|6479|21|0.3%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6827|6827|19|0.2%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|19|0.0%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.2%|
[nixspam](#nixspam)|22222|22222|10|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12566|12566|10|0.0%|0.1%|
[voipbl](#voipbl)|10327|10736|9|0.0%|0.1%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.1%|
[php_bad](#php_bad)|281|281|8|2.8%|0.1%|
[php_harvesters](#php_harvesters)|257|257|5|1.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|312|312|5|1.6%|0.0%|
[zeus](#zeus)|263|263|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3325|3325|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|355|355|1|0.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1235|1235|1|0.0%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt).

The last time downloaded was found to be dated: Sat May 30 11:32:00 UTC 2015.

The ipset `openbl_7d` has **949** entries, **949** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_90d](#openbl_90d)|9797|9797|949|9.6%|100.0%|
[openbl_60d](#openbl_60d)|7680|7680|949|12.3%|100.0%|
[openbl_30d](#openbl_30d)|3339|3339|949|28.4%|100.0%|
[openbl](#openbl)|9797|9797|949|9.6%|100.0%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|941|0.5%|99.1%|
[blocklist_de](#blocklist_de)|21351|21351|563|2.6%|59.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|1784|1784|525|29.4%|55.3%|
[bruteforceblocker](#bruteforceblocker)|2253|2253|506|22.4%|53.3%|
[et_compromised](#et_compromised)|2367|2367|504|21.2%|53.1%|
[shunlist](#shunlist)|1188|1188|371|31.2%|39.0%|
[openbl_1d](#openbl_1d)|220|220|213|96.8%|22.4%|
[dshield](#dshield)|20|5120|101|1.9%|10.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|94|0.0%|9.9%|
[et_block](#et_block)|986|18056524|85|0.0%|8.9%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|84|0.0%|8.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|193|193|45|23.3%|4.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|41|0.0%|4.3%|
[blocklist_de_mail](#blocklist_de_mail)|14356|14356|32|0.2%|3.3%|
[blocklist_de_imap](#blocklist_de_imap)|726|726|30|4.1%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|16|0.0%|1.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|1.1%|
[blocklist_de_apache](#blocklist_de_apache)|12566|12566|3|0.0%|0.3%|
[voipbl](#voipbl)|10327|10736|2|0.0%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|312|312|2|0.6%|0.2%|
[zeus](#zeus)|263|263|1|0.3%|0.1%|
[snort_ipfilter](#snort_ipfilter)|2000|2000|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.1%|
[ciarmy](#ciarmy)|355|355|1|0.2%|0.1%|

## openbl_90d

[OpenBL.org](http://www.openbl.org/) last 90 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_90days.txt).

The last time downloaded was found to be dated: Sat May 30 11:32:00 UTC 2015.

The ipset `openbl_90d` has **9797** entries, **9797** unique IPs.

The following table shows the overlaps of `openbl_90d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_90d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_90d`.
- ` this % ` is the percentage **of this ipset (`openbl_90d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl](#openbl)|9797|9797|9797|100.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|9772|5.5%|99.7%|
[openbl_60d](#openbl_60d)|7680|7680|7680|100.0%|78.3%|
[openbl_30d](#openbl_30d)|3339|3339|3339|100.0%|34.0%|
[et_compromised](#et_compromised)|2367|2367|1434|60.5%|14.6%|
[bruteforceblocker](#bruteforceblocker)|2253|2253|1378|61.1%|14.0%|
[blocklist_de](#blocklist_de)|21351|21351|993|4.6%|10.1%|
[openbl_7d](#openbl_7d)|949|949|949|100.0%|9.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|944|0.0%|9.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|1784|1784|910|51.0%|9.2%|
[shunlist](#shunlist)|1188|1188|604|50.8%|6.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|501|0.0%|5.1%|
[et_block](#et_block)|986|18056524|454|0.0%|4.6%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|449|0.0%|4.5%|
[openbl_1d](#openbl_1d)|220|220|216|98.1%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|216|0.0%|2.2%|
[dshield](#dshield)|20|5120|164|3.2%|1.6%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|63|0.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|14356|14356|60|0.4%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|726|726|52|7.1%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|193|193|49|25.3%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|29|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|2000|2000|24|1.2%|0.2%|
[et_tor](#et_tor)|6470|6470|21|0.3%|0.2%|
[dm_tor](#dm_tor)|6476|6476|21|0.3%|0.2%|
[bm_tor](#bm_tor)|6479|6479|21|0.3%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6827|6827|20|0.2%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|20|0.0%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|14|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|12566|12566|12|0.0%|0.1%|
[voipbl](#voipbl)|10327|10736|11|0.1%|0.1%|
[nixspam](#nixspam)|22222|22222|10|0.0%|0.1%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.0%|
[php_bad](#php_bad)|281|281|8|2.8%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|312|312|7|2.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|6|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|5|1.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1235|1235|3|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3325|3325|3|0.0%|0.0%|
[zeus](#zeus)|263|263|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[xroxy](#xroxy)|1963|1963|1|0.0%|0.0%|
[sslbl](#sslbl)|349|349|1|0.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|4892|4892|1|0.0%|0.0%|
[ciarmy](#ciarmy)|355|355|1|0.2%|0.0%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Sat May 30 15:00:21 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|986|18056524|13|0.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|2000|2000|11|0.5%|84.6%|
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
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|202|0.2%|71.8%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|180|0.5%|64.0%|
[stopforumspam_1d](#stopforumspam_1d)|6827|6827|102|1.4%|36.2%|
[blocklist_de](#blocklist_de)|21351|21351|65|0.3%|23.1%|
[blocklist_de_bots](#blocklist_de_bots)|3325|3325|50|1.5%|17.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|193|193|33|17.0%|11.7%|
[php_spammers](#php_spammers)|417|417|32|7.6%|11.3%|
[snort_ipfilter](#snort_ipfilter)|2000|2000|31|1.5%|11.0%|
[et_tor](#et_tor)|6470|6470|29|0.4%|10.3%|
[dm_tor](#dm_tor)|6476|6476|29|0.4%|10.3%|
[bm_tor](#bm_tor)|6479|6479|29|0.4%|10.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|28|7.5%|9.9%|
[blocklist_de_apache](#blocklist_de_apache)|12566|12566|26|0.2%|9.2%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|24|0.0%|8.5%|
[et_block](#et_block)|986|18056524|24|0.0%|8.5%|
[php_dictionary](#php_dictionary)|433|433|22|5.0%|7.8%|
[blocklist_de_mail](#blocklist_de_mail)|14356|14356|19|0.1%|6.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|16|0.0%|5.6%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|12|0.0%|4.2%|
[ri_web_proxies](#ri_web_proxies)|4892|4892|10|0.2%|3.5%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.2%|
[openbl_90d](#openbl_90d)|9797|9797|8|0.0%|2.8%|
[openbl_60d](#openbl_60d)|7680|7680|8|0.1%|2.8%|
[openbl](#openbl)|9797|9797|8|0.0%|2.8%|
[nixspam](#nixspam)|22222|22222|8|0.0%|2.8%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|7|0.0%|2.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1235|1235|6|0.4%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|1.7%|
[xroxy](#xroxy)|1963|1963|3|0.1%|1.0%|
[proxz](#proxz)|247|247|2|0.8%|0.7%|
[proxyrss](#proxyrss)|1476|1476|2|0.1%|0.7%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.3%|
[zeus](#zeus)|263|263|1|0.3%|0.3%|
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
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|203|0.2%|72.2%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|181|0.5%|64.4%|
[stopforumspam_1d](#stopforumspam_1d)|6827|6827|102|1.4%|36.2%|
[blocklist_de](#blocklist_de)|21351|21351|65|0.3%|23.1%|
[blocklist_de_bots](#blocklist_de_bots)|3325|3325|50|1.5%|17.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|193|193|33|17.0%|11.7%|
[php_spammers](#php_spammers)|417|417|32|7.6%|11.3%|
[snort_ipfilter](#snort_ipfilter)|2000|2000|31|1.5%|11.0%|
[et_tor](#et_tor)|6470|6470|29|0.4%|10.3%|
[dm_tor](#dm_tor)|6476|6476|29|0.4%|10.3%|
[bm_tor](#bm_tor)|6479|6479|29|0.4%|10.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|28|7.5%|9.9%|
[blocklist_de_apache](#blocklist_de_apache)|12566|12566|26|0.2%|9.2%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|24|0.0%|8.5%|
[et_block](#et_block)|986|18056524|24|0.0%|8.5%|
[php_dictionary](#php_dictionary)|433|433|22|5.0%|7.8%|
[blocklist_de_mail](#blocklist_de_mail)|14356|14356|19|0.1%|6.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|5.3%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|12|0.0%|4.2%|
[ri_web_proxies](#ri_web_proxies)|4892|4892|10|0.2%|3.5%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.2%|
[openbl_90d](#openbl_90d)|9797|9797|8|0.0%|2.8%|
[openbl_60d](#openbl_60d)|7680|7680|8|0.1%|2.8%|
[openbl](#openbl)|9797|9797|8|0.0%|2.8%|
[nixspam](#nixspam)|22222|22222|8|0.0%|2.8%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|7|0.0%|2.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1235|1235|6|0.4%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|1.7%|
[xroxy](#xroxy)|1963|1963|3|0.1%|1.0%|
[proxz](#proxz)|247|247|2|0.8%|0.7%|
[proxyrss](#proxyrss)|1476|1476|2|0.1%|0.7%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.3%|
[zeus](#zeus)|263|263|1|0.3%|0.3%|
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
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|81|0.0%|18.7%|
[nixspam](#nixspam)|22222|22222|81|0.3%|18.7%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|64|0.2%|14.7%|
[blocklist_de](#blocklist_de)|21351|21351|58|0.2%|13.3%|
[blocklist_de_mail](#blocklist_de_mail)|14356|14356|48|0.3%|11.0%|
[ri_web_proxies](#ri_web_proxies)|4892|4892|28|0.5%|6.4%|
[stopforumspam_1d](#stopforumspam_1d)|6827|6827|25|0.3%|5.7%|
[xroxy](#xroxy)|1963|1963|24|1.2%|5.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|24|0.0%|5.5%|
[php_commenters](#php_commenters)|281|281|22|7.8%|5.0%|
[php_bad](#php_bad)|281|281|22|7.8%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|10|0.0%|2.3%|
[blocklist_de_bots](#blocklist_de_bots)|3325|3325|10|0.3%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|9|0.0%|2.0%|
[snort_ipfilter](#snort_ipfilter)|2000|2000|7|0.3%|1.6%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|7|0.0%|1.6%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|4|0.0%|0.9%|
[proxz](#proxz)|247|247|4|1.6%|0.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.9%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.9%|
[et_block](#et_block)|986|18056524|4|0.0%|0.9%|
[ri_connect_proxies](#ri_connect_proxies)|1859|1859|3|0.1%|0.6%|
[dm_tor](#dm_tor)|6476|6476|3|0.0%|0.6%|
[bm_tor](#bm_tor)|6479|6479|3|0.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|193|193|2|1.0%|0.4%|
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
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|62|0.0%|24.1%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|47|0.1%|18.2%|
[stopforumspam_1d](#stopforumspam_1d)|6827|6827|33|0.4%|12.8%|
[blocklist_de](#blocklist_de)|21351|21351|27|0.1%|10.5%|
[blocklist_de_bots](#blocklist_de_bots)|3325|3325|22|0.6%|8.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|5.8%|
[php_commenters](#php_commenters)|281|281|9|3.2%|3.5%|
[php_bad](#php_bad)|281|281|9|3.2%|3.5%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|9|0.0%|3.5%|
[snort_ipfilter](#snort_ipfilter)|2000|2000|7|0.3%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|7|0.0%|2.7%|
[et_tor](#et_tor)|6470|6470|7|0.1%|2.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|6|1.6%|2.3%|
[dm_tor](#dm_tor)|6476|6476|6|0.0%|2.3%|
[bm_tor](#bm_tor)|6479|6479|6|0.0%|2.3%|
[openbl_90d](#openbl_90d)|9797|9797|5|0.0%|1.9%|
[openbl_60d](#openbl_60d)|7680|7680|5|0.0%|1.9%|
[openbl](#openbl)|9797|9797|5|0.0%|1.9%|
[nixspam](#nixspam)|22222|22222|4|0.0%|1.5%|
[blocklist_de_ftp](#blocklist_de_ftp)|312|312|4|1.2%|1.5%|
[xroxy](#xroxy)|1963|1963|2|0.1%|0.7%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|193|193|2|1.0%|0.7%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|1|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|1|0.0%|0.3%|
[ri_web_proxies](#ri_web_proxies)|4892|4892|1|0.0%|0.3%|
[proxyrss](#proxyrss)|1476|1476|1|0.0%|0.3%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.3%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|
[fullbogons](#fullbogons)|3642|670590424|1|0.0%|0.3%|
[et_block](#et_block)|986|18056524|1|0.0%|0.3%|
[bogons](#bogons)|13|592708608|1|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|14356|14356|1|0.0%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|12566|12566|1|0.0%|0.3%|

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
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|97|0.1%|23.2%|
[php_dictionary](#php_dictionary)|433|433|84|19.3%|20.1%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|66|0.2%|15.8%|
[nixspam](#nixspam)|22222|22222|66|0.2%|15.8%|
[blocklist_de](#blocklist_de)|21351|21351|54|0.2%|12.9%|
[blocklist_de_mail](#blocklist_de_mail)|14356|14356|35|0.2%|8.3%|
[php_commenters](#php_commenters)|281|281|32|11.3%|7.6%|
[php_bad](#php_bad)|281|281|32|11.3%|7.6%|
[stopforumspam_1d](#stopforumspam_1d)|6827|6827|31|0.4%|7.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|31|0.0%|7.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|26|0.0%|6.2%|
[ri_web_proxies](#ri_web_proxies)|4892|4892|23|0.4%|5.5%|
[xroxy](#xroxy)|1963|1963|18|0.9%|4.3%|
[blocklist_de_bots](#blocklist_de_bots)|3325|3325|13|0.3%|3.1%|
[snort_ipfilter](#snort_ipfilter)|2000|2000|8|0.4%|1.9%|
[et_tor](#et_tor)|6470|6470|6|0.0%|1.4%|
[dm_tor](#dm_tor)|6476|6476|6|0.0%|1.4%|
[bm_tor](#bm_tor)|6479|6479|6|0.0%|1.4%|
[proxz](#proxz)|247|247|5|2.0%|1.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|1.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1235|1235|5|0.4%|1.1%|
[blocklist_de_apache](#blocklist_de_apache)|12566|12566|5|0.0%|1.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|193|193|4|2.0%|0.9%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|3|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|2|0.0%|0.4%|
[ri_connect_proxies](#ri_connect_proxies)|1859|1859|2|0.1%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[et_block](#et_block)|986|18056524|2|0.0%|0.4%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1784|1784|1|0.0%|0.2%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Sat May 30 12:51:23 UTC 2015.

The ipset `proxyrss` has **1476** entries, **1476** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|792|0.8%|53.6%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|673|2.1%|45.5%|
[ri_web_proxies](#ri_web_proxies)|4892|4892|576|11.7%|39.0%|
[xroxy](#xroxy)|1963|1963|537|27.3%|36.3%|
[stopforumspam_1d](#stopforumspam_1d)|6827|6827|382|5.5%|25.8%|
[blocklist_de](#blocklist_de)|21351|21351|248|1.1%|16.8%|
[blocklist_de_bots](#blocklist_de_bots)|3325|3325|246|7.3%|16.6%|
[ri_connect_proxies](#ri_connect_proxies)|1859|1859|214|11.5%|14.4%|
[proxz](#proxz)|247|247|113|45.7%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|64|0.0%|4.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|63|0.0%|4.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|37|0.0%|2.5%|
[nixspam](#nixspam)|22222|22222|7|0.0%|0.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|7|1.0%|0.4%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|3|0.0%|0.2%|
[php_commenters](#php_commenters)|281|281|2|0.7%|0.1%|
[php_bad](#php_bad)|281|281|2|0.7%|0.1%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.1%|
[et_compromised](#et_compromised)|2367|2367|2|0.0%|0.1%|
[dm_tor](#dm_tor)|6476|6476|2|0.0%|0.1%|
[bruteforceblocker](#bruteforceblocker)|2253|2253|2|0.0%|0.1%|
[bm_tor](#bm_tor)|6479|6479|2|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|193|193|2|1.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|2000|2000|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1784|1784|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Sat May 30 12:51:28 UTC 2015.

The ipset `proxz` has **247** entries, **247** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|149|0.1%|60.3%|
[xroxy](#xroxy)|1963|1963|146|7.4%|59.1%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|134|0.4%|54.2%|
[proxyrss](#proxyrss)|1476|1476|113|7.6%|45.7%|
[ri_web_proxies](#ri_web_proxies)|4892|4892|111|2.2%|44.9%|
[blocklist_de](#blocklist_de)|21351|21351|72|0.3%|29.1%|
[stopforumspam_1d](#stopforumspam_1d)|6827|6827|63|0.9%|25.5%|
[blocklist_de_bots](#blocklist_de_bots)|3325|3325|62|1.8%|25.1%|
[ri_connect_proxies](#ri_connect_proxies)|1859|1859|36|1.9%|14.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|31|0.0%|12.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|13|0.0%|5.2%|
[nixspam](#nixspam)|22222|22222|11|0.0%|4.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|10|0.0%|4.0%|
[blocklist_de_mail](#blocklist_de_mail)|14356|14356|9|0.0%|3.6%|
[php_spammers](#php_spammers)|417|417|5|1.1%|2.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|1.6%|
[php_commenters](#php_commenters)|281|281|2|0.7%|0.8%|
[php_bad](#php_bad)|281|281|2|0.7%|0.8%|
[et_compromised](#et_compromised)|2367|2367|2|0.0%|0.8%|
[bruteforceblocker](#bruteforceblocker)|2253|2253|2|0.0%|0.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|193|193|2|1.0%|0.8%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|2|0.0%|0.8%|
[snort_ipfilter](#snort_ipfilter)|2000|2000|1|0.0%|0.4%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.4%|
[dm_tor](#dm_tor)|6476|6476|1|0.0%|0.4%|
[bm_tor](#bm_tor)|6479|6479|1|0.0%|0.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|1784|1784|1|0.0%|0.4%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Sat May 30 12:15:11 UTC 2015.

The ipset `ri_connect_proxies` has **1859** entries, **1859** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|1097|1.1%|59.0%|
[ri_web_proxies](#ri_web_proxies)|4892|4892|748|15.2%|40.2%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|699|2.2%|37.6%|
[xroxy](#xroxy)|1963|1963|300|15.2%|16.1%|
[proxyrss](#proxyrss)|1476|1476|214|14.4%|11.5%|
[stopforumspam_1d](#stopforumspam_1d)|6827|6827|144|2.1%|7.7%|
[blocklist_de](#blocklist_de)|21351|21351|79|0.3%|4.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|77|0.0%|4.1%|
[blocklist_de_bots](#blocklist_de_bots)|3325|3325|76|2.2%|4.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|64|0.0%|3.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|43|0.0%|2.3%|
[proxz](#proxz)|247|247|36|14.5%|1.9%|
[nixspam](#nixspam)|22222|22222|6|0.0%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.3%|
[php_dictionary](#php_dictionary)|433|433|3|0.6%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|14356|14356|3|0.0%|0.1%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.1%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.1%|
[dm_tor](#dm_tor)|6476|6476|2|0.0%|0.1%|
[bm_tor](#bm_tor)|6479|6479|2|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|2000|2000|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Sat May 30 13:43:59 UTC 2015.

The ipset `ri_web_proxies` has **4892** entries, **4892** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|2428|2.6%|49.6%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|1701|5.4%|34.7%|
[xroxy](#xroxy)|1963|1963|770|39.2%|15.7%|
[ri_connect_proxies](#ri_connect_proxies)|1859|1859|748|40.2%|15.2%|
[proxyrss](#proxyrss)|1476|1476|576|39.0%|11.7%|
[stopforumspam_1d](#stopforumspam_1d)|6827|6827|472|6.9%|9.6%|
[blocklist_de](#blocklist_de)|21351|21351|384|1.7%|7.8%|
[blocklist_de_bots](#blocklist_de_bots)|3325|3325|350|10.5%|7.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|166|0.0%|3.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|150|0.0%|3.0%|
[proxz](#proxz)|247|247|111|44.9%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|110|0.0%|2.2%|
[nixspam](#nixspam)|22222|22222|79|0.3%|1.6%|
[blocklist_de_mail](#blocklist_de_mail)|14356|14356|34|0.2%|0.6%|
[php_dictionary](#php_dictionary)|433|433|28|6.4%|0.5%|
[php_spammers](#php_spammers)|417|417|23|5.5%|0.4%|
[php_commenters](#php_commenters)|281|281|10|3.5%|0.2%|
[php_bad](#php_bad)|281|281|10|3.5%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|10|1.4%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6476|6476|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6479|6479|4|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|2000|2000|3|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|193|193|3|1.5%|0.0%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[openbl_90d](#openbl_90d)|9797|9797|1|0.0%|0.0%|
[openbl](#openbl)|9797|9797|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Sat May 30 14:30:05 UTC 2015.

The ipset `shunlist` has **1188** entries, **1188** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|174737|174737|1185|0.6%|99.7%|
[openbl_90d](#openbl_90d)|9797|9797|604|6.1%|50.8%|
[openbl](#openbl)|9797|9797|604|6.1%|50.8%|
[openbl_60d](#openbl_60d)|7680|7680|595|7.7%|50.0%|
[openbl_30d](#openbl_30d)|3339|3339|579|17.3%|48.7%|
[et_compromised](#et_compromised)|2367|2367|498|21.0%|41.9%|
[bruteforceblocker](#bruteforceblocker)|2253|2253|498|22.1%|41.9%|
[blocklist_de](#blocklist_de)|21351|21351|465|2.1%|39.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|1784|1784|425|23.8%|35.7%|
[openbl_7d](#openbl_7d)|949|949|371|39.0%|31.2%|
[dshield](#dshield)|20|5120|129|2.5%|10.8%|
[openbl_1d](#openbl_1d)|220|220|125|56.8%|10.5%|
[et_block](#et_block)|986|18056524|110|0.0%|9.2%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|101|0.0%|8.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|89|0.0%|7.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|72|0.0%|6.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|193|193|42|21.7%|3.5%|
[blocklist_de_apache](#blocklist_de_apache)|12566|12566|31|0.2%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|24|0.0%|2.0%|
[ciarmy](#ciarmy)|355|355|21|5.9%|1.7%|
[voipbl](#voipbl)|10327|10736|12|0.1%|1.0%|
[blocklist_de_mail](#blocklist_de_mail)|14356|14356|5|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|726|726|5|0.6%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|4|0.0%|0.3%|
[sslbl](#sslbl)|349|349|4|1.1%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|2000|2000|2|0.1%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1235|1235|2|0.1%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6827|6827|1|0.0%|0.0%|
[nixspam](#nixspam)|22222|22222|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6476|6476|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6479|6479|1|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|91|91|1|1.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|312|312|1|0.3%|0.0%|

## snort_ipfilter

[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)

Source is downloaded from [this link](http://labs.snort.org/feeds/ip-filter.blf).

The last time downloaded was found to be dated: Sat May 30 13:30:00 UTC 2015.

The ipset `snort_ipfilter` has **2000** entries, **2000** unique IPs.

The following table shows the overlaps of `snort_ipfilter` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `snort_ipfilter`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `snort_ipfilter`.
- ` this % ` is the percentage **of this ipset (`snort_ipfilter`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_tor](#et_tor)|6470|6470|1071|16.5%|53.5%|
[dm_tor](#dm_tor)|6476|6476|993|15.3%|49.6%|
[bm_tor](#bm_tor)|6479|6479|993|15.3%|49.6%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|636|0.6%|31.8%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|506|1.6%|25.3%|
[stopforumspam_1d](#stopforumspam_1d)|6827|6827|345|5.0%|17.2%|
[et_block](#et_block)|986|18056524|290|0.0%|14.5%|
[zeus](#zeus)|263|263|217|82.5%|10.8%|
[zeus_badips](#zeus_badips)|229|229|197|86.0%|9.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|183|49.1%|9.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|164|0.0%|8.2%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|110|0.0%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|67|0.0%|3.3%|
[feodo](#feodo)|71|71|53|74.6%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|49|0.0%|2.4%|
[php_commenters](#php_commenters)|281|281|31|11.0%|1.5%|
[php_bad](#php_bad)|281|281|31|11.0%|1.5%|
[blocklist_de](#blocklist_de)|21351|21351|25|0.1%|1.2%|
[openbl_90d](#openbl_90d)|9797|9797|24|0.2%|1.2%|
[openbl_60d](#openbl_60d)|7680|7680|24|0.3%|1.2%|
[openbl](#openbl)|9797|9797|24|0.2%|1.2%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|23|1.7%|1.1%|
[blocklist_de_apache](#blocklist_de_apache)|12566|12566|22|0.1%|1.1%|
[sslbl](#sslbl)|349|349|21|6.0%|1.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1235|1235|19|1.5%|0.9%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|18|0.0%|0.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|14|0.0%|0.7%|
[palevo](#palevo)|13|13|11|84.6%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.5%|
[php_spammers](#php_spammers)|417|417|8|1.9%|0.4%|
[nixspam](#nixspam)|22222|22222|8|0.0%|0.4%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.3%|
[php_dictionary](#php_dictionary)|433|433|7|1.6%|0.3%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|6|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|14356|14356|5|0.0%|0.2%|
[xroxy](#xroxy)|1963|1963|3|0.1%|0.1%|
[ri_web_proxies](#ri_web_proxies)|4892|4892|3|0.0%|0.1%|
[shunlist](#shunlist)|1188|1188|2|0.1%|0.1%|
[openbl_30d](#openbl_30d)|3339|3339|2|0.0%|0.1%|
[ri_connect_proxies](#ri_connect_proxies)|1859|1859|1|0.0%|0.0%|
[proxz](#proxz)|247|247|1|0.4%|0.0%|
[proxyrss](#proxyrss)|1476|1476|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|949|949|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|259|259|1|0.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2253|2253|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1784|1784|1|0.0%|0.0%|

## spamhaus_drop

[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**

Source is downloaded from [this link](http://www.spamhaus.org/drop/drop.txt).

The last time downloaded was found to be dated: Sat May 30 07:28:58 UTC 2015.

The ipset `spamhaus_drop` has **640** entries, **17925376** unique IPs.

The following table shows the overlaps of `spamhaus_drop` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `spamhaus_drop`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `spamhaus_drop`.
- ` this % ` is the percentage **of this ipset (`spamhaus_drop`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|986|18056524|17920256|99.2%|99.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8401434|2.4%|46.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7079936|77.1%|39.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|2133002|0.2%|11.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|195904|0.1%|1.0%|
[fullbogons](#fullbogons)|3642|670590424|20480|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|1626|0.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|744|0.8%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|512|0.1%|0.0%|
[dshield](#dshield)|20|5120|512|10.0%|0.0%|
[openbl_90d](#openbl_90d)|9797|9797|449|4.5%|0.0%|
[openbl](#openbl)|9797|9797|449|4.5%|0.0%|
[openbl_60d](#openbl_60d)|7680|7680|237|3.0%|0.0%|
[nixspam](#nixspam)|22222|22222|233|1.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|208|0.6%|0.0%|
[openbl_30d](#openbl_30d)|3339|3339|205|6.1%|0.0%|
[blocklist_de](#blocklist_de)|21351|21351|186|0.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1784|1784|108|6.0%|0.0%|
[et_compromised](#et_compromised)|2367|2367|102|4.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2253|2253|102|4.5%|0.0%|
[shunlist](#shunlist)|1188|1188|101|8.5%|0.0%|
[openbl_7d](#openbl_7d)|949|949|84|8.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3325|3325|52|1.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6827|6827|40|0.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|29|2.2%|0.0%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.0%|
[php_bad](#php_bad)|281|281|24|8.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14356|14356|21|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|2000|2000|18|0.9%|0.0%|
[openbl_1d](#openbl_1d)|220|220|18|8.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|16|6.9%|0.0%|
[zeus](#zeus)|263|263|16|6.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|726|726|16|2.2%|0.0%|
[voipbl](#voipbl)|10327|10736|14|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|193|193|6|3.1%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[sslbl](#sslbl)|349|349|3|0.8%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1235|1235|3|0.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12566|12566|3|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[malc0de](#malc0de)|407|407|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6476|6476|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6479|6479|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[et_botcc](#et_botcc)|501|501|1|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|91|91|1|1.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|312|312|1|0.3%|0.0%|

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
[spamhaus_drop](#spamhaus_drop)|640|17925376|512|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|106|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|45|0.1%|0.0%|
[blocklist_de](#blocklist_de)|21351|21351|16|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|15|0.0%|0.0%|
[openbl_90d](#openbl_90d)|9797|9797|14|0.1%|0.0%|
[openbl](#openbl)|9797|9797|14|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3325|3325|12|0.3%|0.0%|
[php_commenters](#php_commenters)|281|281|7|2.4%|0.0%|
[php_bad](#php_bad)|281|281|7|2.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6827|6827|6|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|2000|2000|6|0.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|193|193|6|3.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|5|2.1%|0.0%|
[zeus](#zeus)|263|263|5|1.9%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14356|14356|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12566|12566|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[openbl_60d](#openbl_60d)|7680|7680|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3339|3339|1|0.0%|0.0%|
[malc0de](#malc0de)|407|407|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Sat May 30 15:15:06 UTC 2015.

The ipset `sslbl` has **349** entries, **349** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|986|18056524|27|0.0%|7.7%|
[feodo](#feodo)|71|71|26|36.6%|7.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|23|0.0%|6.5%|
[snort_ipfilter](#snort_ipfilter)|2000|2000|21|1.0%|6.0%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|11|0.0%|3.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|6|0.0%|1.7%|
[shunlist](#shunlist)|1188|1188|4|0.3%|1.1%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|3|0.0%|0.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|1|0.0%|0.2%|
[openbl_90d](#openbl_90d)|9797|9797|1|0.0%|0.2%|
[openbl](#openbl)|9797|9797|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Sat May 30 15:00:02 UTC 2015.

The ipset `stopforumspam_1d` has **6827** entries, **6827** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|5131|5.5%|75.1%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|5059|16.3%|74.1%|
[blocklist_de](#blocklist_de)|21351|21351|1536|7.1%|22.4%|
[blocklist_de_bots](#blocklist_de_bots)|3325|3325|1452|43.6%|21.2%|
[ri_web_proxies](#ri_web_proxies)|4892|4892|472|9.6%|6.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|441|0.0%|6.4%|
[proxyrss](#proxyrss)|1476|1476|382|25.8%|5.5%|
[xroxy](#xroxy)|1963|1963|366|18.6%|5.3%|
[snort_ipfilter](#snort_ipfilter)|2000|2000|345|17.2%|5.0%|
[et_tor](#et_tor)|6470|6470|335|5.1%|4.9%|
[dm_tor](#dm_tor)|6476|6476|330|5.0%|4.8%|
[bm_tor](#bm_tor)|6479|6479|330|5.0%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|241|0.0%|3.5%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|167|44.8%|2.4%|
[ri_connect_proxies](#ri_connect_proxies)|1859|1859|144|7.7%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|135|0.0%|1.9%|
[php_commenters](#php_commenters)|281|281|102|36.2%|1.4%|
[php_bad](#php_bad)|281|281|102|36.2%|1.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|193|193|97|50.2%|1.4%|
[blocklist_de_apache](#blocklist_de_apache)|12566|12566|83|0.6%|1.2%|
[nixspam](#nixspam)|22222|22222|66|0.2%|0.9%|
[proxz](#proxz)|247|247|63|25.5%|0.9%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|57|0.0%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|14356|14356|52|0.3%|0.7%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|40|0.0%|0.5%|
[et_block](#et_block)|986|18056524|40|0.0%|0.5%|
[php_harvesters](#php_harvesters)|257|257|33|12.8%|0.4%|
[php_spammers](#php_spammers)|417|417|31|7.4%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1235|1235|31|2.5%|0.4%|
[php_dictionary](#php_dictionary)|433|433|25|5.7%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|23|0.0%|0.3%|
[openbl_90d](#openbl_90d)|9797|9797|20|0.2%|0.2%|
[openbl](#openbl)|9797|9797|20|0.2%|0.2%|
[openbl_60d](#openbl_60d)|7680|7680|19|0.2%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|10|0.0%|0.1%|
[dshield](#dshield)|20|5120|8|0.1%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|6|0.0%|0.0%|
[voipbl](#voipbl)|10327|10736|3|0.0%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|263|263|1|0.3%|0.0%|
[shunlist](#shunlist)|1188|1188|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3339|3339|1|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2253|2253|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|312|312|1|0.3%|0.0%|

## stopforumspam_30d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip).

The last time downloaded was found to be dated: Sat May 30 00:00:54 UTC 2015.

The ipset `stopforumspam_30d` has **92359** entries, **92359** unique IPs.

The following table shows the overlaps of `stopforumspam_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_30d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|30826|99.4%|33.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|5991|0.0%|6.4%|
[stopforumspam_1d](#stopforumspam_1d)|6827|6827|5131|75.1%|5.5%|
[blocklist_de](#blocklist_de)|21351|21351|2559|11.9%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2449|0.0%|2.6%|
[ri_web_proxies](#ri_web_proxies)|4892|4892|2428|49.6%|2.6%|
[blocklist_de_bots](#blocklist_de_bots)|3325|3325|2247|67.5%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1522|0.0%|1.6%|
[xroxy](#xroxy)|1963|1963|1135|57.8%|1.2%|
[ri_connect_proxies](#ri_connect_proxies)|1859|1859|1097|59.0%|1.1%|
[proxyrss](#proxyrss)|1476|1476|792|53.6%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|748|0.0%|0.8%|
[et_block](#et_block)|986|18056524|746|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|744|0.0%|0.8%|
[snort_ipfilter](#snort_ipfilter)|2000|2000|636|31.8%|0.6%|
[et_tor](#et_tor)|6470|6470|614|9.4%|0.6%|
[dm_tor](#dm_tor)|6476|6476|582|8.9%|0.6%|
[bm_tor](#bm_tor)|6479|6479|582|8.9%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|237|63.7%|0.2%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|226|0.1%|0.2%|
[nixspam](#nixspam)|22222|22222|221|0.9%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|14356|14356|218|1.5%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|12566|12566|215|1.7%|0.2%|
[php_commenters](#php_commenters)|281|281|203|72.2%|0.2%|
[php_bad](#php_bad)|281|281|202|71.8%|0.2%|
[proxz](#proxz)|247|247|149|60.3%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|193|193|130|67.3%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|106|0.0%|0.1%|
[php_spammers](#php_spammers)|417|417|97|23.2%|0.1%|
[php_dictionary](#php_dictionary)|433|433|81|18.7%|0.0%|
[openbl_90d](#openbl_90d)|9797|9797|63|0.6%|0.0%|
[openbl](#openbl)|9797|9797|63|0.6%|0.0%|
[php_harvesters](#php_harvesters)|257|257|62|24.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1235|1235|60|4.8%|0.0%|
[openbl_60d](#openbl_60d)|7680|7680|56|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|42|0.0%|0.0%|
[voipbl](#voipbl)|10327|10736|41|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|22|3.2%|0.0%|
[dshield](#dshield)|20|5120|16|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|15|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|312|312|11|3.5%|0.0%|
[openbl_30d](#openbl_30d)|3339|3339|6|0.1%|0.0%|
[et_compromised](#et_compromised)|2367|2367|6|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2253|2253|6|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1784|1784|5|0.2%|0.0%|
[shunlist](#shunlist)|1188|1188|4|0.3%|0.0%|
[zeus_badips](#zeus_badips)|229|229|3|1.3%|0.0%|
[zeus](#zeus)|263|263|3|1.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|3|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3642|670590424|2|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|726|726|2|0.2%|0.0%|
[sslbl](#sslbl)|349|349|1|0.2%|0.0%|
[ciarmy](#ciarmy)|355|355|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|

## stopforumspam_7d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip).

The last time downloaded was found to be dated: Sat May 30 02:02:03 UTC 2015.

The ipset `stopforumspam_7d` has **30993** entries, **30993** unique IPs.

The following table shows the overlaps of `stopforumspam_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_7d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|30826|33.3%|99.4%|
[stopforumspam_1d](#stopforumspam_1d)|6827|6827|5059|74.1%|16.3%|
[blocklist_de](#blocklist_de)|21351|21351|2235|10.4%|7.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2081|0.0%|6.7%|
[blocklist_de_bots](#blocklist_de_bots)|3325|3325|2053|61.7%|6.6%|
[ri_web_proxies](#ri_web_proxies)|4892|4892|1701|34.7%|5.4%|
[xroxy](#xroxy)|1963|1963|976|49.7%|3.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|919|0.0%|2.9%|
[ri_connect_proxies](#ri_connect_proxies)|1859|1859|699|37.6%|2.2%|
[proxyrss](#proxyrss)|1476|1476|673|45.5%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|563|0.0%|1.8%|
[snort_ipfilter](#snort_ipfilter)|2000|2000|506|25.3%|1.6%|
[et_tor](#et_tor)|6470|6470|485|7.4%|1.5%|
[dm_tor](#dm_tor)|6476|6476|464|7.1%|1.4%|
[bm_tor](#bm_tor)|6479|6479|464|7.1%|1.4%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|208|0.0%|0.6%|
[et_block](#et_block)|986|18056524|208|0.0%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|200|53.7%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|196|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|181|64.4%|0.5%|
[php_bad](#php_bad)|281|281|180|64.0%|0.5%|
[proxz](#proxz)|247|247|134|54.2%|0.4%|
[nixspam](#nixspam)|22222|22222|133|0.5%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|12566|12566|130|1.0%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|193|193|119|61.6%|0.3%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|114|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|14356|14356|113|0.7%|0.3%|
[php_spammers](#php_spammers)|417|417|66|15.8%|0.2%|
[php_dictionary](#php_dictionary)|433|433|64|14.7%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1235|1235|53|4.2%|0.1%|
[php_harvesters](#php_harvesters)|257|257|47|18.2%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|45|0.0%|0.1%|
[openbl_90d](#openbl_90d)|9797|9797|29|0.2%|0.0%|
[openbl](#openbl)|9797|9797|29|0.2%|0.0%|
[openbl_60d](#openbl_60d)|7680|7680|27|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|19|0.0%|0.0%|
[dshield](#dshield)|20|5120|13|0.2%|0.0%|
[voipbl](#voipbl)|10327|10736|11|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|5|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3339|3339|3|0.0%|0.0%|
[et_compromised](#et_compromised)|2367|2367|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2253|2253|3|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1784|1784|3|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|312|312|3|0.9%|0.0%|
[shunlist](#shunlist)|1188|1188|2|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|2|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|263|263|1|0.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|726|726|1|0.1%|0.0%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Sat May 30 15:27:07 UTC 2015.

The ipset `voipbl` has **10327** entries, **10736** unique IPs.

The following table shows the overlaps of `voipbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `voipbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `voipbl`.
- ` this % ` is the percentage **of this ipset (`voipbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1588|0.0%|14.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|429|0.0%|3.9%|
[fullbogons](#fullbogons)|3642|670590424|319|0.0%|2.9%|
[bogons](#bogons)|13|592708608|319|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|295|0.0%|2.7%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|209|0.1%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|41|0.0%|0.3%|
[blocklist_de](#blocklist_de)|21351|21351|41|0.1%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|91|91|32|35.1%|0.2%|
[et_block](#et_block)|986|18056524|17|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|14|0.0%|0.1%|
[shunlist](#shunlist)|1188|1188|12|1.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|11|0.0%|0.1%|
[openbl_90d](#openbl_90d)|9797|9797|11|0.1%|0.1%|
[openbl](#openbl)|9797|9797|11|0.1%|0.1%|
[openbl_60d](#openbl_60d)|7680|7680|9|0.1%|0.0%|
[openbl_30d](#openbl_30d)|3339|3339|4|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6827|6827|3|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1784|1784|3|0.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14356|14356|3|0.0%|0.0%|
[openbl_7d](#openbl_7d)|949|949|2|0.2%|0.0%|
[nixspam](#nixspam)|22222|22222|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[ciarmy](#ciarmy)|355|355|2|0.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|12566|12566|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6476|6476|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2253|2253|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6479|6479|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1235|1235|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3325|3325|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Sat May 30 14:33:01 UTC 2015.

The ipset `xroxy` has **1963** entries, **1963** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|1135|1.2%|57.8%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|976|3.1%|49.7%|
[ri_web_proxies](#ri_web_proxies)|4892|4892|770|15.7%|39.2%|
[proxyrss](#proxyrss)|1476|1476|537|36.3%|27.3%|
[stopforumspam_1d](#stopforumspam_1d)|6827|6827|366|5.3%|18.6%|
[ri_connect_proxies](#ri_connect_proxies)|1859|1859|300|16.1%|15.2%|
[blocklist_de](#blocklist_de)|21351|21351|289|1.3%|14.7%|
[blocklist_de_bots](#blocklist_de_bots)|3325|3325|245|7.3%|12.4%|
[proxz](#proxz)|247|247|146|59.1%|7.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|93|0.0%|4.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|79|0.0%|4.0%|
[nixspam](#nixspam)|22222|22222|70|0.3%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|54|0.0%|2.7%|
[blocklist_de_mail](#blocklist_de_mail)|14356|14356|43|0.2%|2.1%|
[php_dictionary](#php_dictionary)|433|433|24|5.5%|1.2%|
[php_spammers](#php_spammers)|417|417|18|4.3%|0.9%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|13|1.9%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|193|193|6|3.1%|0.3%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|5|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|2000|2000|3|0.1%|0.1%|
[php_commenters](#php_commenters)|281|281|3|1.0%|0.1%|
[php_bad](#php_bad)|281|281|3|1.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.1%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.1%|
[dm_tor](#dm_tor)|6476|6476|2|0.0%|0.1%|
[bm_tor](#bm_tor)|6479|6479|2|0.0%|0.1%|
[openbl_90d](#openbl_90d)|9797|9797|1|0.0%|0.0%|
[openbl](#openbl)|9797|9797|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2253|2253|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1784|1784|1|0.0%|0.0%|

## zeus

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist).

The last time downloaded was found to be dated: Sat May 30 14:07:54 UTC 2015.

The ipset `zeus` has **263** entries, **263** unique IPs.

The following table shows the overlaps of `zeus` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus`.
- ` this % ` is the percentage **of this ipset (`zeus`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|986|18056524|259|0.0%|98.4%|
[zeus_badips](#zeus_badips)|229|229|229|100.0%|87.0%|
[snort_ipfilter](#snort_ipfilter)|2000|2000|217|10.8%|82.5%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|64|0.0%|24.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|19|0.0%|7.2%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|16|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|3.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|7|0.0%|2.6%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|5|0.0%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|3|0.0%|1.1%|
[openbl_90d](#openbl_90d)|9797|9797|2|0.0%|0.7%|
[openbl_60d](#openbl_60d)|7680|7680|2|0.0%|0.7%|
[openbl_30d](#openbl_30d)|3339|3339|2|0.0%|0.7%|
[openbl](#openbl)|9797|9797|2|0.0%|0.7%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|1|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6827|6827|1|0.0%|0.3%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.3%|
[php_bad](#php_bad)|281|281|1|0.3%|0.3%|
[openbl_7d](#openbl_7d)|949|949|1|0.1%|0.3%|
[nixspam](#nixspam)|22222|22222|1|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.3%|
[cleanmx_viruses](#cleanmx_viruses)|259|259|1|0.3%|0.3%|
[bruteforceblocker](#bruteforceblocker)|2253|2253|1|0.0%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1235|1235|1|0.0%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|12566|12566|1|0.0%|0.3%|
[blocklist_de](#blocklist_de)|21351|21351|1|0.0%|0.3%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Sat May 30 15:00:20 UTC 2015.

The ipset `zeus_badips` has **229** entries, **229** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|263|263|229|87.0%|100.0%|
[et_block](#et_block)|986|18056524|228|0.0%|99.5%|
[snort_ipfilter](#snort_ipfilter)|2000|2000|197|9.8%|86.0%|
[alienvault_reputation](#alienvault_reputation)|174737|174737|37|0.0%|16.1%|
[spamhaus_drop](#spamhaus_drop)|640|17925376|16|0.0%|6.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14|0.0%|6.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8|0.0%|3.4%|
[spamhaus_edrop](#spamhaus_edrop)|55|421120|5|0.0%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4|0.0%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|92359|92359|3|0.0%|1.3%|
[stopforumspam_7d](#stopforumspam_7d)|30993|30993|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6827|6827|1|0.0%|0.4%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.4%|
[php_bad](#php_bad)|281|281|1|0.3%|0.4%|
[openbl_90d](#openbl_90d)|9797|9797|1|0.0%|0.4%|
[openbl_60d](#openbl_60d)|7680|7680|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|3339|3339|1|0.0%|0.4%|
[openbl](#openbl)|9797|9797|1|0.0%|0.4%|
[nixspam](#nixspam)|22222|22222|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.4%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.4%|
[cleanmx_viruses](#cleanmx_viruses)|259|259|1|0.3%|0.4%|
[bruteforceblocker](#bruteforceblocker)|2253|2253|1|0.0%|0.4%|
