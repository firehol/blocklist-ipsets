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

As time passes and the internet matures in our life, cyber crime is becoming increasingly sophisticated. Although there are many tools (detection of malware, viruses, intrusion detection and prevension systems, etc) to help us isolate the budguys, there are now a lot more than just such attacks.

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
   I asked them about poisoning. [Here](https://forum.blocklist.de/viewtopic.php?f=4&t=244&sid=847d00d26b0735add3518ff515242cad) you can find their answer. In short, they track it down so that they have an ignorable rate of false positives.
   Also, they only include individual IPs (no subnets) which have attacked their users the last 48 hours and their list contains 20.000 to 40.000 IPs (which is small enough considering the size of the internet).
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

The following list was automatically generated on Mon Jun  1 12:55:43 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|178278 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|22338 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|13824 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|3184 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|1396 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|86 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|526 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|14586 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|95 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|1660 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|159 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6479 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|2183 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|329 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|82 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6472 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|986 subnets, 18056524 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botcc](#et_botcc)|[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)|ipv4 hash:ip|501 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net](http://www.emergingthreats.net/) compromised hosts (seems to be a derivate of other lists)|ipv4 hash:ip|2367 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6470 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[feodo](#feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|76 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
[fullbogons](#fullbogons)|[Team-Cymru.org](http://www.team-cymru.org) IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user - **excellent list - use it only your internet interface**|ipv4 hash:net|3639 subnets, 670579672 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt)
[geolite2_country](https://github.com/ktsaou/blocklist-ipsets/tree/master/geolite2_country)|[MaxMind GeoLite2](http://dev.maxmind.com/geoip/geoip2/geolite2/) databases are free IP geolocation databases comparable to, but less accurate than, MaxMind’s GeoIP2 databases. They include IPs per country, IPs per continent, IPs used by anonymous services (VPNs, Proxies, etc) and Satellite Providers.|ipv4 hash:net|All the world|updated every 7 days  from [this link](http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country-CSV.zip)
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) IPs that have been reported for bad deeds in p2p|ipv4 hash:ip|48134 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=cwworuawihqvocglcoss&fileformat=p2p&archiveformat=gz)
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) hijacked IP-Blocks Hijacked IP space are IP blocks that are being used without permission|ipv4 hash:net|535 subnets, 9177856 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=usrcshglbiilevmyfhse&fileformat=p2p&archiveformat=gz)
[ib_bluetack_level1](#ib_bluetack_level1)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Level 1 (for use in p2p): Companies or organizations who are clearly involved with trying to stop filesharing (e.g. Baytsp, MediaDefender, Mediasentry a.o.). Companies which anti-p2p activity has been seen from. Companies that produce or have a strong financial interest in copyrighted material (e.g. music, movie, software industries a.o.). Government ranges or companies that have a strong financial interest in doing work for governments. Legal industry ranges. IPs or ranges of ISPs from which anti-p2p activity has been observed. Basically this list will block all kinds of internet connections that most people would rather not have during their internet travels.|ipv4 hash:net|218309 subnets, 764987411 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz)
[ib_bluetack_level2](#ib_bluetack_level2)|[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 2 (for use in p2p). General corporate ranges. Ranges used by labs or researchers. Proxies.|ipv4 hash:net|72774 subnets, 348707599 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw&fileformat=p2p&archiveformat=gz)
[ib_bluetack_level3](#ib_bluetack_level3)|[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 3 (for use in p2p). Many portal-type websites. ISP ranges that may be dodgy for some reason. Ranges that belong to an individual, but which have not been determined to be used by a particular company. Ranges for things that are unusual in some way. The L3 list is aka the paranoid list.|ipv4 hash:net|17802 subnets, 139104824 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh&fileformat=p2p&archiveformat=gz)
[ib_bluetack_proxies](#ib_bluetack_proxies)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Open Proxies IPs list (without TOR)|ipv4 hash:ip|673 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=xoebmbyexwuiogmbyprb&fileformat=p2p&archiveformat=gz)
[ib_bluetack_spyware](#ib_bluetack_spyware)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) known malicious SPYWARE and ADWARE IP Address ranges|ipv4 hash:net|3274 subnets, 339192 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=llvtlsjyoyiczbkjsxpf&fileformat=p2p&archiveformat=gz)
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) web server hack and exploit attempts|ipv4 hash:ip|1460 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=ghlzqtqxnzctvvajwwag&fileformat=p2p&archiveformat=gz)
[malc0de](#malc0de)|[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days|ipv4 hash:ip|403 unique IPs|updated every 1 day  from [this link](http://malc0de.com/bl/IP_Blacklist.txt)
[malwaredomainlist](#malwaredomainlist)|[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses|ipv4 hash:ip|1282 unique IPs|updated every 12 hours  from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt)
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.|ipv4 hash:ip|372 unique IPs|updated every 4 hours  from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list)
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|21248 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|137 unique IPs|updated every 1 hour  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|3201 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7590 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|901 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|281 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|433 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|257 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|417 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1460 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|433 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2014 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|5426 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1262 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|714 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|652 subnets, 18338560 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|56 subnets, 421632 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|360 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|6939 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|92062 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|31333 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10343 subnets, 10752 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2011 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|265 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|230 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Mon Jun  1 10:00:42 UTC 2015.

The ipset `alienvault_reputation` has **178278** entries, **178278** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14381|0.0%|8.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8137|0.0%|4.5%|
[openbl_60d](#openbl_60d)|7590|7590|7562|99.6%|4.2%|
[et_block](#et_block)|986|18056524|5787|0.0%|3.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4437|0.0%|2.4%|
[dshield](#dshield)|20|5120|3587|70.0%|2.0%|
[openbl_30d](#openbl_30d)|3201|3201|3181|99.3%|1.7%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1627|0.0%|0.9%|
[et_compromised](#et_compromised)|2367|2367|1541|65.1%|0.8%|
[bruteforceblocker](#bruteforceblocker)|2183|2183|1409|64.5%|0.7%|
[shunlist](#shunlist)|1262|1262|1255|99.4%|0.7%|
[blocklist_de](#blocklist_de)|22338|22338|1146|5.1%|0.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|1660|1660|895|53.9%|0.5%|
[openbl_7d](#openbl_7d)|901|901|887|98.4%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|518|0.0%|0.2%|
[ciarmy](#ciarmy)|329|329|324|98.4%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|288|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|271|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|219|0.2%|0.1%|
[voipbl](#voipbl)|10343|10752|209|1.9%|0.1%|
[openbl_1d](#openbl_1d)|137|137|127|92.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13824|13824|117|0.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|111|0.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14586|14586|82|0.5%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|76|10.6%|0.0%|
[zeus](#zeus)|265|265|65|24.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6939|6939|65|0.9%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|526|526|58|11.0%|0.0%|
[sslbl](#sslbl)|360|360|51|14.1%|0.0%|
[et_tor](#et_tor)|6470|6470|47|0.7%|0.0%|
[dm_tor](#dm_tor)|6472|6472|45|0.6%|0.0%|
[bm_tor](#bm_tor)|6479|6479|45|0.6%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3184|3184|39|1.2%|0.0%|
[zeus_badips](#zeus_badips)|230|230|37|16.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|37|23.2%|0.0%|
[nixspam](#nixspam)|21248|21248|34|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|25|6.7%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|95|95|19|20.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[php_commenters](#php_commenters)|281|281|13|4.6%|0.0%|
[malc0de](#malc0de)|403|403|12|2.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1396|1396|11|0.7%|0.0%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|8|0.5%|0.0%|
[php_dictionary](#php_dictionary)|433|433|7|1.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|6|0.4%|0.0%|
[xroxy](#xroxy)|2011|2011|5|0.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|86|86|5|5.8%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5426|5426|3|0.0%|0.0%|
[proxyrss](#proxyrss)|1460|1460|3|0.2%|0.0%|
[php_spammers](#php_spammers)|417|417|3|0.7%|0.0%|
[et_botcc](#et_botcc)|501|501|3|0.5%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2014|2014|2|0.0%|0.0%|
[proxz](#proxz)|433|433|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[feodo](#feodo)|76|76|1|1.3%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|82|82|1|1.2%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Mon Jun  1 12:42:04 UTC 2015.

The ipset `blocklist_de` has **22338** entries, **22338** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|14586|14586|14586|100.0%|65.2%|
[blocklist_de_apache](#blocklist_de_apache)|13824|13824|13819|99.9%|61.8%|
[blocklist_de_bots](#blocklist_de_bots)|3184|3184|3173|99.6%|14.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2796|0.0%|12.5%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|2217|2.4%|9.9%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|1954|6.2%|8.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|1660|1660|1656|99.7%|7.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1453|0.0%|6.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1432|0.0%|6.4%|
[stopforumspam_1d](#stopforumspam_1d)|6939|6939|1404|20.2%|6.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1396|1396|1396|100.0%|6.2%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|1146|0.6%|5.1%|
[openbl_60d](#openbl_60d)|7590|7590|849|11.1%|3.8%|
[openbl_30d](#openbl_30d)|3201|3201|776|24.2%|3.4%|
[bruteforceblocker](#bruteforceblocker)|2183|2183|728|33.3%|3.2%|
[et_compromised](#et_compromised)|2367|2367|655|27.6%|2.9%|
[openbl_7d](#openbl_7d)|901|901|528|58.6%|2.3%|
[blocklist_de_imap](#blocklist_de_imap)|526|526|526|100.0%|2.3%|
[nixspam](#nixspam)|21248|21248|483|2.2%|2.1%|
[shunlist](#shunlist)|1262|1262|418|33.1%|1.8%|
[ri_web_proxies](#ri_web_proxies)|5426|5426|346|6.3%|1.5%|
[xroxy](#xroxy)|2011|2011|235|11.6%|1.0%|
[proxyrss](#proxyrss)|1460|1460|223|15.2%|0.9%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|175|0.0%|0.7%|
[et_block](#et_block)|986|18056524|174|0.0%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|159|100.0%|0.7%|
[openbl_1d](#openbl_1d)|137|137|119|86.8%|0.5%|
[blocklist_de_ftp](#blocklist_de_ftp)|86|86|86|100.0%|0.3%|
[proxz](#proxz)|433|433|85|19.6%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|95|95|76|80.0%|0.3%|
[php_commenters](#php_commenters)|281|281|62|22.0%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2014|2014|59|2.9%|0.2%|
[dshield](#dshield)|20|5120|55|1.0%|0.2%|
[php_dictionary](#php_dictionary)|433|433|45|10.3%|0.2%|
[php_spammers](#php_spammers)|417|417|44|10.5%|0.1%|
[ciarmy](#ciarmy)|329|329|42|12.7%|0.1%|
[voipbl](#voipbl)|10343|10752|40|0.3%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|40|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|24|9.3%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|7|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|6|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6472|6472|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6479|6479|3|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|1|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Mon Jun  1 12:28:08 UTC 2015.

The ipset `blocklist_de_apache` has **13824** entries, **13824** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22338|22338|13819|61.8%|99.9%|
[blocklist_de_mail](#blocklist_de_mail)|14586|14586|11059|75.8%|79.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2209|0.0%|15.9%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1396|1396|1396|100.0%|10.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1316|0.0%|9.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1066|0.0%|7.7%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|200|0.2%|1.4%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|124|0.3%|0.8%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|117|0.0%|0.8%|
[stopforumspam_1d](#stopforumspam_1d)|6939|6939|62|0.8%|0.4%|
[ciarmy](#ciarmy)|329|329|36|10.9%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|34|21.3%|0.2%|
[shunlist](#shunlist)|1262|1262|29|2.2%|0.2%|
[php_commenters](#php_commenters)|281|281|22|7.8%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3184|3184|21|0.6%|0.1%|
[nixspam](#nixspam)|21248|21248|10|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[voipbl](#voipbl)|10343|10752|5|0.0%|0.0%|
[et_block](#et_block)|986|18056524|4|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7590|7590|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3201|3201|3|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[et_compromised](#et_compromised)|2367|2367|3|0.1%|0.0%|
[dm_tor](#dm_tor)|6472|6472|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2183|2183|3|0.1%|0.0%|
[bm_tor](#bm_tor)|6479|6479|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[xroxy](#xroxy)|2011|2011|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5426|5426|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2014|2014|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[openbl_7d](#openbl_7d)|901|901|1|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Mon Jun  1 12:28:10 UTC 2015.

The ipset `blocklist_de_bots` has **3184** entries, **3184** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22338|22338|3173|14.2%|99.6%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|1963|2.1%|61.6%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|1800|5.7%|56.5%|
[stopforumspam_1d](#stopforumspam_1d)|6939|6939|1348|19.4%|42.3%|
[ri_web_proxies](#ri_web_proxies)|5426|5426|322|5.9%|10.1%|
[proxyrss](#proxyrss)|1460|1460|224|15.3%|7.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|210|0.0%|6.5%|
[xroxy](#xroxy)|2011|2011|208|10.3%|6.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|195|0.0%|6.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|109|68.5%|3.4%|
[proxz](#proxz)|433|433|75|17.3%|2.3%|
[ri_connect_proxies](#ri_connect_proxies)|2014|2014|57|2.8%|1.7%|
[php_commenters](#php_commenters)|281|281|53|18.8%|1.6%|
[nixspam](#nixspam)|21248|21248|43|0.2%|1.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|40|0.0%|1.2%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|39|0.0%|1.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|33|0.0%|1.0%|
[et_block](#et_block)|986|18056524|33|0.0%|1.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|31|0.0%|0.9%|
[php_dictionary](#php_dictionary)|433|433|21|4.8%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|14586|14586|21|0.1%|0.6%|
[blocklist_de_apache](#blocklist_de_apache)|13824|13824|21|0.1%|0.6%|
[php_harvesters](#php_harvesters)|257|257|19|7.3%|0.5%|
[openbl_60d](#openbl_60d)|7590|7590|14|0.1%|0.4%|
[php_spammers](#php_spammers)|417|417|12|2.8%|0.3%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|5|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[voipbl](#voipbl)|10343|10752|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3201|3201|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2183|2183|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Mon Jun  1 12:42:13 UTC 2015.

The ipset `blocklist_de_bruteforce` has **1396** entries, **1396** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_apache](#blocklist_de_apache)|13824|13824|1396|10.0%|100.0%|
[blocklist_de](#blocklist_de)|22338|22338|1396|6.2%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|109|0.0%|7.8%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|35|0.0%|2.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|33|0.0%|2.3%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|30|0.0%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|27|0.0%|1.9%|
[stopforumspam_1d](#stopforumspam_1d)|6939|6939|19|0.2%|1.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|13|8.1%|0.9%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|11|0.0%|0.7%|
[nixspam](#nixspam)|21248|21248|9|0.0%|0.6%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.4%|
[php_commenters](#php_commenters)|281|281|4|1.4%|0.2%|
[et_block](#et_block)|986|18056524|3|0.0%|0.2%|
[voipbl](#voipbl)|10343|10752|2|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.1%|
[xroxy](#xroxy)|2011|2011|1|0.0%|0.0%|
[shunlist](#shunlist)|1262|1262|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5426|5426|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2014|2014|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Mon Jun  1 12:42:10 UTC 2015.

The ipset `blocklist_de_ftp` has **86** entries, **86** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22338|22338|86|0.3%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|6|0.0%|6.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|6|0.0%|6.9%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|5|0.0%|5.8%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|5|0.0%|5.8%|
[openbl_60d](#openbl_60d)|7590|7590|4|0.0%|4.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|4|0.0%|4.6%|
[php_harvesters](#php_harvesters)|257|257|3|1.1%|3.4%|
[openbl_30d](#openbl_30d)|3201|3201|3|0.0%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|2|0.0%|2.3%|
[stopforumspam_1d](#stopforumspam_1d)|6939|6939|1|0.0%|1.1%|
[shunlist](#shunlist)|1262|1262|1|0.0%|1.1%|
[openbl_7d](#openbl_7d)|901|901|1|0.1%|1.1%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|1.1%|
[dshield](#dshield)|20|5120|1|0.0%|1.1%|
[bruteforceblocker](#bruteforceblocker)|2183|2183|1|0.0%|1.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|1|0.6%|1.1%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Mon Jun  1 12:28:09 UTC 2015.

The ipset `blocklist_de_imap` has **526** entries, **526** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22338|22338|526|2.3%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|14586|14586|525|3.5%|99.8%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|58|0.0%|11.0%|
[openbl_60d](#openbl_60d)|7590|7590|36|0.4%|6.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|33|0.0%|6.2%|
[openbl_30d](#openbl_30d)|3201|3201|32|0.9%|6.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|29|0.0%|5.5%|
[openbl_7d](#openbl_7d)|901|901|18|1.9%|3.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|17|0.0%|3.2%|
[et_block](#et_block)|986|18056524|17|0.0%|3.2%|
[et_compromised](#et_compromised)|2367|2367|10|0.4%|1.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|8|0.0%|1.5%|
[bruteforceblocker](#bruteforceblocker)|2183|2183|6|0.2%|1.1%|
[shunlist](#shunlist)|1262|1262|5|0.3%|0.9%|
[openbl_1d](#openbl_1d)|137|137|3|2.1%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.5%|
[nixspam](#nixspam)|21248|21248|2|0.0%|0.3%|
[ciarmy](#ciarmy)|329|329|2|0.6%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|2|1.2%|0.3%|
[voipbl](#voipbl)|10343|10752|1|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|1|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|1|0.0%|0.1%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Mon Jun  1 12:42:08 UTC 2015.

The ipset `blocklist_de_mail` has **14586** entries, **14586** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22338|22338|14586|65.2%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|13824|13824|11059|79.9%|75.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2246|0.0%|15.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1321|0.0%|9.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1116|0.0%|7.6%|
[blocklist_de_imap](#blocklist_de_imap)|526|526|525|99.8%|3.5%|
[nixspam](#nixspam)|21248|21248|425|2.0%|2.9%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|202|0.2%|1.3%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|117|0.3%|0.8%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|82|0.0%|0.5%|
[openbl_60d](#openbl_60d)|7590|7590|45|0.5%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6939|6939|43|0.6%|0.2%|
[openbl_30d](#openbl_30d)|3201|3201|39|1.2%|0.2%|
[xroxy](#xroxy)|2011|2011|26|1.2%|0.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|25|0.0%|0.1%|
[openbl_7d](#openbl_7d)|901|901|25|2.7%|0.1%|
[et_block](#et_block)|986|18056524|25|0.0%|0.1%|
[php_spammers](#php_spammers)|417|417|24|5.7%|0.1%|
[ri_web_proxies](#ri_web_proxies)|5426|5426|23|0.4%|0.1%|
[php_dictionary](#php_dictionary)|433|433|23|5.3%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3184|3184|21|0.6%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|19|11.9%|0.1%|
[php_commenters](#php_commenters)|281|281|17|6.0%|0.1%|
[et_compromised](#et_compromised)|2367|2367|12|0.5%|0.0%|
[proxz](#proxz)|433|433|9|2.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2183|2183|8|0.3%|0.0%|
[shunlist](#shunlist)|1262|1262|6|0.4%|0.0%|
[openbl_1d](#openbl_1d)|137|137|3|2.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6472|6472|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6479|6479|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[ciarmy](#ciarmy)|329|329|2|0.6%|0.0%|
[voipbl](#voipbl)|10343|10752|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2014|2014|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1660|1660|1|0.0%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Mon Jun  1 12:42:10 UTC 2015.

The ipset `blocklist_de_sip` has **95** entries, **95** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22338|22338|76|0.3%|80.0%|
[voipbl](#voipbl)|10343|10752|31|0.2%|32.6%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|19|0.0%|20.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|15.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|10|0.0%|10.5%|
[nixspam](#nixspam)|21248|21248|2|0.0%|2.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|2|0.0%|2.1%|
[shunlist](#shunlist)|1262|1262|1|0.0%|1.0%|
[et_botcc](#et_botcc)|501|501|1|0.1%|1.0%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Mon Jun  1 12:28:05 UTC 2015.

The ipset `blocklist_de_ssh` has **1660** entries, **1660** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22338|22338|1656|7.4%|99.7%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|895|0.5%|53.9%|
[openbl_60d](#openbl_60d)|7590|7590|782|10.3%|47.1%|
[openbl_30d](#openbl_30d)|3201|3201|729|22.7%|43.9%|
[bruteforceblocker](#bruteforceblocker)|2183|2183|713|32.6%|42.9%|
[et_compromised](#et_compromised)|2367|2367|636|26.8%|38.3%|
[openbl_7d](#openbl_7d)|901|901|502|55.7%|30.2%|
[shunlist](#shunlist)|1262|1262|381|30.1%|22.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|187|0.0%|11.2%|
[openbl_1d](#openbl_1d)|137|137|116|84.6%|6.9%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|115|0.0%|6.9%|
[et_block](#et_block)|986|18056524|112|0.0%|6.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|88|0.0%|5.3%|
[dshield](#dshield)|20|5120|52|1.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|32|0.0%|1.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|28|17.6%|1.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6|0.0%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|5|0.0%|0.3%|
[ciarmy](#ciarmy)|329|329|4|1.2%|0.2%|
[voipbl](#voipbl)|10343|10752|2|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|2|0.0%|0.1%|
[xroxy](#xroxy)|2011|2011|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|1|0.1%|0.0%|
[proxz](#proxz)|433|433|1|0.2%|0.0%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.0%|
[nixspam](#nixspam)|21248|21248|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14586|14586|1|0.0%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Mon Jun  1 12:28:11 UTC 2015.

The ipset `blocklist_de_strongips` has **159** entries, **159** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22338|22338|159|0.7%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|112|0.1%|70.4%|
[blocklist_de_bots](#blocklist_de_bots)|3184|3184|109|3.4%|68.5%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|103|0.3%|64.7%|
[stopforumspam_1d](#stopforumspam_1d)|6939|6939|93|1.3%|58.4%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|37|0.0%|23.2%|
[blocklist_de_apache](#blocklist_de_apache)|13824|13824|34|0.2%|21.3%|
[php_commenters](#php_commenters)|281|281|29|10.3%|18.2%|
[openbl_60d](#openbl_60d)|7590|7590|28|0.3%|17.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|1660|1660|28|1.6%|17.6%|
[openbl_30d](#openbl_30d)|3201|3201|25|0.7%|15.7%|
[openbl_7d](#openbl_7d)|901|901|24|2.6%|15.0%|
[shunlist](#shunlist)|1262|1262|20|1.5%|12.5%|
[blocklist_de_mail](#blocklist_de_mail)|14586|14586|19|0.1%|11.9%|
[openbl_1d](#openbl_1d)|137|137|17|12.4%|10.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|16|0.0%|10.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1396|1396|13|0.9%|8.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|6|0.0%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|6|0.0%|3.7%|
[et_block](#et_block)|986|18056524|6|0.0%|3.7%|
[xroxy](#xroxy)|2011|2011|5|0.2%|3.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|4|0.0%|2.5%|
[ri_web_proxies](#ri_web_proxies)|5426|5426|4|0.0%|2.5%|
[proxyrss](#proxyrss)|1460|1460|4|0.2%|2.5%|
[php_spammers](#php_spammers)|417|417|4|0.9%|2.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.8%|
[proxz](#proxz)|433|433|2|0.4%|1.2%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|1.2%|
[nixspam](#nixspam)|21248|21248|2|0.0%|1.2%|
[blocklist_de_imap](#blocklist_de_imap)|526|526|2|0.3%|1.2%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.6%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1|0.0%|0.6%|
[dshield](#dshield)|20|5120|1|0.0%|0.6%|
[blocklist_de_ftp](#blocklist_de_ftp)|86|86|1|1.1%|0.6%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Mon Jun  1 12:36:19 UTC 2015.

The ipset `bm_tor` has **6479** entries, **6479** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[dm_tor](#dm_tor)|6472|6472|6399|98.8%|98.7%|
[et_tor](#et_tor)|6470|6470|5448|84.2%|84.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|624|0.0%|9.6%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|617|0.6%|9.5%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|476|1.5%|7.3%|
[stopforumspam_1d](#stopforumspam_1d)|6939|6939|290|4.1%|4.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|195|0.0%|3.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|170|45.6%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|165|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|45|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7590|7590|19|0.2%|0.2%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[nixspam](#nixspam)|21248|21248|6|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5426|5426|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|986|18056524|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14586|14586|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13824|13824|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|22338|22338|3|0.0%|0.0%|
[xroxy](#xroxy)|2011|2011|2|0.0%|0.0%|
[voipbl](#voipbl)|10343|10752|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|1|0.1%|0.0%|
[shunlist](#shunlist)|1262|1262|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2014|2014|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1460|1460|1|0.0%|0.0%|

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
[fullbogons](#fullbogons)|3639|670579672|592708608|88.3%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|4194304|3.0%|0.7%|
[voipbl](#voipbl)|10343|10752|319|2.9%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2183|2183|1|0.0%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Mon Jun  1 12:19:41 UTC 2015.

The ipset `bruteforceblocker` has **2183** entries, **2183** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_compromised](#et_compromised)|2367|2367|2053|86.7%|94.0%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|1409|0.7%|64.5%|
[openbl_60d](#openbl_60d)|7590|7590|1310|17.2%|60.0%|
[openbl_30d](#openbl_30d)|3201|3201|1239|38.7%|56.7%|
[blocklist_de](#blocklist_de)|22338|22338|728|3.2%|33.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|1660|1660|713|42.9%|32.6%|
[shunlist](#shunlist)|1262|1262|524|41.5%|24.0%|
[openbl_7d](#openbl_7d)|901|901|518|57.4%|23.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|220|0.0%|10.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|116|0.0%|5.3%|
[et_block](#et_block)|986|18056524|102|0.0%|4.6%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|101|0.0%|4.6%|
[openbl_1d](#openbl_1d)|137|137|83|60.5%|3.8%|
[dshield](#dshield)|20|5120|63|1.2%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|61|0.0%|2.7%|
[blocklist_de_mail](#blocklist_de_mail)|14586|14586|8|0.0%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|6|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|526|526|6|1.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|3|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13824|13824|3|0.0%|0.1%|
[proxz](#proxz)|433|433|2|0.4%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[zeus](#zeus)|265|265|1|0.3%|0.0%|
[xroxy](#xroxy)|2011|2011|1|0.0%|0.0%|
[voipbl](#voipbl)|10343|10752|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6939|6939|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|1|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3639|670579672|1|0.0%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|86|86|1|1.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3184|3184|1|0.0%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Mon Jun  1 10:15:14 UTC 2015.

The ipset `ciarmy` has **329** entries, **329** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|178278|178278|324|0.1%|98.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|54|0.0%|16.4%|
[blocklist_de](#blocklist_de)|22338|22338|42|0.1%|12.7%|
[blocklist_de_apache](#blocklist_de_apache)|13824|13824|36|0.2%|10.9%|
[shunlist](#shunlist)|1262|1262|24|1.9%|7.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|16|0.0%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|10|0.0%|3.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1660|1660|4|0.2%|1.2%|
[voipbl](#voipbl)|10343|10752|3|0.0%|0.9%|
[dshield](#dshield)|20|5120|2|0.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|14586|14586|2|0.0%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|526|526|2|0.3%|0.6%|
[openbl_7d](#openbl_7d)|901|901|1|0.1%|0.3%|
[openbl_60d](#openbl_60d)|7590|7590|1|0.0%|0.3%|
[openbl_30d](#openbl_30d)|3201|3201|1|0.0%|0.3%|
[openbl_1d](#openbl_1d)|137|137|1|0.7%|0.3%|

## cleanmx_viruses

[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses

Source is downloaded from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive).

The last time downloaded was found to be dated: Mon Jun  1 06:18:43 UTC 2015.

The ipset `cleanmx_viruses` has **82** entries, **82** unique IPs.

The following table shows the overlaps of `cleanmx_viruses` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `cleanmx_viruses`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `cleanmx_viruses`.
- ` this % ` is the percentage **of this ipset (`cleanmx_viruses`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[malc0de](#malc0de)|403|403|9|2.2%|10.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|7|0.0%|8.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|4|0.0%|4.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|3.6%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|1|0.0%|1.2%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|1|0.0%|1.2%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Mon Jun  1 12:36:16 UTC 2015.

The ipset `dm_tor` has **6472** entries, **6472** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6479|6479|6399|98.7%|98.8%|
[et_tor](#et_tor)|6470|6470|5437|84.0%|84.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|625|0.0%|9.6%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|616|0.6%|9.5%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|475|1.5%|7.3%|
[stopforumspam_1d](#stopforumspam_1d)|6939|6939|289|4.1%|4.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|192|0.0%|2.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|169|45.4%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|165|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|45|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7590|7590|19|0.2%|0.2%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[nixspam](#nixspam)|21248|21248|6|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5426|5426|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|986|18056524|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14586|14586|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13824|13824|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|22338|22338|3|0.0%|0.0%|
[xroxy](#xroxy)|2011|2011|2|0.0%|0.0%|
[voipbl](#voipbl)|10343|10752|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|1|0.1%|0.0%|
[shunlist](#shunlist)|1262|1262|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2014|2014|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1460|1460|1|0.0%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Mon Jun  1 11:27:36 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|178278|178278|3587|2.0%|70.0%|
[et_block](#et_block)|986|18056524|1024|0.0%|20.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|512|0.0%|10.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|256|0.0%|5.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|256|0.0%|5.0%|
[openbl_60d](#openbl_60d)|7590|7590|117|1.5%|2.2%|
[openbl_30d](#openbl_30d)|3201|3201|96|2.9%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|80|0.0%|1.5%|
[et_compromised](#et_compromised)|2367|2367|69|2.9%|1.3%|
[openbl_7d](#openbl_7d)|901|901|66|7.3%|1.2%|
[bruteforceblocker](#bruteforceblocker)|2183|2183|63|2.8%|1.2%|
[shunlist](#shunlist)|1262|1262|61|4.8%|1.1%|
[blocklist_de](#blocklist_de)|22338|22338|55|0.2%|1.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1660|1660|52|3.1%|1.0%|
[openbl_1d](#openbl_1d)|137|137|17|12.4%|0.3%|
[ciarmy](#ciarmy)|329|329|2|0.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13824|13824|2|0.0%|0.0%|
[malc0de](#malc0de)|403|403|1|0.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|1|0.6%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|86|86|1|1.1%|0.0%|

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
[spamhaus_drop](#spamhaus_drop)|652|18338560|17920256|97.7%|99.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8402471|2.4%|46.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7211008|78.5%|39.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|2133460|0.2%|11.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|196184|0.1%|1.0%|
[fullbogons](#fullbogons)|3639|670579672|20480|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|5787|3.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1040|0.3%|0.0%|
[dshield](#dshield)|20|5120|1024|20.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|728|0.7%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|517|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|286|40.0%|0.0%|
[zeus](#zeus)|265|265|259|97.7%|0.0%|
[openbl_60d](#openbl_60d)|7590|7590|241|3.1%|0.0%|
[zeus_badips](#zeus_badips)|230|230|228|99.1%|0.0%|
[openbl_30d](#openbl_30d)|3201|3201|202|6.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|200|0.6%|0.0%|
[blocklist_de](#blocklist_de)|22338|22338|174|0.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1660|1660|112|6.7%|0.0%|
[shunlist](#shunlist)|1262|1262|111|8.7%|0.0%|
[et_compromised](#et_compromised)|2367|2367|103|4.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2183|2183|102|4.6%|0.0%|
[nixspam](#nixspam)|21248|21248|92|0.4%|0.0%|
[openbl_7d](#openbl_7d)|901|901|84|9.3%|0.0%|
[feodo](#feodo)|76|76|67|88.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6939|6939|61|0.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3184|3184|33|1.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|28|2.1%|0.0%|
[sslbl](#sslbl)|360|360|27|7.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14586|14586|25|0.1%|0.0%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.0%|
[openbl_1d](#openbl_1d)|137|137|21|15.3%|0.0%|
[voipbl](#voipbl)|10343|10752|17|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|526|526|17|3.2%|0.0%|
[palevo](#palevo)|13|13|12|92.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|7|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|6|3.7%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13824|13824|4|0.0%|0.0%|
[malc0de](#malc0de)|403|403|3|0.7%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6472|6472|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6479|6479|3|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1396|1396|3|0.2%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[et_botcc](#et_botcc)|501|501|1|0.1%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|178278|178278|3|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[et_block](#et_block)|986|18056524|1|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|95|95|1|1.0%|0.1%|

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
[bruteforceblocker](#bruteforceblocker)|2183|2183|2053|94.0%|86.7%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|1541|0.8%|65.1%|
[openbl_60d](#openbl_60d)|7590|7590|1428|18.8%|60.3%|
[openbl_30d](#openbl_30d)|3201|3201|1306|40.7%|55.1%|
[blocklist_de](#blocklist_de)|22338|22338|655|2.9%|27.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|1660|1660|636|38.3%|26.8%|
[shunlist](#shunlist)|1262|1262|522|41.3%|22.0%|
[openbl_7d](#openbl_7d)|901|901|506|56.1%|21.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|227|0.0%|9.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|140|0.0%|5.9%|
[et_block](#et_block)|986|18056524|103|0.0%|4.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|102|0.0%|4.3%|
[openbl_1d](#openbl_1d)|137|137|74|54.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|70|0.0%|2.9%|
[dshield](#dshield)|20|5120|69|1.3%|2.9%|
[blocklist_de_mail](#blocklist_de_mail)|14586|14586|12|0.0%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|526|526|10|1.9%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|6|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|3|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13824|13824|3|0.0%|0.1%|
[proxz](#proxz)|433|433|2|0.4%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[zeus](#zeus)|265|265|1|0.3%|0.0%|
[xroxy](#xroxy)|2011|2011|1|0.0%|0.0%|
[voipbl](#voipbl)|10343|10752|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6939|6939|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|1|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|86|86|1|1.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3184|3184|1|0.0%|0.0%|

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
[bm_tor](#bm_tor)|6479|6479|5448|84.0%|84.2%|
[dm_tor](#dm_tor)|6472|6472|5437|84.0%|84.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|623|0.6%|9.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|619|0.0%|9.5%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|509|1.6%|7.8%|
[stopforumspam_1d](#stopforumspam_1d)|6939|6939|291|4.1%|4.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|184|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|179|48.1%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|163|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|47|0.0%|0.7%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[openbl_60d](#openbl_60d)|7590|7590|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[nixspam](#nixspam)|21248|21248|5|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5426|5426|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[xroxy](#xroxy)|2011|2011|3|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|986|18056524|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14586|14586|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13824|13824|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|22338|22338|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2014|2014|2|0.0%|0.0%|
[voipbl](#voipbl)|10343|10752|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|1|0.1%|0.0%|
[shunlist](#shunlist)|1262|1262|1|0.0%|0.0%|
[proxz](#proxz)|433|433|1|0.2%|0.0%|
[proxyrss](#proxyrss)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Mon Jun  1 12:36:34 UTC 2015.

The ipset `feodo` has **76** entries, **76** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|986|18056524|67|0.0%|88.1%|
[snort_ipfilter](#snort_ipfilter)|714|714|53|7.4%|69.7%|
[sslbl](#sslbl)|360|360|27|7.5%|35.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|7|0.0%|9.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|3|0.0%|3.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|3.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|1.3%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|1|0.0%|1.3%|

## fullbogons

[Team-Cymru.org](http://www.team-cymru.org) IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user - **excellent list - use it only your internet interface**

Source is downloaded from [this link](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt).

The last time downloaded was found to be dated: Mon Jun  1 09:35:08 UTC 2015.

The ipset `fullbogons` has **3639** entries, **670579672** unique IPs.

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
[spamhaus_drop](#spamhaus_drop)|652|18338560|20480|0.1%|0.0%|
[et_block](#et_block)|986|18056524|20480|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|890|0.2%|0.0%|
[voipbl](#voipbl)|10343|10752|319|2.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|33|2.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|9|0.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2183|2183|1|0.0%|0.0%|

## ib_bluetack_badpeers

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) IPs that have been reported for bad deeds in p2p

Source is downloaded from [this link](http://list.iblocklist.com/?list=cwworuawihqvocglcoss&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Mon Jun  1 04:01:11 UTC 2015.

The ipset `ib_bluetack_badpeers` has **48134** entries, **48134** unique IPs.

The following table shows the overlaps of `ib_bluetack_badpeers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_badpeers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_badpeers`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_badpeers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1172|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|406|0.0%|0.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|230|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|14|0.0%|0.0%|
[fullbogons](#fullbogons)|3639|670579672|14|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|14|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.0%|
[nixspam](#nixspam)|21248|21248|10|0.0%|0.0%|
[et_block](#et_block)|986|18056524|7|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|6|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[xroxy](#xroxy)|2011|2011|3|0.1%|0.0%|
[blocklist_de](#blocklist_de)|22338|22338|3|0.0%|0.0%|
[voipbl](#voipbl)|10343|10752|2|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6939|6939|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14586|14586|2|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5426|5426|1|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1396|1396|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13824|13824|1|0.0%|0.0%|

## ib_bluetack_hijacked

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) hijacked IP-Blocks Hijacked IP space are IP blocks that are being used without permission

Source is downloaded from [this link](http://list.iblocklist.com/?list=usrcshglbiilevmyfhse&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Mon Jun  1 04:30:07 UTC 2015.

The ipset `ib_bluetack_hijacked` has **535** entries, **9177856** unique IPs.

The following table shows the overlaps of `ib_bluetack_hijacked` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_hijacked`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_hijacked`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_hijacked`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|986|18056524|7211008|39.9%|78.5%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|7079936|38.6%|77.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2526625|0.7%|27.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|904796|0.1%|9.8%|
[fullbogons](#fullbogons)|3639|670579672|565248|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|145472|0.1%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1036|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|732|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|518|0.2%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|182|0.5%|0.0%|
[nixspam](#nixspam)|21248|21248|92|0.4%|0.0%|
[blocklist_de](#blocklist_de)|22338|22338|40|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3184|3184|31|0.9%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6939|6939|30|0.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|27|2.1%|0.0%|
[openbl_60d](#openbl_60d)|7590|7590|19|0.2%|0.0%|
[openbl_30d](#openbl_30d)|3201|3201|14|0.4%|0.0%|
[zeus_badips](#zeus_badips)|230|230|10|4.3%|0.0%|
[zeus](#zeus)|265|265|10|3.7%|0.0%|
[openbl_7d](#openbl_7d)|901|901|10|1.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|9|1.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1660|1660|6|0.3%|0.0%|
[et_compromised](#et_compromised)|2367|2367|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2183|2183|5|0.2%|0.0%|
[shunlist](#shunlist)|1262|1262|3|0.2%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6472|6472|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6479|6479|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|3|1.8%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14586|14586|3|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|526|526|3|0.5%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[voipbl](#voipbl)|10343|10752|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.0%|
[openbl_1d](#openbl_1d)|137|137|1|0.7%|0.0%|
[et_botcc](#et_botcc)|501|501|1|0.1%|0.0%|

## ib_bluetack_level1

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Level 1 (for use in p2p): Companies or organizations who are clearly involved with trying to stop filesharing (e.g. Baytsp, MediaDefender, Mediasentry a.o.). Companies which anti-p2p activity has been seen from. Companies that produce or have a strong financial interest in copyrighted material (e.g. music, movie, software industries a.o.). Government ranges or companies that have a strong financial interest in doing work for governments. Legal industry ranges. IPs or ranges of ISPs from which anti-p2p activity has been observed. Basically this list will block all kinds of internet connections that most people would rather not have during their internet travels.

Source is downloaded from [this link](http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Mon Jun  1 09:44:03 UTC 2015.

The ipset `ib_bluetack_level1` has **218309** entries, **764987411** unique IPs.

The following table shows the overlaps of `ib_bluetack_level1` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level1`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level1`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level1`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|16300309|4.6%|2.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2272266|12.3%|0.2%|
[et_block](#et_block)|986|18056524|2133460|11.8%|0.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1354348|0.9%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904796|9.8%|0.1%|
[fullbogons](#fullbogons)|3639|670579672|234359|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|33155|7.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|13248|3.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|4437|2.4%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|1523|1.6%|0.0%|
[blocklist_de](#blocklist_de)|22338|22338|1432|6.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14586|14586|1321|9.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13824|13824|1316|9.5%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|563|1.7%|0.0%|
[nixspam](#nixspam)|21248|21248|428|2.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|406|0.8%|0.0%|
[voipbl](#voipbl)|10343|10752|295|2.7%|0.0%|
[openbl_60d](#openbl_60d)|7590|7590|172|2.2%|0.0%|
[dm_tor](#dm_tor)|6472|6472|165|2.5%|0.0%|
[bm_tor](#bm_tor)|6479|6479|165|2.5%|0.0%|
[et_tor](#et_tor)|6470|6470|163|2.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6939|6939|138|1.9%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5426|5426|115|2.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|97|6.6%|0.0%|
[dshield](#dshield)|20|5120|80|1.5%|0.0%|
[et_compromised](#et_compromised)|2367|2367|70|2.9%|0.0%|
[openbl_30d](#openbl_30d)|3201|3201|68|2.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2014|2014|66|3.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|66|5.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2183|2183|61|2.7%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|58|8.6%|0.0%|
[xroxy](#xroxy)|2011|2011|57|2.8%|0.0%|
[proxyrss](#proxyrss)|1460|1460|43|2.9%|0.0%|
[et_botcc](#et_botcc)|501|501|40|7.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3184|3184|40|1.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1660|1660|32|1.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1396|1396|27|1.9%|0.0%|
[shunlist](#shunlist)|1262|1262|26|2.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|17|4.5%|0.0%|
[proxz](#proxz)|433|433|16|3.6%|0.0%|
[openbl_7d](#openbl_7d)|901|901|16|1.7%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|12|1.6%|0.0%|
[malc0de](#malc0de)|403|403|12|2.9%|0.0%|
[ciarmy](#ciarmy)|329|329|10|3.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|9|2.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|526|526|8|1.5%|0.0%|
[zeus](#zeus)|265|265|7|2.6%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.0%|
[php_commenters](#php_commenters)|281|281|5|1.7%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[zeus_badips](#zeus_badips)|230|230|4|1.7%|0.0%|
[sslbl](#sslbl)|360|360|3|0.8%|0.0%|
[feodo](#feodo)|76|76|3|3.9%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|82|82|3|3.6%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|95|95|2|2.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|86|86|2|2.3%|0.0%|
[openbl_1d](#openbl_1d)|137|137|1|0.7%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|1|0.6%|0.0%|

## ib_bluetack_level2

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 2 (for use in p2p). General corporate ranges. Ranges used by labs or researchers. Proxies.

Source is downloaded from [this link](http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Mon Jun  1 04:31:06 UTC 2015.

The ipset `ib_bluetack_level2` has **72774** entries, **348707599** unique IPs.

The following table shows the overlaps of `ib_bluetack_level2` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level2`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level2`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level2`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|16300309|2.1%|4.6%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|8598042|46.8%|2.4%|
[et_block](#et_block)|986|18056524|8402471|46.5%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2830140|2.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2526625|27.5%|0.7%|
[fullbogons](#fullbogons)|3639|670579672|248319|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|33368|7.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|8137|4.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|7733|2.2%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|2477|2.6%|0.0%|
[blocklist_de](#blocklist_de)|22338|22338|1453|6.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14586|14586|1116|7.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13824|13824|1066|7.7%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|938|2.9%|0.0%|
[nixspam](#nixspam)|21248|21248|590|2.7%|0.0%|
[voipbl](#voipbl)|10343|10752|431|4.0%|0.0%|
[openbl_60d](#openbl_60d)|7590|7590|344|4.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6939|6939|242|3.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|230|0.4%|0.0%|
[bm_tor](#bm_tor)|6479|6479|195|3.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3184|3184|195|6.1%|0.0%|
[dm_tor](#dm_tor)|6472|6472|192|2.9%|0.0%|
[et_tor](#et_tor)|6470|6470|184|2.8%|0.0%|
[openbl_30d](#openbl_30d)|3201|3201|178|5.5%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5426|5426|173|3.1%|0.0%|
[et_compromised](#et_compromised)|2367|2367|140|5.9%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2183|2183|116|5.3%|0.0%|
[xroxy](#xroxy)|2011|2011|98|4.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1660|1660|88|5.3%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2014|2014|81|4.0%|0.0%|
[shunlist](#shunlist)|1262|1262|69|5.4%|0.0%|
[proxyrss](#proxyrss)|1460|1460|64|4.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|45|3.0%|0.0%|
[openbl_7d](#openbl_7d)|901|901|40|4.4%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1396|1396|33|2.3%|0.0%|
[php_spammers](#php_spammers)|417|417|31|7.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|526|526|29|5.5%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|28|4.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|26|2.0%|0.0%|
[malc0de](#malc0de)|403|403|25|6.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|24|3.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|21|5.6%|0.0%|
[et_botcc](#et_botcc)|501|501|21|4.1%|0.0%|
[proxz](#proxz)|433|433|19|4.3%|0.0%|
[ciarmy](#ciarmy)|329|329|16|4.8%|0.0%|
[php_dictionary](#php_dictionary)|433|433|10|2.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|95|95|10|10.5%|0.0%|
[zeus](#zeus)|265|265|9|3.3%|0.0%|
[php_commenters](#php_commenters)|281|281|9|3.2%|0.0%|
[zeus_badips](#zeus_badips)|230|230|8|3.4%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[sslbl](#sslbl)|360|360|6|1.6%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|6|3.7%|0.0%|
[openbl_1d](#openbl_1d)|137|137|5|3.6%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|82|82|4|4.8%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|86|86|4|4.6%|0.0%|
[palevo](#palevo)|13|13|3|23.0%|0.0%|
[feodo](#feodo)|76|76|3|3.9%|0.0%|

## ib_bluetack_level3

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 3 (for use in p2p). Many portal-type websites. ISP ranges that may be dodgy for some reason. Ranges that belong to an individual, but which have not been determined to be used by a particular company. Ranges for things that are unusual in some way. The L3 list is aka the paranoid list.

Source is downloaded from [this link](http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Mon Jun  1 04:30:27 UTC 2015.

The ipset `ib_bluetack_level3` has **17802** entries, **139104824** unique IPs.

The following table shows the overlaps of `ib_bluetack_level3` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level3`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level3`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level3`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[fullbogons](#fullbogons)|3639|670579672|4233775|0.6%|3.0%|
[bogons](#bogons)|13|592708608|4194304|0.7%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2830140|0.8%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1354348|0.1%|0.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|270785|64.2%|0.1%|
[et_block](#et_block)|986|18056524|196184|1.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|195904|1.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|14381|8.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|9231|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|5946|6.4%|0.0%|
[blocklist_de](#blocklist_de)|22338|22338|2796|12.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14586|14586|2246|15.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13824|13824|2209|15.9%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|2107|6.7%|0.0%|
[voipbl](#voipbl)|10343|10752|1591|14.7%|0.0%|
[nixspam](#nixspam)|21248|21248|1534|7.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1172|2.4%|0.0%|
[openbl_60d](#openbl_60d)|7590|7590|716|9.4%|0.0%|
[dm_tor](#dm_tor)|6472|6472|625|9.6%|0.0%|
[bm_tor](#bm_tor)|6479|6479|624|9.6%|0.0%|
[et_tor](#et_tor)|6470|6470|619|9.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6939|6939|497|7.1%|0.0%|
[openbl_30d](#openbl_30d)|3201|3201|283|8.8%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[et_compromised](#et_compromised)|2367|2367|227|9.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2183|2183|220|10.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3184|3184|210|6.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1660|1660|187|11.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5426|5426|154|2.8%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|146|11.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|125|33.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|110|7.5%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1396|1396|109|7.8%|0.0%|
[shunlist](#shunlist)|1262|1262|102|8.0%|0.0%|
[openbl_7d](#openbl_7d)|901|901|92|10.2%|0.0%|
[xroxy](#xroxy)|2011|2011|84|4.1%|0.0%|
[et_botcc](#et_botcc)|501|501|74|14.7%|0.0%|
[malc0de](#malc0de)|403|403|71|17.6%|0.0%|
[ciarmy](#ciarmy)|329|329|54|16.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|51|7.5%|0.0%|
[proxyrss](#proxyrss)|1460|1460|49|3.3%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2014|2014|46|2.2%|0.0%|
[proxz](#proxz)|433|433|42|9.6%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|526|526|33|6.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|29|4.0%|0.0%|
[php_spammers](#php_spammers)|417|417|26|6.2%|0.0%|
[php_dictionary](#php_dictionary)|433|433|24|5.5%|0.0%|
[sslbl](#sslbl)|360|360|23|6.3%|0.0%|
[zeus](#zeus)|265|265|18|6.7%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|16|10.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|15|5.8%|0.0%|
[php_commenters](#php_commenters)|281|281|15|5.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|95|95|15|15.7%|0.0%|
[zeus_badips](#zeus_badips)|230|230|14|6.0%|0.0%|
[openbl_1d](#openbl_1d)|137|137|12|8.7%|0.0%|
[feodo](#feodo)|76|76|7|9.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|82|82|7|8.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|86|86|6|6.9%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|

## ib_bluetack_proxies

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Open Proxies IPs list (without TOR)

Source is downloaded from [this link](http://list.iblocklist.com/?list=xoebmbyexwuiogmbyprb&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Mon Jun  1 04:30:04 UTC 2015.

The ipset `ib_bluetack_proxies` has **673** entries, **673** unique IPs.

The following table shows the overlaps of `ib_bluetack_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_proxies`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|58|0.0%|8.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|51|0.0%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|28|0.0%|4.1%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|22|0.0%|3.2%|
[xroxy](#xroxy)|2011|2011|13|0.6%|1.9%|
[proxyrss](#proxyrss)|1460|1460|12|0.8%|1.7%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|11|0.0%|1.6%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|11|0.0%|1.6%|
[ri_web_proxies](#ri_web_proxies)|5426|5426|10|0.1%|1.4%|
[ri_connect_proxies](#ri_connect_proxies)|2014|2014|6|0.2%|0.8%|
[stopforumspam_1d](#stopforumspam_1d)|6939|6939|5|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2|0.0%|0.2%|
[nixspam](#nixspam)|21248|21248|2|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.2%|
[et_block](#et_block)|986|18056524|2|0.0%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3184|3184|2|0.0%|0.2%|
[blocklist_de](#blocklist_de)|22338|22338|2|0.0%|0.2%|
[proxz](#proxz)|433|433|1|0.2%|0.1%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.1%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|1|0.0%|0.1%|

## ib_bluetack_spyware

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) known malicious SPYWARE and ADWARE IP Address ranges

Source is downloaded from [this link](http://list.iblocklist.com/?list=llvtlsjyoyiczbkjsxpf&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Mon Jun  1 04:00:05 UTC 2015.

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
[spamhaus_drop](#spamhaus_drop)|652|18338560|1037|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1036|0.0%|0.3%|
[fullbogons](#fullbogons)|3639|670579672|890|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|288|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|44|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|25|1.9%|0.0%|
[et_tor](#et_tor)|6470|6470|21|0.3%|0.0%|
[dm_tor](#dm_tor)|6472|6472|21|0.3%|0.0%|
[bm_tor](#bm_tor)|6479|6479|21|0.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|19|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|19|1.3%|0.0%|
[nixspam](#nixspam)|21248|21248|17|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6939|6939|13|0.1%|0.0%|
[blocklist_de](#blocklist_de)|22338|22338|7|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|6|0.8%|0.0%|
[openbl_60d](#openbl_60d)|7590|7590|6|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5426|5426|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|5|1.3%|0.0%|
[voipbl](#voipbl)|10343|10752|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3201|3201|4|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[malc0de](#malc0de)|403|403|3|0.7%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|82|82|3|3.6%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3184|3184|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13824|13824|3|0.0%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|95|95|2|2.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1396|1396|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[zeus](#zeus)|265|265|1|0.3%|0.0%|
[xroxy](#xroxy)|2011|2011|1|0.0%|0.0%|
[sslbl](#sslbl)|360|360|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|1|0.0%|0.0%|
[shunlist](#shunlist)|1262|1262|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.0%|
[openbl_7d](#openbl_7d)|901|901|1|0.1%|0.0%|
[openbl_1d](#openbl_1d)|137|137|1|0.7%|0.0%|
[feodo](#feodo)|76|76|1|1.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2183|2183|1|0.0%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1660|1660|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14586|14586|1|0.0%|0.0%|

## ib_bluetack_webexploit

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) web server hack and exploit attempts

Source is downloaded from [this link](http://list.iblocklist.com/?list=ghlzqtqxnzctvvajwwag&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Mon Jun  1 04:00:04 UTC 2015.

The ipset `ib_bluetack_webexploit` has **1460** entries, **1460** unique IPs.

The following table shows the overlaps of `ib_bluetack_webexploit` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_webexploit`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_webexploit`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_webexploit`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|110|0.0%|7.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|97|0.0%|6.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|45|0.0%|3.0%|
[fullbogons](#fullbogons)|3639|670579672|33|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|19|0.0%|1.3%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|8|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|6|0.0%|0.4%|
[et_block](#et_block)|986|18056524|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|3|0.2%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|2|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7590|7590|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|3201|3201|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.1%|
[et_compromised](#et_compromised)|2367|2367|2|0.0%|0.1%|
[blocklist_de](#blocklist_de)|22338|22338|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6939|6939|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5426|5426|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|901|901|1|0.1%|0.0%|
[nixspam](#nixspam)|21248|21248|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[et_botcc](#et_botcc)|501|501|1|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|1|0.6%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1660|1660|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3184|3184|1|0.0%|0.0%|

## malc0de

[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days

Source is downloaded from [this link](http://malc0de.com/bl/IP_Blacklist.txt).

The last time downloaded was found to be dated: Sun May 31 13:17:02 UTC 2015.

The ipset `malc0de` has **403** entries, **403** unique IPs.

The following table shows the overlaps of `malc0de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `malc0de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `malc0de`.
- ` this % ` is the percentage **of this ipset (`malc0de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|71|0.0%|17.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|25|0.0%|6.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|12|0.0%|2.9%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|12|0.0%|2.9%|
[cleanmx_viruses](#cleanmx_viruses)|82|82|9|10.9%|2.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|4|0.0%|0.9%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|4|0.3%|0.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.7%|
[et_block](#et_block)|986|18056524|3|0.0%|0.7%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|1|0.0%|0.2%|
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
[spamhaus_drop](#spamhaus_drop)|652|18338560|29|0.0%|2.2%|
[et_block](#et_block)|986|18056524|28|0.0%|2.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|26|0.0%|2.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|25|0.0%|1.9%|
[snort_ipfilter](#snort_ipfilter)|714|714|23|3.2%|1.7%|
[fullbogons](#fullbogons)|3639|670579672|9|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|6|0.0%|0.4%|
[malc0de](#malc0de)|403|403|4|0.9%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|3|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|2|0.0%|0.1%|
[nixspam](#nixspam)|21248|21248|1|0.0%|0.0%|
[et_botcc](#et_botcc)|501|501|1|0.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|82|82|1|1.2%|0.0%|

## maxmind_proxy_fraud

[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.

Source is downloaded from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list).

The last time downloaded was found to be dated: Mon Jun  1 10:36:17 UTC 2015.

The ipset `maxmind_proxy_fraud` has **372** entries, **372** unique IPs.

The following table shows the overlaps of `maxmind_proxy_fraud` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `maxmind_proxy_fraud`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `maxmind_proxy_fraud`.
- ` this % ` is the percentage **of this ipset (`maxmind_proxy_fraud`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|234|0.2%|62.9%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|201|0.6%|54.0%|
[et_tor](#et_tor)|6470|6470|179|2.7%|48.1%|
[bm_tor](#bm_tor)|6479|6479|170|2.6%|45.6%|
[dm_tor](#dm_tor)|6472|6472|169|2.6%|45.4%|
[stopforumspam_1d](#stopforumspam_1d)|6939|6939|157|2.2%|42.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|125|0.0%|33.6%|
[php_commenters](#php_commenters)|281|281|28|9.9%|7.5%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|25|0.0%|6.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|21|0.0%|5.6%|
[openbl_60d](#openbl_60d)|7590|7590|18|0.2%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|17|0.0%|4.5%|
[php_harvesters](#php_harvesters)|257|257|6|2.3%|1.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|1.3%|
[ri_web_proxies](#ri_web_proxies)|5426|5426|4|0.0%|1.0%|
[php_spammers](#php_spammers)|417|417|4|0.9%|1.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|1.0%|
[shunlist](#shunlist)|1262|1262|2|0.1%|0.5%|
[xroxy](#xroxy)|2011|2011|1|0.0%|0.2%|
[voipbl](#voipbl)|10343|10752|1|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|714|714|1|0.1%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2014|2014|1|0.0%|0.2%|
[nixspam](#nixspam)|21248|21248|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|14586|14586|1|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|13824|13824|1|0.0%|0.2%|
[blocklist_de](#blocklist_de)|22338|22338|1|0.0%|0.2%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Mon Jun  1 12:45:01 UTC 2015.

The ipset `nixspam` has **21248** entries, **21248** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1534|0.0%|7.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|590|0.0%|2.7%|
[blocklist_de](#blocklist_de)|22338|22338|483|2.1%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|428|0.0%|2.0%|
[blocklist_de_mail](#blocklist_de_mail)|14586|14586|425|2.9%|2.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|225|0.2%|1.0%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|137|0.4%|0.6%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|92|0.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|92|0.0%|0.4%|
[et_block](#et_block)|986|18056524|92|0.0%|0.4%|
[php_dictionary](#php_dictionary)|433|433|80|18.4%|0.3%|
[ri_web_proxies](#ri_web_proxies)|5426|5426|75|1.3%|0.3%|
[xroxy](#xroxy)|2011|2011|68|3.3%|0.3%|
[php_spammers](#php_spammers)|417|417|61|14.6%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6939|6939|48|0.6%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3184|3184|43|1.3%|0.2%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|34|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|17|0.0%|0.0%|
[proxz](#proxz)|433|433|14|3.2%|0.0%|
[openbl_60d](#openbl_60d)|7590|7590|12|0.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2014|2014|10|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|10|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13824|13824|10|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1396|1396|9|0.6%|0.0%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.0%|
[proxyrss](#proxyrss)|1460|1460|6|0.4%|0.0%|
[dm_tor](#dm_tor)|6472|6472|6|0.0%|0.0%|
[bm_tor](#bm_tor)|6479|6479|6|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|5|1.9%|0.0%|
[et_tor](#et_tor)|6470|6470|5|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|3|0.4%|0.0%|
[shunlist](#shunlist)|1262|1262|3|0.2%|0.0%|
[voipbl](#voipbl)|10343|10752|2|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3201|3201|2|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|2|1.2%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|95|95|2|2.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|526|526|2|0.3%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[zeus](#zeus)|265|265|1|0.3%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1660|1660|1|0.0%|0.0%|

## openbl_1d

[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_1days.txt).

The last time downloaded was found to be dated: Mon Jun  1 12:32:00 UTC 2015.

The ipset `openbl_1d` has **137** entries, **137** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7590|7590|135|1.7%|98.5%|
[openbl_30d](#openbl_30d)|3201|3201|135|4.2%|98.5%|
[openbl_7d](#openbl_7d)|901|901|133|14.7%|97.0%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|127|0.0%|92.7%|
[blocklist_de](#blocklist_de)|22338|22338|119|0.5%|86.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|1660|1660|116|6.9%|84.6%|
[bruteforceblocker](#bruteforceblocker)|2183|2183|83|3.8%|60.5%|
[shunlist](#shunlist)|1262|1262|75|5.9%|54.7%|
[et_compromised](#et_compromised)|2367|2367|74|3.1%|54.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|21|0.0%|15.3%|
[et_block](#et_block)|986|18056524|21|0.0%|15.3%|
[dshield](#dshield)|20|5120|17|0.3%|12.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|17|10.6%|12.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|12|0.0%|8.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|5|0.0%|3.6%|
[blocklist_de_mail](#blocklist_de_mail)|14586|14586|3|0.0%|2.1%|
[blocklist_de_imap](#blocklist_de_imap)|526|526|3|0.5%|2.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1|0.0%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.7%|
[ciarmy](#ciarmy)|329|329|1|0.3%|0.7%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt).

The last time downloaded was found to be dated: Mon Jun  1 11:42:00 UTC 2015.

The ipset `openbl_30d` has **3201** entries, **3201** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7590|7590|3201|42.1%|100.0%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|3181|1.7%|99.3%|
[et_compromised](#et_compromised)|2367|2367|1306|55.1%|40.7%|
[bruteforceblocker](#bruteforceblocker)|2183|2183|1239|56.7%|38.7%|
[openbl_7d](#openbl_7d)|901|901|901|100.0%|28.1%|
[blocklist_de](#blocklist_de)|22338|22338|776|3.4%|24.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1660|1660|729|43.9%|22.7%|
[shunlist](#shunlist)|1262|1262|602|47.7%|18.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|283|0.0%|8.8%|
[et_block](#et_block)|986|18056524|202|0.0%|6.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|200|0.0%|6.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|178|0.0%|5.5%|
[openbl_1d](#openbl_1d)|137|137|135|98.5%|4.2%|
[dshield](#dshield)|20|5120|96|1.8%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|68|0.0%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|14586|14586|39|0.2%|1.2%|
[blocklist_de_imap](#blocklist_de_imap)|526|526|32|6.0%|0.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|25|15.7%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|14|0.0%|0.4%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|6|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|4|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.1%|
[voipbl](#voipbl)|10343|10752|3|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|86|86|3|3.4%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13824|13824|3|0.0%|0.0%|
[zeus](#zeus)|265|265|2|0.7%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|2|0.2%|0.0%|
[nixspam](#nixspam)|21248|21248|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6939|6939|1|0.0%|0.0%|
[ciarmy](#ciarmy)|329|329|1|0.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3184|3184|1|0.0%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt).

The last time downloaded was found to be dated: Mon Jun  1 11:42:00 UTC 2015.

The ipset `openbl_60d` has **7590** entries, **7590** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|178278|178278|7562|4.2%|99.6%|
[openbl_30d](#openbl_30d)|3201|3201|3201|100.0%|42.1%|
[et_compromised](#et_compromised)|2367|2367|1428|60.3%|18.8%|
[bruteforceblocker](#bruteforceblocker)|2183|2183|1310|60.0%|17.2%|
[openbl_7d](#openbl_7d)|901|901|901|100.0%|11.8%|
[blocklist_de](#blocklist_de)|22338|22338|849|3.8%|11.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|1660|1660|782|47.1%|10.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|716|0.0%|9.4%|
[shunlist](#shunlist)|1262|1262|620|49.1%|8.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|344|0.0%|4.5%|
[et_block](#et_block)|986|18056524|241|0.0%|3.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|239|0.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|172|0.0%|2.2%|
[openbl_1d](#openbl_1d)|137|137|135|98.5%|1.7%|
[dshield](#dshield)|20|5120|117|2.2%|1.5%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|54|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|14586|14586|45|0.3%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|526|526|36|6.8%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|28|17.6%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|27|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6939|6939|21|0.3%|0.2%|
[et_tor](#et_tor)|6470|6470|21|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|19|0.0%|0.2%|
[dm_tor](#dm_tor)|6472|6472|19|0.2%|0.2%|
[bm_tor](#bm_tor)|6479|6479|19|0.2%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3184|3184|14|0.4%|0.1%|
[nixspam](#nixspam)|21248|21248|12|0.0%|0.1%|
[voipbl](#voipbl)|10343|10752|9|0.0%|0.1%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|6|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|6|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|86|86|4|4.6%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|3|0.4%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13824|13824|3|0.0%|0.0%|
[zeus](#zeus)|265|265|2|0.7%|0.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[ciarmy](#ciarmy)|329|329|1|0.3%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt).

The last time downloaded was found to be dated: Mon Jun  1 11:42:00 UTC 2015.

The ipset `openbl_7d` has **901** entries, **901** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7590|7590|901|11.8%|100.0%|
[openbl_30d](#openbl_30d)|3201|3201|901|28.1%|100.0%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|887|0.4%|98.4%|
[blocklist_de](#blocklist_de)|22338|22338|528|2.3%|58.6%|
[bruteforceblocker](#bruteforceblocker)|2183|2183|518|23.7%|57.4%|
[et_compromised](#et_compromised)|2367|2367|506|21.3%|56.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|1660|1660|502|30.2%|55.7%|
[shunlist](#shunlist)|1262|1262|385|30.5%|42.7%|
[openbl_1d](#openbl_1d)|137|137|133|97.0%|14.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|92|0.0%|10.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|84|0.0%|9.3%|
[et_block](#et_block)|986|18056524|84|0.0%|9.3%|
[dshield](#dshield)|20|5120|66|1.2%|7.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|40|0.0%|4.4%|
[blocklist_de_mail](#blocklist_de_mail)|14586|14586|25|0.1%|2.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|24|15.0%|2.6%|
[blocklist_de_imap](#blocklist_de_imap)|526|526|18|3.4%|1.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|16|0.0%|1.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|1.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|5|0.0%|0.5%|
[voipbl](#voipbl)|10343|10752|3|0.0%|0.3%|
[zeus](#zeus)|265|265|1|0.3%|0.1%|
[snort_ipfilter](#snort_ipfilter)|714|714|1|0.1%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.1%|
[ciarmy](#ciarmy)|329|329|1|0.3%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|86|86|1|1.1%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13824|13824|1|0.0%|0.1%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Mon Jun  1 12:36:31 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|986|18056524|12|0.0%|92.3%|
[snort_ipfilter](#snort_ipfilter)|714|714|11|1.5%|84.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|3|0.0%|23.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|15.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1|0.0%|7.6%|

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
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|203|0.2%|72.2%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|170|0.5%|60.4%|
[stopforumspam_1d](#stopforumspam_1d)|6939|6939|100|1.4%|35.5%|
[blocklist_de](#blocklist_de)|22338|22338|62|0.2%|22.0%|
[blocklist_de_bots](#blocklist_de_bots)|3184|3184|53|1.6%|18.8%|
[php_spammers](#php_spammers)|417|417|32|7.6%|11.3%|
[et_tor](#et_tor)|6470|6470|29|0.4%|10.3%|
[dm_tor](#dm_tor)|6472|6472|29|0.4%|10.3%|
[bm_tor](#bm_tor)|6479|6479|29|0.4%|10.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|29|18.2%|10.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|28|7.5%|9.9%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|24|0.0%|8.5%|
[et_block](#et_block)|986|18056524|24|0.0%|8.5%|
[php_dictionary](#php_dictionary)|433|433|22|5.0%|7.8%|
[blocklist_de_apache](#blocklist_de_apache)|13824|13824|22|0.1%|7.8%|
[blocklist_de_mail](#blocklist_de_mail)|14586|14586|17|0.1%|6.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|5.3%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|13|0.0%|4.6%|
[ri_web_proxies](#ri_web_proxies)|5426|5426|11|0.2%|3.9%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.2%|
[openbl_60d](#openbl_60d)|7590|7590|8|0.1%|2.8%|
[nixspam](#nixspam)|21248|21248|8|0.0%|2.8%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|7|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|1.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1396|1396|4|0.2%|1.4%|
[xroxy](#xroxy)|2011|2011|3|0.1%|1.0%|
[proxz](#proxz)|433|433|2|0.4%|0.7%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.3%|
[zeus](#zeus)|265|265|1|0.3%|0.3%|
[snort_ipfilter](#snort_ipfilter)|714|714|1|0.1%|0.3%|
[proxyrss](#proxyrss)|1460|1460|1|0.0%|0.3%|
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
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|83|0.0%|19.1%|
[nixspam](#nixspam)|21248|21248|80|0.3%|18.4%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|68|0.2%|15.7%|
[blocklist_de](#blocklist_de)|22338|22338|45|0.2%|10.3%|
[ri_web_proxies](#ri_web_proxies)|5426|5426|29|0.5%|6.6%|
[xroxy](#xroxy)|2011|2011|24|1.1%|5.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|24|0.0%|5.5%|
[blocklist_de_mail](#blocklist_de_mail)|14586|14586|23|0.1%|5.3%|
[stopforumspam_1d](#stopforumspam_1d)|6939|6939|22|0.3%|5.0%|
[php_commenters](#php_commenters)|281|281|22|7.8%|5.0%|
[blocklist_de_bots](#blocklist_de_bots)|3184|3184|21|0.6%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|10|0.0%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|9|0.0%|2.0%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|7|0.0%|1.6%|
[proxz](#proxz)|433|433|6|1.3%|1.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|4|0.0%|0.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.9%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.9%|
[et_block](#et_block)|986|18056524|4|0.0%|0.9%|
[dm_tor](#dm_tor)|6472|6472|4|0.0%|0.9%|
[bm_tor](#bm_tor)|6479|6479|4|0.0%|0.9%|
[ri_connect_proxies](#ri_connect_proxies)|2014|2014|3|0.1%|0.6%|
[snort_ipfilter](#snort_ipfilter)|714|714|2|0.2%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|2|1.2%|0.4%|
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
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|63|0.0%|24.5%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|47|0.1%|18.2%|
[stopforumspam_1d](#stopforumspam_1d)|6939|6939|33|0.4%|12.8%|
[blocklist_de](#blocklist_de)|22338|22338|24|0.1%|9.3%|
[blocklist_de_bots](#blocklist_de_bots)|3184|3184|19|0.5%|7.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|5.8%|
[php_commenters](#php_commenters)|281|281|9|3.2%|3.5%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|9|0.0%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|7|0.0%|2.7%|
[et_tor](#et_tor)|6470|6470|7|0.1%|2.7%|
[dm_tor](#dm_tor)|6472|6472|7|0.1%|2.7%|
[bm_tor](#bm_tor)|6479|6479|7|0.1%|2.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|6|1.6%|2.3%|
[nixspam](#nixspam)|21248|21248|5|0.0%|1.9%|
[blocklist_de_ftp](#blocklist_de_ftp)|86|86|3|3.4%|1.1%|
[xroxy](#xroxy)|2011|2011|2|0.0%|0.7%|
[proxyrss](#proxyrss)|1460|1460|2|0.1%|0.7%|
[openbl_60d](#openbl_60d)|7590|7590|2|0.0%|0.7%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|14586|14586|2|0.0%|0.7%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|1|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1|0.0%|0.3%|
[ri_web_proxies](#ri_web_proxies)|5426|5426|1|0.0%|0.3%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.3%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|
[fullbogons](#fullbogons)|3639|670579672|1|0.0%|0.3%|
[et_block](#et_block)|986|18056524|1|0.0%|0.3%|
[bogons](#bogons)|13|592708608|1|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|1|0.6%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|13824|13824|1|0.0%|0.3%|

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
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|99|0.1%|23.7%|
[php_dictionary](#php_dictionary)|433|433|84|19.3%|20.1%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|70|0.2%|16.7%|
[nixspam](#nixspam)|21248|21248|61|0.2%|14.6%|
[blocklist_de](#blocklist_de)|22338|22338|44|0.1%|10.5%|
[php_commenters](#php_commenters)|281|281|32|11.3%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|31|0.0%|7.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|26|0.0%|6.2%|
[ri_web_proxies](#ri_web_proxies)|5426|5426|24|0.4%|5.7%|
[blocklist_de_mail](#blocklist_de_mail)|14586|14586|24|0.1%|5.7%|
[stopforumspam_1d](#stopforumspam_1d)|6939|6939|21|0.3%|5.0%|
[xroxy](#xroxy)|2011|2011|18|0.8%|4.3%|
[blocklist_de_bots](#blocklist_de_bots)|3184|3184|12|0.3%|2.8%|
[proxz](#proxz)|433|433|6|1.3%|1.4%|
[et_tor](#et_tor)|6470|6470|6|0.0%|1.4%|
[dm_tor](#dm_tor)|6472|6472|6|0.0%|1.4%|
[bm_tor](#bm_tor)|6479|6479|6|0.0%|1.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1396|1396|6|0.4%|1.4%|
[blocklist_de_apache](#blocklist_de_apache)|13824|13824|6|0.0%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|1.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|4|2.5%|0.9%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|3|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2|0.0%|0.4%|
[snort_ipfilter](#snort_ipfilter)|714|714|2|0.2%|0.4%|
[ri_connect_proxies](#ri_connect_proxies)|2014|2014|2|0.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[et_block](#et_block)|986|18056524|2|0.0%|0.4%|
[proxyrss](#proxyrss)|1460|1460|1|0.0%|0.2%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1660|1660|1|0.0%|0.2%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Mon Jun  1 11:01:32 UTC 2015.

The ipset `proxyrss` has **1460** entries, **1460** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|789|0.8%|54.0%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|688|2.1%|47.1%|
[ri_web_proxies](#ri_web_proxies)|5426|5426|592|10.9%|40.5%|
[xroxy](#xroxy)|2011|2011|447|22.2%|30.6%|
[stopforumspam_1d](#stopforumspam_1d)|6939|6939|413|5.9%|28.2%|
[blocklist_de_bots](#blocklist_de_bots)|3184|3184|224|7.0%|15.3%|
[blocklist_de](#blocklist_de)|22338|22338|223|0.9%|15.2%|
[ri_connect_proxies](#ri_connect_proxies)|2014|2014|213|10.5%|14.5%|
[proxz](#proxz)|433|433|159|36.7%|10.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|64|0.0%|4.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|49|0.0%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|43|0.0%|2.9%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|12|1.7%|0.8%|
[nixspam](#nixspam)|21248|21248|6|0.0%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|4|2.5%|0.2%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|3|0.0%|0.2%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.1%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.0%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6472|6472|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6479|6479|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Mon Jun  1 11:01:38 UTC 2015.

The ipset `proxz` has **433** entries, **433** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|256|0.2%|59.1%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|232|0.7%|53.5%|
[xroxy](#xroxy)|2011|2011|221|10.9%|51.0%|
[ri_web_proxies](#ri_web_proxies)|5426|5426|186|3.4%|42.9%|
[proxyrss](#proxyrss)|1460|1460|159|10.8%|36.7%|
[stopforumspam_1d](#stopforumspam_1d)|6939|6939|100|1.4%|23.0%|
[blocklist_de](#blocklist_de)|22338|22338|85|0.3%|19.6%|
[blocklist_de_bots](#blocklist_de_bots)|3184|3184|75|2.3%|17.3%|
[ri_connect_proxies](#ri_connect_proxies)|2014|2014|67|3.3%|15.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|42|0.0%|9.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|19|0.0%|4.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|16|0.0%|3.6%|
[nixspam](#nixspam)|21248|21248|14|0.0%|3.2%|
[blocklist_de_mail](#blocklist_de_mail)|14586|14586|9|0.0%|2.0%|
[php_spammers](#php_spammers)|417|417|6|1.4%|1.3%|
[php_dictionary](#php_dictionary)|433|433|6|1.3%|1.3%|
[php_commenters](#php_commenters)|281|281|2|0.7%|0.4%|
[et_compromised](#et_compromised)|2367|2367|2|0.0%|0.4%|
[bruteforceblocker](#bruteforceblocker)|2183|2183|2|0.0%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|2|1.2%|0.4%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|2|0.0%|0.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.2%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1660|1660|1|0.0%|0.2%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Mon Jun  1 11:55:40 UTC 2015.

The ipset `ri_connect_proxies` has **2014** entries, **2014** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|1184|1.2%|58.7%|
[ri_web_proxies](#ri_web_proxies)|5426|5426|815|15.0%|40.4%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|691|2.2%|34.3%|
[xroxy](#xroxy)|2011|2011|317|15.7%|15.7%|
[proxyrss](#proxyrss)|1460|1460|213|14.5%|10.5%|
[stopforumspam_1d](#stopforumspam_1d)|6939|6939|155|2.2%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|81|0.0%|4.0%|
[proxz](#proxz)|433|433|67|15.4%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|66|0.0%|3.2%|
[blocklist_de](#blocklist_de)|22338|22338|59|0.2%|2.9%|
[blocklist_de_bots](#blocklist_de_bots)|3184|3184|57|1.7%|2.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|46|0.0%|2.2%|
[nixspam](#nixspam)|21248|21248|10|0.0%|0.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.2%|
[php_dictionary](#php_dictionary)|433|433|3|0.6%|0.1%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[dm_tor](#dm_tor)|6472|6472|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6479|6479|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14586|14586|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1396|1396|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13824|13824|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Mon Jun  1 11:54:06 UTC 2015.

The ipset `ri_web_proxies` has **5426** entries, **5426** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|2650|2.8%|48.8%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|1733|5.5%|31.9%|
[ri_connect_proxies](#ri_connect_proxies)|2014|2014|815|40.4%|15.0%|
[xroxy](#xroxy)|2011|2011|811|40.3%|14.9%|
[proxyrss](#proxyrss)|1460|1460|592|40.5%|10.9%|
[stopforumspam_1d](#stopforumspam_1d)|6939|6939|564|8.1%|10.3%|
[blocklist_de](#blocklist_de)|22338|22338|346|1.5%|6.3%|
[blocklist_de_bots](#blocklist_de_bots)|3184|3184|322|10.1%|5.9%|
[proxz](#proxz)|433|433|186|42.9%|3.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|173|0.0%|3.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|154|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|115|0.0%|2.1%|
[nixspam](#nixspam)|21248|21248|75|0.3%|1.3%|
[php_dictionary](#php_dictionary)|433|433|29|6.6%|0.5%|
[php_spammers](#php_spammers)|417|417|24|5.7%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|14586|14586|23|0.1%|0.4%|
[php_commenters](#php_commenters)|281|281|11|3.9%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|10|1.4%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.0%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|4|2.5%|0.0%|
[dm_tor](#dm_tor)|6472|6472|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6479|6479|3|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|3|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|2|0.2%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1396|1396|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13824|13824|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Mon Jun  1 10:30:05 UTC 2015.

The ipset `shunlist` has **1262** entries, **1262** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|178278|178278|1255|0.7%|99.4%|
[openbl_60d](#openbl_60d)|7590|7590|620|8.1%|49.1%|
[openbl_30d](#openbl_30d)|3201|3201|602|18.8%|47.7%|
[bruteforceblocker](#bruteforceblocker)|2183|2183|524|24.0%|41.5%|
[et_compromised](#et_compromised)|2367|2367|522|22.0%|41.3%|
[blocklist_de](#blocklist_de)|22338|22338|418|1.8%|33.1%|
[openbl_7d](#openbl_7d)|901|901|385|42.7%|30.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|1660|1660|381|22.9%|30.1%|
[et_block](#et_block)|986|18056524|111|0.0%|8.7%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|102|0.0%|8.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|102|0.0%|8.0%|
[openbl_1d](#openbl_1d)|137|137|75|54.7%|5.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|69|0.0%|5.4%|
[dshield](#dshield)|20|5120|61|1.1%|4.8%|
[sslbl](#sslbl)|360|360|43|11.9%|3.4%|
[blocklist_de_apache](#blocklist_de_apache)|13824|13824|29|0.2%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|26|0.0%|2.0%|
[ciarmy](#ciarmy)|329|329|24|7.2%|1.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|20|12.5%|1.5%|
[voipbl](#voipbl)|10343|10752|13|0.1%|1.0%|
[blocklist_de_mail](#blocklist_de_mail)|14586|14586|6|0.0%|0.4%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|5|0.0%|0.3%|
[blocklist_de_imap](#blocklist_de_imap)|526|526|5|0.9%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|4|0.0%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|3|0.0%|0.2%|
[nixspam](#nixspam)|21248|21248|3|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6939|6939|2|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.1%|
[snort_ipfilter](#snort_ipfilter)|714|714|1|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6472|6472|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6479|6479|1|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|95|95|1|1.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|86|86|1|1.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1396|1396|1|0.0%|0.0%|

## snort_ipfilter

[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)

Source is downloaded from [this link](http://labs.snort.org/feeds/ip-filter.blf).

The last time downloaded was found to be dated: Mon Jun  1 01:30:00 UTC 2015.

The ipset `snort_ipfilter` has **714** entries, **714** unique IPs.

The following table shows the overlaps of `snort_ipfilter` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `snort_ipfilter`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `snort_ipfilter`.
- ` this % ` is the percentage **of this ipset (`snort_ipfilter`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|986|18056524|286|0.0%|40.0%|
[zeus](#zeus)|265|265|216|81.5%|30.2%|
[zeus_badips](#zeus_badips)|230|230|195|84.7%|27.3%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|76|0.0%|10.6%|
[feodo](#feodo)|76|76|53|69.7%|7.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|29|0.0%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|24|0.0%|3.3%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|23|1.7%|3.2%|
[sslbl](#sslbl)|360|360|21|5.8%|2.9%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|16|0.0%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|12|0.0%|1.6%|
[palevo](#palevo)|13|13|11|84.6%|1.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|9|0.0%|1.2%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|8|0.0%|1.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|6|0.0%|0.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|6|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|3|0.0%|0.4%|
[openbl_60d](#openbl_60d)|7590|7590|3|0.0%|0.4%|
[nixspam](#nixspam)|21248|21248|3|0.0%|0.4%|
[xroxy](#xroxy)|2011|2011|2|0.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6939|6939|2|0.0%|0.2%|
[ri_web_proxies](#ri_web_proxies)|5426|5426|2|0.0%|0.2%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.2%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.2%|
[openbl_30d](#openbl_30d)|3201|3201|2|0.0%|0.2%|
[shunlist](#shunlist)|1262|1262|1|0.0%|0.1%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.1%|
[openbl_7d](#openbl_7d)|901|901|1|0.1%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.1%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.1%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.1%|
[dm_tor](#dm_tor)|6472|6472|1|0.0%|0.1%|
[bruteforceblocker](#bruteforceblocker)|2183|2183|1|0.0%|0.1%|
[bm_tor](#bm_tor)|6479|6479|1|0.0%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|1660|1660|1|0.0%|0.1%|
[blocklist_de](#blocklist_de)|22338|22338|1|0.0%|0.1%|

## spamhaus_drop

[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**

Source is downloaded from [this link](http://www.spamhaus.org/drop/drop.txt).

The last time downloaded was found to be dated: Sun May 31 20:43:30 UTC 2015.

The ipset `spamhaus_drop` has **652** entries, **18338560** unique IPs.

The following table shows the overlaps of `spamhaus_drop` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `spamhaus_drop`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `spamhaus_drop`.
- ` this % ` is the percentage **of this ipset (`spamhaus_drop`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|986|18056524|17920256|99.2%|97.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8598042|2.4%|46.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7079936|77.1%|38.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|2272266|0.2%|12.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|195904|0.1%|1.0%|
[fullbogons](#fullbogons)|3639|670579672|20480|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|1627|0.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|971|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|512|0.1%|0.0%|
[dshield](#dshield)|20|5120|512|10.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|342|1.0%|0.0%|
[openbl_60d](#openbl_60d)|7590|7590|239|3.1%|0.0%|
[openbl_30d](#openbl_30d)|3201|3201|200|6.2%|0.0%|
[blocklist_de](#blocklist_de)|22338|22338|175|0.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1660|1660|115|6.9%|0.0%|
[shunlist](#shunlist)|1262|1262|102|8.0%|0.0%|
[et_compromised](#et_compromised)|2367|2367|102|4.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2183|2183|101|4.6%|0.0%|
[nixspam](#nixspam)|21248|21248|92|0.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6939|6939|89|1.2%|0.0%|
[openbl_7d](#openbl_7d)|901|901|84|9.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3184|3184|33|1.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|29|2.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14586|14586|25|0.1%|0.0%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.0%|
[openbl_1d](#openbl_1d)|137|137|21|15.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|526|526|17|3.2%|0.0%|
[zeus_badips](#zeus_badips)|230|230|16|6.9%|0.0%|
[zeus](#zeus)|265|265|16|6.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|16|2.2%|0.0%|
[voipbl](#voipbl)|10343|10752|14|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|6|3.7%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[malc0de](#malc0de)|403|403|4|0.9%|0.0%|
[sslbl](#sslbl)|360|360|3|0.8%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6472|6472|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6479|6479|2|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1396|1396|2|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13824|13824|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[et_botcc](#et_botcc)|501|501|1|0.1%|0.0%|

## spamhaus_edrop

[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**

Source is downloaded from [this link](http://www.spamhaus.org/drop/edrop.txt).

The last time downloaded was found to be dated: Sat May 30 16:25:14 UTC 2015.

The ipset `spamhaus_edrop` has **56** entries, **421632** unique IPs.

The following table shows the overlaps of `spamhaus_edrop` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `spamhaus_edrop`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `spamhaus_edrop`.
- ` this % ` is the percentage **of this ipset (`spamhaus_edrop`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|270785|0.1%|64.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|33368|0.0%|7.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|33155|0.0%|7.8%|
[et_block](#et_block)|986|18056524|517|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|512|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|271|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|103|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|37|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6939|6939|7|0.1%|0.0%|
[php_commenters](#php_commenters)|281|281|7|2.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|6|0.8%|0.0%|
[openbl_60d](#openbl_60d)|7590|7590|6|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3201|3201|6|0.1%|0.0%|
[blocklist_de](#blocklist_de)|22338|22338|6|0.0%|0.0%|
[zeus_badips](#zeus_badips)|230|230|5|2.1%|0.0%|
[zeus](#zeus)|265|265|5|1.8%|0.0%|
[shunlist](#shunlist)|1262|1262|5|0.3%|0.0%|
[openbl_7d](#openbl_7d)|901|901|5|0.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3184|3184|5|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|4|2.5%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[nixspam](#nixspam)|21248|21248|1|0.0%|0.0%|
[malc0de](#malc0de)|403|403|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13824|13824|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Mon Jun  1 12:45:05 UTC 2015.

The ipset `sslbl` has **360** entries, **360** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|178278|178278|51|0.0%|14.1%|
[shunlist](#shunlist)|1262|1262|43|3.4%|11.9%|
[feodo](#feodo)|76|76|27|35.5%|7.5%|
[et_block](#et_block)|986|18056524|27|0.0%|7.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|23|0.0%|6.3%|
[snort_ipfilter](#snort_ipfilter)|714|714|21|2.9%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|6|0.0%|1.6%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|3|0.0%|0.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Mon Jun  1 12:00:02 UTC 2015.

The ipset `stopforumspam_1d` has **6939** entries, **6939** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|5512|5.9%|79.4%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|5418|17.2%|78.0%|
[blocklist_de](#blocklist_de)|22338|22338|1404|6.2%|20.2%|
[blocklist_de_bots](#blocklist_de_bots)|3184|3184|1348|42.3%|19.4%|
[ri_web_proxies](#ri_web_proxies)|5426|5426|564|10.3%|8.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|497|0.0%|7.1%|
[proxyrss](#proxyrss)|1460|1460|413|28.2%|5.9%|
[xroxy](#xroxy)|2011|2011|353|17.5%|5.0%|
[et_tor](#et_tor)|6470|6470|291|4.4%|4.1%|
[bm_tor](#bm_tor)|6479|6479|290|4.4%|4.1%|
[dm_tor](#dm_tor)|6472|6472|289|4.4%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|242|0.0%|3.4%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|157|42.2%|2.2%|
[ri_connect_proxies](#ri_connect_proxies)|2014|2014|155|7.6%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|138|0.0%|1.9%|
[proxz](#proxz)|433|433|100|23.0%|1.4%|
[php_commenters](#php_commenters)|281|281|100|35.5%|1.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|93|58.4%|1.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|89|0.0%|1.2%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|65|0.0%|0.9%|
[blocklist_de_apache](#blocklist_de_apache)|13824|13824|62|0.4%|0.8%|
[et_block](#et_block)|986|18056524|61|0.0%|0.8%|
[nixspam](#nixspam)|21248|21248|48|0.2%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|14586|14586|43|0.2%|0.6%|
[php_harvesters](#php_harvesters)|257|257|33|12.8%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|30|0.0%|0.4%|
[php_dictionary](#php_dictionary)|433|433|22|5.0%|0.3%|
[php_spammers](#php_spammers)|417|417|21|5.0%|0.3%|
[openbl_60d](#openbl_60d)|7590|7590|21|0.2%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1396|1396|19|1.3%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|13|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|7|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|5|0.7%|0.0%|
[voipbl](#voipbl)|10343|10752|4|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|2|0.2%|0.0%|
[shunlist](#shunlist)|1262|1262|2|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[zeus](#zeus)|265|265|1|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3201|3201|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2183|2183|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|86|86|1|1.1%|0.0%|

## stopforumspam_30d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip).

The last time downloaded was found to be dated: Mon Jun  1 00:00:39 UTC 2015.

The ipset `stopforumspam_30d` has **92062** entries, **92062** unique IPs.

The following table shows the overlaps of `stopforumspam_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_30d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|31183|99.5%|33.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|5946|0.0%|6.4%|
[stopforumspam_1d](#stopforumspam_1d)|6939|6939|5512|79.4%|5.9%|
[ri_web_proxies](#ri_web_proxies)|5426|5426|2650|48.8%|2.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2477|0.0%|2.6%|
[blocklist_de](#blocklist_de)|22338|22338|2217|9.9%|2.4%|
[blocklist_de_bots](#blocklist_de_bots)|3184|3184|1963|61.6%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1523|0.0%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|2014|2014|1184|58.7%|1.2%|
[xroxy](#xroxy)|2011|2011|1179|58.6%|1.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|971|0.0%|1.0%|
[proxyrss](#proxyrss)|1460|1460|789|54.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|732|0.0%|0.7%|
[et_block](#et_block)|986|18056524|728|0.0%|0.7%|
[et_tor](#et_tor)|6470|6470|623|9.6%|0.6%|
[bm_tor](#bm_tor)|6479|6479|617|9.5%|0.6%|
[dm_tor](#dm_tor)|6472|6472|616|9.5%|0.6%|
[proxz](#proxz)|433|433|256|59.1%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|234|62.9%|0.2%|
[nixspam](#nixspam)|21248|21248|225|1.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|219|0.1%|0.2%|
[php_commenters](#php_commenters)|281|281|203|72.2%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|14586|14586|202|1.3%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|13824|13824|200|1.4%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|112|70.4%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|103|0.0%|0.1%|
[php_spammers](#php_spammers)|417|417|99|23.7%|0.1%|
[php_dictionary](#php_dictionary)|433|433|83|19.1%|0.0%|
[php_harvesters](#php_harvesters)|257|257|63|24.5%|0.0%|
[openbl_60d](#openbl_60d)|7590|7590|54|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|44|0.0%|0.0%|
[voipbl](#voipbl)|10343|10752|40|0.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1396|1396|35|2.5%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|22|3.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|8|1.1%|0.0%|
[et_compromised](#et_compromised)|2367|2367|6|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2183|2183|6|0.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|86|86|6|6.9%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1660|1660|5|0.3%|0.0%|
[shunlist](#shunlist)|1262|1262|4|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3201|3201|4|0.1%|0.0%|
[zeus_badips](#zeus_badips)|230|230|3|1.3%|0.0%|
[zeus](#zeus)|265|265|3|1.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|3|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3639|670579672|2|0.0%|0.0%|
[sslbl](#sslbl)|360|360|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|526|526|1|0.1%|0.0%|

## stopforumspam_7d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip).

The last time downloaded was found to be dated: Mon Jun  1 02:00:09 UTC 2015.

The ipset `stopforumspam_7d` has **31333** entries, **31333** unique IPs.

The following table shows the overlaps of `stopforumspam_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_7d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|31183|33.8%|99.5%|
[stopforumspam_1d](#stopforumspam_1d)|6939|6939|5418|78.0%|17.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2107|0.0%|6.7%|
[blocklist_de](#blocklist_de)|22338|22338|1954|8.7%|6.2%|
[blocklist_de_bots](#blocklist_de_bots)|3184|3184|1800|56.5%|5.7%|
[ri_web_proxies](#ri_web_proxies)|5426|5426|1733|31.9%|5.5%|
[xroxy](#xroxy)|2011|2011|989|49.1%|3.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|938|0.0%|2.9%|
[ri_connect_proxies](#ri_connect_proxies)|2014|2014|691|34.3%|2.2%|
[proxyrss](#proxyrss)|1460|1460|688|47.1%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|563|0.0%|1.7%|
[et_tor](#et_tor)|6470|6470|509|7.8%|1.6%|
[bm_tor](#bm_tor)|6479|6479|476|7.3%|1.5%|
[dm_tor](#dm_tor)|6472|6472|475|7.3%|1.5%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|342|0.0%|1.0%|
[proxz](#proxz)|433|433|232|53.5%|0.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|201|54.0%|0.6%|
[et_block](#et_block)|986|18056524|200|0.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|182|0.0%|0.5%|
[php_commenters](#php_commenters)|281|281|170|60.4%|0.5%|
[nixspam](#nixspam)|21248|21248|137|0.6%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|13824|13824|124|0.8%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|14586|14586|117|0.8%|0.3%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|111|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|103|64.7%|0.3%|
[php_spammers](#php_spammers)|417|417|70|16.7%|0.2%|
[php_dictionary](#php_dictionary)|433|433|68|15.7%|0.2%|
[php_harvesters](#php_harvesters)|257|257|47|18.2%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|37|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1396|1396|30|2.1%|0.0%|
[openbl_60d](#openbl_60d)|7590|7590|27|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|19|0.0%|0.0%|
[voipbl](#voipbl)|10343|10752|12|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|5|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|86|86|5|5.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|3|0.4%|0.0%|
[shunlist](#shunlist)|1262|1262|3|0.2%|0.0%|
[et_compromised](#et_compromised)|2367|2367|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2183|2183|3|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|2|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1660|1660|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[zeus](#zeus)|265|265|1|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3201|3201|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|526|526|1|0.1%|0.0%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Mon Jun  1 08:54:15 UTC 2015.

The ipset `voipbl` has **10343** entries, **10752** unique IPs.

The following table shows the overlaps of `voipbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `voipbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `voipbl`.
- ` this % ` is the percentage **of this ipset (`voipbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1591|0.0%|14.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|431|0.0%|4.0%|
[fullbogons](#fullbogons)|3639|670579672|319|0.0%|2.9%|
[bogons](#bogons)|13|592708608|319|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|295|0.0%|2.7%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|209|0.1%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|40|0.0%|0.3%|
[blocklist_de](#blocklist_de)|22338|22338|40|0.1%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|95|95|31|32.6%|0.2%|
[et_block](#et_block)|986|18056524|17|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|14|0.0%|0.1%|
[shunlist](#shunlist)|1262|1262|13|1.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|12|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7590|7590|9|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13824|13824|5|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6939|6939|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[openbl_7d](#openbl_7d)|901|901|3|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3201|3201|3|0.0%|0.0%|
[ciarmy](#ciarmy)|329|329|3|0.9%|0.0%|
[nixspam](#nixspam)|21248|21248|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6472|6472|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6479|6479|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1660|1660|2|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1396|1396|2|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2183|2183|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14586|14586|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|526|526|1|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3184|3184|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Mon Jun  1 12:33:01 UTC 2015.

The ipset `xroxy` has **2011** entries, **2011** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|1179|1.2%|58.6%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|989|3.1%|49.1%|
[ri_web_proxies](#ri_web_proxies)|5426|5426|811|14.9%|40.3%|
[proxyrss](#proxyrss)|1460|1460|447|30.6%|22.2%|
[stopforumspam_1d](#stopforumspam_1d)|6939|6939|353|5.0%|17.5%|
[ri_connect_proxies](#ri_connect_proxies)|2014|2014|317|15.7%|15.7%|
[blocklist_de](#blocklist_de)|22338|22338|235|1.0%|11.6%|
[proxz](#proxz)|433|433|221|51.0%|10.9%|
[blocklist_de_bots](#blocklist_de_bots)|3184|3184|208|6.5%|10.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|98|0.0%|4.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|84|0.0%|4.1%|
[nixspam](#nixspam)|21248|21248|68|0.3%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|57|0.0%|2.8%|
[blocklist_de_mail](#blocklist_de_mail)|14586|14586|26|0.1%|1.2%|
[php_dictionary](#php_dictionary)|433|433|24|5.5%|1.1%|
[php_spammers](#php_spammers)|417|417|18|4.3%|0.8%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|13|1.9%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|5|3.1%|0.2%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|5|0.0%|0.2%|
[php_commenters](#php_commenters)|281|281|3|1.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.1%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|714|714|2|0.2%|0.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[dm_tor](#dm_tor)|6472|6472|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6479|6479|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2183|2183|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1660|1660|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1396|1396|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13824|13824|1|0.0%|0.0%|

## zeus

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist).

The last time downloaded was found to be dated: Mon Jun  1 08:30:03 UTC 2015.

The ipset `zeus` has **265** entries, **265** unique IPs.

The following table shows the overlaps of `zeus` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus`.
- ` this % ` is the percentage **of this ipset (`zeus`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|986|18056524|259|0.0%|97.7%|
[zeus_badips](#zeus_badips)|230|230|230|100.0%|86.7%|
[snort_ipfilter](#snort_ipfilter)|714|714|216|30.2%|81.5%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|65|0.0%|24.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|18|0.0%|6.7%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|16|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|7|0.0%|2.6%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|5|0.0%|1.8%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|3|0.0%|1.1%|
[openbl_60d](#openbl_60d)|7590|7590|2|0.0%|0.7%|
[openbl_30d](#openbl_30d)|3201|3201|2|0.0%|0.7%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|1|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6939|6939|1|0.0%|0.3%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.3%|
[openbl_7d](#openbl_7d)|901|901|1|0.1%|0.3%|
[nixspam](#nixspam)|21248|21248|1|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.3%|
[bruteforceblocker](#bruteforceblocker)|2183|2183|1|0.0%|0.3%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Mon Jun  1 12:36:29 UTC 2015.

The ipset `zeus_badips` has **230** entries, **230** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|265|265|230|86.7%|100.0%|
[et_block](#et_block)|986|18056524|228|0.0%|99.1%|
[snort_ipfilter](#snort_ipfilter)|714|714|195|27.3%|84.7%|
[alienvault_reputation](#alienvault_reputation)|178278|178278|37|0.0%|16.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|16|0.0%|6.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8|0.0%|3.4%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|5|0.0%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4|0.0%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|3|0.0%|1.3%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6939|6939|1|0.0%|0.4%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.4%|
[openbl_60d](#openbl_60d)|7590|7590|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|3201|3201|1|0.0%|0.4%|
[nixspam](#nixspam)|21248|21248|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.4%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.4%|
[bruteforceblocker](#bruteforceblocker)|2183|2183|1|0.0%|0.4%|
