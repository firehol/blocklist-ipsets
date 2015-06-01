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

The following list was automatically generated on Mon Jun  1 01:38:23 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|173880 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|21806 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|13887 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|3052 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|1532 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|100 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|563 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|14062 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|96 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|1712 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|177 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6377 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|2198 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|308 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|279 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6351 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|986 subnets, 18056524 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botcc](#et_botcc)|[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)|ipv4 hash:ip|501 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net](http://www.emergingthreats.net/) compromised hosts (seems to be a derivate of other lists)|ipv4 hash:ip|2367 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6470 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[feodo](#feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|71 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
[fullbogons](#fullbogons)|[Team-Cymru.org](http://www.team-cymru.org) IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user - **excellent list - use it only your internet interface**|ipv4 hash:net|3639 subnets, 670580696 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt)
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
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|18399 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|141 unique IPs|updated every 1 hour  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|3228 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7618 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|901 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|281 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|433 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|257 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|417 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1640 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|392 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1975 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|5291 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1227 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|714 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|652 subnets, 18338560 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|56 subnets, 421632 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|360 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|6675 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|92062 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|31070 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10343 subnets, 10752 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2005 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|264 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|229 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Sun May 31 22:00:57 UTC 2015.

The ipset `alienvault_reputation` has **173880** entries, **173880** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14372|0.0%|8.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8136|0.0%|4.6%|
[openbl_60d](#openbl_60d)|7618|7618|7594|99.6%|4.3%|
[et_block](#et_block)|986|18056524|5787|0.0%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4436|0.0%|2.5%|
[dshield](#dshield)|20|5120|3846|75.1%|2.2%|
[openbl_30d](#openbl_30d)|3228|3228|3212|99.5%|1.8%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1627|0.0%|0.9%|
[et_compromised](#et_compromised)|2367|2367|1537|64.9%|0.8%|
[bruteforceblocker](#bruteforceblocker)|2198|2198|1417|64.4%|0.8%|
[shunlist](#shunlist)|1227|1227|1224|99.7%|0.7%|
[blocklist_de](#blocklist_de)|21806|21806|1190|5.4%|0.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|1712|1712|938|54.7%|0.5%|
[openbl_7d](#openbl_7d)|901|901|891|98.8%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|518|0.0%|0.2%|
[ciarmy](#ciarmy)|308|308|296|96.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|288|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|271|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|218|0.2%|0.1%|
[voipbl](#voipbl)|10343|10752|209|1.9%|0.1%|
[openbl_1d](#openbl_1d)|141|141|134|95.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13887|13887|125|0.9%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|110|0.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14062|14062|78|0.5%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|76|10.6%|0.0%|
[zeus](#zeus)|264|264|65|24.6%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|64|0.9%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|58|32.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|563|563|55|9.7%|0.0%|
[sslbl](#sslbl)|360|360|50|13.8%|0.0%|
[et_tor](#et_tor)|6470|6470|47|0.7%|0.0%|
[bm_tor](#bm_tor)|6377|6377|47|0.7%|0.0%|
[dm_tor](#dm_tor)|6351|6351|46|0.7%|0.0%|
[zeus_badips](#zeus_badips)|229|229|37|16.1%|0.0%|
[nixspam](#nixspam)|18399|18399|34|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3052|3052|34|1.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|25|6.7%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|96|96|20|20.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[php_commenters](#php_commenters)|281|281|13|4.6%|0.0%|
[malc0de](#malc0de)|403|403|11|2.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1532|1532|11|0.7%|0.0%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|8|0.5%|0.0%|
[php_dictionary](#php_dictionary)|433|433|7|1.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|6|0.4%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|100|100|6|6.0%|0.0%|
[xroxy](#xroxy)|2005|2005|5|0.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|279|279|5|1.7%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5291|5291|3|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|3|0.7%|0.0%|
[et_botcc](#et_botcc)|501|501|3|0.5%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1975|1975|2|0.1%|0.0%|
[proxz](#proxz)|392|392|2|0.5%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[feodo](#feodo)|71|71|1|1.4%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Mon Jun  1 01:14:04 UTC 2015.

The ipset `blocklist_de` has **21806** entries, **21806** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|14062|14062|14045|99.8%|64.4%|
[blocklist_de_apache](#blocklist_de_apache)|13887|13887|13883|99.9%|63.6%|
[blocklist_de_bots](#blocklist_de_bots)|3052|3052|3039|99.5%|13.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2776|0.0%|12.7%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|2346|2.5%|10.7%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|1797|5.7%|8.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1712|1712|1709|99.8%|7.8%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1532|1532|1529|99.8%|7.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1459|0.0%|6.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1431|0.0%|6.5%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|1316|19.7%|6.0%|
[alienvault_reputation](#alienvault_reputation)|173880|173880|1190|0.6%|5.4%|
[openbl_60d](#openbl_60d)|7618|7618|880|11.5%|4.0%|
[openbl_30d](#openbl_30d)|3228|3228|813|25.1%|3.7%|
[bruteforceblocker](#bruteforceblocker)|2198|2198|730|33.2%|3.3%|
[et_compromised](#et_compromised)|2367|2367|660|27.8%|3.0%|
[blocklist_de_imap](#blocklist_de_imap)|563|563|563|100.0%|2.5%|
[openbl_7d](#openbl_7d)|901|901|559|62.0%|2.5%|
[shunlist](#shunlist)|1227|1227|434|35.3%|1.9%|
[nixspam](#nixspam)|18399|18399|407|2.2%|1.8%|
[ri_web_proxies](#ri_web_proxies)|5291|5291|336|6.3%|1.5%|
[proxyrss](#proxyrss)|1640|1640|250|15.2%|1.1%|
[xroxy](#xroxy)|2005|2005|243|12.1%|1.1%|
[et_block](#et_block)|986|18056524|183|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|182|0.0%|0.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|177|100.0%|0.8%|
[openbl_1d](#openbl_1d)|141|141|121|85.8%|0.5%|
[dshield](#dshield)|20|5120|119|2.3%|0.5%|
[blocklist_de_ftp](#blocklist_de_ftp)|100|100|100|100.0%|0.4%|
[proxz](#proxz)|392|392|87|22.1%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|96|96|77|80.2%|0.3%|
[ri_connect_proxies](#ri_connect_proxies)|1975|1975|66|3.3%|0.3%|
[php_commenters](#php_commenters)|281|281|56|19.9%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|55|0.0%|0.2%|
[voipbl](#voipbl)|10343|10752|46|0.4%|0.2%|
[php_dictionary](#php_dictionary)|433|433|46|10.6%|0.2%|
[ciarmy](#ciarmy)|308|308|46|14.9%|0.2%|
[php_spammers](#php_spammers)|417|417|45|10.7%|0.2%|
[php_harvesters](#php_harvesters)|257|257|22|8.5%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|12|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|3|0.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6351|6351|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6377|6377|3|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[zeus](#zeus)|264|264|1|0.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|1|0.1%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Mon Jun  1 01:28:08 UTC 2015.

The ipset `blocklist_de_apache` has **13887** entries, **13887** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|21806|21806|13883|63.6%|99.9%|
[blocklist_de_mail](#blocklist_de_mail)|14062|14062|11059|78.6%|79.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2203|0.0%|15.8%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1532|1532|1532|100.0%|11.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1311|0.0%|9.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1069|0.0%|7.6%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|204|0.2%|1.4%|
[alienvault_reputation](#alienvault_reputation)|173880|173880|125|0.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|111|0.3%|0.7%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|70|1.0%|0.5%|
[ciarmy](#ciarmy)|308|308|40|12.9%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|36|20.3%|0.2%|
[shunlist](#shunlist)|1227|1227|26|2.1%|0.1%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3052|3052|21|0.6%|0.1%|
[nixspam](#nixspam)|18399|18399|10|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[openbl_60d](#openbl_60d)|7618|7618|6|0.0%|0.0%|
[et_block](#et_block)|986|18056524|6|0.0%|0.0%|
[voipbl](#voipbl)|10343|10752|5|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3228|3228|5|0.1%|0.0%|
[dshield](#dshield)|20|5120|4|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|3|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[et_compromised](#et_compromised)|2367|2367|3|0.1%|0.0%|
[dm_tor](#dm_tor)|6351|6351|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2198|2198|3|0.1%|0.0%|
[bm_tor](#bm_tor)|6377|6377|3|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[zeus](#zeus)|264|264|1|0.3%|0.0%|
[xroxy](#xroxy)|2005|2005|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5291|5291|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1975|1975|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[openbl_7d](#openbl_7d)|901|901|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Mon Jun  1 01:28:10 UTC 2015.

The ipset `blocklist_de_bots` has **3052** entries, **3052** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|21806|21806|3039|13.9%|99.5%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|2071|2.2%|67.8%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|1641|5.2%|53.7%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|1244|18.6%|40.7%|
[ri_web_proxies](#ri_web_proxies)|5291|5291|315|5.9%|10.3%|
[proxyrss](#proxyrss)|1640|1640|250|15.2%|8.1%|
[xroxy](#xroxy)|2005|2005|216|10.7%|7.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|216|0.0%|7.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|199|0.0%|6.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|103|58.1%|3.3%|
[proxz](#proxz)|392|392|76|19.3%|2.4%|
[ri_connect_proxies](#ri_connect_proxies)|1975|1975|64|3.2%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|48|0.0%|1.5%|
[nixspam](#nixspam)|18399|18399|47|0.2%|1.5%|
[php_commenters](#php_commenters)|281|281|45|16.0%|1.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|43|0.0%|1.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|40|0.0%|1.3%|
[et_block](#et_block)|986|18056524|40|0.0%|1.3%|
[alienvault_reputation](#alienvault_reputation)|173880|173880|34|0.0%|1.1%|
[blocklist_de_mail](#blocklist_de_mail)|14062|14062|21|0.1%|0.6%|
[blocklist_de_apache](#blocklist_de_apache)|13887|13887|21|0.1%|0.6%|
[php_harvesters](#php_harvesters)|257|257|19|7.3%|0.6%|
[php_dictionary](#php_dictionary)|433|433|18|4.1%|0.5%|
[php_spammers](#php_spammers)|417|417|12|2.8%|0.3%|
[openbl_60d](#openbl_60d)|7618|7618|8|0.1%|0.2%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|4|0.0%|0.1%|
[voipbl](#voipbl)|10343|10752|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3228|3228|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2198|2198|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Mon Jun  1 01:28:12 UTC 2015.

The ipset `blocklist_de_bruteforce` has **1532** entries, **1532** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_apache](#blocklist_de_apache)|13887|13887|1532|11.0%|100.0%|
[blocklist_de](#blocklist_de)|21806|21806|1529|7.0%|99.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|105|0.0%|6.8%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|36|0.0%|2.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|35|0.0%|2.2%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|28|0.0%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|24|0.0%|1.5%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|19|0.2%|1.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|13|7.3%|0.8%|
[alienvault_reputation](#alienvault_reputation)|173880|173880|11|0.0%|0.7%|
[nixspam](#nixspam)|18399|18399|10|0.0%|0.6%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.3%|
[php_commenters](#php_commenters)|281|281|4|1.4%|0.2%|
[et_block](#et_block)|986|18056524|4|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|3|0.0%|0.1%|
[voipbl](#voipbl)|10343|10752|2|0.0%|0.1%|
[zeus](#zeus)|264|264|1|0.3%|0.0%|
[xroxy](#xroxy)|2005|2005|1|0.0%|0.0%|
[shunlist](#shunlist)|1227|1227|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5291|5291|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1975|1975|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Mon Jun  1 01:14:08 UTC 2015.

The ipset `blocklist_de_ftp` has **100** entries, **100** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|21806|21806|100|0.4%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|7|0.0%|7.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|7|0.0%|7.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7|0.0%|7.0%|
[alienvault_reputation](#alienvault_reputation)|173880|173880|6|0.0%|6.0%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|5|0.0%|5.0%|
[openbl_60d](#openbl_60d)|7618|7618|3|0.0%|3.0%|
[nixspam](#nixspam)|18399|18399|3|0.0%|3.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|2.0%|
[openbl_30d](#openbl_30d)|3228|3228|2|0.0%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|2|0.0%|2.0%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|1|0.0%|1.0%|
[shunlist](#shunlist)|1227|1227|1|0.0%|1.0%|
[openbl_7d](#openbl_7d)|901|901|1|0.1%|1.0%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|1.0%|
[dshield](#dshield)|20|5120|1|0.0%|1.0%|
[bruteforceblocker](#bruteforceblocker)|2198|2198|1|0.0%|1.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|1|0.5%|1.0%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Mon Jun  1 01:28:09 UTC 2015.

The ipset `blocklist_de_imap` has **563** entries, **563** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|14062|14062|563|4.0%|100.0%|
[blocklist_de](#blocklist_de)|21806|21806|563|2.5%|100.0%|
[alienvault_reputation](#alienvault_reputation)|173880|173880|55|0.0%|9.7%|
[openbl_60d](#openbl_60d)|7618|7618|35|0.4%|6.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|35|0.0%|6.2%|
[openbl_30d](#openbl_30d)|3228|3228|33|1.0%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|31|0.0%|5.5%|
[openbl_7d](#openbl_7d)|901|901|20|2.2%|3.5%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|16|0.0%|2.8%|
[et_block](#et_block)|986|18056524|16|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|10|0.0%|1.7%|
[et_compromised](#et_compromised)|2367|2367|8|0.3%|1.4%|
[bruteforceblocker](#bruteforceblocker)|2198|2198|6|0.2%|1.0%|
[openbl_1d](#openbl_1d)|141|141|3|2.1%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.5%|
[shunlist](#shunlist)|1227|1227|2|0.1%|0.3%|
[ciarmy](#ciarmy)|308|308|2|0.6%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|2|1.1%|0.3%|
[voipbl](#voipbl)|10343|10752|1|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|1|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|1|0.0%|0.1%|
[nixspam](#nixspam)|18399|18399|1|0.0%|0.1%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Mon Jun  1 01:28:07 UTC 2015.

The ipset `blocklist_de_mail` has **14062** entries, **14062** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|21806|21806|14045|64.4%|99.8%|
[blocklist_de_apache](#blocklist_de_apache)|13887|13887|11059|79.6%|78.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2227|0.0%|15.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1315|0.0%|9.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1107|0.0%|7.8%|
[blocklist_de_imap](#blocklist_de_imap)|563|563|563|100.0%|4.0%|
[nixspam](#nixspam)|18399|18399|346|1.8%|2.4%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|209|0.2%|1.4%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|110|0.3%|0.7%|
[alienvault_reputation](#alienvault_reputation)|173880|173880|78|0.0%|0.5%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|56|0.8%|0.3%|
[openbl_60d](#openbl_60d)|7618|7618|43|0.5%|0.3%|
[openbl_30d](#openbl_30d)|3228|3228|40|1.2%|0.2%|
[php_dictionary](#php_dictionary)|433|433|28|6.4%|0.1%|
[xroxy](#xroxy)|2005|2005|26|1.2%|0.1%|
[php_spammers](#php_spammers)|417|417|26|6.2%|0.1%|
[openbl_7d](#openbl_7d)|901|901|24|2.6%|0.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|23|0.0%|0.1%|
[ri_web_proxies](#ri_web_proxies)|5291|5291|23|0.4%|0.1%|
[et_block](#et_block)|986|18056524|23|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3052|3052|21|0.6%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|19|10.7%|0.1%|
[php_commenters](#php_commenters)|281|281|17|6.0%|0.1%|
[et_compromised](#et_compromised)|2367|2367|11|0.4%|0.0%|
[proxz](#proxz)|392|392|10|2.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2198|2198|8|0.3%|0.0%|
[openbl_1d](#openbl_1d)|141|141|4|2.8%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[shunlist](#shunlist)|1227|1227|3|0.2%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6351|6351|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6377|6377|3|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[ciarmy](#ciarmy)|308|308|2|0.6%|0.0%|
[voipbl](#voipbl)|10343|10752|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1975|1975|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Mon Jun  1 01:14:08 UTC 2015.

The ipset `blocklist_de_sip` has **96** entries, **96** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|21806|21806|77|0.3%|80.2%|
[voipbl](#voipbl)|10343|10752|38|0.3%|39.5%|
[alienvault_reputation](#alienvault_reputation)|173880|173880|20|0.0%|20.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|16|0.0%|16.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|13|0.0%|13.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4|0.0%|4.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|2.0%|
[shunlist](#shunlist)|1227|1227|1|0.0%|1.0%|
[et_botcc](#et_botcc)|501|501|1|0.1%|1.0%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Mon Jun  1 01:28:05 UTC 2015.

The ipset `blocklist_de_ssh` has **1712** entries, **1712** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|21806|21806|1709|7.8%|99.8%|
[alienvault_reputation](#alienvault_reputation)|173880|173880|938|0.5%|54.7%|
[openbl_60d](#openbl_60d)|7618|7618|819|10.7%|47.8%|
[openbl_30d](#openbl_30d)|3228|3228|765|23.6%|44.6%|
[bruteforceblocker](#bruteforceblocker)|2198|2198|717|32.6%|41.8%|
[et_compromised](#et_compromised)|2367|2367|644|27.2%|37.6%|
[openbl_7d](#openbl_7d)|901|901|533|59.1%|31.1%|
[shunlist](#shunlist)|1227|1227|404|32.9%|23.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|179|0.0%|10.4%|
[openbl_1d](#openbl_1d)|141|141|117|82.9%|6.8%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|115|0.0%|6.7%|
[dshield](#dshield)|20|5120|114|2.2%|6.6%|
[et_block](#et_block)|986|18056524|113|0.0%|6.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|91|0.0%|5.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|50|28.2%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|31|0.0%|1.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|6|0.0%|0.3%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|5|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|3|0.0%|0.1%|
[ciarmy](#ciarmy)|308|308|3|0.9%|0.1%|
[voipbl](#voipbl)|10343|10752|2|0.0%|0.1%|
[xroxy](#xroxy)|2005|2005|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|1|0.1%|0.0%|
[proxz](#proxz)|392|392|1|0.2%|0.0%|
[proxyrss](#proxyrss)|1640|1640|1|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.0%|
[nixspam](#nixspam)|18399|18399|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Mon Jun  1 01:14:11 UTC 2015.

The ipset `blocklist_de_strongips` has **177** entries, **177** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|21806|21806|177|0.8%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|112|0.1%|63.2%|
[blocklist_de_bots](#blocklist_de_bots)|3052|3052|103|3.3%|58.1%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|102|0.3%|57.6%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|90|1.3%|50.8%|
[alienvault_reputation](#alienvault_reputation)|173880|173880|58|0.0%|32.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|1712|1712|50|2.9%|28.2%|
[openbl_60d](#openbl_60d)|7618|7618|49|0.6%|27.6%|
[openbl_30d](#openbl_30d)|3228|3228|47|1.4%|26.5%|
[openbl_7d](#openbl_7d)|901|901|46|5.1%|25.9%|
[shunlist](#shunlist)|1227|1227|42|3.4%|23.7%|
[blocklist_de_apache](#blocklist_de_apache)|13887|13887|36|0.2%|20.3%|
[php_commenters](#php_commenters)|281|281|29|10.3%|16.3%|
[blocklist_de_mail](#blocklist_de_mail)|14062|14062|19|0.1%|10.7%|
[openbl_1d](#openbl_1d)|141|141|18|12.7%|10.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|16|0.0%|9.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1532|1532|13|0.8%|7.3%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|10|0.0%|5.6%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|6|0.0%|3.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|6|0.0%|3.3%|
[et_block](#et_block)|986|18056524|6|0.0%|3.3%|
[xroxy](#xroxy)|2005|2005|5|0.2%|2.8%|
[ri_web_proxies](#ri_web_proxies)|5291|5291|4|0.0%|2.2%|
[proxyrss](#proxyrss)|1640|1640|4|0.2%|2.2%|
[php_spammers](#php_spammers)|417|417|4|0.9%|2.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.6%|
[proxz](#proxz)|392|392|2|0.5%|1.1%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|1.1%|
[nixspam](#nixspam)|18399|18399|2|0.0%|1.1%|
[blocklist_de_imap](#blocklist_de_imap)|563|563|2|0.3%|1.1%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.5%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1|0.0%|0.5%|
[blocklist_de_ftp](#blocklist_de_ftp)|100|100|1|1.0%|0.5%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Mon Jun  1 01:09:06 UTC 2015.

The ipset `bm_tor` has **6377** entries, **6377** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[dm_tor](#dm_tor)|6351|6351|6288|99.0%|98.6%|
[et_tor](#et_tor)|6470|6470|5528|85.4%|86.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|607|0.0%|9.5%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|590|0.6%|9.2%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|473|1.5%|7.4%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|303|4.5%|4.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|191|0.0%|2.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|172|46.2%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|160|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|173880|173880|47|0.0%|0.7%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[openbl_60d](#openbl_60d)|7618|7618|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5291|5291|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[xroxy](#xroxy)|2005|2005|3|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|986|18056524|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14062|14062|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13887|13887|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|21806|21806|3|0.0%|0.0%|
[voipbl](#voipbl)|10343|10752|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1975|1975|2|0.1%|0.0%|
[nixspam](#nixspam)|18399|18399|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|1|0.1%|0.0%|
[shunlist](#shunlist)|1227|1227|1|0.0%|0.0%|
[proxz](#proxz)|392|392|1|0.2%|0.0%|

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
[fullbogons](#fullbogons)|3639|670580696|592708608|88.3%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|4194304|3.0%|0.7%|
[voipbl](#voipbl)|10343|10752|319|2.9%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2198|2198|1|0.0%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Sun May 31 23:45:19 UTC 2015.

The ipset `bruteforceblocker` has **2198** entries, **2198** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_compromised](#et_compromised)|2367|2367|2087|88.1%|94.9%|
[alienvault_reputation](#alienvault_reputation)|173880|173880|1417|0.8%|64.4%|
[openbl_60d](#openbl_60d)|7618|7618|1321|17.3%|60.1%|
[openbl_30d](#openbl_30d)|3228|3228|1244|38.5%|56.5%|
[blocklist_de](#blocklist_de)|21806|21806|730|3.3%|33.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1712|1712|717|41.8%|32.6%|
[openbl_7d](#openbl_7d)|901|901|518|57.4%|23.5%|
[shunlist](#shunlist)|1227|1227|511|41.6%|23.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|217|0.0%|9.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|117|0.0%|5.3%|
[dshield](#dshield)|20|5120|117|2.2%|5.3%|
[et_block](#et_block)|986|18056524|103|0.0%|4.6%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|102|0.0%|4.6%|
[openbl_1d](#openbl_1d)|141|141|83|58.8%|3.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|63|0.0%|2.8%|
[blocklist_de_mail](#blocklist_de_mail)|14062|14062|8|0.0%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|7|0.0%|0.3%|
[blocklist_de_imap](#blocklist_de_imap)|563|563|6|1.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|4|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13887|13887|3|0.0%|0.1%|
[proxz](#proxz)|392|392|2|0.5%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|264|264|1|0.3%|0.0%|
[xroxy](#xroxy)|2005|2005|1|0.0%|0.0%|
[voipbl](#voipbl)|10343|10752|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|1|0.1%|0.0%|
[proxyrss](#proxyrss)|1640|1640|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3639|670580696|1|0.0%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|100|100|1|1.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3052|3052|1|0.0%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Mon Jun  1 01:15:16 UTC 2015.

The ipset `ciarmy` has **308** entries, **308** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|173880|173880|296|0.1%|96.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|51|0.0%|16.5%|
[blocklist_de](#blocklist_de)|21806|21806|46|0.2%|14.9%|
[blocklist_de_apache](#blocklist_de_apache)|13887|13887|40|0.2%|12.9%|
[shunlist](#shunlist)|1227|1227|23|1.8%|7.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|16|0.0%|5.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|10|0.0%|3.2%|
[dshield](#dshield)|20|5120|4|0.0%|1.2%|
[voipbl](#voipbl)|10343|10752|3|0.0%|0.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|1712|1712|3|0.1%|0.9%|
[blocklist_de_mail](#blocklist_de_mail)|14062|14062|2|0.0%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|563|563|2|0.3%|0.6%|
[openbl_7d](#openbl_7d)|901|901|1|0.1%|0.3%|
[openbl_60d](#openbl_60d)|7618|7618|1|0.0%|0.3%|
[openbl_30d](#openbl_30d)|3228|3228|1|0.0%|0.3%|
[openbl_1d](#openbl_1d)|141|141|1|0.7%|0.3%|

## cleanmx_viruses

[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses

Source is downloaded from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive).

The last time downloaded was found to be dated: Sun May 31 18:10:16 UTC 2015.

The ipset `cleanmx_viruses` has **279** entries, **279** unique IPs.

The following table shows the overlaps of `cleanmx_viruses` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `cleanmx_viruses`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `cleanmx_viruses`.
- ` this % ` is the percentage **of this ipset (`cleanmx_viruses`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|34|0.0%|12.1%|
[malc0de](#malc0de)|403|403|14|3.4%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|6|0.0%|2.1%|
[alienvault_reputation](#alienvault_reputation)|173880|173880|5|0.0%|1.7%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|3|0.2%|1.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|1.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|1|0.0%|0.3%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Mon Jun  1 01:09:05 UTC 2015.

The ipset `dm_tor` has **6351** entries, **6351** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6377|6377|6288|98.6%|99.0%|
[et_tor](#et_tor)|6470|6470|5520|85.3%|86.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|607|0.0%|9.5%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|589|0.6%|9.2%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|471|1.5%|7.4%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|303|4.5%|4.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|190|0.0%|2.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|172|46.2%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|160|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|173880|173880|46|0.0%|0.7%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7618|7618|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5291|5291|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[xroxy](#xroxy)|2005|2005|3|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|986|18056524|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14062|14062|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13887|13887|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|21806|21806|3|0.0%|0.0%|
[voipbl](#voipbl)|10343|10752|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1975|1975|2|0.1%|0.0%|
[nixspam](#nixspam)|18399|18399|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|1|0.1%|0.0%|
[shunlist](#shunlist)|1227|1227|1|0.0%|0.0%|
[proxz](#proxz)|392|392|1|0.2%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Sun May 31 23:23:30 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|173880|173880|3846|2.2%|75.1%|
[et_block](#et_block)|986|18056524|1024|0.0%|20.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|512|0.0%|10.0%|
[openbl_60d](#openbl_60d)|7618|7618|187|2.4%|3.6%|
[openbl_30d](#openbl_30d)|3228|3228|162|5.0%|3.1%|
[shunlist](#shunlist)|1227|1227|128|10.4%|2.5%|
[et_compromised](#et_compromised)|2367|2367|124|5.2%|2.4%|
[blocklist_de](#blocklist_de)|21806|21806|119|0.5%|2.3%|
[bruteforceblocker](#bruteforceblocker)|2198|2198|117|5.3%|2.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1712|1712|114|6.6%|2.2%|
[openbl_7d](#openbl_7d)|901|901|98|10.8%|1.9%|
[openbl_1d](#openbl_1d)|141|141|18|12.7%|0.3%|
[ciarmy](#ciarmy)|308|308|4|1.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13887|13887|4|0.0%|0.0%|
[malc0de](#malc0de)|403|403|1|0.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|100|100|1|1.0%|0.0%|

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
[fullbogons](#fullbogons)|3639|670580696|20480|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|173880|173880|5787|3.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1040|0.3%|0.0%|
[dshield](#dshield)|20|5120|1024|20.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|728|0.7%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|517|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|286|40.0%|0.0%|
[nixspam](#nixspam)|18399|18399|260|1.4%|0.0%|
[zeus](#zeus)|264|264|259|98.1%|0.0%|
[openbl_60d](#openbl_60d)|7618|7618|241|3.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|228|99.5%|0.0%|
[openbl_30d](#openbl_30d)|3228|3228|205|6.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|202|0.6%|0.0%|
[blocklist_de](#blocklist_de)|21806|21806|183|0.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1712|1712|113|6.6%|0.0%|
[shunlist](#shunlist)|1227|1227|111|9.0%|0.0%|
[et_compromised](#et_compromised)|2367|2367|103|4.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2198|2198|103|4.6%|0.0%|
[openbl_7d](#openbl_7d)|901|901|85|9.4%|0.0%|
[feodo](#feodo)|71|71|67|94.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3052|3052|40|1.3%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|34|0.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|28|2.1%|0.0%|
[sslbl](#sslbl)|360|360|27|7.5%|0.0%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14062|14062|23|0.1%|0.0%|
[openbl_1d](#openbl_1d)|141|141|19|13.4%|0.0%|
[voipbl](#voipbl)|10343|10752|17|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|563|563|16|2.8%|0.0%|
[palevo](#palevo)|13|13|13|100.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|7|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|6|3.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13887|13887|6|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1532|1532|4|0.2%|0.0%|
[malc0de](#malc0de)|403|403|3|0.7%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6351|6351|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6377|6377|3|0.0%|0.0%|
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
[alienvault_reputation](#alienvault_reputation)|173880|173880|3|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[et_block](#et_block)|986|18056524|1|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|96|96|1|1.0%|0.1%|

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
[bruteforceblocker](#bruteforceblocker)|2198|2198|2087|94.9%|88.1%|
[alienvault_reputation](#alienvault_reputation)|173880|173880|1537|0.8%|64.9%|
[openbl_60d](#openbl_60d)|7618|7618|1426|18.7%|60.2%|
[openbl_30d](#openbl_30d)|3228|3228|1311|40.6%|55.3%|
[blocklist_de](#blocklist_de)|21806|21806|660|3.0%|27.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|1712|1712|644|37.6%|27.2%|
[shunlist](#shunlist)|1227|1227|514|41.8%|21.7%|
[openbl_7d](#openbl_7d)|901|901|511|56.7%|21.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|227|0.0%|9.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|140|0.0%|5.9%|
[dshield](#dshield)|20|5120|124|2.4%|5.2%|
[et_block](#et_block)|986|18056524|103|0.0%|4.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|102|0.0%|4.3%|
[openbl_1d](#openbl_1d)|141|141|76|53.9%|3.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|70|0.0%|2.9%|
[blocklist_de_mail](#blocklist_de_mail)|14062|14062|11|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|563|563|8|1.4%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|6|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|3|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13887|13887|3|0.0%|0.1%|
[proxz](#proxz)|392|392|2|0.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|264|264|1|0.3%|0.0%|
[xroxy](#xroxy)|2005|2005|1|0.0%|0.0%|
[voipbl](#voipbl)|10343|10752|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|1|0.1%|0.0%|
[proxyrss](#proxyrss)|1640|1640|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|100|100|1|1.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3052|3052|1|0.0%|0.0%|

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
[bm_tor](#bm_tor)|6377|6377|5528|86.6%|85.4%|
[dm_tor](#dm_tor)|6351|6351|5520|86.9%|85.3%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|623|0.6%|9.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|619|0.0%|9.5%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|500|1.6%|7.7%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|310|4.6%|4.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|184|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|179|48.1%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|163|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|173880|173880|47|0.0%|0.7%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[openbl_60d](#openbl_60d)|7618|7618|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5291|5291|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[xroxy](#xroxy)|2005|2005|3|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|986|18056524|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14062|14062|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13887|13887|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|21806|21806|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1975|1975|2|0.1%|0.0%|
[nixspam](#nixspam)|18399|18399|2|0.0%|0.0%|
[voipbl](#voipbl)|10343|10752|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|1|0.1%|0.0%|
[shunlist](#shunlist)|1227|1227|1|0.0%|0.0%|
[proxz](#proxz)|392|392|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Mon Jun  1 01:09:33 UTC 2015.

The ipset `feodo` has **71** entries, **71** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|986|18056524|67|0.0%|94.3%|
[snort_ipfilter](#snort_ipfilter)|714|714|53|7.4%|74.6%|
[sslbl](#sslbl)|360|360|27|7.5%|38.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|6|0.0%|8.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|3|0.0%|4.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|4.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|1.4%|
[alienvault_reputation](#alienvault_reputation)|173880|173880|1|0.0%|1.4%|

## fullbogons

[Team-Cymru.org](http://www.team-cymru.org) IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user - **excellent list - use it only your internet interface**

Source is downloaded from [this link](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt).

The last time downloaded was found to be dated: Sun May 31 09:35:10 UTC 2015.

The ipset `fullbogons` has **3639** entries, **670580696** unique IPs.

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
[bruteforceblocker](#bruteforceblocker)|2198|2198|1|0.0%|0.0%|

## ib_bluetack_badpeers

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) IPs that have been reported for bad deeds in p2p

Source is downloaded from [this link](http://list.iblocklist.com/?list=cwworuawihqvocglcoss&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sun May 31 03:51:18 UTC 2015.

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
[fullbogons](#fullbogons)|3639|670580696|14|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|173880|173880|14|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.0%|
[et_block](#et_block)|986|18056524|7|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|6|0.0%|0.0%|
[nixspam](#nixspam)|18399|18399|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[xroxy](#xroxy)|2005|2005|3|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|3|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|21806|21806|3|0.0%|0.0%|
[voipbl](#voipbl)|10343|10752|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14062|14062|2|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5291|5291|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1640|1640|1|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1532|1532|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13887|13887|1|0.0%|0.0%|

## ib_bluetack_hijacked

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) hijacked IP-Blocks Hijacked IP space are IP blocks that are being used without permission

Source is downloaded from [this link](http://list.iblocklist.com/?list=usrcshglbiilevmyfhse&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sun May 31 04:20:01 UTC 2015.

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
[fullbogons](#fullbogons)|3639|670580696|565248|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|145472|0.1%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1036|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|732|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|173880|173880|518|0.2%|0.0%|
[nixspam](#nixspam)|18399|18399|259|1.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|192|0.6%|0.0%|
[blocklist_de](#blocklist_de)|21806|21806|55|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3052|3052|43|1.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|30|0.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|27|2.1%|0.0%|
[openbl_60d](#openbl_60d)|7618|7618|19|0.2%|0.0%|
[openbl_30d](#openbl_30d)|3228|3228|14|0.4%|0.0%|
[openbl_7d](#openbl_7d)|901|901|11|1.2%|0.0%|
[zeus_badips](#zeus_badips)|229|229|10|4.3%|0.0%|
[zeus](#zeus)|264|264|10|3.7%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|9|1.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1712|1712|7|0.4%|0.0%|
[et_compromised](#et_compromised)|2367|2367|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2198|2198|5|0.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14062|14062|4|0.0%|0.0%|
[shunlist](#shunlist)|1227|1227|3|0.2%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6351|6351|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6377|6377|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|3|1.6%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|563|563|3|0.5%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[openbl_1d](#openbl_1d)|141|141|2|1.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[voipbl](#voipbl)|10343|10752|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.0%|
[et_botcc](#et_botcc)|501|501|1|0.1%|0.0%|

## ib_bluetack_level1

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Level 1 (for use in p2p): Companies or organizations who are clearly involved with trying to stop filesharing (e.g. Baytsp, MediaDefender, Mediasentry a.o.). Companies which anti-p2p activity has been seen from. Companies that produce or have a strong financial interest in copyrighted material (e.g. music, movie, software industries a.o.). Government ranges or companies that have a strong financial interest in doing work for governments. Legal industry ranges. IPs or ranges of ISPs from which anti-p2p activity has been observed. Basically this list will block all kinds of internet connections that most people would rather not have during their internet travels.

Source is downloaded from [this link](http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sun May 31 09:38:59 UTC 2015.

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
[fullbogons](#fullbogons)|3639|670580696|234359|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|33155|7.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|13248|3.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|173880|173880|4436|2.5%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|1523|1.6%|0.0%|
[blocklist_de](#blocklist_de)|21806|21806|1431|6.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14062|14062|1315|9.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13887|13887|1311|9.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|567|1.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|406|0.8%|0.0%|
[nixspam](#nixspam)|18399|18399|321|1.7%|0.0%|
[voipbl](#voipbl)|10343|10752|295|2.7%|0.0%|
[openbl_60d](#openbl_60d)|7618|7618|173|2.2%|0.0%|
[et_tor](#et_tor)|6470|6470|163|2.5%|0.0%|
[dm_tor](#dm_tor)|6351|6351|160|2.5%|0.0%|
[bm_tor](#bm_tor)|6377|6377|160|2.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|140|2.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5291|5291|114|2.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|97|6.6%|0.0%|
[et_compromised](#et_compromised)|2367|2367|70|2.9%|0.0%|
[openbl_30d](#openbl_30d)|3228|3228|68|2.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|66|5.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1975|1975|65|3.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2198|2198|63|2.8%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|58|8.6%|0.0%|
[xroxy](#xroxy)|2005|2005|57|2.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3052|3052|48|1.5%|0.0%|
[et_botcc](#et_botcc)|501|501|40|7.9%|0.0%|
[proxyrss](#proxyrss)|1640|1640|36|2.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1712|1712|31|1.8%|0.0%|
[shunlist](#shunlist)|1227|1227|24|1.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1532|1532|24|1.5%|0.0%|
[openbl_7d](#openbl_7d)|901|901|17|1.8%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|17|4.5%|0.0%|
[proxz](#proxz)|392|392|15|3.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|12|1.6%|0.0%|
[malc0de](#malc0de)|403|403|12|2.9%|0.0%|
[ciarmy](#ciarmy)|308|308|10|3.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|563|563|10|1.7%|0.0%|
[php_dictionary](#php_dictionary)|433|433|9|2.0%|0.0%|
[zeus](#zeus)|264|264|7|2.6%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|279|279|6|2.1%|0.0%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.0%|
[php_commenters](#php_commenters)|281|281|5|1.7%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[zeus_badips](#zeus_badips)|229|229|4|1.7%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|96|96|4|4.1%|0.0%|
[sslbl](#sslbl)|360|360|3|0.8%|0.0%|
[feodo](#feodo)|71|71|3|4.2%|0.0%|
[openbl_1d](#openbl_1d)|141|141|2|1.4%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|100|100|2|2.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|1|0.5%|0.0%|

## ib_bluetack_level2

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 2 (for use in p2p). General corporate ranges. Ranges used by labs or researchers. Proxies.

Source is downloaded from [this link](http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sun May 31 04:20:35 UTC 2015.

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
[fullbogons](#fullbogons)|3639|670580696|248319|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|33368|7.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|173880|173880|8136|4.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|7733|2.2%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|2477|2.6%|0.0%|
[blocklist_de](#blocklist_de)|21806|21806|1459|6.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14062|14062|1107|7.8%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13887|13887|1069|7.6%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|937|3.0%|0.0%|
[nixspam](#nixspam)|18399|18399|440|2.3%|0.0%|
[voipbl](#voipbl)|10343|10752|431|4.0%|0.0%|
[openbl_60d](#openbl_60d)|7618|7618|362|4.7%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|233|3.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|230|0.4%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3052|3052|199|6.5%|0.0%|
[bm_tor](#bm_tor)|6377|6377|191|2.9%|0.0%|
[dm_tor](#dm_tor)|6351|6351|190|2.9%|0.0%|
[et_tor](#et_tor)|6470|6470|184|2.8%|0.0%|
[openbl_30d](#openbl_30d)|3228|3228|179|5.5%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5291|5291|172|3.2%|0.0%|
[et_compromised](#et_compromised)|2367|2367|140|5.9%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2198|2198|117|5.3%|0.0%|
[xroxy](#xroxy)|2005|2005|96|4.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1712|1712|91|5.3%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1975|1975|79|4.0%|0.0%|
[shunlist](#shunlist)|1227|1227|69|5.6%|0.0%|
[proxyrss](#proxyrss)|1640|1640|64|3.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|45|3.0%|0.0%|
[openbl_7d](#openbl_7d)|901|901|40|4.4%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1532|1532|35|2.2%|0.0%|
[php_spammers](#php_spammers)|417|417|31|7.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|563|563|31|5.5%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|28|4.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|26|2.0%|0.0%|
[malc0de](#malc0de)|403|403|25|6.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|24|3.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|21|5.6%|0.0%|
[et_botcc](#et_botcc)|501|501|21|4.1%|0.0%|
[ciarmy](#ciarmy)|308|308|16|5.1%|0.0%|
[proxz](#proxz)|392|392|15|3.8%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|96|96|13|13.5%|0.0%|
[php_dictionary](#php_dictionary)|433|433|10|2.3%|0.0%|
[zeus](#zeus)|264|264|9|3.4%|0.0%|
[php_commenters](#php_commenters)|281|281|9|3.2%|0.0%|
[zeus_badips](#zeus_badips)|229|229|8|3.4%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|279|279|8|2.8%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|100|100|7|7.0%|0.0%|
[sslbl](#sslbl)|360|360|6|1.6%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|6|3.3%|0.0%|
[openbl_1d](#openbl_1d)|141|141|4|2.8%|0.0%|
[feodo](#feodo)|71|71|3|4.2%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|

## ib_bluetack_level3

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 3 (for use in p2p). Many portal-type websites. ISP ranges that may be dodgy for some reason. Ranges that belong to an individual, but which have not been determined to be used by a particular company. Ranges for things that are unusual in some way. The L3 list is aka the paranoid list.

Source is downloaded from [this link](http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sun May 31 04:20:05 UTC 2015.

The ipset `ib_bluetack_level3` has **17802** entries, **139104824** unique IPs.

The following table shows the overlaps of `ib_bluetack_level3` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level3`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level3`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level3`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[fullbogons](#fullbogons)|3639|670580696|4233775|0.6%|3.0%|
[bogons](#bogons)|13|592708608|4194304|0.7%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2830140|0.8%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1354348|0.1%|0.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|270785|64.2%|0.1%|
[et_block](#et_block)|986|18056524|196184|1.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|195904|1.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[alienvault_reputation](#alienvault_reputation)|173880|173880|14372|8.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|9231|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|5946|6.4%|0.0%|
[blocklist_de](#blocklist_de)|21806|21806|2776|12.7%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14062|14062|2227|15.8%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13887|13887|2203|15.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|2085|6.7%|0.0%|
[voipbl](#voipbl)|10343|10752|1591|14.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1172|2.4%|0.0%|
[nixspam](#nixspam)|18399|18399|939|5.1%|0.0%|
[openbl_60d](#openbl_60d)|7618|7618|715|9.3%|0.0%|
[et_tor](#et_tor)|6470|6470|619|9.5%|0.0%|
[dm_tor](#dm_tor)|6351|6351|607|9.5%|0.0%|
[bm_tor](#bm_tor)|6377|6377|607|9.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|496|7.4%|0.0%|
[openbl_30d](#openbl_30d)|3228|3228|282|8.7%|0.0%|
[et_compromised](#et_compromised)|2367|2367|227|9.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2198|2198|217|9.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3052|3052|216|7.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1712|1712|179|10.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5291|5291|153|2.8%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|146|11.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|125|33.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|110|7.5%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1532|1532|105|6.8%|0.0%|
[shunlist](#shunlist)|1227|1227|93|7.5%|0.0%|
[openbl_7d](#openbl_7d)|901|901|90|9.9%|0.0%|
[xroxy](#xroxy)|2005|2005|84|4.1%|0.0%|
[et_botcc](#et_botcc)|501|501|74|14.7%|0.0%|
[malc0de](#malc0de)|403|403|71|17.6%|0.0%|
[proxyrss](#proxyrss)|1640|1640|56|3.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|51|7.5%|0.0%|
[ciarmy](#ciarmy)|308|308|51|16.5%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1975|1975|45|2.2%|0.0%|
[proxz](#proxz)|392|392|41|10.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|563|563|35|6.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|279|279|34|12.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|29|4.0%|0.0%|
[php_spammers](#php_spammers)|417|417|26|6.2%|0.0%|
[php_dictionary](#php_dictionary)|433|433|24|5.5%|0.0%|
[sslbl](#sslbl)|360|360|23|6.3%|0.0%|
[zeus](#zeus)|264|264|19|7.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|16|9.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|96|96|16|16.6%|0.0%|
[php_harvesters](#php_harvesters)|257|257|15|5.8%|0.0%|
[php_commenters](#php_commenters)|281|281|15|5.3%|0.0%|
[openbl_1d](#openbl_1d)|141|141|15|10.6%|0.0%|
[zeus_badips](#zeus_badips)|229|229|14|6.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|100|100|7|7.0%|0.0%|
[feodo](#feodo)|71|71|6|8.4%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|

## ib_bluetack_proxies

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Open Proxies IPs list (without TOR)

Source is downloaded from [this link](http://list.iblocklist.com/?list=xoebmbyexwuiogmbyprb&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sun May 31 04:20:25 UTC 2015.

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
[xroxy](#xroxy)|2005|2005|13|0.6%|1.9%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|11|0.0%|1.6%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|11|0.0%|1.6%|
[ri_web_proxies](#ri_web_proxies)|5291|5291|10|0.1%|1.4%|
[proxyrss](#proxyrss)|1640|1640|10|0.6%|1.4%|
[ri_connect_proxies](#ri_connect_proxies)|1975|1975|6|0.3%|0.8%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|5|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.2%|
[et_block](#et_block)|986|18056524|2|0.0%|0.2%|
[blocklist_de](#blocklist_de)|21806|21806|2|0.0%|0.2%|
[proxz](#proxz)|392|392|1|0.2%|0.1%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.1%|
[nixspam](#nixspam)|18399|18399|1|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|14062|14062|1|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3052|3052|1|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|173880|173880|1|0.0%|0.1%|

## ib_bluetack_spyware

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) known malicious SPYWARE and ADWARE IP Address ranges

Source is downloaded from [this link](http://list.iblocklist.com/?list=llvtlsjyoyiczbkjsxpf&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sun May 31 03:50:04 UTC 2015.

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
[fullbogons](#fullbogons)|3639|670580696|890|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|173880|173880|288|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|44|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|25|1.9%|0.0%|
[et_tor](#et_tor)|6470|6470|21|0.3%|0.0%|
[dm_tor](#dm_tor)|6351|6351|21|0.3%|0.0%|
[bm_tor](#bm_tor)|6377|6377|21|0.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|20|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|19|1.3%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|11|0.1%|0.0%|
[nixspam](#nixspam)|18399|18399|11|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|6|0.8%|0.0%|
[openbl_60d](#openbl_60d)|7618|7618|6|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5291|5291|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|5|1.3%|0.0%|
[voipbl](#voipbl)|10343|10752|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3228|3228|4|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|21806|21806|4|0.0%|0.0%|
[malc0de](#malc0de)|403|403|3|0.7%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|279|279|3|1.0%|0.0%|
[openbl_7d](#openbl_7d)|901|901|2|0.2%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|96|96|2|2.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13887|13887|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|264|264|1|0.3%|0.0%|
[xroxy](#xroxy)|2005|2005|1|0.0%|0.0%|
[sslbl](#sslbl)|360|360|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|1|0.0%|0.0%|
[shunlist](#shunlist)|1227|1227|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|
[openbl_1d](#openbl_1d)|141|141|1|0.7%|0.0%|
[feodo](#feodo)|71|71|1|1.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2198|2198|1|0.0%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1712|1712|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14062|14062|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1532|1532|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3052|3052|1|0.0%|0.0%|

## ib_bluetack_webexploit

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) web server hack and exploit attempts

Source is downloaded from [this link](http://list.iblocklist.com/?list=ghlzqtqxnzctvvajwwag&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Sun May 31 03:50:04 UTC 2015.

The ipset `ib_bluetack_webexploit` has **1460** entries, **1460** unique IPs.

The following table shows the overlaps of `ib_bluetack_webexploit` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_webexploit`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_webexploit`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_webexploit`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|110|0.0%|7.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|97|0.0%|6.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|45|0.0%|3.0%|
[fullbogons](#fullbogons)|3639|670580696|33|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|19|0.0%|1.3%|
[alienvault_reputation](#alienvault_reputation)|173880|173880|8|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|6|0.0%|0.4%|
[et_block](#et_block)|986|18056524|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|3|0.2%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|2|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7618|7618|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|3228|3228|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.1%|
[et_compromised](#et_compromised)|2367|2367|2|0.0%|0.1%|
[blocklist_de](#blocklist_de)|21806|21806|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5291|5291|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|901|901|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[et_botcc](#et_botcc)|501|501|1|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2198|2198|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|1|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1712|1712|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3052|3052|1|0.0%|0.0%|

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
[cleanmx_viruses](#cleanmx_viruses)|279|279|14|5.0%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|12|0.0%|2.9%|
[alienvault_reputation](#alienvault_reputation)|173880|173880|11|0.0%|2.7%|
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
[fullbogons](#fullbogons)|3639|670580696|9|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|173880|173880|6|0.0%|0.4%|
[malc0de](#malc0de)|403|403|4|0.9%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|3|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.2%|
[cleanmx_viruses](#cleanmx_viruses)|279|279|3|1.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|2|0.0%|0.1%|
[et_botcc](#et_botcc)|501|501|1|0.1%|0.0%|

## maxmind_proxy_fraud

[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.

Source is downloaded from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list).

The last time downloaded was found to be dated: Sun May 31 22:09:14 UTC 2015.

The ipset `maxmind_proxy_fraud` has **372** entries, **372** unique IPs.

The following table shows the overlaps of `maxmind_proxy_fraud` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `maxmind_proxy_fraud`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `maxmind_proxy_fraud`.
- ` this % ` is the percentage **of this ipset (`maxmind_proxy_fraud`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|234|0.2%|62.9%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|200|0.6%|53.7%|
[et_tor](#et_tor)|6470|6470|179|2.7%|48.1%|
[dm_tor](#dm_tor)|6351|6351|172|2.7%|46.2%|
[bm_tor](#bm_tor)|6377|6377|172|2.6%|46.2%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|160|2.3%|43.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|125|0.0%|33.6%|
[php_commenters](#php_commenters)|281|281|28|9.9%|7.5%|
[alienvault_reputation](#alienvault_reputation)|173880|173880|25|0.0%|6.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|21|0.0%|5.6%|
[openbl_60d](#openbl_60d)|7618|7618|18|0.2%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|17|0.0%|4.5%|
[php_harvesters](#php_harvesters)|257|257|6|2.3%|1.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|1.3%|
[ri_web_proxies](#ri_web_proxies)|5291|5291|4|0.0%|1.0%|
[php_spammers](#php_spammers)|417|417|4|0.9%|1.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|1.0%|
[blocklist_de](#blocklist_de)|21806|21806|3|0.0%|0.8%|
[shunlist](#shunlist)|1227|1227|2|0.1%|0.5%|
[blocklist_de_apache](#blocklist_de_apache)|13887|13887|2|0.0%|0.5%|
[xroxy](#xroxy)|2005|2005|1|0.0%|0.2%|
[voipbl](#voipbl)|10343|10752|1|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|714|714|1|0.1%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|1975|1975|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|14062|14062|1|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1532|1532|1|0.0%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3052|3052|1|0.0%|0.2%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Mon Jun  1 01:30:02 UTC 2015.

The ipset `nixspam` has **18399** entries, **18399** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|939|0.0%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|440|0.0%|2.3%|
[blocklist_de](#blocklist_de)|21806|21806|407|1.8%|2.2%|
[blocklist_de_mail](#blocklist_de_mail)|14062|14062|346|2.4%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|321|0.0%|1.7%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|265|0.0%|1.4%|
[et_block](#et_block)|986|18056524|260|0.0%|1.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|259|0.0%|1.4%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|215|0.2%|1.1%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|132|0.4%|0.7%|
[ri_web_proxies](#ri_web_proxies)|5291|5291|77|1.4%|0.4%|
[php_dictionary](#php_dictionary)|433|433|71|16.3%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|65|0.9%|0.3%|
[xroxy](#xroxy)|2005|2005|63|3.1%|0.3%|
[php_spammers](#php_spammers)|417|417|57|13.6%|0.3%|
[blocklist_de_bots](#blocklist_de_bots)|3052|3052|47|1.5%|0.2%|
[alienvault_reputation](#alienvault_reputation)|173880|173880|34|0.0%|0.1%|
[proxz](#proxz)|392|392|12|3.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|11|0.0%|0.0%|
[php_commenters](#php_commenters)|281|281|10|3.5%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1532|1532|10|0.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13887|13887|10|0.0%|0.0%|
[proxyrss](#proxyrss)|1640|1640|8|0.4%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1975|1975|7|0.3%|0.0%|
[openbl_60d](#openbl_60d)|7618|7618|6|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|5|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|3|0.4%|0.0%|
[php_harvesters](#php_harvesters)|257|257|3|1.1%|0.0%|
[openbl_30d](#openbl_30d)|3228|3228|3|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|100|100|3|3.0%|0.0%|
[shunlist](#shunlist)|1227|1227|2|0.1%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6351|6351|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6377|6377|2|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|2|1.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|264|264|1|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1712|1712|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|563|563|1|0.1%|0.0%|

## openbl_1d

[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_1days.txt).

The last time downloaded was found to be dated: Mon Jun  1 01:32:00 UTC 2015.

The ipset `openbl_1d` has **141** entries, **141** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7618|7618|139|1.8%|98.5%|
[openbl_30d](#openbl_30d)|3228|3228|139|4.3%|98.5%|
[openbl_7d](#openbl_7d)|901|901|138|15.3%|97.8%|
[alienvault_reputation](#alienvault_reputation)|173880|173880|134|0.0%|95.0%|
[blocklist_de](#blocklist_de)|21806|21806|121|0.5%|85.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|1712|1712|117|6.8%|82.9%|
[bruteforceblocker](#bruteforceblocker)|2198|2198|83|3.7%|58.8%|
[et_compromised](#et_compromised)|2367|2367|76|3.2%|53.9%|
[shunlist](#shunlist)|1227|1227|70|5.7%|49.6%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|20|0.0%|14.1%|
[et_block](#et_block)|986|18056524|19|0.0%|13.4%|
[dshield](#dshield)|20|5120|18|0.3%|12.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|18|10.1%|12.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|10.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|4|0.0%|2.8%|
[blocklist_de_mail](#blocklist_de_mail)|14062|14062|4|0.0%|2.8%|
[blocklist_de_imap](#blocklist_de_imap)|563|563|3|0.5%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|2|0.0%|1.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|1.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.7%|
[ciarmy](#ciarmy)|308|308|1|0.3%|0.7%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt).

The last time downloaded was found to be dated: Sun May 31 23:42:00 UTC 2015.

The ipset `openbl_30d` has **3228** entries, **3228** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7618|7618|3228|42.3%|100.0%|
[alienvault_reputation](#alienvault_reputation)|173880|173880|3212|1.8%|99.5%|
[et_compromised](#et_compromised)|2367|2367|1311|55.3%|40.6%|
[bruteforceblocker](#bruteforceblocker)|2198|2198|1244|56.5%|38.5%|
[openbl_7d](#openbl_7d)|901|901|901|100.0%|27.9%|
[blocklist_de](#blocklist_de)|21806|21806|813|3.7%|25.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|1712|1712|765|44.6%|23.6%|
[shunlist](#shunlist)|1227|1227|589|48.0%|18.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|282|0.0%|8.7%|
[et_block](#et_block)|986|18056524|205|0.0%|6.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|203|0.0%|6.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|179|0.0%|5.5%|
[dshield](#dshield)|20|5120|162|3.1%|5.0%|
[openbl_1d](#openbl_1d)|141|141|139|98.5%|4.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|68|0.0%|2.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|47|26.5%|1.4%|
[blocklist_de_mail](#blocklist_de_mail)|14062|14062|40|0.2%|1.2%|
[blocklist_de_imap](#blocklist_de_imap)|563|563|33|5.8%|1.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|14|0.0%|0.4%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|6|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13887|13887|5|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|4|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.1%|
[voipbl](#voipbl)|10343|10752|3|0.0%|0.0%|
[nixspam](#nixspam)|18399|18399|3|0.0%|0.0%|
[zeus](#zeus)|264|264|2|0.7%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|2|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|100|100|2|2.0%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|1|0.0%|0.0%|
[ciarmy](#ciarmy)|308|308|1|0.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3052|3052|1|0.0%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt).

The last time downloaded was found to be dated: Sun May 31 23:42:00 UTC 2015.

The ipset `openbl_60d` has **7618** entries, **7618** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|173880|173880|7594|4.3%|99.6%|
[openbl_30d](#openbl_30d)|3228|3228|3228|100.0%|42.3%|
[et_compromised](#et_compromised)|2367|2367|1426|60.2%|18.7%|
[bruteforceblocker](#bruteforceblocker)|2198|2198|1321|60.1%|17.3%|
[openbl_7d](#openbl_7d)|901|901|901|100.0%|11.8%|
[blocklist_de](#blocklist_de)|21806|21806|880|4.0%|11.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|1712|1712|819|47.8%|10.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|715|0.0%|9.3%|
[shunlist](#shunlist)|1227|1227|606|49.3%|7.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|362|0.0%|4.7%|
[et_block](#et_block)|986|18056524|241|0.0%|3.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|239|0.0%|3.1%|
[dshield](#dshield)|20|5120|187|3.6%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|173|0.0%|2.2%|
[openbl_1d](#openbl_1d)|141|141|139|98.5%|1.8%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|54|0.0%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|49|27.6%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|14062|14062|43|0.3%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|563|563|35|6.2%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|27|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|21|0.3%|0.2%|
[et_tor](#et_tor)|6470|6470|21|0.3%|0.2%|
[bm_tor](#bm_tor)|6377|6377|21|0.3%|0.2%|
[dm_tor](#dm_tor)|6351|6351|20|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|19|0.0%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.2%|
[voipbl](#voipbl)|10343|10752|9|0.0%|0.1%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3052|3052|8|0.2%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|6|0.0%|0.0%|
[nixspam](#nixspam)|18399|18399|6|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|6|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13887|13887|6|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|3|0.4%|0.0%|
[php_harvesters](#php_harvesters)|257|257|3|1.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|100|100|3|3.0%|0.0%|
[zeus](#zeus)|264|264|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[ciarmy](#ciarmy)|308|308|1|0.3%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt).

The last time downloaded was found to be dated: Sun May 31 23:42:00 UTC 2015.

The ipset `openbl_7d` has **901** entries, **901** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7618|7618|901|11.8%|100.0%|
[openbl_30d](#openbl_30d)|3228|3228|901|27.9%|100.0%|
[alienvault_reputation](#alienvault_reputation)|173880|173880|891|0.5%|98.8%|
[blocklist_de](#blocklist_de)|21806|21806|559|2.5%|62.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1712|1712|533|31.1%|59.1%|
[bruteforceblocker](#bruteforceblocker)|2198|2198|518|23.5%|57.4%|
[et_compromised](#et_compromised)|2367|2367|511|21.5%|56.7%|
[shunlist](#shunlist)|1227|1227|380|30.9%|42.1%|
[openbl_1d](#openbl_1d)|141|141|138|97.8%|15.3%|
[dshield](#dshield)|20|5120|98|1.9%|10.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|90|0.0%|9.9%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|85|0.0%|9.4%|
[et_block](#et_block)|986|18056524|85|0.0%|9.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|46|25.9%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|40|0.0%|4.4%|
[blocklist_de_mail](#blocklist_de_mail)|14062|14062|24|0.1%|2.6%|
[blocklist_de_imap](#blocklist_de_imap)|563|563|20|3.5%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|17|0.0%|1.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|1.2%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|5|0.0%|0.5%|
[voipbl](#voipbl)|10343|10752|3|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.2%|
[zeus](#zeus)|264|264|1|0.3%|0.1%|
[snort_ipfilter](#snort_ipfilter)|714|714|1|0.1%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ciarmy](#ciarmy)|308|308|1|0.3%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|100|100|1|1.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13887|13887|1|0.0%|0.1%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Mon Jun  1 01:09:30 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|986|18056524|13|0.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|11|1.5%|84.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2|0.0%|15.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|7.6%|
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
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|178|0.5%|63.3%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|82|1.2%|29.1%|
[blocklist_de](#blocklist_de)|21806|21806|56|0.2%|19.9%|
[blocklist_de_bots](#blocklist_de_bots)|3052|3052|45|1.4%|16.0%|
[php_spammers](#php_spammers)|417|417|32|7.6%|11.3%|
[et_tor](#et_tor)|6470|6470|29|0.4%|10.3%|
[dm_tor](#dm_tor)|6351|6351|29|0.4%|10.3%|
[bm_tor](#bm_tor)|6377|6377|29|0.4%|10.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|29|16.3%|10.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|28|7.5%|9.9%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|24|0.0%|8.5%|
[et_block](#et_block)|986|18056524|24|0.0%|8.5%|
[blocklist_de_apache](#blocklist_de_apache)|13887|13887|24|0.1%|8.5%|
[php_dictionary](#php_dictionary)|433|433|22|5.0%|7.8%|
[blocklist_de_mail](#blocklist_de_mail)|14062|14062|17|0.1%|6.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|5.3%|
[alienvault_reputation](#alienvault_reputation)|173880|173880|13|0.0%|4.6%|
[ri_web_proxies](#ri_web_proxies)|5291|5291|11|0.2%|3.9%|
[nixspam](#nixspam)|18399|18399|10|0.0%|3.5%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.2%|
[openbl_60d](#openbl_60d)|7618|7618|8|0.1%|2.8%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|7|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|1.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1532|1532|4|0.2%|1.4%|
[xroxy](#xroxy)|2005|2005|3|0.1%|1.0%|
[proxz](#proxz)|392|392|2|0.5%|0.7%|
[proxyrss](#proxyrss)|1640|1640|2|0.1%|0.7%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.3%|
[zeus](#zeus)|264|264|1|0.3%|0.3%|
[snort_ipfilter](#snort_ipfilter)|714|714|1|0.1%|0.3%|
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
[nixspam](#nixspam)|18399|18399|71|0.3%|16.3%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|64|0.2%|14.7%|
[blocklist_de](#blocklist_de)|21806|21806|46|0.2%|10.6%|
[ri_web_proxies](#ri_web_proxies)|5291|5291|28|0.5%|6.4%|
[blocklist_de_mail](#blocklist_de_mail)|14062|14062|28|0.1%|6.4%|
[xroxy](#xroxy)|2005|2005|24|1.1%|5.5%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|24|0.3%|5.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|24|0.0%|5.5%|
[php_commenters](#php_commenters)|281|281|22|7.8%|5.0%|
[blocklist_de_bots](#blocklist_de_bots)|3052|3052|18|0.5%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|10|0.0%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|9|0.0%|2.0%|
[alienvault_reputation](#alienvault_reputation)|173880|173880|7|0.0%|1.6%|
[proxz](#proxz)|392|392|6|1.5%|1.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|4|0.0%|0.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.9%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.9%|
[et_block](#et_block)|986|18056524|4|0.0%|0.9%|
[dm_tor](#dm_tor)|6351|6351|4|0.0%|0.9%|
[bm_tor](#bm_tor)|6377|6377|4|0.0%|0.9%|
[ri_connect_proxies](#ri_connect_proxies)|1975|1975|3|0.1%|0.6%|
[snort_ipfilter](#snort_ipfilter)|714|714|2|0.2%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|2|1.1%|0.4%|
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
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|45|0.1%|17.5%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|39|0.5%|15.1%|
[blocklist_de](#blocklist_de)|21806|21806|22|0.1%|8.5%|
[blocklist_de_bots](#blocklist_de_bots)|3052|3052|19|0.6%|7.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|5.8%|
[php_commenters](#php_commenters)|281|281|9|3.2%|3.5%|
[alienvault_reputation](#alienvault_reputation)|173880|173880|9|0.0%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|7|0.0%|2.7%|
[et_tor](#et_tor)|6470|6470|7|0.1%|2.7%|
[dm_tor](#dm_tor)|6351|6351|7|0.1%|2.7%|
[bm_tor](#bm_tor)|6377|6377|7|0.1%|2.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|6|1.6%|2.3%|
[openbl_60d](#openbl_60d)|7618|7618|3|0.0%|1.1%|
[nixspam](#nixspam)|18399|18399|3|0.0%|1.1%|
[xroxy](#xroxy)|2005|2005|2|0.0%|0.7%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.7%|
[blocklist_de_ftp](#blocklist_de_ftp)|100|100|2|2.0%|0.7%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|1|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1|0.0%|0.3%|
[ri_web_proxies](#ri_web_proxies)|5291|5291|1|0.0%|0.3%|
[proxyrss](#proxyrss)|1640|1640|1|0.0%|0.3%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.3%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|
[fullbogons](#fullbogons)|3639|670580696|1|0.0%|0.3%|
[et_block](#et_block)|986|18056524|1|0.0%|0.3%|
[bogons](#bogons)|13|592708608|1|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|1|0.5%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|14062|14062|1|0.0%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|13887|13887|1|0.0%|0.3%|

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
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|69|0.2%|16.5%|
[nixspam](#nixspam)|18399|18399|57|0.3%|13.6%|
[blocklist_de](#blocklist_de)|21806|21806|45|0.2%|10.7%|
[php_commenters](#php_commenters)|281|281|32|11.3%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|31|0.0%|7.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|26|0.0%|6.2%|
[blocklist_de_mail](#blocklist_de_mail)|14062|14062|26|0.1%|6.2%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|24|0.3%|5.7%|
[ri_web_proxies](#ri_web_proxies)|5291|5291|24|0.4%|5.7%|
[xroxy](#xroxy)|2005|2005|18|0.8%|4.3%|
[blocklist_de_bots](#blocklist_de_bots)|3052|3052|12|0.3%|2.8%|
[proxz](#proxz)|392|392|6|1.5%|1.4%|
[et_tor](#et_tor)|6470|6470|6|0.0%|1.4%|
[dm_tor](#dm_tor)|6351|6351|6|0.0%|1.4%|
[bm_tor](#bm_tor)|6377|6377|6|0.0%|1.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1532|1532|6|0.3%|1.4%|
[blocklist_de_apache](#blocklist_de_apache)|13887|13887|6|0.0%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|1.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|4|2.2%|0.9%|
[alienvault_reputation](#alienvault_reputation)|173880|173880|3|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2|0.0%|0.4%|
[snort_ipfilter](#snort_ipfilter)|714|714|2|0.2%|0.4%|
[ri_connect_proxies](#ri_connect_proxies)|1975|1975|2|0.1%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[et_block](#et_block)|986|18056524|2|0.0%|0.4%|
[proxyrss](#proxyrss)|1640|1640|1|0.0%|0.2%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1712|1712|1|0.0%|0.2%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Sun May 31 22:31:20 UTC 2015.

The ipset `proxyrss` has **1640** entries, **1640** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|893|0.9%|54.4%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|655|2.1%|39.9%|
[ri_web_proxies](#ri_web_proxies)|5291|5291|596|11.2%|36.3%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|521|7.8%|31.7%|
[xroxy](#xroxy)|2005|2005|471|23.4%|28.7%|
[blocklist_de_bots](#blocklist_de_bots)|3052|3052|250|8.1%|15.2%|
[blocklist_de](#blocklist_de)|21806|21806|250|1.1%|15.2%|
[ri_connect_proxies](#ri_connect_proxies)|1975|1975|186|9.4%|11.3%|
[proxz](#proxz)|392|392|147|37.5%|8.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|64|0.0%|3.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|56|0.0%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|36|0.0%|2.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|10|1.4%|0.6%|
[nixspam](#nixspam)|18399|18399|8|0.0%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|4|2.2%|0.2%|
[php_commenters](#php_commenters)|281|281|2|0.7%|0.1%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2198|2198|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1712|1712|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Mon Jun  1 00:51:28 UTC 2015.

The ipset `proxz` has **392** entries, **392** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|235|0.2%|59.9%|
[xroxy](#xroxy)|2005|2005|210|10.4%|53.5%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|201|0.6%|51.2%|
[ri_web_proxies](#ri_web_proxies)|5291|5291|176|3.3%|44.8%|
[proxyrss](#proxyrss)|1640|1640|147|8.9%|37.5%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|107|1.6%|27.2%|
[blocklist_de](#blocklist_de)|21806|21806|87|0.3%|22.1%|
[blocklist_de_bots](#blocklist_de_bots)|3052|3052|76|2.4%|19.3%|
[ri_connect_proxies](#ri_connect_proxies)|1975|1975|60|3.0%|15.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|41|0.0%|10.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|15|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|15|0.0%|3.8%|
[nixspam](#nixspam)|18399|18399|12|0.0%|3.0%|
[blocklist_de_mail](#blocklist_de_mail)|14062|14062|10|0.0%|2.5%|
[php_spammers](#php_spammers)|417|417|6|1.4%|1.5%|
[php_dictionary](#php_dictionary)|433|433|6|1.3%|1.5%|
[php_commenters](#php_commenters)|281|281|2|0.7%|0.5%|
[et_compromised](#et_compromised)|2367|2367|2|0.0%|0.5%|
[bruteforceblocker](#bruteforceblocker)|2198|2198|2|0.0%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|2|1.1%|0.5%|
[alienvault_reputation](#alienvault_reputation)|173880|173880|2|0.0%|0.5%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.2%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.2%|
[dm_tor](#dm_tor)|6351|6351|1|0.0%|0.2%|
[bm_tor](#bm_tor)|6377|6377|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1712|1712|1|0.0%|0.2%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Sun May 31 22:12:00 UTC 2015.

The ipset `ri_connect_proxies` has **1975** entries, **1975** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|1165|1.2%|58.9%|
[ri_web_proxies](#ri_web_proxies)|5291|5291|792|14.9%|40.1%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|695|2.2%|35.1%|
[xroxy](#xroxy)|2005|2005|314|15.6%|15.8%|
[proxyrss](#proxyrss)|1640|1640|186|11.3%|9.4%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|153|2.2%|7.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|79|0.0%|4.0%|
[blocklist_de](#blocklist_de)|21806|21806|66|0.3%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|65|0.0%|3.2%|
[blocklist_de_bots](#blocklist_de_bots)|3052|3052|64|2.0%|3.2%|
[proxz](#proxz)|392|392|60|15.3%|3.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|45|0.0%|2.2%|
[nixspam](#nixspam)|18399|18399|7|0.0%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.3%|
[php_dictionary](#php_dictionary)|433|433|3|0.6%|0.1%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.1%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.1%|
[dm_tor](#dm_tor)|6351|6351|2|0.0%|0.1%|
[bm_tor](#bm_tor)|6377|6377|2|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|173880|173880|2|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14062|14062|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1532|1532|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13887|13887|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Sun May 31 22:10:45 UTC 2015.

The ipset `ri_web_proxies` has **5291** entries, **5291** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|2601|2.8%|49.1%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|1714|5.5%|32.3%|
[xroxy](#xroxy)|2005|2005|799|39.8%|15.1%|
[ri_connect_proxies](#ri_connect_proxies)|1975|1975|792|40.1%|14.9%|
[proxyrss](#proxyrss)|1640|1640|596|36.3%|11.2%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|555|8.3%|10.4%|
[blocklist_de](#blocklist_de)|21806|21806|336|1.5%|6.3%|
[blocklist_de_bots](#blocklist_de_bots)|3052|3052|315|10.3%|5.9%|
[proxz](#proxz)|392|392|176|44.8%|3.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|172|0.0%|3.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|153|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|114|0.0%|2.1%|
[nixspam](#nixspam)|18399|18399|77|0.4%|1.4%|
[php_dictionary](#php_dictionary)|433|433|28|6.4%|0.5%|
[php_spammers](#php_spammers)|417|417|24|5.7%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|14062|14062|23|0.1%|0.4%|
[php_commenters](#php_commenters)|281|281|11|3.9%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|10|1.4%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.0%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6351|6351|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6377|6377|4|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|4|2.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|173880|173880|3|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|2|0.2%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1532|1532|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13887|13887|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Sun May 31 22:30:05 UTC 2015.

The ipset `shunlist` has **1227** entries, **1227** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|173880|173880|1224|0.7%|99.7%|
[openbl_60d](#openbl_60d)|7618|7618|606|7.9%|49.3%|
[openbl_30d](#openbl_30d)|3228|3228|589|18.2%|48.0%|
[et_compromised](#et_compromised)|2367|2367|514|21.7%|41.8%|
[bruteforceblocker](#bruteforceblocker)|2198|2198|511|23.2%|41.6%|
[blocklist_de](#blocklist_de)|21806|21806|434|1.9%|35.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|1712|1712|404|23.5%|32.9%|
[openbl_7d](#openbl_7d)|901|901|380|42.1%|30.9%|
[dshield](#dshield)|20|5120|128|2.5%|10.4%|
[et_block](#et_block)|986|18056524|111|0.0%|9.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|102|0.0%|8.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|93|0.0%|7.5%|
[openbl_1d](#openbl_1d)|141|141|70|49.6%|5.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|69|0.0%|5.6%|
[sslbl](#sslbl)|360|360|43|11.9%|3.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|42|23.7%|3.4%|
[blocklist_de_apache](#blocklist_de_apache)|13887|13887|26|0.1%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|24|0.0%|1.9%|
[ciarmy](#ciarmy)|308|308|23|7.4%|1.8%|
[voipbl](#voipbl)|10343|10752|13|0.1%|1.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|5|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|4|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|14062|14062|3|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|2|0.0%|0.1%|
[nixspam](#nixspam)|18399|18399|2|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|563|563|2|0.3%|0.1%|
[snort_ipfilter](#snort_ipfilter)|714|714|1|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6351|6351|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6377|6377|1|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|96|96|1|1.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|100|100|1|1.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1532|1532|1|0.0%|0.0%|

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
[zeus](#zeus)|264|264|215|81.4%|30.1%|
[zeus_badips](#zeus_badips)|229|229|195|85.1%|27.3%|
[alienvault_reputation](#alienvault_reputation)|173880|173880|76|0.0%|10.6%|
[feodo](#feodo)|71|71|53|74.6%|7.4%|
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
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|3|0.0%|0.4%|
[openbl_60d](#openbl_60d)|7618|7618|3|0.0%|0.4%|
[nixspam](#nixspam)|18399|18399|3|0.0%|0.4%|
[xroxy](#xroxy)|2005|2005|2|0.0%|0.2%|
[ri_web_proxies](#ri_web_proxies)|5291|5291|2|0.0%|0.2%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.2%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.2%|
[openbl_30d](#openbl_30d)|3228|3228|2|0.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|1|0.0%|0.1%|
[shunlist](#shunlist)|1227|1227|1|0.0%|0.1%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.1%|
[openbl_7d](#openbl_7d)|901|901|1|0.1%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.1%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.1%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.1%|
[dm_tor](#dm_tor)|6351|6351|1|0.0%|0.1%|
[bruteforceblocker](#bruteforceblocker)|2198|2198|1|0.0%|0.1%|
[bm_tor](#bm_tor)|6377|6377|1|0.0%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|1712|1712|1|0.0%|0.1%|
[blocklist_de](#blocklist_de)|21806|21806|1|0.0%|0.1%|

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
[fullbogons](#fullbogons)|3639|670580696|20480|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|173880|173880|1627|0.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|971|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|512|0.1%|0.0%|
[dshield](#dshield)|20|5120|512|10.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|347|1.1%|0.0%|
[nixspam](#nixspam)|18399|18399|265|1.4%|0.0%|
[openbl_60d](#openbl_60d)|7618|7618|239|3.1%|0.0%|
[openbl_30d](#openbl_30d)|3228|3228|203|6.2%|0.0%|
[blocklist_de](#blocklist_de)|21806|21806|182|0.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1712|1712|115|6.7%|0.0%|
[shunlist](#shunlist)|1227|1227|102|8.3%|0.0%|
[et_compromised](#et_compromised)|2367|2367|102|4.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2198|2198|102|4.6%|0.0%|
[openbl_7d](#openbl_7d)|901|901|85|9.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|66|0.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3052|3052|40|1.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|29|2.2%|0.0%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14062|14062|23|0.1%|0.0%|
[openbl_1d](#openbl_1d)|141|141|20|14.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|16|6.9%|0.0%|
[zeus](#zeus)|264|264|16|6.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|16|2.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|563|563|16|2.8%|0.0%|
[voipbl](#voipbl)|10343|10752|14|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|6|3.3%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[malc0de](#malc0de)|403|403|4|0.9%|0.0%|
[sslbl](#sslbl)|360|360|3|0.8%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1532|1532|3|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13887|13887|3|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6351|6351|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6377|6377|2|0.0%|0.0%|
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
[alienvault_reputation](#alienvault_reputation)|173880|173880|271|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|103|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|43|0.1%|0.0%|
[blocklist_de](#blocklist_de)|21806|21806|12|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|10|5.6%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|7|0.1%|0.0%|
[php_commenters](#php_commenters)|281|281|7|2.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|6|0.8%|0.0%|
[openbl_60d](#openbl_60d)|7618|7618|6|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3228|3228|6|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|5|2.1%|0.0%|
[zeus](#zeus)|264|264|5|1.8%|0.0%|
[shunlist](#shunlist)|1227|1227|5|0.4%|0.0%|
[openbl_7d](#openbl_7d)|901|901|5|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1712|1712|5|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3052|3052|4|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13887|13887|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[malc0de](#malc0de)|403|403|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Mon Jun  1 01:15:06 UTC 2015.

The ipset `sslbl` has **360** entries, **360** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|173880|173880|50|0.0%|13.8%|
[shunlist](#shunlist)|1227|1227|43|3.5%|11.9%|
[feodo](#feodo)|71|71|27|38.0%|7.5%|
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

The last time downloaded was found to be dated: Mon Jun  1 01:00:02 UTC 2015.

The ipset `stopforumspam_1d` has **6675** entries, **6675** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|6587|7.1%|98.6%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|3704|11.9%|55.4%|
[blocklist_de](#blocklist_de)|21806|21806|1316|6.0%|19.7%|
[blocklist_de_bots](#blocklist_de_bots)|3052|3052|1244|40.7%|18.6%|
[ri_web_proxies](#ri_web_proxies)|5291|5291|555|10.4%|8.3%|
[proxyrss](#proxyrss)|1640|1640|521|31.7%|7.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|496|0.0%|7.4%|
[xroxy](#xroxy)|2005|2005|361|18.0%|5.4%|
[et_tor](#et_tor)|6470|6470|310|4.7%|4.6%|
[dm_tor](#dm_tor)|6351|6351|303|4.7%|4.5%|
[bm_tor](#bm_tor)|6377|6377|303|4.7%|4.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|233|0.0%|3.4%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|160|43.0%|2.3%|
[ri_connect_proxies](#ri_connect_proxies)|1975|1975|153|7.7%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|140|0.0%|2.0%|
[proxz](#proxz)|392|392|107|27.2%|1.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|90|50.8%|1.3%|
[php_commenters](#php_commenters)|281|281|82|29.1%|1.2%|
[blocklist_de_apache](#blocklist_de_apache)|13887|13887|70|0.5%|1.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|66|0.0%|0.9%|
[nixspam](#nixspam)|18399|18399|65|0.3%|0.9%|
[alienvault_reputation](#alienvault_reputation)|173880|173880|64|0.0%|0.9%|
[blocklist_de_mail](#blocklist_de_mail)|14062|14062|56|0.3%|0.8%|
[php_harvesters](#php_harvesters)|257|257|39|15.1%|0.5%|
[et_block](#et_block)|986|18056524|34|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|30|0.0%|0.4%|
[php_spammers](#php_spammers)|417|417|24|5.7%|0.3%|
[php_dictionary](#php_dictionary)|433|433|24|5.5%|0.3%|
[openbl_60d](#openbl_60d)|7618|7618|21|0.2%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1532|1532|19|1.2%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|11|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|7|0.0%|0.1%|
[voipbl](#voipbl)|10343|10752|5|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|5|0.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.0%|
[shunlist](#shunlist)|1227|1227|2|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|1|0.1%|0.0%|
[openbl_30d](#openbl_30d)|3228|3228|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2198|2198|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|100|100|1|1.0%|0.0%|

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
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|31068|99.9%|33.7%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|6587|98.6%|7.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|5946|0.0%|6.4%|
[ri_web_proxies](#ri_web_proxies)|5291|5291|2601|49.1%|2.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2477|0.0%|2.6%|
[blocklist_de](#blocklist_de)|21806|21806|2346|10.7%|2.5%|
[blocklist_de_bots](#blocklist_de_bots)|3052|3052|2071|67.8%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1523|0.0%|1.6%|
[xroxy](#xroxy)|2005|2005|1175|58.6%|1.2%|
[ri_connect_proxies](#ri_connect_proxies)|1975|1975|1165|58.9%|1.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|971|0.0%|1.0%|
[proxyrss](#proxyrss)|1640|1640|893|54.4%|0.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|732|0.0%|0.7%|
[et_block](#et_block)|986|18056524|728|0.0%|0.7%|
[et_tor](#et_tor)|6470|6470|623|9.6%|0.6%|
[bm_tor](#bm_tor)|6377|6377|590|9.2%|0.6%|
[dm_tor](#dm_tor)|6351|6351|589|9.2%|0.6%|
[proxz](#proxz)|392|392|235|59.9%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|234|62.9%|0.2%|
[alienvault_reputation](#alienvault_reputation)|173880|173880|218|0.1%|0.2%|
[nixspam](#nixspam)|18399|18399|215|1.1%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|14062|14062|209|1.4%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|13887|13887|204|1.4%|0.2%|
[php_commenters](#php_commenters)|281|281|203|72.2%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|112|63.2%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|103|0.0%|0.1%|
[php_spammers](#php_spammers)|417|417|99|23.7%|0.1%|
[php_dictionary](#php_dictionary)|433|433|83|19.1%|0.0%|
[php_harvesters](#php_harvesters)|257|257|63|24.5%|0.0%|
[openbl_60d](#openbl_60d)|7618|7618|54|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|44|0.0%|0.0%|
[voipbl](#voipbl)|10343|10752|40|0.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1532|1532|36|2.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|22|3.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|8|1.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2198|2198|7|0.3%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|100|100|7|7.0%|0.0%|
[et_compromised](#et_compromised)|2367|2367|6|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1712|1712|6|0.3%|0.0%|
[shunlist](#shunlist)|1227|1227|4|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3228|3228|4|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|3|1.3%|0.0%|
[zeus](#zeus)|264|264|3|1.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|3|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3639|670580696|2|0.0%|0.0%|
[sslbl](#sslbl)|360|360|1|0.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|279|279|1|0.3%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|563|563|1|0.1%|0.0%|

## stopforumspam_7d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip).

The last time downloaded was found to be dated: Sun May 31 02:00:09 UTC 2015.

The ipset `stopforumspam_7d` has **31070** entries, **31070** unique IPs.

The following table shows the overlaps of `stopforumspam_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_7d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|31068|33.7%|99.9%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|3704|55.4%|11.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2085|0.0%|6.7%|
[blocklist_de](#blocklist_de)|21806|21806|1797|8.2%|5.7%|
[ri_web_proxies](#ri_web_proxies)|5291|5291|1714|32.3%|5.5%|
[blocklist_de_bots](#blocklist_de_bots)|3052|3052|1641|53.7%|5.2%|
[xroxy](#xroxy)|2005|2005|993|49.5%|3.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|937|0.0%|3.0%|
[ri_connect_proxies](#ri_connect_proxies)|1975|1975|695|35.1%|2.2%|
[proxyrss](#proxyrss)|1640|1640|655|39.9%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|567|0.0%|1.8%|
[et_tor](#et_tor)|6470|6470|500|7.7%|1.6%|
[bm_tor](#bm_tor)|6377|6377|473|7.4%|1.5%|
[dm_tor](#dm_tor)|6351|6351|471|7.4%|1.5%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|347|0.0%|1.1%|
[et_block](#et_block)|986|18056524|202|0.0%|0.6%|
[proxz](#proxz)|392|392|201|51.2%|0.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|200|53.7%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|192|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|178|63.3%|0.5%|
[nixspam](#nixspam)|18399|18399|132|0.7%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|13887|13887|111|0.7%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|14062|14062|110|0.7%|0.3%|
[alienvault_reputation](#alienvault_reputation)|173880|173880|110|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|102|57.6%|0.3%|
[php_spammers](#php_spammers)|417|417|69|16.5%|0.2%|
[php_dictionary](#php_dictionary)|433|433|64|14.7%|0.2%|
[php_harvesters](#php_harvesters)|257|257|45|17.5%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|43|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1532|1532|28|1.8%|0.0%|
[openbl_60d](#openbl_60d)|7618|7618|27|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|20|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.0%|
[voipbl](#voipbl)|10343|10752|10|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|100|100|5|5.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2198|2198|4|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|3|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.0%|
[et_compromised](#et_compromised)|2367|2367|3|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1712|1712|3|0.1%|0.0%|
[shunlist](#shunlist)|1227|1227|2|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|2|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|264|264|1|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3228|3228|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|563|563|1|0.1%|0.0%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Mon Jun  1 00:36:40 UTC 2015.

The ipset `voipbl` has **10343** entries, **10752** unique IPs.

The following table shows the overlaps of `voipbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `voipbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `voipbl`.
- ` this % ` is the percentage **of this ipset (`voipbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1591|0.0%|14.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|431|0.0%|4.0%|
[fullbogons](#fullbogons)|3639|670580696|319|0.0%|2.9%|
[bogons](#bogons)|13|592708608|319|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|295|0.0%|2.7%|
[alienvault_reputation](#alienvault_reputation)|173880|173880|209|0.1%|1.9%|
[blocklist_de](#blocklist_de)|21806|21806|46|0.2%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|40|0.0%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|96|96|38|39.5%|0.3%|
[et_block](#et_block)|986|18056524|17|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|14|0.0%|0.1%|
[shunlist](#shunlist)|1227|1227|13|1.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|10|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7618|7618|9|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|5|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13887|13887|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[openbl_7d](#openbl_7d)|901|901|3|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3228|3228|3|0.0%|0.0%|
[ciarmy](#ciarmy)|308|308|3|0.9%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6351|6351|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6377|6377|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1712|1712|2|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1532|1532|2|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2198|2198|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14062|14062|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|563|563|1|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3052|3052|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Mon Jun  1 01:33:01 UTC 2015.

The ipset `xroxy` has **2005** entries, **2005** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|1175|1.2%|58.6%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|993|3.1%|49.5%|
[ri_web_proxies](#ri_web_proxies)|5291|5291|799|15.1%|39.8%|
[proxyrss](#proxyrss)|1640|1640|471|28.7%|23.4%|
[stopforumspam_1d](#stopforumspam_1d)|6675|6675|361|5.4%|18.0%|
[ri_connect_proxies](#ri_connect_proxies)|1975|1975|314|15.8%|15.6%|
[blocklist_de](#blocklist_de)|21806|21806|243|1.1%|12.1%|
[blocklist_de_bots](#blocklist_de_bots)|3052|3052|216|7.0%|10.7%|
[proxz](#proxz)|392|392|210|53.5%|10.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|96|0.0%|4.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|84|0.0%|4.1%|
[nixspam](#nixspam)|18399|18399|63|0.3%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|57|0.0%|2.8%|
[blocklist_de_mail](#blocklist_de_mail)|14062|14062|26|0.1%|1.2%|
[php_dictionary](#php_dictionary)|433|433|24|5.5%|1.1%|
[php_spammers](#php_spammers)|417|417|18|4.3%|0.8%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|13|1.9%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|177|177|5|2.8%|0.2%|
[alienvault_reputation](#alienvault_reputation)|173880|173880|5|0.0%|0.2%|
[php_commenters](#php_commenters)|281|281|3|1.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.1%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.1%|
[dm_tor](#dm_tor)|6351|6351|3|0.0%|0.1%|
[bm_tor](#bm_tor)|6377|6377|3|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|714|714|2|0.2%|0.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2198|2198|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1712|1712|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1532|1532|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13887|13887|1|0.0%|0.0%|

## zeus

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist).

The last time downloaded was found to be dated: Mon Jun  1 00:23:18 UTC 2015.

The ipset `zeus` has **264** entries, **264** unique IPs.

The following table shows the overlaps of `zeus` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus`.
- ` this % ` is the percentage **of this ipset (`zeus`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|986|18056524|259|0.0%|98.1%|
[zeus_badips](#zeus_badips)|229|229|229|100.0%|86.7%|
[snort_ipfilter](#snort_ipfilter)|714|714|215|30.1%|81.4%|
[alienvault_reputation](#alienvault_reputation)|173880|173880|65|0.0%|24.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|19|0.0%|7.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|16|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|7|0.0%|2.6%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|5|0.0%|1.8%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|3|0.0%|1.1%|
[openbl_60d](#openbl_60d)|7618|7618|2|0.0%|0.7%|
[openbl_30d](#openbl_30d)|3228|3228|2|0.0%|0.7%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|1|0.0%|0.3%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.3%|
[openbl_7d](#openbl_7d)|901|901|1|0.1%|0.3%|
[nixspam](#nixspam)|18399|18399|1|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.3%|
[bruteforceblocker](#bruteforceblocker)|2198|2198|1|0.0%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1532|1532|1|0.0%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|13887|13887|1|0.0%|0.3%|
[blocklist_de](#blocklist_de)|21806|21806|1|0.0%|0.3%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Mon Jun  1 01:09:28 UTC 2015.

The ipset `zeus_badips` has **229** entries, **229** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|264|264|229|86.7%|100.0%|
[et_block](#et_block)|986|18056524|228|0.0%|99.5%|
[snort_ipfilter](#snort_ipfilter)|714|714|195|27.3%|85.1%|
[alienvault_reputation](#alienvault_reputation)|173880|173880|37|0.0%|16.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|16|0.0%|6.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14|0.0%|6.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8|0.0%|3.4%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|5|0.0%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4|0.0%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|3|0.0%|1.3%|
[stopforumspam_7d](#stopforumspam_7d)|31070|31070|1|0.0%|0.4%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.4%|
[openbl_60d](#openbl_60d)|7618|7618|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|3228|3228|1|0.0%|0.4%|
[nixspam](#nixspam)|18399|18399|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.4%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.4%|
[bruteforceblocker](#bruteforceblocker)|2198|2198|1|0.0%|0.4%|
