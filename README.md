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

The following list was automatically generated on Mon Jun  1 06:56:58 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|175192 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|22021 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|13791 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|3196 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|1384 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|98 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|528 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|14254 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|92 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|1692 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|178 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6405 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|2188 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|319 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|82 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6402 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
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
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|18400 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|127 unique IPs|updated every 1 hour  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|3216 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7607 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|897 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|281 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|433 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|257 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|417 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1706 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|415 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|1998 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|5374 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1255 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|714 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|652 subnets, 18338560 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|56 subnets, 421632 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|361 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|6640 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|92062 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|31333 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10343 subnets, 10752 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2008 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|265 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|229 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Mon Jun  1 04:00:43 UTC 2015.

The ipset `alienvault_reputation` has **175192** entries, **175192** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14378|0.0%|8.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8137|0.0%|4.6%|
[openbl_60d](#openbl_60d)|7607|7607|7587|99.7%|4.3%|
[et_block](#et_block)|986|18056524|5787|0.0%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4437|0.0%|2.5%|
[dshield](#dshield)|20|5120|3587|70.0%|2.0%|
[openbl_30d](#openbl_30d)|3216|3216|3204|99.6%|1.8%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1627|0.0%|0.9%|
[et_compromised](#et_compromised)|2367|2367|1538|64.9%|0.8%|
[bruteforceblocker](#bruteforceblocker)|2188|2188|1409|64.3%|0.8%|
[shunlist](#shunlist)|1255|1255|1247|99.3%|0.7%|
[blocklist_de](#blocklist_de)|22021|22021|1177|5.3%|0.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|1692|1692|926|54.7%|0.5%|
[openbl_7d](#openbl_7d)|897|897|891|99.3%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|518|0.0%|0.2%|
[ciarmy](#ciarmy)|319|319|312|97.8%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|288|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|271|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|219|0.2%|0.1%|
[voipbl](#voipbl)|10343|10752|209|1.9%|0.1%|
[openbl_1d](#openbl_1d)|127|127|124|97.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13791|13791|119|0.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|111|0.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14254|14254|83|0.5%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|76|10.6%|0.0%|
[zeus](#zeus)|265|265|65|24.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6640|6640|64|0.9%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|528|528|58|10.9%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|57|32.0%|0.0%|
[sslbl](#sslbl)|361|361|51|14.1%|0.0%|
[et_tor](#et_tor)|6470|6470|47|0.7%|0.0%|
[dm_tor](#dm_tor)|6402|6402|46|0.7%|0.0%|
[bm_tor](#bm_tor)|6405|6405|46|0.7%|0.0%|
[nixspam](#nixspam)|18400|18400|39|0.2%|0.0%|
[zeus_badips](#zeus_badips)|229|229|37|16.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3196|3196|35|1.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|25|6.7%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|92|92|19|20.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[php_commenters](#php_commenters)|281|281|13|4.6%|0.0%|
[malc0de](#malc0de)|403|403|11|2.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1384|1384|11|0.7%|0.0%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|8|0.5%|0.0%|
[php_dictionary](#php_dictionary)|433|433|7|1.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|6|0.4%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|98|98|6|6.1%|0.0%|
[xroxy](#xroxy)|2008|2008|5|0.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5374|5374|3|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|3|0.7%|0.0%|
[et_botcc](#et_botcc)|501|501|3|0.5%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1998|1998|2|0.1%|0.0%|
[proxz](#proxz)|415|415|2|0.4%|0.0%|
[proxyrss](#proxyrss)|1706|1706|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[feodo](#feodo)|71|71|1|1.4%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|82|82|1|1.2%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Mon Jun  1 06:28:04 UTC 2015.

The ipset `blocklist_de` has **22021** entries, **22021** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|14254|14254|14238|99.8%|64.6%|
[blocklist_de_apache](#blocklist_de_apache)|13791|13791|13790|99.9%|62.6%|
[blocklist_de_bots](#blocklist_de_bots)|3196|3196|3196|100.0%|14.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2779|0.0%|12.6%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|2332|2.5%|10.5%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|2070|6.6%|9.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|1692|1692|1692|100.0%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1449|0.0%|6.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1434|0.0%|6.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1384|1384|1384|100.0%|6.2%|
[stopforumspam_1d](#stopforumspam_1d)|6640|6640|1365|20.5%|6.1%|
[alienvault_reputation](#alienvault_reputation)|175192|175192|1177|0.6%|5.3%|
[openbl_60d](#openbl_60d)|7607|7607|870|11.4%|3.9%|
[openbl_30d](#openbl_30d)|3216|3216|801|24.9%|3.6%|
[bruteforceblocker](#bruteforceblocker)|2188|2188|733|33.5%|3.3%|
[et_compromised](#et_compromised)|2367|2367|658|27.7%|2.9%|
[openbl_7d](#openbl_7d)|897|897|551|61.4%|2.5%|
[blocklist_de_imap](#blocklist_de_imap)|528|528|527|99.8%|2.3%|
[shunlist](#shunlist)|1255|1255|445|35.4%|2.0%|
[nixspam](#nixspam)|18400|18400|361|1.9%|1.6%|
[ri_web_proxies](#ri_web_proxies)|5374|5374|347|6.4%|1.5%|
[proxyrss](#proxyrss)|1706|1706|253|14.8%|1.1%|
[xroxy](#xroxy)|2008|2008|245|12.2%|1.1%|
[et_block](#et_block)|986|18056524|178|0.0%|0.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|178|100.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|177|0.0%|0.8%|
[openbl_1d](#openbl_1d)|127|127|110|86.6%|0.4%|
[blocklist_de_ftp](#blocklist_de_ftp)|98|98|98|100.0%|0.4%|
[proxz](#proxz)|415|415|92|22.1%|0.4%|
[blocklist_de_sip](#blocklist_de_sip)|92|92|73|79.3%|0.3%|
[ri_connect_proxies](#ri_connect_proxies)|1998|1998|63|3.1%|0.2%|
[php_commenters](#php_commenters)|281|281|59|20.9%|0.2%|
[dshield](#dshield)|20|5120|50|0.9%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|49|0.0%|0.2%|
[php_spammers](#php_spammers)|417|417|43|10.3%|0.1%|
[voipbl](#voipbl)|10343|10752|42|0.3%|0.1%|
[php_dictionary](#php_dictionary)|433|433|42|9.6%|0.1%|
[ciarmy](#ciarmy)|319|319|42|13.1%|0.1%|
[php_harvesters](#php_harvesters)|257|257|22|8.5%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|12|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6402|6402|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6405|6405|3|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[zeus](#zeus)|265|265|1|0.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|1|0.1%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Mon Jun  1 06:42:06 UTC 2015.

The ipset `blocklist_de_apache` has **13791** entries, **13791** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22021|22021|13790|62.6%|99.9%|
[blocklist_de_mail](#blocklist_de_mail)|14254|14254|11059|77.5%|80.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2208|0.0%|16.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1384|1384|1384|100.0%|10.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1314|0.0%|9.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1069|0.0%|7.7%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|196|0.2%|1.4%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|121|0.3%|0.8%|
[alienvault_reputation](#alienvault_reputation)|175192|175192|119|0.0%|0.8%|
[stopforumspam_1d](#stopforumspam_1d)|6640|6640|67|1.0%|0.4%|
[ciarmy](#ciarmy)|319|319|35|10.9%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|34|19.1%|0.2%|
[shunlist](#shunlist)|1255|1255|29|2.3%|0.2%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3196|3196|21|0.6%|0.1%|
[nixspam](#nixspam)|18400|18400|9|0.0%|0.0%|
[voipbl](#voipbl)|10343|10752|5|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.0%|
[openbl_60d](#openbl_60d)|7607|7607|5|0.0%|0.0%|
[et_block](#et_block)|986|18056524|5|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3216|3216|4|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[et_compromised](#et_compromised)|2367|2367|3|0.1%|0.0%|
[dm_tor](#dm_tor)|6402|6402|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2188|2188|3|0.1%|0.0%|
[bm_tor](#bm_tor)|6405|6405|3|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2|0.0%|0.0%|
[zeus](#zeus)|265|265|1|0.3%|0.0%|
[xroxy](#xroxy)|2008|2008|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5374|5374|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1998|1998|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[openbl_7d](#openbl_7d)|897|897|1|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Mon Jun  1 06:28:09 UTC 2015.

The ipset `blocklist_de_bots` has **3196** entries, **3196** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22021|22021|3196|14.5%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|2076|2.2%|64.9%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|1912|6.1%|59.8%|
[stopforumspam_1d](#stopforumspam_1d)|6640|6640|1300|19.5%|40.6%|
[ri_web_proxies](#ri_web_proxies)|5374|5374|326|6.0%|10.2%|
[proxyrss](#proxyrss)|1706|1706|252|14.7%|7.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|220|0.0%|6.8%|
[xroxy](#xroxy)|2008|2008|218|10.8%|6.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|197|0.0%|6.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|107|60.1%|3.3%|
[proxz](#proxz)|415|415|82|19.7%|2.5%|
[ri_connect_proxies](#ri_connect_proxies)|1998|1998|61|3.0%|1.9%|
[php_commenters](#php_commenters)|281|281|48|17.0%|1.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|48|0.0%|1.5%|
[nixspam](#nixspam)|18400|18400|44|0.2%|1.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|40|0.0%|1.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|37|0.0%|1.1%|
[et_block](#et_block)|986|18056524|37|0.0%|1.1%|
[alienvault_reputation](#alienvault_reputation)|175192|175192|35|0.0%|1.0%|
[blocklist_de_mail](#blocklist_de_mail)|14254|14254|21|0.1%|0.6%|
[blocklist_de_apache](#blocklist_de_apache)|13791|13791|21|0.1%|0.6%|
[php_dictionary](#php_dictionary)|433|433|19|4.3%|0.5%|
[php_harvesters](#php_harvesters)|257|257|18|7.0%|0.5%|
[php_spammers](#php_spammers)|417|417|12|2.8%|0.3%|
[openbl_60d](#openbl_60d)|7607|7607|8|0.1%|0.2%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|5|0.0%|0.1%|
[voipbl](#voipbl)|10343|10752|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3216|3216|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2188|2188|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Mon Jun  1 06:28:11 UTC 2015.

The ipset `blocklist_de_bruteforce` has **1384** entries, **1384** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_apache](#blocklist_de_apache)|13791|13791|1384|10.0%|100.0%|
[blocklist_de](#blocklist_de)|22021|22021|1384|6.2%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|108|0.0%|7.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|33|0.0%|2.3%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|31|0.0%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|27|0.0%|1.9%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|26|0.0%|1.8%|
[stopforumspam_1d](#stopforumspam_1d)|6640|6640|17|0.2%|1.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|12|6.7%|0.8%|
[alienvault_reputation](#alienvault_reputation)|175192|175192|11|0.0%|0.7%|
[nixspam](#nixspam)|18400|18400|9|0.0%|0.6%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.3%|
[php_commenters](#php_commenters)|281|281|4|1.4%|0.2%|
[et_block](#et_block)|986|18056524|3|0.0%|0.2%|
[voipbl](#voipbl)|10343|10752|2|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.1%|
[zeus](#zeus)|265|265|1|0.3%|0.0%|
[xroxy](#xroxy)|2008|2008|1|0.0%|0.0%|
[shunlist](#shunlist)|1255|1255|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5374|5374|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1998|1998|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Mon Jun  1 06:42:13 UTC 2015.

The ipset `blocklist_de_ftp` has **98** entries, **98** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22021|22021|98|0.4%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|7|0.0%|7.1%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|6|0.0%|6.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|6|0.0%|6.1%|
[alienvault_reputation](#alienvault_reputation)|175192|175192|6|0.0%|6.1%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|5|0.0%|5.1%|
[openbl_60d](#openbl_60d)|7607|7607|4|0.0%|4.0%|
[openbl_30d](#openbl_30d)|3216|3216|3|0.0%|3.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|2|0.0%|2.0%|
[stopforumspam_1d](#stopforumspam_1d)|6640|6640|1|0.0%|1.0%|
[shunlist](#shunlist)|1255|1255|1|0.0%|1.0%|
[openbl_7d](#openbl_7d)|897|897|1|0.1%|1.0%|
[nixspam](#nixspam)|18400|18400|1|0.0%|1.0%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|1.0%|
[bruteforceblocker](#bruteforceblocker)|2188|2188|1|0.0%|1.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|1|0.5%|1.0%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Mon Jun  1 06:42:12 UTC 2015.

The ipset `blocklist_de_imap` has **528** entries, **528** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|14254|14254|528|3.7%|100.0%|
[blocklist_de](#blocklist_de)|22021|22021|527|2.3%|99.8%|
[alienvault_reputation](#alienvault_reputation)|175192|175192|58|0.0%|10.9%|
[openbl_60d](#openbl_60d)|7607|7607|36|0.4%|6.8%|
[openbl_30d](#openbl_30d)|3216|3216|32|0.9%|6.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|31|0.0%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|30|0.0%|5.6%|
[openbl_7d](#openbl_7d)|897|897|19|2.1%|3.5%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|18|0.0%|3.4%|
[et_block](#et_block)|986|18056524|18|0.0%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|10|0.0%|1.8%|
[et_compromised](#et_compromised)|2367|2367|9|0.3%|1.7%|
[shunlist](#shunlist)|1255|1255|5|0.3%|0.9%|
[bruteforceblocker](#bruteforceblocker)|2188|2188|5|0.2%|0.9%|
[openbl_1d](#openbl_1d)|127|127|4|3.1%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.5%|
[nixspam](#nixspam)|18400|18400|2|0.0%|0.3%|
[ciarmy](#ciarmy)|319|319|2|0.6%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|2|1.1%|0.3%|
[voipbl](#voipbl)|10343|10752|1|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|1|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|1|0.0%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|1692|1692|1|0.0%|0.1%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Mon Jun  1 06:42:07 UTC 2015.

The ipset `blocklist_de_mail` has **14254** entries, **14254** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22021|22021|14238|64.6%|99.8%|
[blocklist_de_apache](#blocklist_de_apache)|13791|13791|11059|80.1%|77.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2217|0.0%|15.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1318|0.0%|9.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1107|0.0%|7.7%|
[blocklist_de_imap](#blocklist_de_imap)|528|528|528|100.0%|3.7%|
[nixspam](#nixspam)|18400|18400|306|1.6%|2.1%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|201|0.2%|1.4%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|116|0.3%|0.8%|
[alienvault_reputation](#alienvault_reputation)|175192|175192|83|0.0%|0.5%|
[stopforumspam_1d](#stopforumspam_1d)|6640|6640|52|0.7%|0.3%|
[openbl_60d](#openbl_60d)|7607|7607|46|0.6%|0.3%|
[openbl_30d](#openbl_30d)|3216|3216|40|1.2%|0.2%|
[xroxy](#xroxy)|2008|2008|25|1.2%|0.1%|
[php_spammers](#php_spammers)|417|417|25|5.9%|0.1%|
[openbl_7d](#openbl_7d)|897|897|25|2.7%|0.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|24|0.0%|0.1%|
[et_block](#et_block)|986|18056524|24|0.0%|0.1%|
[php_dictionary](#php_dictionary)|433|433|23|5.3%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3196|3196|21|0.6%|0.1%|
[ri_web_proxies](#ri_web_proxies)|5374|5374|20|0.3%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|19|10.6%|0.1%|
[php_commenters](#php_commenters)|281|281|17|6.0%|0.1%|
[et_compromised](#et_compromised)|2367|2367|11|0.4%|0.0%|
[proxz](#proxz)|415|415|9|2.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2188|2188|7|0.3%|0.0%|
[shunlist](#shunlist)|1255|1255|5|0.3%|0.0%|
[openbl_1d](#openbl_1d)|127|127|5|3.9%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6402|6402|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6405|6405|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[ciarmy](#ciarmy)|319|319|2|0.6%|0.0%|
[voipbl](#voipbl)|10343|10752|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1998|1998|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1692|1692|1|0.0%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Mon Jun  1 06:28:08 UTC 2015.

The ipset `blocklist_de_sip` has **92** entries, **92** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22021|22021|73|0.3%|79.3%|
[voipbl](#voipbl)|10343|10752|33|0.3%|35.8%|
[alienvault_reputation](#alienvault_reputation)|175192|175192|19|0.0%|20.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|16.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|11|0.0%|11.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4|0.0%|4.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|2.1%|
[shunlist](#shunlist)|1255|1255|1|0.0%|1.0%|
[nixspam](#nixspam)|18400|18400|1|0.0%|1.0%|
[et_botcc](#et_botcc)|501|501|1|0.1%|1.0%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Mon Jun  1 06:28:04 UTC 2015.

The ipset `blocklist_de_ssh` has **1692** entries, **1692** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22021|22021|1692|7.6%|100.0%|
[alienvault_reputation](#alienvault_reputation)|175192|175192|926|0.5%|54.7%|
[openbl_60d](#openbl_60d)|7607|7607|807|10.6%|47.6%|
[openbl_30d](#openbl_30d)|3216|3216|753|23.4%|44.5%|
[bruteforceblocker](#bruteforceblocker)|2188|2188|719|32.8%|42.4%|
[et_compromised](#et_compromised)|2367|2367|640|27.0%|37.8%|
[openbl_7d](#openbl_7d)|897|897|524|58.4%|30.9%|
[shunlist](#shunlist)|1255|1255|410|32.6%|24.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|183|0.0%|10.8%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|114|0.0%|6.7%|
[et_block](#et_block)|986|18056524|112|0.0%|6.6%|
[openbl_1d](#openbl_1d)|127|127|105|82.6%|6.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|87|0.0%|5.1%|
[dshield](#dshield)|20|5120|49|0.9%|2.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|49|27.5%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|30|0.0%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|6|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6|0.0%|0.3%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|5|0.0%|0.2%|
[ciarmy](#ciarmy)|319|319|4|1.2%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|3|0.0%|0.1%|
[voipbl](#voipbl)|10343|10752|2|0.0%|0.1%|
[nixspam](#nixspam)|18400|18400|2|0.0%|0.1%|
[xroxy](#xroxy)|2008|2008|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|1|0.1%|0.0%|
[proxz](#proxz)|415|415|1|0.2%|0.0%|
[proxyrss](#proxyrss)|1706|1706|1|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14254|14254|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|528|528|1|0.1%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Mon Jun  1 06:42:15 UTC 2015.

The ipset `blocklist_de_strongips` has **178** entries, **178** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22021|22021|178|0.8%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|112|0.1%|62.9%|
[blocklist_de_bots](#blocklist_de_bots)|3196|3196|107|3.3%|60.1%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|103|0.3%|57.8%|
[stopforumspam_1d](#stopforumspam_1d)|6640|6640|95|1.4%|53.3%|
[alienvault_reputation](#alienvault_reputation)|175192|175192|57|0.0%|32.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1692|1692|49|2.8%|27.5%|
[openbl_60d](#openbl_60d)|7607|7607|48|0.6%|26.9%|
[openbl_30d](#openbl_30d)|3216|3216|46|1.4%|25.8%|
[openbl_7d](#openbl_7d)|897|897|45|5.0%|25.2%|
[shunlist](#shunlist)|1255|1255|41|3.2%|23.0%|
[blocklist_de_apache](#blocklist_de_apache)|13791|13791|34|0.2%|19.1%|
[php_commenters](#php_commenters)|281|281|29|10.3%|16.2%|
[blocklist_de_mail](#blocklist_de_mail)|14254|14254|19|0.1%|10.6%|
[openbl_1d](#openbl_1d)|127|127|18|14.1%|10.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|16|0.0%|8.9%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1384|1384|12|0.8%|6.7%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|10|0.0%|5.6%|
[xroxy](#xroxy)|2008|2008|5|0.2%|2.8%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|5|0.0%|2.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|5|0.0%|2.8%|
[et_block](#et_block)|986|18056524|5|0.0%|2.8%|
[ri_web_proxies](#ri_web_proxies)|5374|5374|4|0.0%|2.2%|
[proxyrss](#proxyrss)|1706|1706|4|0.2%|2.2%|
[php_spammers](#php_spammers)|417|417|4|0.9%|2.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.6%|
[proxz](#proxz)|415|415|2|0.4%|1.1%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|1.1%|
[nixspam](#nixspam)|18400|18400|2|0.0%|1.1%|
[blocklist_de_imap](#blocklist_de_imap)|528|528|2|0.3%|1.1%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.5%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1|0.0%|0.5%|
[blocklist_de_ftp](#blocklist_de_ftp)|98|98|1|1.0%|0.5%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Mon Jun  1 06:54:09 UTC 2015.

The ipset `bm_tor` has **6405** entries, **6405** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[dm_tor](#dm_tor)|6402|6402|6402|100.0%|99.9%|
[et_tor](#et_tor)|6470|6470|5487|84.8%|85.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|627|0.0%|9.7%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|621|0.6%|9.6%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|478|1.5%|7.4%|
[stopforumspam_1d](#stopforumspam_1d)|6640|6640|296|4.4%|4.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|195|0.0%|3.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|171|45.9%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|166|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|175192|175192|46|0.0%|0.7%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7607|7607|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5374|5374|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|986|18056524|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14254|14254|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13791|13791|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|22021|22021|3|0.0%|0.0%|
[xroxy](#xroxy)|2008|2008|2|0.0%|0.0%|
[voipbl](#voipbl)|10343|10752|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2|0.0%|0.0%|
[nixspam](#nixspam)|18400|18400|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|1|0.1%|0.0%|
[shunlist](#shunlist)|1255|1255|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1998|1998|1|0.0%|0.0%|

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
[bruteforceblocker](#bruteforceblocker)|2188|2188|1|0.0%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Mon Jun  1 06:01:00 UTC 2015.

The ipset `bruteforceblocker` has **2188** entries, **2188** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_compromised](#et_compromised)|2367|2367|2065|87.2%|94.3%|
[alienvault_reputation](#alienvault_reputation)|175192|175192|1409|0.8%|64.3%|
[openbl_60d](#openbl_60d)|7607|7607|1310|17.2%|59.8%|
[openbl_30d](#openbl_30d)|3216|3216|1239|38.5%|56.6%|
[blocklist_de](#blocklist_de)|22021|22021|733|3.3%|33.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|1692|1692|719|42.4%|32.8%|
[shunlist](#shunlist)|1255|1255|521|41.5%|23.8%|
[openbl_7d](#openbl_7d)|897|897|518|57.7%|23.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|219|0.0%|10.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|115|0.0%|5.2%|
[et_block](#et_block)|986|18056524|103|0.0%|4.7%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|102|0.0%|4.6%|
[openbl_1d](#openbl_1d)|127|127|76|59.8%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|61|0.0%|2.7%|
[dshield](#dshield)|20|5120|35|0.6%|1.5%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|7|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|14254|14254|7|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|528|528|5|0.9%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|4|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13791|13791|3|0.0%|0.1%|
[proxz](#proxz)|415|415|2|0.4%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|265|265|1|0.3%|0.0%|
[xroxy](#xroxy)|2008|2008|1|0.0%|0.0%|
[voipbl](#voipbl)|10343|10752|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6640|6640|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|1|0.1%|0.0%|
[proxyrss](#proxyrss)|1706|1706|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3639|670580696|1|0.0%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|98|98|1|1.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3196|3196|1|0.0%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Mon Jun  1 04:15:15 UTC 2015.

The ipset `ciarmy` has **319** entries, **319** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|175192|175192|312|0.1%|97.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|52|0.0%|16.3%|
[blocklist_de](#blocklist_de)|22021|22021|42|0.1%|13.1%|
[blocklist_de_apache](#blocklist_de_apache)|13791|13791|35|0.2%|10.9%|
[shunlist](#shunlist)|1255|1255|24|1.9%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|16|0.0%|5.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|10|0.0%|3.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|1692|1692|4|0.2%|1.2%|
[voipbl](#voipbl)|10343|10752|3|0.0%|0.9%|
[blocklist_de_mail](#blocklist_de_mail)|14254|14254|2|0.0%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|528|528|2|0.3%|0.6%|
[openbl_7d](#openbl_7d)|897|897|1|0.1%|0.3%|
[openbl_60d](#openbl_60d)|7607|7607|1|0.0%|0.3%|
[openbl_30d](#openbl_30d)|3216|3216|1|0.0%|0.3%|
[openbl_1d](#openbl_1d)|127|127|1|0.7%|0.3%|
[dshield](#dshield)|20|5120|1|0.0%|0.3%|

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
[alienvault_reputation](#alienvault_reputation)|175192|175192|1|0.0%|1.2%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Mon Jun  1 06:54:05 UTC 2015.

The ipset `dm_tor` has **6402** entries, **6402** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6405|6405|6402|99.9%|100.0%|
[et_tor](#et_tor)|6470|6470|5484|84.7%|85.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|627|0.0%|9.7%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|621|0.6%|9.7%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|478|1.5%|7.4%|
[stopforumspam_1d](#stopforumspam_1d)|6640|6640|296|4.4%|4.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|195|0.0%|3.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|171|45.9%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|166|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|175192|175192|46|0.0%|0.7%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7607|7607|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5374|5374|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|986|18056524|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14254|14254|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13791|13791|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|22021|22021|3|0.0%|0.0%|
[xroxy](#xroxy)|2008|2008|2|0.0%|0.0%|
[voipbl](#voipbl)|10343|10752|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2|0.0%|0.0%|
[nixspam](#nixspam)|18400|18400|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|1|0.1%|0.0%|
[shunlist](#shunlist)|1255|1255|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1998|1998|1|0.0%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Mon Jun  1 03:26:41 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|175192|175192|3587|2.0%|70.0%|
[et_block](#et_block)|986|18056524|1280|0.0%|25.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|256|0.0%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|256|0.0%|5.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|139|0.0%|2.7%|
[openbl_60d](#openbl_60d)|7607|7607|72|0.9%|1.4%|
[openbl_30d](#openbl_30d)|3216|3216|61|1.8%|1.1%|
[blocklist_de](#blocklist_de)|22021|22021|50|0.2%|0.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|1692|1692|49|2.8%|0.9%|
[shunlist](#shunlist)|1255|1255|41|3.2%|0.8%|
[et_compromised](#et_compromised)|2367|2367|38|1.6%|0.7%|
[openbl_7d](#openbl_7d)|897|897|36|4.0%|0.7%|
[bruteforceblocker](#bruteforceblocker)|2188|2188|35|1.5%|0.6%|
[openbl_1d](#openbl_1d)|127|127|16|12.5%|0.3%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[voipbl](#voipbl)|10343|10752|3|0.0%|0.0%|
[nixspam](#nixspam)|18400|18400|1|0.0%|0.0%|
[ciarmy](#ciarmy)|319|319|1|0.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1384|1384|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13791|13791|1|0.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|175192|175192|5787|3.3%|0.0%|
[dshield](#dshield)|20|5120|1280|25.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1040|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|728|0.7%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|517|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|286|40.0%|0.0%|
[zeus](#zeus)|265|265|258|97.3%|0.0%|
[nixspam](#nixspam)|18400|18400|244|1.3%|0.0%|
[openbl_60d](#openbl_60d)|7607|7607|241|3.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|228|99.5%|0.0%|
[openbl_30d](#openbl_30d)|3216|3216|205|6.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|200|0.6%|0.0%|
[blocklist_de](#blocklist_de)|22021|22021|178|0.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1692|1692|112|6.6%|0.0%|
[shunlist](#shunlist)|1255|1255|111|8.8%|0.0%|
[et_compromised](#et_compromised)|2367|2367|103|4.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2188|2188|103|4.7%|0.0%|
[openbl_7d](#openbl_7d)|897|897|85|9.4%|0.0%|
[feodo](#feodo)|71|71|67|94.3%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6640|6640|57|0.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3196|3196|37|1.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|28|2.1%|0.0%|
[sslbl](#sslbl)|361|361|27|7.4%|0.0%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14254|14254|24|0.1%|0.0%|
[openbl_1d](#openbl_1d)|127|127|20|15.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|528|528|18|3.4%|0.0%|
[voipbl](#voipbl)|10343|10752|17|0.1%|0.0%|
[palevo](#palevo)|13|13|13|100.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|7|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|5|2.8%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13791|13791|5|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[malc0de](#malc0de)|403|403|3|0.7%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6402|6402|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6405|6405|3|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1384|1384|3|0.2%|0.0%|
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
[alienvault_reputation](#alienvault_reputation)|175192|175192|3|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[et_block](#et_block)|986|18056524|1|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|92|92|1|1.0%|0.1%|

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
[bruteforceblocker](#bruteforceblocker)|2188|2188|2065|94.3%|87.2%|
[alienvault_reputation](#alienvault_reputation)|175192|175192|1538|0.8%|64.9%|
[openbl_60d](#openbl_60d)|7607|7607|1426|18.7%|60.2%|
[openbl_30d](#openbl_30d)|3216|3216|1310|40.7%|55.3%|
[blocklist_de](#blocklist_de)|22021|22021|658|2.9%|27.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|1692|1692|640|37.8%|27.0%|
[shunlist](#shunlist)|1255|1255|520|41.4%|21.9%|
[openbl_7d](#openbl_7d)|897|897|508|56.6%|21.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|227|0.0%|9.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|140|0.0%|5.9%|
[et_block](#et_block)|986|18056524|103|0.0%|4.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|102|0.0%|4.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|70|0.0%|2.9%|
[openbl_1d](#openbl_1d)|127|127|69|54.3%|2.9%|
[dshield](#dshield)|20|5120|38|0.7%|1.6%|
[blocklist_de_mail](#blocklist_de_mail)|14254|14254|11|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|528|528|9|1.7%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|6|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|3|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13791|13791|3|0.0%|0.1%|
[proxz](#proxz)|415|415|2|0.4%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|265|265|1|0.3%|0.0%|
[xroxy](#xroxy)|2008|2008|1|0.0%|0.0%|
[voipbl](#voipbl)|10343|10752|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6640|6640|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|1|0.1%|0.0%|
[proxyrss](#proxyrss)|1706|1706|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|98|98|1|1.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3196|3196|1|0.0%|0.0%|

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
[bm_tor](#bm_tor)|6405|6405|5487|85.6%|84.8%|
[dm_tor](#dm_tor)|6402|6402|5484|85.6%|84.7%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|623|0.6%|9.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|619|0.0%|9.5%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|509|1.6%|7.8%|
[stopforumspam_1d](#stopforumspam_1d)|6640|6640|298|4.4%|4.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|184|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|179|48.1%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|163|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|175192|175192|47|0.0%|0.7%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[openbl_60d](#openbl_60d)|7607|7607|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5374|5374|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[xroxy](#xroxy)|2008|2008|3|0.1%|0.0%|
[nixspam](#nixspam)|18400|18400|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_block](#et_block)|986|18056524|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14254|14254|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13791|13791|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|22021|22021|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1998|1998|2|0.1%|0.0%|
[voipbl](#voipbl)|10343|10752|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|1|0.1%|0.0%|
[shunlist](#shunlist)|1255|1255|1|0.0%|0.0%|
[proxz](#proxz)|415|415|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Mon Jun  1 06:54:27 UTC 2015.

The ipset `feodo` has **71** entries, **71** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|986|18056524|67|0.0%|94.3%|
[snort_ipfilter](#snort_ipfilter)|714|714|53|7.4%|74.6%|
[sslbl](#sslbl)|361|361|27|7.4%|38.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|6|0.0%|8.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|3|0.0%|4.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|4.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|1.4%|
[alienvault_reputation](#alienvault_reputation)|175192|175192|1|0.0%|1.4%|

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
[bruteforceblocker](#bruteforceblocker)|2188|2188|1|0.0%|0.0%|

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
[fullbogons](#fullbogons)|3639|670580696|14|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|175192|175192|14|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.0%|
[et_block](#et_block)|986|18056524|7|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|6|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|5|0.0%|0.0%|
[nixspam](#nixspam)|18400|18400|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[dshield](#dshield)|20|5120|4|0.0%|0.0%|
[xroxy](#xroxy)|2008|2008|3|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6640|6640|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|22021|22021|3|0.0%|0.0%|
[voipbl](#voipbl)|10343|10752|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14254|14254|2|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5374|5374|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1706|1706|1|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1384|1384|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13791|13791|1|0.0%|0.0%|

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
[fullbogons](#fullbogons)|3639|670580696|565248|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|145472|0.1%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1036|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|732|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|175192|175192|518|0.2%|0.0%|
[nixspam](#nixspam)|18400|18400|243|1.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|182|0.5%|0.0%|
[blocklist_de](#blocklist_de)|22021|22021|49|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3196|3196|40|1.2%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6640|6640|34|0.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|27|2.1%|0.0%|
[openbl_60d](#openbl_60d)|7607|7607|19|0.2%|0.0%|
[openbl_30d](#openbl_30d)|3216|3216|14|0.4%|0.0%|
[openbl_7d](#openbl_7d)|897|897|11|1.2%|0.0%|
[zeus_badips](#zeus_badips)|229|229|10|4.3%|0.0%|
[zeus](#zeus)|265|265|10|3.7%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|9|1.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1692|1692|6|0.3%|0.0%|
[et_compromised](#et_compromised)|2367|2367|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2188|2188|5|0.2%|0.0%|
[shunlist](#shunlist)|1255|1255|3|0.2%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6402|6402|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6405|6405|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|3|1.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14254|14254|3|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|528|528|3|0.5%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[voipbl](#voipbl)|10343|10752|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.0%|
[openbl_1d](#openbl_1d)|127|127|1|0.7%|0.0%|
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
[alienvault_reputation](#alienvault_reputation)|175192|175192|4437|2.5%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|1523|1.6%|0.0%|
[blocklist_de](#blocklist_de)|22021|22021|1434|6.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14254|14254|1318|9.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13791|13791|1314|9.5%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|563|1.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|406|0.8%|0.0%|
[nixspam](#nixspam)|18400|18400|336|1.8%|0.0%|
[voipbl](#voipbl)|10343|10752|295|2.7%|0.0%|
[openbl_60d](#openbl_60d)|7607|7607|173|2.2%|0.0%|
[dm_tor](#dm_tor)|6402|6402|166|2.5%|0.0%|
[bm_tor](#bm_tor)|6405|6405|166|2.5%|0.0%|
[et_tor](#et_tor)|6470|6470|163|2.5%|0.0%|
[dshield](#dshield)|20|5120|139|2.7%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6640|6640|137|2.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5374|5374|115|2.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|97|6.6%|0.0%|
[et_compromised](#et_compromised)|2367|2367|70|2.9%|0.0%|
[openbl_30d](#openbl_30d)|3216|3216|68|2.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1998|1998|66|3.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|66|5.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2188|2188|61|2.7%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|58|8.6%|0.0%|
[xroxy](#xroxy)|2008|2008|57|2.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3196|3196|48|1.5%|0.0%|
[et_botcc](#et_botcc)|501|501|40|7.9%|0.0%|
[proxyrss](#proxyrss)|1706|1706|35|2.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1692|1692|30|1.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1384|1384|27|1.9%|0.0%|
[shunlist](#shunlist)|1255|1255|26|2.0%|0.0%|
[openbl_7d](#openbl_7d)|897|897|17|1.8%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|17|4.5%|0.0%|
[proxz](#proxz)|415|415|16|3.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|12|1.6%|0.0%|
[malc0de](#malc0de)|403|403|12|2.9%|0.0%|
[ciarmy](#ciarmy)|319|319|10|3.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|528|528|10|1.8%|0.0%|
[php_dictionary](#php_dictionary)|433|433|9|2.0%|0.0%|
[zeus](#zeus)|265|265|8|3.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.0%|
[php_commenters](#php_commenters)|281|281|5|1.7%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[zeus_badips](#zeus_badips)|229|229|4|1.7%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|92|92|4|4.3%|0.0%|
[sslbl](#sslbl)|361|361|3|0.8%|0.0%|
[feodo](#feodo)|71|71|3|4.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|82|82|3|3.6%|0.0%|
[openbl_1d](#openbl_1d)|127|127|2|1.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|98|98|2|2.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|1|0.5%|0.0%|

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
[fullbogons](#fullbogons)|3639|670580696|248319|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|33368|7.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|175192|175192|8137|4.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|7733|2.2%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|2477|2.6%|0.0%|
[blocklist_de](#blocklist_de)|22021|22021|1449|6.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14254|14254|1107|7.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13791|13791|1069|7.7%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|938|2.9%|0.0%|
[nixspam](#nixspam)|18400|18400|456|2.4%|0.0%|
[voipbl](#voipbl)|10343|10752|431|4.0%|0.0%|
[openbl_60d](#openbl_60d)|7607|7607|356|4.6%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6640|6640|241|3.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|230|0.4%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3196|3196|197|6.1%|0.0%|
[dm_tor](#dm_tor)|6402|6402|195|3.0%|0.0%|
[bm_tor](#bm_tor)|6405|6405|195|3.0%|0.0%|
[et_tor](#et_tor)|6470|6470|184|2.8%|0.0%|
[openbl_30d](#openbl_30d)|3216|3216|178|5.5%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5374|5374|172|3.2%|0.0%|
[et_compromised](#et_compromised)|2367|2367|140|5.9%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2188|2188|115|5.2%|0.0%|
[xroxy](#xroxy)|2008|2008|98|4.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1692|1692|87|5.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1998|1998|81|4.0%|0.0%|
[shunlist](#shunlist)|1255|1255|69|5.4%|0.0%|
[proxyrss](#proxyrss)|1706|1706|67|3.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|45|3.0%|0.0%|
[openbl_7d](#openbl_7d)|897|897|40|4.4%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1384|1384|33|2.3%|0.0%|
[php_spammers](#php_spammers)|417|417|31|7.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|528|528|30|5.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|28|4.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|26|2.0%|0.0%|
[malc0de](#malc0de)|403|403|25|6.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|24|3.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|21|5.6%|0.0%|
[et_botcc](#et_botcc)|501|501|21|4.1%|0.0%|
[proxz](#proxz)|415|415|16|3.8%|0.0%|
[ciarmy](#ciarmy)|319|319|16|5.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|92|92|11|11.9%|0.0%|
[php_dictionary](#php_dictionary)|433|433|10|2.3%|0.0%|
[zeus](#zeus)|265|265|9|3.3%|0.0%|
[php_commenters](#php_commenters)|281|281|9|3.2%|0.0%|
[zeus_badips](#zeus_badips)|229|229|8|3.4%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[sslbl](#sslbl)|361|361|6|1.6%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|98|98|6|6.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|5|2.8%|0.0%|
[openbl_1d](#openbl_1d)|127|127|4|3.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|82|82|4|4.8%|0.0%|
[feodo](#feodo)|71|71|3|4.2%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|

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
[fullbogons](#fullbogons)|3639|670580696|4233775|0.6%|3.0%|
[bogons](#bogons)|13|592708608|4194304|0.7%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2830140|0.8%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1354348|0.1%|0.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|270785|64.2%|0.1%|
[et_block](#et_block)|986|18056524|196184|1.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|195904|1.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[alienvault_reputation](#alienvault_reputation)|175192|175192|14378|8.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|9231|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|5946|6.4%|0.0%|
[blocklist_de](#blocklist_de)|22021|22021|2779|12.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14254|14254|2217|15.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13791|13791|2208|16.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|2107|6.7%|0.0%|
[voipbl](#voipbl)|10343|10752|1591|14.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1172|2.4%|0.0%|
[nixspam](#nixspam)|18400|18400|1096|5.9%|0.0%|
[openbl_60d](#openbl_60d)|7607|7607|716|9.4%|0.0%|
[dm_tor](#dm_tor)|6402|6402|627|9.7%|0.0%|
[bm_tor](#bm_tor)|6405|6405|627|9.7%|0.0%|
[et_tor](#et_tor)|6470|6470|619|9.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6640|6640|465|7.0%|0.0%|
[openbl_30d](#openbl_30d)|3216|3216|284|8.8%|0.0%|
[et_compromised](#et_compromised)|2367|2367|227|9.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3196|3196|220|6.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2188|2188|219|10.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1692|1692|183|10.8%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5374|5374|154|2.8%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|146|11.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|125|33.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|110|7.5%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1384|1384|108|7.8%|0.0%|
[shunlist](#shunlist)|1255|1255|100|7.9%|0.0%|
[openbl_7d](#openbl_7d)|897|897|91|10.1%|0.0%|
[xroxy](#xroxy)|2008|2008|84|4.1%|0.0%|
[et_botcc](#et_botcc)|501|501|74|14.7%|0.0%|
[malc0de](#malc0de)|403|403|71|17.6%|0.0%|
[ciarmy](#ciarmy)|319|319|52|16.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|51|7.5%|0.0%|
[proxyrss](#proxyrss)|1706|1706|50|2.9%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1998|1998|46|2.3%|0.0%|
[proxz](#proxz)|415|415|42|10.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|528|528|31|5.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|29|4.0%|0.0%|
[php_spammers](#php_spammers)|417|417|26|6.2%|0.0%|
[php_dictionary](#php_dictionary)|433|433|24|5.5%|0.0%|
[sslbl](#sslbl)|361|361|23|6.3%|0.0%|
[zeus](#zeus)|265|265|19|7.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|16|8.9%|0.0%|
[php_harvesters](#php_harvesters)|257|257|15|5.8%|0.0%|
[php_commenters](#php_commenters)|281|281|15|5.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|92|92|15|16.3%|0.0%|
[zeus_badips](#zeus_badips)|229|229|14|6.1%|0.0%|
[openbl_1d](#openbl_1d)|127|127|12|9.4%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|82|82|7|8.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|98|98|7|7.1%|0.0%|
[feodo](#feodo)|71|71|6|8.4%|0.0%|
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
[xroxy](#xroxy)|2008|2008|13|0.6%|1.9%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|11|0.0%|1.6%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|11|0.0%|1.6%|
[ri_web_proxies](#ri_web_proxies)|5374|5374|10|0.1%|1.4%|
[proxyrss](#proxyrss)|1706|1706|8|0.4%|1.1%|
[stopforumspam_1d](#stopforumspam_1d)|6640|6640|7|0.1%|1.0%|
[ri_connect_proxies](#ri_connect_proxies)|1998|1998|6|0.3%|0.8%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.2%|
[et_block](#et_block)|986|18056524|2|0.0%|0.2%|
[blocklist_de](#blocklist_de)|22021|22021|2|0.0%|0.2%|
[proxz](#proxz)|415|415|1|0.2%|0.1%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.1%|
[nixspam](#nixspam)|18400|18400|1|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|14254|14254|1|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3196|3196|1|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|175192|175192|1|0.0%|0.1%|

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
[fullbogons](#fullbogons)|3639|670580696|890|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|175192|175192|288|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|44|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|25|1.9%|0.0%|
[et_tor](#et_tor)|6470|6470|21|0.3%|0.0%|
[dm_tor](#dm_tor)|6402|6402|21|0.3%|0.0%|
[bm_tor](#bm_tor)|6405|6405|21|0.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|19|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|19|1.3%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6640|6640|11|0.1%|0.0%|
[nixspam](#nixspam)|18400|18400|10|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|6|0.8%|0.0%|
[openbl_60d](#openbl_60d)|7607|7607|6|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5374|5374|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|5|1.3%|0.0%|
[blocklist_de](#blocklist_de)|22021|22021|5|0.0%|0.0%|
[voipbl](#voipbl)|10343|10752|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3216|3216|4|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[malc0de](#malc0de)|403|403|3|0.7%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|82|82|3|3.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13791|13791|3|0.0%|0.0%|
[openbl_7d](#openbl_7d)|897|897|2|0.2%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|92|92|2|2.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1384|1384|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|265|265|1|0.3%|0.0%|
[xroxy](#xroxy)|2008|2008|1|0.0%|0.0%|
[sslbl](#sslbl)|361|361|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|1|0.0%|0.0%|
[shunlist](#shunlist)|1255|1255|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|
[openbl_1d](#openbl_1d)|127|127|1|0.7%|0.0%|
[feodo](#feodo)|71|71|1|1.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2188|2188|1|0.0%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1692|1692|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14254|14254|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3196|3196|1|0.0%|0.0%|

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
[fullbogons](#fullbogons)|3639|670580696|33|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|19|0.0%|1.3%|
[alienvault_reputation](#alienvault_reputation)|175192|175192|8|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|6|0.0%|0.4%|
[et_block](#et_block)|986|18056524|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|3|0.2%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|2|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7607|7607|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|3216|3216|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.1%|
[et_compromised](#et_compromised)|2367|2367|2|0.0%|0.1%|
[blocklist_de](#blocklist_de)|22021|22021|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|6640|6640|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5374|5374|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|897|897|1|0.1%|0.0%|
[nixspam](#nixspam)|18400|18400|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[et_botcc](#et_botcc)|501|501|1|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2188|2188|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|1|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1692|1692|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3196|3196|1|0.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|175192|175192|11|0.0%|2.7%|
[cleanmx_viruses](#cleanmx_viruses)|82|82|9|10.9%|2.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|4|0.0%|0.9%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|4|0.3%|0.9%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.7%|
[et_block](#et_block)|986|18056524|3|0.0%|0.7%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|1|0.0%|0.2%|

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
[alienvault_reputation](#alienvault_reputation)|175192|175192|6|0.0%|0.4%|
[malc0de](#malc0de)|403|403|4|0.9%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|3|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|2|0.0%|0.1%|
[et_botcc](#et_botcc)|501|501|1|0.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|82|82|1|1.2%|0.0%|

## maxmind_proxy_fraud

[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.

Source is downloaded from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list).

The last time downloaded was found to be dated: Mon Jun  1 06:27:05 UTC 2015.

The ipset `maxmind_proxy_fraud` has **372** entries, **372** unique IPs.

The following table shows the overlaps of `maxmind_proxy_fraud` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `maxmind_proxy_fraud`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `maxmind_proxy_fraud`.
- ` this % ` is the percentage **of this ipset (`maxmind_proxy_fraud`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|234|0.2%|62.9%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|201|0.6%|54.0%|
[et_tor](#et_tor)|6470|6470|179|2.7%|48.1%|
[dm_tor](#dm_tor)|6402|6402|171|2.6%|45.9%|
[bm_tor](#bm_tor)|6405|6405|171|2.6%|45.9%|
[stopforumspam_1d](#stopforumspam_1d)|6640|6640|158|2.3%|42.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|125|0.0%|33.6%|
[php_commenters](#php_commenters)|281|281|28|9.9%|7.5%|
[alienvault_reputation](#alienvault_reputation)|175192|175192|25|0.0%|6.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|21|0.0%|5.6%|
[openbl_60d](#openbl_60d)|7607|7607|18|0.2%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|17|0.0%|4.5%|
[php_harvesters](#php_harvesters)|257|257|6|2.3%|1.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|1.3%|
[ri_web_proxies](#ri_web_proxies)|5374|5374|4|0.0%|1.0%|
[php_spammers](#php_spammers)|417|417|4|0.9%|1.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|1.0%|
[shunlist](#shunlist)|1255|1255|2|0.1%|0.5%|
[blocklist_de](#blocklist_de)|22021|22021|2|0.0%|0.5%|
[xroxy](#xroxy)|2008|2008|1|0.0%|0.2%|
[voipbl](#voipbl)|10343|10752|1|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|714|714|1|0.1%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|1998|1998|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|14254|14254|1|0.0%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3196|3196|1|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|13791|13791|1|0.0%|0.2%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Mon Jun  1 06:45:02 UTC 2015.

The ipset `nixspam` has **18400** entries, **18400** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1096|0.0%|5.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|456|0.0%|2.4%|
[blocklist_de](#blocklist_de)|22021|22021|361|1.6%|1.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|336|0.0%|1.8%|
[blocklist_de_mail](#blocklist_de_mail)|14254|14254|306|2.1%|1.6%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|245|0.0%|1.3%|
[et_block](#et_block)|986|18056524|244|0.0%|1.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|243|0.0%|1.3%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|205|0.2%|1.1%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|132|0.4%|0.7%|
[php_dictionary](#php_dictionary)|433|433|71|16.3%|0.3%|
[ri_web_proxies](#ri_web_proxies)|5374|5374|70|1.3%|0.3%|
[php_spammers](#php_spammers)|417|417|63|15.1%|0.3%|
[xroxy](#xroxy)|2008|2008|56|2.7%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6640|6640|47|0.7%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3196|3196|44|1.3%|0.2%|
[alienvault_reputation](#alienvault_reputation)|175192|175192|39|0.0%|0.2%|
[proxz](#proxz)|415|415|12|2.8%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|1998|1998|10|0.5%|0.0%|
[openbl_60d](#openbl_60d)|7607|7607|10|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|10|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1384|1384|9|0.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13791|13791|9|0.0%|0.0%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.0%|
[proxyrss](#proxyrss)|1706|1706|6|0.3%|0.0%|
[php_harvesters](#php_harvesters)|257|257|5|1.9%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[shunlist](#shunlist)|1255|1255|3|0.2%|0.0%|
[openbl_30d](#openbl_30d)|3216|3216|3|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6402|6402|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6405|6405|2|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|2|1.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1692|1692|2|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|528|528|2|0.3%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|265|265|1|0.3%|0.0%|
[voipbl](#voipbl)|10343|10752|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|92|92|1|1.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|98|98|1|1.0%|0.0%|

## openbl_1d

[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_1days.txt).

The last time downloaded was found to be dated: Mon Jun  1 06:32:00 UTC 2015.

The ipset `openbl_1d` has **127** entries, **127** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7607|7607|125|1.6%|98.4%|
[openbl_30d](#openbl_30d)|3216|3216|125|3.8%|98.4%|
[openbl_7d](#openbl_7d)|897|897|124|13.8%|97.6%|
[alienvault_reputation](#alienvault_reputation)|175192|175192|124|0.0%|97.6%|
[blocklist_de](#blocklist_de)|22021|22021|110|0.4%|86.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|1692|1692|105|6.2%|82.6%|
[bruteforceblocker](#bruteforceblocker)|2188|2188|76|3.4%|59.8%|
[shunlist](#shunlist)|1255|1255|69|5.4%|54.3%|
[et_compromised](#et_compromised)|2367|2367|69|2.9%|54.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|21|0.0%|16.5%|
[et_block](#et_block)|986|18056524|20|0.0%|15.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|18|10.1%|14.1%|
[dshield](#dshield)|20|5120|16|0.3%|12.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|12|0.0%|9.4%|
[blocklist_de_mail](#blocklist_de_mail)|14254|14254|5|0.0%|3.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|4|0.0%|3.1%|
[blocklist_de_imap](#blocklist_de_imap)|528|528|4|0.7%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|2|0.0%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.7%|
[ciarmy](#ciarmy)|319|319|1|0.3%|0.7%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt).

The last time downloaded was found to be dated: Mon Jun  1 03:42:00 UTC 2015.

The ipset `openbl_30d` has **3216** entries, **3216** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7607|7607|3216|42.2%|100.0%|
[alienvault_reputation](#alienvault_reputation)|175192|175192|3204|1.8%|99.6%|
[et_compromised](#et_compromised)|2367|2367|1310|55.3%|40.7%|
[bruteforceblocker](#bruteforceblocker)|2188|2188|1239|56.6%|38.5%|
[openbl_7d](#openbl_7d)|897|897|897|100.0%|27.8%|
[blocklist_de](#blocklist_de)|22021|22021|801|3.6%|24.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|1692|1692|753|44.5%|23.4%|
[shunlist](#shunlist)|1255|1255|598|47.6%|18.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|284|0.0%|8.8%|
[et_block](#et_block)|986|18056524|205|0.0%|6.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|203|0.0%|6.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|178|0.0%|5.5%|
[openbl_1d](#openbl_1d)|127|127|125|98.4%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|68|0.0%|2.1%|
[dshield](#dshield)|20|5120|61|1.1%|1.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|46|25.8%|1.4%|
[blocklist_de_mail](#blocklist_de_mail)|14254|14254|40|0.2%|1.2%|
[blocklist_de_imap](#blocklist_de_imap)|528|528|32|6.0%|0.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|14|0.0%|0.4%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|6|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|4|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13791|13791|4|0.0%|0.1%|
[voipbl](#voipbl)|10343|10752|3|0.0%|0.0%|
[nixspam](#nixspam)|18400|18400|3|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|98|98|3|3.0%|0.0%|
[zeus](#zeus)|265|265|2|0.7%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|2|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6640|6640|1|0.0%|0.0%|
[ciarmy](#ciarmy)|319|319|1|0.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3196|3196|1|0.0%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt).

The last time downloaded was found to be dated: Mon Jun  1 03:42:00 UTC 2015.

The ipset `openbl_60d` has **7607** entries, **7607** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|175192|175192|7587|4.3%|99.7%|
[openbl_30d](#openbl_30d)|3216|3216|3216|100.0%|42.2%|
[et_compromised](#et_compromised)|2367|2367|1426|60.2%|18.7%|
[bruteforceblocker](#bruteforceblocker)|2188|2188|1310|59.8%|17.2%|
[openbl_7d](#openbl_7d)|897|897|897|100.0%|11.7%|
[blocklist_de](#blocklist_de)|22021|22021|870|3.9%|11.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|1692|1692|807|47.6%|10.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|716|0.0%|9.4%|
[shunlist](#shunlist)|1255|1255|615|49.0%|8.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|356|0.0%|4.6%|
[et_block](#et_block)|986|18056524|241|0.0%|3.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|239|0.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|173|0.0%|2.2%|
[openbl_1d](#openbl_1d)|127|127|125|98.4%|1.6%|
[dshield](#dshield)|20|5120|72|1.4%|0.9%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|54|0.0%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|48|26.9%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|14254|14254|46|0.3%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|528|528|36|6.8%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|27|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6640|6640|21|0.3%|0.2%|
[et_tor](#et_tor)|6470|6470|21|0.3%|0.2%|
[dm_tor](#dm_tor)|6402|6402|20|0.3%|0.2%|
[bm_tor](#bm_tor)|6405|6405|20|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|19|0.0%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.2%|
[nixspam](#nixspam)|18400|18400|10|0.0%|0.1%|
[voipbl](#voipbl)|10343|10752|9|0.0%|0.1%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3196|3196|8|0.2%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|6|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|6|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13791|13791|5|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|98|98|4|4.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|3|0.4%|0.0%|
[php_harvesters](#php_harvesters)|257|257|3|1.1%|0.0%|
[zeus](#zeus)|265|265|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[ciarmy](#ciarmy)|319|319|1|0.3%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt).

The last time downloaded was found to be dated: Mon Jun  1 03:42:00 UTC 2015.

The ipset `openbl_7d` has **897** entries, **897** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7607|7607|897|11.7%|100.0%|
[openbl_30d](#openbl_30d)|3216|3216|897|27.8%|100.0%|
[alienvault_reputation](#alienvault_reputation)|175192|175192|891|0.5%|99.3%|
[blocklist_de](#blocklist_de)|22021|22021|551|2.5%|61.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|1692|1692|524|30.9%|58.4%|
[bruteforceblocker](#bruteforceblocker)|2188|2188|518|23.6%|57.7%|
[et_compromised](#et_compromised)|2367|2367|508|21.4%|56.6%|
[shunlist](#shunlist)|1255|1255|386|30.7%|43.0%|
[openbl_1d](#openbl_1d)|127|127|124|97.6%|13.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|91|0.0%|10.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|85|0.0%|9.4%|
[et_block](#et_block)|986|18056524|85|0.0%|9.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|45|25.2%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|40|0.0%|4.4%|
[dshield](#dshield)|20|5120|36|0.7%|4.0%|
[blocklist_de_mail](#blocklist_de_mail)|14254|14254|25|0.1%|2.7%|
[blocklist_de_imap](#blocklist_de_imap)|528|528|19|3.5%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|17|0.0%|1.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|1.2%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|5|0.0%|0.5%|
[voipbl](#voipbl)|10343|10752|3|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.2%|
[zeus](#zeus)|265|265|1|0.3%|0.1%|
[snort_ipfilter](#snort_ipfilter)|714|714|1|0.1%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ciarmy](#ciarmy)|319|319|1|0.3%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|98|98|1|1.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13791|13791|1|0.0%|0.1%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Mon Jun  1 06:54:24 UTC 2015.

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
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|170|0.5%|60.4%|
[stopforumspam_1d](#stopforumspam_1d)|6640|6640|98|1.4%|34.8%|
[blocklist_de](#blocklist_de)|22021|22021|59|0.2%|20.9%|
[blocklist_de_bots](#blocklist_de_bots)|3196|3196|48|1.5%|17.0%|
[php_spammers](#php_spammers)|417|417|32|7.6%|11.3%|
[et_tor](#et_tor)|6470|6470|29|0.4%|10.3%|
[dm_tor](#dm_tor)|6402|6402|29|0.4%|10.3%|
[bm_tor](#bm_tor)|6405|6405|29|0.4%|10.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|29|16.2%|10.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|28|7.5%|9.9%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|24|0.0%|8.5%|
[et_block](#et_block)|986|18056524|24|0.0%|8.5%|
[blocklist_de_apache](#blocklist_de_apache)|13791|13791|24|0.1%|8.5%|
[php_dictionary](#php_dictionary)|433|433|22|5.0%|7.8%|
[blocklist_de_mail](#blocklist_de_mail)|14254|14254|17|0.1%|6.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|5.3%|
[alienvault_reputation](#alienvault_reputation)|175192|175192|13|0.0%|4.6%|
[ri_web_proxies](#ri_web_proxies)|5374|5374|11|0.2%|3.9%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.2%|
[openbl_60d](#openbl_60d)|7607|7607|8|0.1%|2.8%|
[nixspam](#nixspam)|18400|18400|8|0.0%|2.8%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|7|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|1.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1384|1384|4|0.2%|1.4%|
[xroxy](#xroxy)|2008|2008|3|0.1%|1.0%|
[proxz](#proxz)|415|415|2|0.4%|0.7%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.3%|
[zeus](#zeus)|265|265|1|0.3%|0.3%|
[snort_ipfilter](#snort_ipfilter)|714|714|1|0.1%|0.3%|
[proxyrss](#proxyrss)|1706|1706|1|0.0%|0.3%|
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
[nixspam](#nixspam)|18400|18400|71|0.3%|16.3%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|68|0.2%|15.7%|
[blocklist_de](#blocklist_de)|22021|22021|42|0.1%|9.6%|
[ri_web_proxies](#ri_web_proxies)|5374|5374|29|0.5%|6.6%|
[xroxy](#xroxy)|2008|2008|24|1.1%|5.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|24|0.0%|5.5%|
[blocklist_de_mail](#blocklist_de_mail)|14254|14254|23|0.1%|5.3%|
[stopforumspam_1d](#stopforumspam_1d)|6640|6640|22|0.3%|5.0%|
[php_commenters](#php_commenters)|281|281|22|7.8%|5.0%|
[blocklist_de_bots](#blocklist_de_bots)|3196|3196|19|0.5%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|10|0.0%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|9|0.0%|2.0%|
[alienvault_reputation](#alienvault_reputation)|175192|175192|7|0.0%|1.6%|
[proxz](#proxz)|415|415|6|1.4%|1.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|4|0.0%|0.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.9%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.9%|
[et_block](#et_block)|986|18056524|4|0.0%|0.9%|
[dm_tor](#dm_tor)|6402|6402|4|0.0%|0.9%|
[bm_tor](#bm_tor)|6405|6405|4|0.0%|0.9%|
[ri_connect_proxies](#ri_connect_proxies)|1998|1998|3|0.1%|0.6%|
[snort_ipfilter](#snort_ipfilter)|714|714|2|0.2%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|2|1.1%|0.4%|
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
[stopforumspam_1d](#stopforumspam_1d)|6640|6640|39|0.5%|15.1%|
[blocklist_de](#blocklist_de)|22021|22021|22|0.0%|8.5%|
[blocklist_de_bots](#blocklist_de_bots)|3196|3196|18|0.5%|7.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|5.8%|
[php_commenters](#php_commenters)|281|281|9|3.2%|3.5%|
[alienvault_reputation](#alienvault_reputation)|175192|175192|9|0.0%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|7|0.0%|2.7%|
[et_tor](#et_tor)|6470|6470|7|0.1%|2.7%|
[dm_tor](#dm_tor)|6402|6402|7|0.1%|2.7%|
[bm_tor](#bm_tor)|6405|6405|7|0.1%|2.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|6|1.6%|2.3%|
[nixspam](#nixspam)|18400|18400|5|0.0%|1.9%|
[openbl_60d](#openbl_60d)|7607|7607|3|0.0%|1.1%|
[xroxy](#xroxy)|2008|2008|2|0.0%|0.7%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|14254|14254|2|0.0%|0.7%|
[blocklist_de_ftp](#blocklist_de_ftp)|98|98|2|2.0%|0.7%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|1|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1|0.0%|0.3%|
[ri_web_proxies](#ri_web_proxies)|5374|5374|1|0.0%|0.3%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.3%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|
[fullbogons](#fullbogons)|3639|670580696|1|0.0%|0.3%|
[et_block](#et_block)|986|18056524|1|0.0%|0.3%|
[bogons](#bogons)|13|592708608|1|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|1|0.5%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|13791|13791|1|0.0%|0.3%|

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
[nixspam](#nixspam)|18400|18400|63|0.3%|15.1%|
[blocklist_de](#blocklist_de)|22021|22021|43|0.1%|10.3%|
[php_commenters](#php_commenters)|281|281|32|11.3%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|31|0.0%|7.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|26|0.0%|6.2%|
[blocklist_de_mail](#blocklist_de_mail)|14254|14254|25|0.1%|5.9%|
[ri_web_proxies](#ri_web_proxies)|5374|5374|24|0.4%|5.7%|
[stopforumspam_1d](#stopforumspam_1d)|6640|6640|23|0.3%|5.5%|
[xroxy](#xroxy)|2008|2008|18|0.8%|4.3%|
[blocklist_de_bots](#blocklist_de_bots)|3196|3196|12|0.3%|2.8%|
[proxz](#proxz)|415|415|6|1.4%|1.4%|
[et_tor](#et_tor)|6470|6470|6|0.0%|1.4%|
[dm_tor](#dm_tor)|6402|6402|6|0.0%|1.4%|
[bm_tor](#bm_tor)|6405|6405|6|0.0%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|1.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1384|1384|5|0.3%|1.1%|
[blocklist_de_apache](#blocklist_de_apache)|13791|13791|5|0.0%|1.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|4|2.2%|0.9%|
[alienvault_reputation](#alienvault_reputation)|175192|175192|3|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2|0.0%|0.4%|
[snort_ipfilter](#snort_ipfilter)|714|714|2|0.2%|0.4%|
[ri_connect_proxies](#ri_connect_proxies)|1998|1998|2|0.1%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[et_block](#et_block)|986|18056524|2|0.0%|0.4%|
[proxyrss](#proxyrss)|1706|1706|1|0.0%|0.2%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1692|1692|1|0.0%|0.2%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Mon Jun  1 03:11:23 UTC 2015.

The ipset `proxyrss` has **1706** entries, **1706** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|919|0.9%|53.8%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|790|2.5%|46.3%|
[ri_web_proxies](#ri_web_proxies)|5374|5374|642|11.9%|37.6%|
[stopforumspam_1d](#stopforumspam_1d)|6640|6640|529|7.9%|31.0%|
[xroxy](#xroxy)|2008|2008|477|23.7%|27.9%|
[blocklist_de](#blocklist_de)|22021|22021|253|1.1%|14.8%|
[blocklist_de_bots](#blocklist_de_bots)|3196|3196|252|7.8%|14.7%|
[ri_connect_proxies](#ri_connect_proxies)|1998|1998|214|10.7%|12.5%|
[proxz](#proxz)|415|415|159|38.3%|9.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|67|0.0%|3.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|50|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|35|0.0%|2.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|8|1.1%|0.4%|
[nixspam](#nixspam)|18400|18400|6|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|4|2.2%|0.2%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.0%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2188|2188|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1692|1692|1|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|175192|175192|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Mon Jun  1 05:51:34 UTC 2015.

The ipset `proxz` has **415** entries, **415** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|250|0.2%|60.2%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|227|0.7%|54.6%|
[xroxy](#xroxy)|2008|2008|219|10.9%|52.7%|
[ri_web_proxies](#ri_web_proxies)|5374|5374|183|3.4%|44.0%|
[proxyrss](#proxyrss)|1706|1706|159|9.3%|38.3%|
[stopforumspam_1d](#stopforumspam_1d)|6640|6640|97|1.4%|23.3%|
[blocklist_de](#blocklist_de)|22021|22021|92|0.4%|22.1%|
[blocklist_de_bots](#blocklist_de_bots)|3196|3196|82|2.5%|19.7%|
[ri_connect_proxies](#ri_connect_proxies)|1998|1998|64|3.2%|15.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|42|0.0%|10.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|16|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|16|0.0%|3.8%|
[nixspam](#nixspam)|18400|18400|12|0.0%|2.8%|
[blocklist_de_mail](#blocklist_de_mail)|14254|14254|9|0.0%|2.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|1.4%|
[php_dictionary](#php_dictionary)|433|433|6|1.3%|1.4%|
[php_commenters](#php_commenters)|281|281|2|0.7%|0.4%|
[et_compromised](#et_compromised)|2367|2367|2|0.0%|0.4%|
[bruteforceblocker](#bruteforceblocker)|2188|2188|2|0.0%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|2|1.1%|0.4%|
[alienvault_reputation](#alienvault_reputation)|175192|175192|2|0.0%|0.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.2%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1692|1692|1|0.0%|0.2%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Mon Jun  1 04:52:33 UTC 2015.

The ipset `ri_connect_proxies` has **1998** entries, **1998** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|1177|1.2%|58.9%|
[ri_web_proxies](#ri_web_proxies)|5374|5374|812|15.1%|40.6%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|684|2.1%|34.2%|
[xroxy](#xroxy)|2008|2008|315|15.6%|15.7%|
[proxyrss](#proxyrss)|1706|1706|214|12.5%|10.7%|
[stopforumspam_1d](#stopforumspam_1d)|6640|6640|157|2.3%|7.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|81|0.0%|4.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|66|0.0%|3.3%|
[proxz](#proxz)|415|415|64|15.4%|3.2%|
[blocklist_de](#blocklist_de)|22021|22021|63|0.2%|3.1%|
[blocklist_de_bots](#blocklist_de_bots)|3196|3196|61|1.9%|3.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|46|0.0%|2.3%|
[nixspam](#nixspam)|18400|18400|10|0.0%|0.5%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.3%|
[php_dictionary](#php_dictionary)|433|433|3|0.6%|0.1%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.1%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|175192|175192|2|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[dm_tor](#dm_tor)|6402|6402|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6405|6405|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14254|14254|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1384|1384|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13791|13791|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Mon Jun  1 04:50:48 UTC 2015.

The ipset `ri_web_proxies` has **5374** entries, **5374** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|2628|2.8%|48.9%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|1713|5.4%|31.8%|
[ri_connect_proxies](#ri_connect_proxies)|1998|1998|812|40.6%|15.1%|
[xroxy](#xroxy)|2008|2008|805|40.0%|14.9%|
[proxyrss](#proxyrss)|1706|1706|642|37.6%|11.9%|
[stopforumspam_1d](#stopforumspam_1d)|6640|6640|567|8.5%|10.5%|
[blocklist_de](#blocklist_de)|22021|22021|347|1.5%|6.4%|
[blocklist_de_bots](#blocklist_de_bots)|3196|3196|326|10.2%|6.0%|
[proxz](#proxz)|415|415|183|44.0%|3.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|172|0.0%|3.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|154|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|115|0.0%|2.1%|
[nixspam](#nixspam)|18400|18400|70|0.3%|1.3%|
[php_dictionary](#php_dictionary)|433|433|29|6.6%|0.5%|
[php_spammers](#php_spammers)|417|417|24|5.7%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|14254|14254|20|0.1%|0.3%|
[php_commenters](#php_commenters)|281|281|11|3.9%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|10|1.4%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.0%|
[et_tor](#et_tor)|6470|6470|4|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|4|2.2%|0.0%|
[dm_tor](#dm_tor)|6402|6402|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6405|6405|3|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|175192|175192|3|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|2|0.2%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1384|1384|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13791|13791|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Mon Jun  1 06:30:07 UTC 2015.

The ipset `shunlist` has **1255** entries, **1255** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|175192|175192|1247|0.7%|99.3%|
[openbl_60d](#openbl_60d)|7607|7607|615|8.0%|49.0%|
[openbl_30d](#openbl_30d)|3216|3216|598|18.5%|47.6%|
[bruteforceblocker](#bruteforceblocker)|2188|2188|521|23.8%|41.5%|
[et_compromised](#et_compromised)|2367|2367|520|21.9%|41.4%|
[blocklist_de](#blocklist_de)|22021|22021|445|2.0%|35.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|1692|1692|410|24.2%|32.6%|
[openbl_7d](#openbl_7d)|897|897|386|43.0%|30.7%|
[et_block](#et_block)|986|18056524|111|0.0%|8.8%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|102|0.0%|8.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|100|0.0%|7.9%|
[openbl_1d](#openbl_1d)|127|127|69|54.3%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|69|0.0%|5.4%|
[sslbl](#sslbl)|361|361|43|11.9%|3.4%|
[dshield](#dshield)|20|5120|41|0.8%|3.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|41|23.0%|3.2%|
[blocklist_de_apache](#blocklist_de_apache)|13791|13791|29|0.2%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|26|0.0%|2.0%|
[ciarmy](#ciarmy)|319|319|24|7.5%|1.9%|
[voipbl](#voipbl)|10343|10752|13|0.1%|1.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|5|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|14254|14254|5|0.0%|0.3%|
[blocklist_de_imap](#blocklist_de_imap)|528|528|5|0.9%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|4|0.0%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|3|0.0%|0.2%|
[nixspam](#nixspam)|18400|18400|3|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6640|6640|2|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.1%|
[snort_ipfilter](#snort_ipfilter)|714|714|1|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6402|6402|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6405|6405|1|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|92|92|1|1.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|98|98|1|1.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1384|1384|1|0.0%|0.0%|

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
[zeus](#zeus)|265|265|214|80.7%|29.9%|
[zeus_badips](#zeus_badips)|229|229|195|85.1%|27.3%|
[alienvault_reputation](#alienvault_reputation)|175192|175192|76|0.0%|10.6%|
[feodo](#feodo)|71|71|53|74.6%|7.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|29|0.0%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|24|0.0%|3.3%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|23|1.7%|3.2%|
[sslbl](#sslbl)|361|361|21|5.8%|2.9%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|16|0.0%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|12|0.0%|1.6%|
[palevo](#palevo)|13|13|11|84.6%|1.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|9|0.0%|1.2%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|8|0.0%|1.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|6|0.0%|0.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|6|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|3|0.0%|0.4%|
[openbl_60d](#openbl_60d)|7607|7607|3|0.0%|0.4%|
[xroxy](#xroxy)|2008|2008|2|0.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|6640|6640|2|0.0%|0.2%|
[ri_web_proxies](#ri_web_proxies)|5374|5374|2|0.0%|0.2%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.2%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.2%|
[openbl_30d](#openbl_30d)|3216|3216|2|0.0%|0.2%|
[shunlist](#shunlist)|1255|1255|1|0.0%|0.1%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.1%|
[openbl_7d](#openbl_7d)|897|897|1|0.1%|0.1%|
[nixspam](#nixspam)|18400|18400|1|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.1%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.1%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.1%|
[dm_tor](#dm_tor)|6402|6402|1|0.0%|0.1%|
[bruteforceblocker](#bruteforceblocker)|2188|2188|1|0.0%|0.1%|
[bm_tor](#bm_tor)|6405|6405|1|0.0%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|1692|1692|1|0.0%|0.1%|
[blocklist_de](#blocklist_de)|22021|22021|1|0.0%|0.1%|

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
[alienvault_reputation](#alienvault_reputation)|175192|175192|1627|0.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|971|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|512|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|342|1.0%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[nixspam](#nixspam)|18400|18400|245|1.3%|0.0%|
[openbl_60d](#openbl_60d)|7607|7607|239|3.1%|0.0%|
[openbl_30d](#openbl_30d)|3216|3216|203|6.3%|0.0%|
[blocklist_de](#blocklist_de)|22021|22021|177|0.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1692|1692|114|6.7%|0.0%|
[shunlist](#shunlist)|1255|1255|102|8.1%|0.0%|
[et_compromised](#et_compromised)|2367|2367|102|4.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2188|2188|102|4.6%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6640|6640|86|1.2%|0.0%|
[openbl_7d](#openbl_7d)|897|897|85|9.4%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3196|3196|37|1.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|29|2.2%|0.0%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14254|14254|24|0.1%|0.0%|
[openbl_1d](#openbl_1d)|127|127|21|16.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|528|528|18|3.4%|0.0%|
[zeus_badips](#zeus_badips)|229|229|16|6.9%|0.0%|
[zeus](#zeus)|265|265|16|6.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|16|2.2%|0.0%|
[voipbl](#voipbl)|10343|10752|14|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|5|2.8%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[malc0de](#malc0de)|403|403|4|0.9%|0.0%|
[sslbl](#sslbl)|361|361|3|0.8%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6470|6470|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6402|6402|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6405|6405|2|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1384|1384|2|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13791|13791|2|0.0%|0.0%|
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
[alienvault_reputation](#alienvault_reputation)|175192|175192|271|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|103|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|37|0.1%|0.0%|
[blocklist_de](#blocklist_de)|22021|22021|12|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|10|5.6%|0.0%|
[php_commenters](#php_commenters)|281|281|7|2.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|6|0.8%|0.0%|
[openbl_60d](#openbl_60d)|7607|7607|6|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3216|3216|6|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|5|2.1%|0.0%|
[zeus](#zeus)|265|265|5|1.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6640|6640|5|0.0%|0.0%|
[shunlist](#shunlist)|1255|1255|5|0.3%|0.0%|
[openbl_7d](#openbl_7d)|897|897|5|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1692|1692|5|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3196|3196|5|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13791|13791|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[malc0de](#malc0de)|403|403|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Mon Jun  1 06:45:06 UTC 2015.

The ipset `sslbl` has **361** entries, **361** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|175192|175192|51|0.0%|14.1%|
[shunlist](#shunlist)|1255|1255|43|3.4%|11.9%|
[feodo](#feodo)|71|71|27|38.0%|7.4%|
[et_block](#et_block)|986|18056524|27|0.0%|7.4%|
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

The last time downloaded was found to be dated: Mon Jun  1 06:00:02 UTC 2015.

The ipset `stopforumspam_1d` has **6640** entries, **6640** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|6090|19.4%|91.7%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|6033|6.5%|90.8%|
[blocklist_de](#blocklist_de)|22021|22021|1365|6.1%|20.5%|
[blocklist_de_bots](#blocklist_de_bots)|3196|3196|1300|40.6%|19.5%|
[ri_web_proxies](#ri_web_proxies)|5374|5374|567|10.5%|8.5%|
[proxyrss](#proxyrss)|1706|1706|529|31.0%|7.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|465|0.0%|7.0%|
[xroxy](#xroxy)|2008|2008|361|17.9%|5.4%|
[et_tor](#et_tor)|6470|6470|298|4.6%|4.4%|
[dm_tor](#dm_tor)|6402|6402|296|4.6%|4.4%|
[bm_tor](#bm_tor)|6405|6405|296|4.6%|4.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|241|0.0%|3.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|158|42.4%|2.3%|
[ri_connect_proxies](#ri_connect_proxies)|1998|1998|157|7.8%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|137|0.0%|2.0%|
[php_commenters](#php_commenters)|281|281|98|34.8%|1.4%|
[proxz](#proxz)|415|415|97|23.3%|1.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|95|53.3%|1.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|86|0.0%|1.2%|
[blocklist_de_apache](#blocklist_de_apache)|13791|13791|67|0.4%|1.0%|
[alienvault_reputation](#alienvault_reputation)|175192|175192|64|0.0%|0.9%|
[et_block](#et_block)|986|18056524|57|0.0%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|14254|14254|52|0.3%|0.7%|
[nixspam](#nixspam)|18400|18400|47|0.2%|0.7%|
[php_harvesters](#php_harvesters)|257|257|39|15.1%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|34|0.0%|0.5%|
[php_spammers](#php_spammers)|417|417|23|5.5%|0.3%|
[php_dictionary](#php_dictionary)|433|433|22|5.0%|0.3%|
[openbl_60d](#openbl_60d)|7607|7607|21|0.2%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1384|1384|17|1.2%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|11|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|7|1.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|5|0.0%|0.0%|
[voipbl](#voipbl)|10343|10752|4|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|2|0.2%|0.0%|
[shunlist](#shunlist)|1255|1255|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|265|265|1|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3216|3216|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2188|2188|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|98|98|1|1.0%|0.0%|

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
[stopforumspam_1d](#stopforumspam_1d)|6640|6640|6033|90.8%|6.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|5946|0.0%|6.4%|
[ri_web_proxies](#ri_web_proxies)|5374|5374|2628|48.9%|2.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2477|0.0%|2.6%|
[blocklist_de](#blocklist_de)|22021|22021|2332|10.5%|2.5%|
[blocklist_de_bots](#blocklist_de_bots)|3196|3196|2076|64.9%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1523|0.0%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|1998|1998|1177|58.9%|1.2%|
[xroxy](#xroxy)|2008|2008|1176|58.5%|1.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|971|0.0%|1.0%|
[proxyrss](#proxyrss)|1706|1706|919|53.8%|0.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|732|0.0%|0.7%|
[et_block](#et_block)|986|18056524|728|0.0%|0.7%|
[et_tor](#et_tor)|6470|6470|623|9.6%|0.6%|
[dm_tor](#dm_tor)|6402|6402|621|9.7%|0.6%|
[bm_tor](#bm_tor)|6405|6405|621|9.6%|0.6%|
[proxz](#proxz)|415|415|250|60.2%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|234|62.9%|0.2%|
[alienvault_reputation](#alienvault_reputation)|175192|175192|219|0.1%|0.2%|
[nixspam](#nixspam)|18400|18400|205|1.1%|0.2%|
[php_commenters](#php_commenters)|281|281|203|72.2%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|14254|14254|201|1.4%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|13791|13791|196|1.4%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|112|62.9%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|103|0.0%|0.1%|
[php_spammers](#php_spammers)|417|417|99|23.7%|0.1%|
[php_dictionary](#php_dictionary)|433|433|83|19.1%|0.0%|
[php_harvesters](#php_harvesters)|257|257|63|24.5%|0.0%|
[openbl_60d](#openbl_60d)|7607|7607|54|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|44|0.0%|0.0%|
[voipbl](#voipbl)|10343|10752|40|0.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1384|1384|31|2.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|22|3.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|8|1.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2188|2188|7|0.3%|0.0%|
[et_compromised](#et_compromised)|2367|2367|6|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1692|1692|6|0.3%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|98|98|6|6.1%|0.0%|
[shunlist](#shunlist)|1255|1255|4|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3216|3216|4|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|3|1.3%|0.0%|
[zeus](#zeus)|265|265|3|1.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|3|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3639|670580696|2|0.0%|0.0%|
[sslbl](#sslbl)|361|361|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|528|528|1|0.1%|0.0%|

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
[stopforumspam_1d](#stopforumspam_1d)|6640|6640|6090|91.7%|19.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2107|0.0%|6.7%|
[blocklist_de](#blocklist_de)|22021|22021|2070|9.4%|6.6%|
[blocklist_de_bots](#blocklist_de_bots)|3196|3196|1912|59.8%|6.1%|
[ri_web_proxies](#ri_web_proxies)|5374|5374|1713|31.8%|5.4%|
[xroxy](#xroxy)|2008|2008|986|49.1%|3.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|938|0.0%|2.9%|
[proxyrss](#proxyrss)|1706|1706|790|46.3%|2.5%|
[ri_connect_proxies](#ri_connect_proxies)|1998|1998|684|34.2%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|563|0.0%|1.7%|
[et_tor](#et_tor)|6470|6470|509|7.8%|1.6%|
[dm_tor](#dm_tor)|6402|6402|478|7.4%|1.5%|
[bm_tor](#bm_tor)|6405|6405|478|7.4%|1.5%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|342|0.0%|1.0%|
[proxz](#proxz)|415|415|227|54.6%|0.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|201|54.0%|0.6%|
[et_block](#et_block)|986|18056524|200|0.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|182|0.0%|0.5%|
[php_commenters](#php_commenters)|281|281|170|60.4%|0.5%|
[nixspam](#nixspam)|18400|18400|132|0.7%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|13791|13791|121|0.8%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|14254|14254|116|0.8%|0.3%|
[alienvault_reputation](#alienvault_reputation)|175192|175192|111|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|103|57.8%|0.3%|
[php_spammers](#php_spammers)|417|417|70|16.7%|0.2%|
[php_dictionary](#php_dictionary)|433|433|68|15.7%|0.2%|
[php_harvesters](#php_harvesters)|257|257|47|18.2%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|37|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7607|7607|27|0.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1384|1384|26|1.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|19|0.0%|0.0%|
[voipbl](#voipbl)|10343|10752|12|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|5|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|98|98|5|5.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2188|2188|4|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|714|714|3|0.4%|0.0%|
[shunlist](#shunlist)|1255|1255|3|0.2%|0.0%|
[et_compromised](#et_compromised)|2367|2367|3|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1692|1692|3|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|2|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|229|229|1|0.4%|0.0%|
[zeus](#zeus)|265|265|1|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3216|3216|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|528|528|1|0.1%|0.0%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Mon Jun  1 04:45:12 UTC 2015.

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
[alienvault_reputation](#alienvault_reputation)|175192|175192|209|0.1%|1.9%|
[blocklist_de](#blocklist_de)|22021|22021|42|0.1%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|40|0.0%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|92|92|33|35.8%|0.3%|
[et_block](#et_block)|986|18056524|17|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|14|0.0%|0.1%|
[shunlist](#shunlist)|1255|1255|13|1.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|12|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7607|7607|9|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13791|13791|5|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|6640|6640|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[openbl_7d](#openbl_7d)|897|897|3|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3216|3216|3|0.0%|0.0%|
[dshield](#dshield)|20|5120|3|0.0%|0.0%|
[ciarmy](#ciarmy)|319|319|3|0.9%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6402|6402|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6405|6405|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1692|1692|2|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1384|1384|2|0.1%|0.0%|
[nixspam](#nixspam)|18400|18400|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[et_tor](#et_tor)|6470|6470|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2188|2188|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14254|14254|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|528|528|1|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3196|3196|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Mon Jun  1 06:33:01 UTC 2015.

The ipset `xroxy` has **2008** entries, **2008** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|1176|1.2%|58.5%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|986|3.1%|49.1%|
[ri_web_proxies](#ri_web_proxies)|5374|5374|805|14.9%|40.0%|
[proxyrss](#proxyrss)|1706|1706|477|27.9%|23.7%|
[stopforumspam_1d](#stopforumspam_1d)|6640|6640|361|5.4%|17.9%|
[ri_connect_proxies](#ri_connect_proxies)|1998|1998|315|15.7%|15.6%|
[blocklist_de](#blocklist_de)|22021|22021|245|1.1%|12.2%|
[proxz](#proxz)|415|415|219|52.7%|10.9%|
[blocklist_de_bots](#blocklist_de_bots)|3196|3196|218|6.8%|10.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|98|0.0%|4.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|84|0.0%|4.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|57|0.0%|2.8%|
[nixspam](#nixspam)|18400|18400|56|0.3%|2.7%|
[blocklist_de_mail](#blocklist_de_mail)|14254|14254|25|0.1%|1.2%|
[php_dictionary](#php_dictionary)|433|433|24|5.5%|1.1%|
[php_spammers](#php_spammers)|417|417|18|4.3%|0.8%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|13|1.9%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|178|178|5|2.8%|0.2%|
[alienvault_reputation](#alienvault_reputation)|175192|175192|5|0.0%|0.2%|
[php_commenters](#php_commenters)|281|281|3|1.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.1%|
[et_tor](#et_tor)|6470|6470|3|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|714|714|2|0.2%|0.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[dm_tor](#dm_tor)|6402|6402|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6405|6405|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2188|2188|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1692|1692|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1384|1384|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13791|13791|1|0.0%|0.0%|

## zeus

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist).

The last time downloaded was found to be dated: Mon Jun  1 04:39:18 UTC 2015.

The ipset `zeus` has **265** entries, **265** unique IPs.

The following table shows the overlaps of `zeus` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus`.
- ` this % ` is the percentage **of this ipset (`zeus`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|986|18056524|258|0.0%|97.3%|
[zeus_badips](#zeus_badips)|229|229|229|100.0%|86.4%|
[snort_ipfilter](#snort_ipfilter)|714|714|214|29.9%|80.7%|
[alienvault_reputation](#alienvault_reputation)|175192|175192|65|0.0%|24.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|19|0.0%|7.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|16|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|8|0.0%|3.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|5|0.0%|1.8%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|3|0.0%|1.1%|
[openbl_60d](#openbl_60d)|7607|7607|2|0.0%|0.7%|
[openbl_30d](#openbl_30d)|3216|3216|2|0.0%|0.7%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|1|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|6640|6640|1|0.0%|0.3%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.3%|
[openbl_7d](#openbl_7d)|897|897|1|0.1%|0.3%|
[nixspam](#nixspam)|18400|18400|1|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.3%|
[bruteforceblocker](#bruteforceblocker)|2188|2188|1|0.0%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1384|1384|1|0.0%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|13791|13791|1|0.0%|0.3%|
[blocklist_de](#blocklist_de)|22021|22021|1|0.0%|0.3%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Mon Jun  1 06:54:21 UTC 2015.

The ipset `zeus_badips` has **229** entries, **229** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|265|265|229|86.4%|100.0%|
[et_block](#et_block)|986|18056524|228|0.0%|99.5%|
[snort_ipfilter](#snort_ipfilter)|714|714|195|27.3%|85.1%|
[alienvault_reputation](#alienvault_reputation)|175192|175192|37|0.0%|16.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|16|0.0%|6.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14|0.0%|6.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8|0.0%|3.4%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|5|0.0%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4|0.0%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|3|0.0%|1.3%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|6640|6640|1|0.0%|0.4%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.4%|
[openbl_60d](#openbl_60d)|7607|7607|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|3216|3216|1|0.0%|0.4%|
[nixspam](#nixspam)|18400|18400|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.4%|
[et_compromised](#et_compromised)|2367|2367|1|0.0%|0.4%|
[bruteforceblocker](#bruteforceblocker)|2188|2188|1|0.0%|0.4%|
