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

The following list was automatically generated on Mon Jun  1 19:27:59 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|178819 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|22462 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|13852 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|3202 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|1437 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|199 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|620 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|14595 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|97 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|1615 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|159 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6535 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|2178 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|339 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|426 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6558 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|997 subnets, 18338381 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botcc](#et_botcc)|[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)|ipv4 hash:ip|505 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net compromised hosts](http://doc.emergingthreats.net/bin/view/Main/CompromisedHost) - (this seems to be based on bruteforceblocker)|ipv4 hash:ip|2191 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6360 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[feodo](#feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|77 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
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
[malc0de](#malc0de)|[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days|ipv4 hash:ip|397 unique IPs|updated every 1 day  from [this link](http://malc0de.com/bl/IP_Blacklist.txt)
[malwaredomainlist](#malwaredomainlist)|[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses|ipv4 hash:ip|1282 unique IPs|updated every 12 hours  from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt)
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.|ipv4 hash:ip|372 unique IPs|updated every 4 hours  from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list)
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|23859 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|141 unique IPs|updated every 1 hour  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|3197 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7581 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|901 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|281 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|433 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|257 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|417 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1596 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|459 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2030 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|5512 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1241 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|6251 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|652 subnets, 18338560 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|56 subnets, 421632 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|364 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|7099 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|92062 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|31333 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10350 subnets, 10759 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2016 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|267 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|231 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Mon Jun  1 16:00:36 UTC 2015.

The ipset `alienvault_reputation` has **178819** entries, **178819** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14383|0.0%|8.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8138|0.0%|4.5%|
[openbl_60d](#openbl_60d)|7581|7581|7561|99.7%|4.2%|
[et_block](#et_block)|997|18338381|5028|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4437|0.0%|2.4%|
[dshield](#dshield)|20|5120|3840|75.0%|2.1%|
[openbl_30d](#openbl_30d)|3197|3197|3185|99.6%|1.7%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1628|0.0%|0.9%|
[et_compromised](#et_compromised)|2191|2191|1421|64.8%|0.7%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|1408|64.6%|0.7%|
[shunlist](#shunlist)|1241|1241|1229|99.0%|0.6%|
[blocklist_de](#blocklist_de)|22462|22462|1112|4.9%|0.6%|
[openbl_7d](#openbl_7d)|901|901|895|99.3%|0.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|1615|1615|866|53.6%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|518|0.0%|0.2%|
[ciarmy](#ciarmy)|339|339|332|97.9%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|288|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|271|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|219|0.2%|0.1%|
[voipbl](#voipbl)|10350|10759|209|1.9%|0.1%|
[openbl_1d](#openbl_1d)|141|141|135|95.7%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|115|1.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|111|0.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|111|0.8%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14595|14595|86|0.5%|0.0%|
[zeus](#zeus)|267|267|66|24.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|620|620|58|9.3%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7099|7099|57|0.8%|0.0%|
[sslbl](#sslbl)|364|364|51|14.0%|0.0%|
[dm_tor](#dm_tor)|6558|6558|46|0.7%|0.0%|
[et_tor](#et_tor)|6360|6360|45|0.7%|0.0%|
[bm_tor](#bm_tor)|6535|6535|45|0.6%|0.0%|
[nixspam](#nixspam)|23859|23859|40|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3202|3202|39|1.2%|0.0%|
[zeus_badips](#zeus_badips)|231|231|37|16.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|36|22.6%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|25|6.7%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|97|97|18|18.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[php_commenters](#php_commenters)|281|281|13|4.6%|0.0%|
[malc0de](#malc0de)|397|397|12|3.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1437|1437|12|0.8%|0.0%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|8|0.5%|0.0%|
[php_dictionary](#php_dictionary)|433|433|7|1.6%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|199|199|7|3.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|6|0.4%|0.0%|
[xroxy](#xroxy)|2016|2016|5|0.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|426|426|4|0.9%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5512|5512|3|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|3|0.7%|0.0%|
[et_botcc](#et_botcc)|505|505|3|0.5%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2030|2030|2|0.0%|0.0%|
[proxz](#proxz)|459|459|2|0.4%|0.0%|
[proxyrss](#proxyrss)|1596|1596|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[feodo](#feodo)|77|77|1|1.2%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Mon Jun  1 18:56:03 UTC 2015.

The ipset `blocklist_de` has **22462** entries, **22462** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|14595|14595|14595|100.0%|64.9%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|13852|100.0%|61.6%|
[blocklist_de_bots](#blocklist_de_bots)|3202|3202|3202|100.0%|14.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2803|0.0%|12.4%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|2155|2.3%|9.5%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|1892|6.0%|8.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|1615|1615|1612|99.8%|7.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1456|0.0%|6.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1437|1437|1436|99.9%|6.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1428|0.0%|6.3%|
[stopforumspam_1d](#stopforumspam_1d)|7099|7099|1423|20.0%|6.3%|
[alienvault_reputation](#alienvault_reputation)|178819|178819|1112|0.6%|4.9%|
[openbl_60d](#openbl_60d)|7581|7581|824|10.8%|3.6%|
[openbl_30d](#openbl_30d)|3197|3197|755|23.6%|3.3%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|707|32.4%|3.1%|
[et_compromised](#et_compromised)|2191|2191|701|31.9%|3.1%|
[blocklist_de_imap](#blocklist_de_imap)|620|620|620|100.0%|2.7%|
[openbl_7d](#openbl_7d)|901|901|517|57.3%|2.3%|
[nixspam](#nixspam)|23859|23859|483|2.0%|2.1%|
[shunlist](#shunlist)|1241|1241|409|32.9%|1.8%|
[ri_web_proxies](#ri_web_proxies)|5512|5512|359|6.5%|1.5%|
[xroxy](#xroxy)|2016|2016|237|11.7%|1.0%|
[proxyrss](#proxyrss)|1596|1596|234|14.6%|1.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|199|199|199|100.0%|0.8%|
[et_block](#et_block)|997|18338381|181|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|173|0.0%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|159|100.0%|0.7%|
[dshield](#dshield)|20|5120|124|2.4%|0.5%|
[openbl_1d](#openbl_1d)|141|141|117|82.9%|0.5%|
[proxz](#proxz)|459|459|93|20.2%|0.4%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|83|1.3%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|97|97|78|80.4%|0.3%|
[php_commenters](#php_commenters)|281|281|63|22.4%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2030|2030|59|2.9%|0.2%|
[php_spammers](#php_spammers)|417|417|41|9.8%|0.1%|
[php_dictionary](#php_dictionary)|433|433|39|9.0%|0.1%|
[voipbl](#voipbl)|10350|10759|37|0.3%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|36|0.0%|0.1%|
[ciarmy](#ciarmy)|339|339|36|10.6%|0.1%|
[php_harvesters](#php_harvesters)|257|257|25|9.7%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|9|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|7|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.0%|
[et_tor](#et_tor)|6360|6360|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6558|6558|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6535|6535|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Mon Jun  1 18:56:07 UTC 2015.

The ipset `blocklist_de_apache` has **13852** entries, **13852** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22462|22462|13852|61.6%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|14595|14595|11059|75.7%|79.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2200|0.0%|15.8%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1437|1437|1436|99.9%|10.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1318|0.0%|9.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1064|0.0%|7.6%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|198|0.2%|1.4%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|122|0.3%|0.8%|
[alienvault_reputation](#alienvault_reputation)|178819|178819|111|0.0%|0.8%|
[stopforumspam_1d](#stopforumspam_1d)|7099|7099|59|0.8%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|35|22.0%|0.2%|
[ciarmy](#ciarmy)|339|339|30|8.8%|0.2%|
[shunlist](#shunlist)|1241|1241|28|2.2%|0.2%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3202|3202|21|0.6%|0.1%|
[nixspam](#nixspam)|23859|23859|14|0.0%|0.1%|
[et_block](#et_block)|997|18338381|6|0.0%|0.0%|
[voipbl](#voipbl)|10350|10759|5|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|5|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.0%|
[dshield](#dshield)|20|5120|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|3|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7581|7581|3|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3197|3197|3|0.0%|0.0%|
[et_tor](#et_tor)|6360|6360|3|0.0%|0.0%|
[et_compromised](#et_compromised)|2191|2191|3|0.1%|0.0%|
[dm_tor](#dm_tor)|6558|6558|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|3|0.1%|0.0%|
[bm_tor](#bm_tor)|6535|6535|3|0.0%|0.0%|
[xroxy](#xroxy)|2016|2016|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5512|5512|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2030|2030|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Mon Jun  1 18:56:09 UTC 2015.

The ipset `blocklist_de_bots` has **3202** entries, **3202** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22462|22462|3202|14.2%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|1907|2.0%|59.5%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|1738|5.5%|54.2%|
[stopforumspam_1d](#stopforumspam_1d)|7099|7099|1372|19.3%|42.8%|
[ri_web_proxies](#ri_web_proxies)|5512|5512|331|6.0%|10.3%|
[proxyrss](#proxyrss)|1596|1596|234|14.6%|7.3%|
[xroxy](#xroxy)|2016|2016|209|10.3%|6.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|201|0.0%|6.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|198|0.0%|6.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|111|69.8%|3.4%|
[proxz](#proxz)|459|459|82|17.8%|2.5%|
[ri_connect_proxies](#ri_connect_proxies)|2030|2030|57|2.8%|1.7%|
[php_commenters](#php_commenters)|281|281|52|18.5%|1.6%|
[nixspam](#nixspam)|23859|23859|43|0.1%|1.3%|
[alienvault_reputation](#alienvault_reputation)|178819|178819|39|0.0%|1.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|35|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|33|0.0%|1.0%|
[et_block](#et_block)|997|18338381|33|0.0%|1.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|28|0.0%|0.8%|
[php_dictionary](#php_dictionary)|433|433|22|5.0%|0.6%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|21|0.3%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|14595|14595|21|0.1%|0.6%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|21|0.1%|0.6%|
[php_harvesters](#php_harvesters)|257|257|20|7.7%|0.6%|
[php_spammers](#php_spammers)|417|417|15|3.5%|0.4%|
[openbl_60d](#openbl_60d)|7581|7581|15|0.1%|0.4%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|4|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.0%|
[voipbl](#voipbl)|10350|10759|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3197|3197|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2191|2191|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Mon Jun  1 18:56:11 UTC 2015.

The ipset `blocklist_de_bruteforce` has **1437** entries, **1437** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|1436|10.3%|99.9%|
[blocklist_de](#blocklist_de)|22462|22462|1436|6.3%|99.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|106|0.0%|7.3%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|35|0.0%|2.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|32|0.0%|2.2%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|30|0.0%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|27|0.0%|1.8%|
[stopforumspam_1d](#stopforumspam_1d)|7099|7099|17|0.2%|1.1%|
[nixspam](#nixspam)|23859|23859|13|0.0%|0.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|12|7.5%|0.8%|
[alienvault_reputation](#alienvault_reputation)|178819|178819|12|0.0%|0.8%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.3%|
[php_commenters](#php_commenters)|281|281|5|1.7%|0.3%|
[et_block](#et_block)|997|18338381|4|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|3|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.2%|
[voipbl](#voipbl)|10350|10759|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|2|0.0%|0.1%|
[shunlist](#shunlist)|1241|1241|2|0.1%|0.1%|
[xroxy](#xroxy)|2016|2016|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5512|5512|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2030|2030|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Mon Jun  1 18:56:08 UTC 2015.

The ipset `blocklist_de_ftp` has **199** entries, **199** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22462|22462|199|0.8%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|20|0.0%|10.0%|
[alienvault_reputation](#alienvault_reputation)|178819|178819|7|0.0%|3.5%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|6|0.0%|3.0%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|5|0.0%|2.5%|
[openbl_60d](#openbl_60d)|7581|7581|4|0.0%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|4|0.0%|2.0%|
[php_harvesters](#php_harvesters)|257|257|3|1.1%|1.5%|
[openbl_30d](#openbl_30d)|3197|3197|3|0.0%|1.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|1.5%|
[nixspam](#nixspam)|23859|23859|2|0.0%|1.0%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|1|0.0%|0.5%|
[shunlist](#shunlist)|1241|1241|1|0.0%|0.5%|
[openbl_7d](#openbl_7d)|901|901|1|0.1%|0.5%|
[et_compromised](#et_compromised)|2191|2191|1|0.0%|0.5%|
[dshield](#dshield)|20|5120|1|0.0%|0.5%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|1|0.0%|0.5%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Mon Jun  1 18:56:08 UTC 2015.

The ipset `blocklist_de_imap` has **620** entries, **620** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|14595|14595|620|4.2%|100.0%|
[blocklist_de](#blocklist_de)|22462|22462|620|2.7%|100.0%|
[alienvault_reputation](#alienvault_reputation)|178819|178819|58|0.0%|9.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|43|0.0%|6.9%|
[openbl_60d](#openbl_60d)|7581|7581|37|0.4%|5.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|35|0.0%|5.6%|
[openbl_30d](#openbl_30d)|3197|3197|33|1.0%|5.3%|
[openbl_7d](#openbl_7d)|901|901|19|2.1%|3.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|17|0.0%|2.7%|
[et_block](#et_block)|997|18338381|17|0.0%|2.7%|
[et_compromised](#et_compromised)|2191|2191|10|0.4%|1.6%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|9|0.4%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|8|0.0%|1.2%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|6|0.0%|0.9%|
[shunlist](#shunlist)|1241|1241|5|0.4%|0.8%|
[nixspam](#nixspam)|23859|23859|3|0.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.3%|
[ciarmy](#ciarmy)|339|339|2|0.5%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|2|1.2%|0.3%|
[voipbl](#voipbl)|10350|10759|1|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|1|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|1|0.0%|0.1%|
[openbl_1d](#openbl_1d)|141|141|1|0.7%|0.1%|
[dshield](#dshield)|20|5120|1|0.0%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|1615|1615|1|0.0%|0.1%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Mon Jun  1 18:56:06 UTC 2015.

The ipset `blocklist_de_mail` has **14595** entries, **14595** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22462|22462|14595|64.9%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|11059|79.8%|75.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2257|0.0%|15.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1323|0.0%|9.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1119|0.0%|7.6%|
[blocklist_de_imap](#blocklist_de_imap)|620|620|620|100.0%|4.2%|
[nixspam](#nixspam)|23859|23859|422|1.7%|2.8%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|196|0.2%|1.3%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|114|0.3%|0.7%|
[alienvault_reputation](#alienvault_reputation)|178819|178819|86|0.0%|0.5%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|57|0.9%|0.3%|
[openbl_60d](#openbl_60d)|7581|7581|49|0.6%|0.3%|
[openbl_30d](#openbl_30d)|3197|3197|43|1.3%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7099|7099|40|0.5%|0.2%|
[ri_web_proxies](#ri_web_proxies)|5512|5512|27|0.4%|0.1%|
[xroxy](#xroxy)|2016|2016|26|1.2%|0.1%|
[openbl_7d](#openbl_7d)|901|901|26|2.8%|0.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|23|0.0%|0.1%|
[et_block](#et_block)|997|18338381|23|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3202|3202|21|0.6%|0.1%|
[php_spammers](#php_spammers)|417|417|20|4.7%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|20|12.5%|0.1%|
[php_dictionary](#php_dictionary)|433|433|17|3.9%|0.1%|
[php_commenters](#php_commenters)|281|281|17|6.0%|0.1%|
[et_compromised](#et_compromised)|2191|2191|12|0.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|11|0.5%|0.0%|
[proxz](#proxz)|459|459|10|2.1%|0.0%|
[shunlist](#shunlist)|1241|1241|7|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[et_tor](#et_tor)|6360|6360|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6558|6558|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6535|6535|3|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[ciarmy](#ciarmy)|339|339|2|0.5%|0.0%|
[voipbl](#voipbl)|10350|10759|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2030|2030|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|141|141|1|0.7%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1615|1615|1|0.0%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Mon Jun  1 19:10:08 UTC 2015.

The ipset `blocklist_de_sip` has **97** entries, **97** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22462|22462|78|0.3%|80.4%|
[voipbl](#voipbl)|10350|10759|28|0.2%|28.8%|
[alienvault_reputation](#alienvault_reputation)|178819|178819|18|0.0%|18.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14|0.0%|14.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|9.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|2|0.0%|2.0%|
[et_block](#et_block)|997|18338381|2|0.0%|2.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1|0.0%|1.0%|
[nixspam](#nixspam)|23859|23859|1|0.0%|1.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|1.0%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Mon Jun  1 19:10:03 UTC 2015.

The ipset `blocklist_de_ssh` has **1615** entries, **1615** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22462|22462|1612|7.1%|99.8%|
[alienvault_reputation](#alienvault_reputation)|178819|178819|866|0.4%|53.6%|
[openbl_60d](#openbl_60d)|7581|7581|755|9.9%|46.7%|
[openbl_30d](#openbl_30d)|3197|3197|707|22.1%|43.7%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|692|31.7%|42.8%|
[et_compromised](#et_compromised)|2191|2191|685|31.2%|42.4%|
[openbl_7d](#openbl_7d)|901|901|490|54.3%|30.3%|
[shunlist](#shunlist)|1241|1241|374|30.1%|23.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|190|0.0%|11.7%|
[et_block](#et_block)|997|18338381|117|0.0%|7.2%|
[dshield](#dshield)|20|5120|117|2.2%|7.2%|
[openbl_1d](#openbl_1d)|141|141|116|82.2%|7.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|113|0.0%|6.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|86|0.0%|5.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|29|0.0%|1.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|27|16.9%|1.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.3%|
[ciarmy](#ciarmy)|339|339|4|1.1%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|3|0.0%|0.1%|
[voipbl](#voipbl)|10350|10759|2|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|2|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.1%|
[xroxy](#xroxy)|2016|2016|1|0.0%|0.0%|
[proxz](#proxz)|459|459|1|0.2%|0.0%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.0%|
[nixspam](#nixspam)|23859|23859|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14595|14595|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|620|620|1|0.1%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Mon Jun  1 18:56:11 UTC 2015.

The ipset `blocklist_de_strongips` has **159** entries, **159** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|22462|22462|159|0.7%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|113|0.1%|71.0%|
[blocklist_de_bots](#blocklist_de_bots)|3202|3202|111|3.4%|69.8%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|104|0.3%|65.4%|
[stopforumspam_1d](#stopforumspam_1d)|7099|7099|99|1.3%|62.2%|
[alienvault_reputation](#alienvault_reputation)|178819|178819|36|0.0%|22.6%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|35|0.2%|22.0%|
[php_commenters](#php_commenters)|281|281|29|10.3%|18.2%|
[openbl_60d](#openbl_60d)|7581|7581|27|0.3%|16.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|1615|1615|27|1.6%|16.9%|
[openbl_30d](#openbl_30d)|3197|3197|24|0.7%|15.0%|
[openbl_7d](#openbl_7d)|901|901|23|2.5%|14.4%|
[blocklist_de_mail](#blocklist_de_mail)|14595|14595|20|0.1%|12.5%|
[shunlist](#shunlist)|1241|1241|18|1.4%|11.3%|
[openbl_1d](#openbl_1d)|141|141|17|12.0%|10.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|16|0.0%|10.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1437|1437|12|0.8%|7.5%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|7|0.0%|4.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7|0.0%|4.4%|
[et_block](#et_block)|997|18338381|7|0.0%|4.4%|
[xroxy](#xroxy)|2016|2016|4|0.1%|2.5%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|4|0.0%|2.5%|
[proxyrss](#proxyrss)|1596|1596|4|0.2%|2.5%|
[php_spammers](#php_spammers)|417|417|4|0.9%|2.5%|
[ri_web_proxies](#ri_web_proxies)|5512|5512|3|0.0%|1.8%|
[proxz](#proxz)|459|459|3|0.6%|1.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.8%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|1.2%|
[nixspam](#nixspam)|23859|23859|2|0.0%|1.2%|
[blocklist_de_imap](#blocklist_de_imap)|620|620|2|0.3%|1.2%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|1|0.0%|0.6%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.6%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Mon Jun  1 19:27:08 UTC 2015.

The ipset `bm_tor` has **6535** entries, **6535** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[dm_tor](#dm_tor)|6558|6558|6456|98.4%|98.7%|
[et_tor](#et_tor)|6360|6360|5974|93.9%|91.4%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|1055|16.8%|16.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|631|0.0%|9.6%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|620|0.6%|9.4%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|478|1.5%|7.3%|
[stopforumspam_1d](#stopforumspam_1d)|7099|7099|291|4.0%|4.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|190|0.0%|2.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|171|45.9%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|167|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|178819|178819|45|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7581|7581|19|0.2%|0.2%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[nixspam](#nixspam)|23859|23859|5|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[et_block](#et_block)|997|18338381|4|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5512|5512|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14595|14595|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|22462|22462|3|0.0%|0.0%|
[xroxy](#xroxy)|2016|2016|2|0.0%|0.0%|
[voipbl](#voipbl)|10350|10759|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2|0.0%|0.0%|
[shunlist](#shunlist)|1241|1241|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2030|2030|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1596|1596|1|0.0%|0.0%|

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
[voipbl](#voipbl)|10350|10759|319|2.9%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|1|0.0%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Mon Jun  1 18:36:14 UTC 2015.

The ipset `bruteforceblocker` has **2178** entries, **2178** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_compromised](#et_compromised)|2191|2191|2157|98.4%|99.0%|
[alienvault_reputation](#alienvault_reputation)|178819|178819|1408|0.7%|64.6%|
[openbl_60d](#openbl_60d)|7581|7581|1306|17.2%|59.9%|
[openbl_30d](#openbl_30d)|3197|3197|1235|38.6%|56.7%|
[blocklist_de](#blocklist_de)|22462|22462|707|3.1%|32.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|1615|1615|692|42.8%|31.7%|
[shunlist](#shunlist)|1241|1241|519|41.8%|23.8%|
[openbl_7d](#openbl_7d)|901|901|516|57.2%|23.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|219|0.0%|10.0%|
[dshield](#dshield)|20|5120|117|2.2%|5.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|116|0.0%|5.3%|
[et_block](#et_block)|997|18338381|103|0.0%|4.7%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|101|0.0%|4.6%|
[openbl_1d](#openbl_1d)|141|141|77|54.6%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|62|0.0%|2.8%|
[blocklist_de_mail](#blocklist_de_mail)|14595|14595|11|0.0%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|620|620|9|1.4%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|6|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|3|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7099|7099|3|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|3|0.0%|0.1%|
[proxz](#proxz)|459|459|2|0.4%|0.0%|
[zeus_badips](#zeus_badips)|231|231|1|0.4%|0.0%|
[zeus](#zeus)|267|267|1|0.3%|0.0%|
[xroxy](#xroxy)|2016|2016|1|0.0%|0.0%|
[voipbl](#voipbl)|10350|10759|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3639|670579672|1|0.0%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|199|199|1|0.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3202|3202|1|0.0%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Mon Jun  1 19:15:17 UTC 2015.

The ipset `ciarmy` has **339** entries, **339** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|178819|178819|332|0.1%|97.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|54|0.0%|15.9%|
[blocklist_de](#blocklist_de)|22462|22462|36|0.1%|10.6%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|30|0.2%|8.8%|
[shunlist](#shunlist)|1241|1241|25|2.0%|7.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|16|0.0%|4.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|10|0.0%|2.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|1615|1615|4|0.2%|1.1%|
[voipbl](#voipbl)|10350|10759|3|0.0%|0.8%|
[et_block](#et_block)|997|18338381|2|0.0%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|14595|14595|2|0.0%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|620|620|2|0.3%|0.5%|
[openbl_7d](#openbl_7d)|901|901|1|0.1%|0.2%|
[openbl_60d](#openbl_60d)|7581|7581|1|0.0%|0.2%|
[openbl_30d](#openbl_30d)|3197|3197|1|0.0%|0.2%|
[cleanmx_viruses](#cleanmx_viruses)|426|426|1|0.2%|0.2%|

## cleanmx_viruses

[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses

Source is downloaded from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive).

The last time downloaded was found to be dated: Mon Jun  1 18:27:32 UTC 2015.

The ipset `cleanmx_viruses` has **426** entries, **426** unique IPs.

The following table shows the overlaps of `cleanmx_viruses` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `cleanmx_viruses`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `cleanmx_viruses`.
- ` this % ` is the percentage **of this ipset (`cleanmx_viruses`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|59|0.0%|13.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|15|0.0%|3.5%|
[malc0de](#malc0de)|397|397|13|3.2%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|13|0.0%|3.0%|
[alienvault_reputation](#alienvault_reputation)|178819|178819|4|0.0%|0.9%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|3|0.0%|0.7%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|2|0.1%|0.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.2%|
[et_block](#et_block)|997|18338381|1|0.0%|0.2%|
[ciarmy](#ciarmy)|339|339|1|0.2%|0.2%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Mon Jun  1 19:27:07 UTC 2015.

The ipset `dm_tor` has **6558** entries, **6558** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6535|6535|6456|98.7%|98.4%|
[et_tor](#et_tor)|6360|6360|5967|93.8%|90.9%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|1055|16.8%|16.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|631|0.0%|9.6%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|620|0.6%|9.4%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|479|1.5%|7.3%|
[stopforumspam_1d](#stopforumspam_1d)|7099|7099|291|4.0%|4.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|189|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|171|45.9%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|168|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|178819|178819|46|0.0%|0.7%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7581|7581|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[nixspam](#nixspam)|23859|23859|4|0.0%|0.0%|
[et_block](#et_block)|997|18338381|4|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5512|5512|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14595|14595|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|22462|22462|3|0.0%|0.0%|
[xroxy](#xroxy)|2016|2016|2|0.0%|0.0%|
[voipbl](#voipbl)|10350|10759|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2|0.0%|0.0%|
[shunlist](#shunlist)|1241|1241|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2030|2030|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1596|1596|1|0.0%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Mon Jun  1 19:17:29 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|178819|178819|3840|2.1%|75.0%|
[et_block](#et_block)|997|18338381|1280|0.0%|25.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|512|0.0%|10.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|256|0.0%|5.0%|
[openbl_60d](#openbl_60d)|7581|7581|193|2.5%|3.7%|
[openbl_30d](#openbl_30d)|3197|3197|166|5.1%|3.2%|
[shunlist](#shunlist)|1241|1241|130|10.4%|2.5%|
[blocklist_de](#blocklist_de)|22462|22462|124|0.5%|2.4%|
[et_compromised](#et_compromised)|2191|2191|117|5.3%|2.2%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|117|5.3%|2.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1615|1615|117|7.2%|2.2%|
[openbl_7d](#openbl_7d)|901|901|101|11.2%|1.9%|
[openbl_1d](#openbl_1d)|141|141|16|11.3%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|5|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|2|0.0%|0.0%|
[voipbl](#voipbl)|10350|10759|1|0.0%|0.0%|
[nixspam](#nixspam)|23859|23859|1|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|1|0.0%|0.0%|
[malc0de](#malc0de)|397|397|1|0.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14595|14595|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|620|620|1|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|199|199|1|0.5%|0.0%|

## et_block

[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)

Source is downloaded from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt).

The last time downloaded was found to be dated: Mon Jun  1 04:30:02 UTC 2015.

The ipset `et_block` has **997** entries, **18338381** unique IPs.

The following table shows the overlaps of `et_block` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_block`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_block`.
- ` this % ` is the percentage **of this ipset (`et_block`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[spamhaus_drop](#spamhaus_drop)|652|18338560|18333440|99.9%|99.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8598823|2.4%|46.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7079936|77.1%|38.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|2272672|0.2%|12.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|196186|0.1%|1.0%|
[fullbogons](#fullbogons)|3639|670579672|20480|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|178819|178819|5028|2.8%|0.0%|
[dshield](#dshield)|20|5120|1280|25.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1040|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|975|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|517|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|342|1.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|297|4.7%|0.0%|
[zeus](#zeus)|267|267|260|97.3%|0.0%|
[openbl_60d](#openbl_60d)|7581|7581|245|3.2%|0.0%|
[zeus_badips](#zeus_badips)|231|231|229|99.1%|0.0%|
[openbl_30d](#openbl_30d)|3197|3197|206|6.4%|0.0%|
[nixspam](#nixspam)|23859|23859|185|0.7%|0.0%|
[blocklist_de](#blocklist_de)|22462|22462|181|0.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1615|1615|117|7.2%|0.0%|
[shunlist](#shunlist)|1241|1241|108|8.7%|0.0%|
[et_compromised](#et_compromised)|2191|2191|104|4.7%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|103|4.7%|0.0%|
[openbl_7d](#openbl_7d)|901|901|89|9.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7099|7099|82|1.1%|0.0%|
[feodo](#feodo)|77|77|71|92.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3202|3202|33|1.0%|0.0%|
[sslbl](#sslbl)|364|364|30|8.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|29|2.2%|0.0%|
[voipbl](#voipbl)|10350|10759|24|0.2%|0.0%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14595|14595|23|0.1%|0.0%|
[openbl_1d](#openbl_1d)|141|141|17|12.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|620|620|17|2.7%|0.0%|
[palevo](#palevo)|13|13|12|92.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|10|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|7|4.4%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|6|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[malc0de](#malc0de)|397|397|4|1.0%|0.0%|
[et_tor](#et_tor)|6360|6360|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6558|6558|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6535|6535|4|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1437|1437|4|0.2%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[ciarmy](#ciarmy)|339|339|2|0.5%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|97|97|2|2.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|426|426|1|0.2%|0.0%|

## et_botcc

[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)

Source is downloaded from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules).

The last time downloaded was found to be dated: Mon Jun  1 04:30:01 UTC 2015.

The ipset `et_botcc` has **505** entries, **505** unique IPs.

The following table shows the overlaps of `et_botcc` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_botcc`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_botcc`.
- ` this % ` is the percentage **of this ipset (`et_botcc`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|78|0.0%|15.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|41|0.0%|8.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|22|0.0%|4.3%|
[alienvault_reputation](#alienvault_reputation)|178819|178819|3|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[et_block](#et_block)|997|18338381|1|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|97|97|1|1.0%|0.1%|

## et_compromised

[EmergingThreats.net compromised hosts](http://doc.emergingthreats.net/bin/view/Main/CompromisedHost) - (this seems to be based on bruteforceblocker)

Source is downloaded from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt).

The last time downloaded was found to be dated: Mon Jun  1 04:30:09 UTC 2015.

The ipset `et_compromised` has **2191** entries, **2191** unique IPs.

The following table shows the overlaps of `et_compromised` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_compromised`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_compromised`.
- ` this % ` is the percentage **of this ipset (`et_compromised`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bruteforceblocker](#bruteforceblocker)|2178|2178|2157|99.0%|98.4%|
[alienvault_reputation](#alienvault_reputation)|178819|178819|1421|0.7%|64.8%|
[openbl_60d](#openbl_60d)|7581|7581|1319|17.3%|60.2%|
[openbl_30d](#openbl_30d)|3197|3197|1241|38.8%|56.6%|
[blocklist_de](#blocklist_de)|22462|22462|701|3.1%|31.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|1615|1615|685|42.4%|31.2%|
[shunlist](#shunlist)|1241|1241|520|41.9%|23.7%|
[openbl_7d](#openbl_7d)|901|901|515|57.1%|23.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|219|0.0%|9.9%|
[dshield](#dshield)|20|5120|117|2.2%|5.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|116|0.0%|5.2%|
[et_block](#et_block)|997|18338381|104|0.0%|4.7%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|102|0.0%|4.6%|
[openbl_1d](#openbl_1d)|141|141|77|54.6%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|62|0.0%|2.8%|
[blocklist_de_mail](#blocklist_de_mail)|14595|14595|12|0.0%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|620|620|10|1.6%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|7|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|4|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7099|7099|3|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|3|0.0%|0.1%|
[proxz](#proxz)|459|459|2|0.4%|0.0%|
[zeus_badips](#zeus_badips)|231|231|1|0.4%|0.0%|
[zeus](#zeus)|267|267|1|0.3%|0.0%|
[xroxy](#xroxy)|2016|2016|1|0.0%|0.0%|
[voipbl](#voipbl)|10350|10759|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|199|199|1|0.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3202|3202|1|0.0%|0.0%|

## et_tor

[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs

Source is downloaded from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules).

The last time downloaded was found to be dated: Mon Jun  1 04:30:10 UTC 2015.

The ipset `et_tor` has **6360** entries, **6360** unique IPs.

The following table shows the overlaps of `et_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_tor`.
- ` this % ` is the percentage **of this ipset (`et_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6535|6535|5974|91.4%|93.9%|
[dm_tor](#dm_tor)|6558|6558|5967|90.9%|93.8%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|1073|17.1%|16.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|628|0.0%|9.8%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|622|0.6%|9.7%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|480|1.5%|7.5%|
[stopforumspam_1d](#stopforumspam_1d)|7099|7099|293|4.1%|4.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|191|0.0%|3.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|169|45.4%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|167|0.0%|2.6%|
[alienvault_reputation](#alienvault_reputation)|178819|178819|45|0.0%|0.7%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[openbl_60d](#openbl_60d)|7581|7581|19|0.2%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|19|0.0%|0.2%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[php_harvesters](#php_harvesters)|257|257|6|2.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5512|5512|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[nixspam](#nixspam)|23859|23859|4|0.0%|0.0%|
[et_block](#et_block)|997|18338381|4|0.0%|0.0%|
[xroxy](#xroxy)|2016|2016|3|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14595|14595|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|22462|22462|3|0.0%|0.0%|
[voipbl](#voipbl)|10350|10759|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2030|2030|2|0.0%|0.0%|
[shunlist](#shunlist)|1241|1241|1|0.0%|0.0%|
[proxz](#proxz)|459|459|1|0.2%|0.0%|
[proxyrss](#proxyrss)|1596|1596|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Mon Jun  1 19:27:15 UTC 2015.

The ipset `feodo` has **77** entries, **77** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|997|18338381|71|0.0%|92.2%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|58|0.9%|75.3%|
[sslbl](#sslbl)|364|364|31|8.5%|40.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|7|0.0%|9.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|3|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|3.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|1.2%|
[alienvault_reputation](#alienvault_reputation)|178819|178819|1|0.0%|1.2%|

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
[et_block](#et_block)|997|18338381|20480|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|890|0.2%|0.0%|
[voipbl](#voipbl)|10350|10759|319|2.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|33|2.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|9|0.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|1|0.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|178819|178819|14|0.0%|0.0%|
[nixspam](#nixspam)|23859|23859|12|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.0%|
[et_block](#et_block)|997|18338381|10|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|6|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|5|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7099|7099|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[xroxy](#xroxy)|2016|2016|3|0.1%|0.0%|
[blocklist_de](#blocklist_de)|22462|22462|3|0.0%|0.0%|
[voipbl](#voipbl)|10350|10759|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5512|5512|1|0.0%|0.0%|
[proxz](#proxz)|459|459|1|0.2%|0.0%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14595|14595|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1437|1437|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3202|3202|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|1|0.0%|0.0%|

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
[spamhaus_drop](#spamhaus_drop)|652|18338560|7079936|38.6%|77.1%|
[et_block](#et_block)|997|18338381|7079936|38.6%|77.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2526625|0.7%|27.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|904796|0.1%|9.8%|
[fullbogons](#fullbogons)|3639|670579672|565248|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|145472|0.1%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1036|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|732|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178819|178819|518|0.2%|0.0%|
[nixspam](#nixspam)|23859|23859|185|0.7%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|182|0.5%|0.0%|
[blocklist_de](#blocklist_de)|22462|22462|36|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7099|7099|30|0.4%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3202|3202|28|0.8%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|27|2.1%|0.0%|
[openbl_60d](#openbl_60d)|7581|7581|19|0.2%|0.0%|
[openbl_30d](#openbl_30d)|3197|3197|14|0.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|11|0.1%|0.0%|
[zeus_badips](#zeus_badips)|231|231|10|4.3%|0.0%|
[zeus](#zeus)|267|267|10|3.7%|0.0%|
[openbl_7d](#openbl_7d)|901|901|10|1.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[et_compromised](#et_compromised)|2191|2191|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|5|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1615|1615|5|0.3%|0.0%|
[shunlist](#shunlist)|1241|1241|3|0.2%|0.0%|
[et_tor](#et_tor)|6360|6360|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6558|6558|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6535|6535|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|3|1.8%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14595|14595|3|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|620|620|2|0.3%|0.0%|
[voipbl](#voipbl)|10350|10759|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.0%|
[openbl_1d](#openbl_1d)|141|141|1|0.7%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|

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
[et_block](#et_block)|997|18338381|2272672|12.3%|0.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2272266|12.3%|0.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1354348|0.9%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904796|9.8%|0.1%|
[fullbogons](#fullbogons)|3639|670579672|234359|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|33155|7.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|13248|3.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178819|178819|4437|2.4%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|1523|1.6%|0.0%|
[blocklist_de](#blocklist_de)|22462|22462|1428|6.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14595|14595|1323|9.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|1318|9.5%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|563|1.7%|0.0%|
[nixspam](#nixspam)|23859|23859|482|2.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|406|0.8%|0.0%|
[voipbl](#voipbl)|10350|10759|295|2.7%|0.0%|
[openbl_60d](#openbl_60d)|7581|7581|172|2.2%|0.0%|
[dm_tor](#dm_tor)|6558|6558|168|2.5%|0.0%|
[et_tor](#et_tor)|6360|6360|167|2.6%|0.0%|
[bm_tor](#bm_tor)|6535|6535|167|2.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7099|7099|155|2.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5512|5512|118|2.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|97|6.6%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|68|1.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2030|2030|68|3.3%|0.0%|
[openbl_30d](#openbl_30d)|3197|3197|68|2.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|66|5.1%|0.0%|
[et_compromised](#et_compromised)|2191|2191|62|2.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|62|2.8%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|58|8.6%|0.0%|
[xroxy](#xroxy)|2016|2016|57|2.8%|0.0%|
[et_botcc](#et_botcc)|505|505|41|8.1%|0.0%|
[proxyrss](#proxyrss)|1596|1596|35|2.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3202|3202|35|1.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1615|1615|29|1.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1437|1437|27|1.8%|0.0%|
[shunlist](#shunlist)|1241|1241|25|2.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|17|4.5%|0.0%|
[proxz](#proxz)|459|459|16|3.4%|0.0%|
[openbl_7d](#openbl_7d)|901|901|15|1.6%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|426|426|15|3.5%|0.0%|
[malc0de](#malc0de)|397|397|12|3.0%|0.0%|
[ciarmy](#ciarmy)|339|339|10|2.9%|0.0%|
[php_dictionary](#php_dictionary)|433|433|9|2.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|620|620|8|1.2%|0.0%|
[zeus](#zeus)|267|267|7|2.6%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.0%|
[php_commenters](#php_commenters)|281|281|5|1.7%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[zeus_badips](#zeus_badips)|231|231|4|1.7%|0.0%|
[sslbl](#sslbl)|364|364|3|0.8%|0.0%|
[feodo](#feodo)|77|77|3|3.8%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|199|199|3|1.5%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|97|97|2|2.0%|0.0%|
[openbl_1d](#openbl_1d)|141|141|1|0.7%|0.0%|

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
[et_block](#et_block)|997|18338381|8598823|46.8%|2.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|8598042|46.8%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2830140|2.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2526625|27.5%|0.7%|
[fullbogons](#fullbogons)|3639|670579672|248319|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|33368|7.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178819|178819|8138|4.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|7733|2.2%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|2477|2.6%|0.0%|
[blocklist_de](#blocklist_de)|22462|22462|1456|6.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14595|14595|1119|7.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|1064|7.6%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|938|2.9%|0.0%|
[nixspam](#nixspam)|23859|23859|637|2.6%|0.0%|
[voipbl](#voipbl)|10350|10759|431|4.0%|0.0%|
[openbl_60d](#openbl_60d)|7581|7581|342|4.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7099|7099|242|3.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|230|0.4%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3202|3202|201|6.2%|0.0%|
[et_tor](#et_tor)|6360|6360|191|3.0%|0.0%|
[bm_tor](#bm_tor)|6535|6535|190|2.9%|0.0%|
[dm_tor](#dm_tor)|6558|6558|189|2.8%|0.0%|
[openbl_30d](#openbl_30d)|3197|3197|177|5.5%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5512|5512|173|3.1%|0.0%|
[et_compromised](#et_compromised)|2191|2191|116|5.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|116|5.3%|0.0%|
[xroxy](#xroxy)|2016|2016|99|4.9%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|97|1.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1615|1615|86|5.3%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2030|2030|82|4.0%|0.0%|
[shunlist](#shunlist)|1241|1241|69|5.5%|0.0%|
[proxyrss](#proxyrss)|1596|1596|64|4.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|45|3.0%|0.0%|
[openbl_7d](#openbl_7d)|901|901|41|4.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|620|620|35|5.6%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1437|1437|32|2.2%|0.0%|
[php_spammers](#php_spammers)|417|417|31|7.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|28|4.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|26|2.0%|0.0%|
[malc0de](#malc0de)|397|397|25|6.2%|0.0%|
[proxz](#proxz)|459|459|22|4.7%|0.0%|
[et_botcc](#et_botcc)|505|505|22|4.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|21|5.6%|0.0%|
[ciarmy](#ciarmy)|339|339|16|4.7%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|426|426|13|3.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|10|2.3%|0.0%|
[zeus](#zeus)|267|267|9|3.3%|0.0%|
[php_commenters](#php_commenters)|281|281|9|3.2%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|97|97|9|9.2%|0.0%|
[zeus_badips](#zeus_badips)|231|231|8|3.4%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|7|4.4%|0.0%|
[sslbl](#sslbl)|364|364|6|1.6%|0.0%|
[openbl_1d](#openbl_1d)|141|141|5|3.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|199|199|4|2.0%|0.0%|
[feodo](#feodo)|77|77|3|3.8%|0.0%|
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
[fullbogons](#fullbogons)|3639|670579672|4233775|0.6%|3.0%|
[bogons](#bogons)|13|592708608|4194304|0.7%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2830140|0.8%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1354348|0.1%|0.9%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|270785|64.2%|0.1%|
[et_block](#et_block)|997|18338381|196186|1.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|195904|1.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[alienvault_reputation](#alienvault_reputation)|178819|178819|14383|8.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|9231|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|5946|6.4%|0.0%|
[blocklist_de](#blocklist_de)|22462|22462|2803|12.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14595|14595|2257|15.4%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|2200|15.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|2107|6.7%|0.0%|
[voipbl](#voipbl)|10350|10759|1591|14.7%|0.0%|
[nixspam](#nixspam)|23859|23859|1517|6.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1172|2.4%|0.0%|
[openbl_60d](#openbl_60d)|7581|7581|716|9.4%|0.0%|
[dm_tor](#dm_tor)|6558|6558|631|9.6%|0.0%|
[bm_tor](#bm_tor)|6535|6535|631|9.6%|0.0%|
[et_tor](#et_tor)|6360|6360|628|9.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7099|7099|498|7.0%|0.0%|
[openbl_30d](#openbl_30d)|3197|3197|283|8.8%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[et_compromised](#et_compromised)|2191|2191|219|9.9%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|219|10.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|211|3.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3202|3202|198|6.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1615|1615|190|11.7%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5512|5512|158|2.8%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|146|11.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|125|33.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|110|7.5%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1437|1437|106|7.3%|0.0%|
[shunlist](#shunlist)|1241|1241|98|7.8%|0.0%|
[openbl_7d](#openbl_7d)|901|901|90|9.9%|0.0%|
[xroxy](#xroxy)|2016|2016|84|4.1%|0.0%|
[et_botcc](#et_botcc)|505|505|78|15.4%|0.0%|
[malc0de](#malc0de)|397|397|68|17.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|426|426|59|13.8%|0.0%|
[ciarmy](#ciarmy)|339|339|54|15.9%|0.0%|
[proxyrss](#proxyrss)|1596|1596|51|3.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|51|7.5%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2030|2030|47|2.3%|0.0%|
[proxz](#proxz)|459|459|45|9.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|620|620|43|6.9%|0.0%|
[php_spammers](#php_spammers)|417|417|26|6.2%|0.0%|
[sslbl](#sslbl)|364|364|24|6.5%|0.0%|
[php_dictionary](#php_dictionary)|433|433|24|5.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|199|199|20|10.0%|0.0%|
[zeus](#zeus)|267|267|19|7.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|16|10.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|15|5.8%|0.0%|
[php_commenters](#php_commenters)|281|281|15|5.3%|0.0%|
[zeus_badips](#zeus_badips)|231|231|14|6.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|97|97|14|14.4%|0.0%|
[openbl_1d](#openbl_1d)|141|141|11|7.8%|0.0%|
[feodo](#feodo)|77|77|7|9.0%|0.0%|
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
[xroxy](#xroxy)|2016|2016|13|0.6%|1.9%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|11|0.0%|1.6%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|11|0.0%|1.6%|
[ri_web_proxies](#ri_web_proxies)|5512|5512|10|0.1%|1.4%|
[proxyrss](#proxyrss)|1596|1596|10|0.6%|1.4%|
[stopforumspam_1d](#stopforumspam_1d)|7099|7099|6|0.0%|0.8%|
[ri_connect_proxies](#ri_connect_proxies)|2030|2030|6|0.2%|0.8%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.2%|
[et_block](#et_block)|997|18338381|2|0.0%|0.2%|
[blocklist_de](#blocklist_de)|22462|22462|2|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|1|0.0%|0.1%|
[proxz](#proxz)|459|459|1|0.2%|0.1%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.1%|
[nixspam](#nixspam)|23859|23859|1|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|14595|14595|1|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3202|3202|1|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|178819|178819|1|0.0%|0.1%|

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
[et_block](#et_block)|997|18338381|1040|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1037|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1036|0.0%|0.3%|
[fullbogons](#fullbogons)|3639|670579672|890|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|178819|178819|288|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|44|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|25|1.9%|0.0%|
[dm_tor](#dm_tor)|6558|6558|21|0.3%|0.0%|
[bm_tor](#bm_tor)|6535|6535|21|0.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|19|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|19|1.3%|0.0%|
[et_tor](#et_tor)|6360|6360|19|0.2%|0.0%|
[nixspam](#nixspam)|23859|23859|17|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|13|0.2%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7099|7099|11|0.1%|0.0%|
[blocklist_de](#blocklist_de)|22462|22462|9|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7581|7581|6|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5512|5512|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|5|1.3%|0.0%|
[voipbl](#voipbl)|10350|10759|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3197|3197|4|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|4|0.0%|0.0%|
[malc0de](#malc0de)|397|397|3|0.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1437|1437|3|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3202|3202|3|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1615|1615|2|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|97|97|2|2.0%|0.0%|
[zeus_badips](#zeus_badips)|231|231|1|0.4%|0.0%|
[zeus](#zeus)|267|267|1|0.3%|0.0%|
[xroxy](#xroxy)|2016|2016|1|0.0%|0.0%|
[sslbl](#sslbl)|364|364|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|1|0.0%|0.0%|
[shunlist](#shunlist)|1241|1241|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|
[openbl_7d](#openbl_7d)|901|901|1|0.1%|0.0%|
[feodo](#feodo)|77|77|1|1.2%|0.0%|
[et_compromised](#et_compromised)|2191|2191|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|426|426|1|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|1|0.0%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14595|14595|1|0.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|178819|178819|8|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|6|0.0%|0.4%|
[et_block](#et_block)|997|18338381|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|3|0.2%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|2|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7581|7581|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|3197|3197|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7099|7099|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5512|5512|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|901|901|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2191|2191|1|0.0%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|426|426|1|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1615|1615|1|0.0%|0.0%|
[blocklist_de](#blocklist_de)|22462|22462|1|0.0%|0.0%|

## malc0de

[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days

Source is downloaded from [this link](http://malc0de.com/bl/IP_Blacklist.txt).

The last time downloaded was found to be dated: Mon Jun  1 13:17:02 UTC 2015.

The ipset `malc0de` has **397** entries, **397** unique IPs.

The following table shows the overlaps of `malc0de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `malc0de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `malc0de`.
- ` this % ` is the percentage **of this ipset (`malc0de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|68|0.0%|17.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|25|0.0%|6.2%|
[cleanmx_viruses](#cleanmx_viruses)|426|426|13|3.0%|3.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|12|0.0%|3.0%|
[alienvault_reputation](#alienvault_reputation)|178819|178819|12|0.0%|3.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|4|0.0%|1.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|4|0.3%|1.0%|
[et_block](#et_block)|997|18338381|4|0.0%|1.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.7%|
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
[et_block](#et_block)|997|18338381|29|0.0%|2.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.1%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|26|0.4%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|26|0.0%|2.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|25|0.0%|1.9%|
[fullbogons](#fullbogons)|3639|670579672|9|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|178819|178819|6|0.0%|0.4%|
[malc0de](#malc0de)|397|397|4|1.0%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|3|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|2|0.0%|0.1%|
[cleanmx_viruses](#cleanmx_viruses)|426|426|2|0.4%|0.1%|
[nixspam](#nixspam)|23859|23859|1|0.0%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|

## maxmind_proxy_fraud

[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.

Source is downloaded from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list).

The last time downloaded was found to be dated: Mon Jun  1 18:54:24 UTC 2015.

The ipset `maxmind_proxy_fraud` has **372** entries, **372** unique IPs.

The following table shows the overlaps of `maxmind_proxy_fraud` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `maxmind_proxy_fraud`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `maxmind_proxy_fraud`.
- ` this % ` is the percentage **of this ipset (`maxmind_proxy_fraud`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|234|0.2%|62.9%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|201|0.6%|54.0%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|176|2.8%|47.3%|
[dm_tor](#dm_tor)|6558|6558|171|2.6%|45.9%|
[bm_tor](#bm_tor)|6535|6535|171|2.6%|45.9%|
[et_tor](#et_tor)|6360|6360|169|2.6%|45.4%|
[stopforumspam_1d](#stopforumspam_1d)|7099|7099|158|2.2%|42.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|125|0.0%|33.6%|
[php_commenters](#php_commenters)|281|281|28|9.9%|7.5%|
[alienvault_reputation](#alienvault_reputation)|178819|178819|25|0.0%|6.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|21|0.0%|5.6%|
[openbl_60d](#openbl_60d)|7581|7581|18|0.2%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|17|0.0%|4.5%|
[php_harvesters](#php_harvesters)|257|257|6|2.3%|1.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|1.3%|
[ri_web_proxies](#ri_web_proxies)|5512|5512|4|0.0%|1.0%|
[php_spammers](#php_spammers)|417|417|4|0.9%|1.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|1.0%|
[shunlist](#shunlist)|1241|1241|2|0.1%|0.5%|
[xroxy](#xroxy)|2016|2016|1|0.0%|0.2%|
[voipbl](#voipbl)|10350|10759|1|0.0%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2030|2030|1|0.0%|0.2%|
[nixspam](#nixspam)|23859|23859|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|14595|14595|1|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|1|0.0%|0.2%|
[blocklist_de](#blocklist_de)|22462|22462|1|0.0%|0.2%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Mon Jun  1 19:15:02 UTC 2015.

The ipset `nixspam` has **23859** entries, **23859** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1517|0.0%|6.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|637|0.0%|2.6%|
[blocklist_de](#blocklist_de)|22462|22462|483|2.1%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|482|0.0%|2.0%|
[blocklist_de_mail](#blocklist_de_mail)|14595|14595|422|2.8%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|225|0.2%|0.9%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|185|0.0%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|185|0.0%|0.7%|
[et_block](#et_block)|997|18338381|185|0.0%|0.7%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|141|2.2%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|132|0.4%|0.5%|
[ri_web_proxies](#ri_web_proxies)|5512|5512|85|1.5%|0.3%|
[php_dictionary](#php_dictionary)|433|433|79|18.2%|0.3%|
[xroxy](#xroxy)|2016|2016|64|3.1%|0.2%|
[php_spammers](#php_spammers)|417|417|62|14.8%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7099|7099|52|0.7%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3202|3202|43|1.3%|0.1%|
[alienvault_reputation](#alienvault_reputation)|178819|178819|40|0.0%|0.1%|
[proxz](#proxz)|459|459|18|3.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|17|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|14|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1437|1437|13|0.9%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|12|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7581|7581|9|0.1%|0.0%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2030|2030|7|0.3%|0.0%|
[proxyrss](#proxyrss)|1596|1596|6|0.3%|0.0%|
[bm_tor](#bm_tor)|6535|6535|5|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|4|1.5%|0.0%|
[et_tor](#et_tor)|6360|6360|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6558|6558|4|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|3|0.0%|0.0%|
[shunlist](#shunlist)|1241|1241|3|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|620|620|3|0.4%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|2|1.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|199|199|2|1.0%|0.0%|
[voipbl](#voipbl)|10350|10759|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1615|1615|1|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|97|97|1|1.0%|0.0%|

## openbl_1d

[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_1days.txt).

The last time downloaded was found to be dated: Mon Jun  1 18:32:00 UTC 2015.

The ipset `openbl_1d` has **141** entries, **141** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7581|7581|136|1.7%|96.4%|
[openbl_30d](#openbl_30d)|3197|3197|136|4.2%|96.4%|
[alienvault_reputation](#alienvault_reputation)|178819|178819|135|0.0%|95.7%|
[openbl_7d](#openbl_7d)|901|901|134|14.8%|95.0%|
[blocklist_de](#blocklist_de)|22462|22462|117|0.5%|82.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|1615|1615|116|7.1%|82.2%|
[et_compromised](#et_compromised)|2191|2191|77|3.5%|54.6%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|77|3.5%|54.6%|
[shunlist](#shunlist)|1241|1241|71|5.7%|50.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|17|0.0%|12.0%|
[et_block](#et_block)|997|18338381|17|0.0%|12.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|17|10.6%|12.0%|
[dshield](#dshield)|20|5120|16|0.3%|11.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|11|0.0%|7.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|5|0.0%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1|0.0%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|14595|14595|1|0.0%|0.7%|
[blocklist_de_imap](#blocklist_de_imap)|620|620|1|0.1%|0.7%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt).

The last time downloaded was found to be dated: Mon Jun  1 15:42:00 UTC 2015.

The ipset `openbl_30d` has **3197** entries, **3197** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7581|7581|3197|42.1%|100.0%|
[alienvault_reputation](#alienvault_reputation)|178819|178819|3185|1.7%|99.6%|
[et_compromised](#et_compromised)|2191|2191|1241|56.6%|38.8%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|1235|56.7%|38.6%|
[openbl_7d](#openbl_7d)|901|901|901|100.0%|28.1%|
[blocklist_de](#blocklist_de)|22462|22462|755|3.3%|23.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|1615|1615|707|43.7%|22.1%|
[shunlist](#shunlist)|1241|1241|596|48.0%|18.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|283|0.0%|8.8%|
[et_block](#et_block)|997|18338381|206|0.0%|6.4%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|201|0.0%|6.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|177|0.0%|5.5%|
[dshield](#dshield)|20|5120|166|3.2%|5.1%|
[openbl_1d](#openbl_1d)|141|141|136|96.4%|4.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|68|0.0%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|14595|14595|43|0.2%|1.3%|
[blocklist_de_imap](#blocklist_de_imap)|620|620|33|5.3%|1.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|24|15.0%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|14|0.0%|0.4%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|6|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|4|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.1%|
[voipbl](#voipbl)|10350|10759|3|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|199|199|3|1.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|3|0.0%|0.0%|
[zeus](#zeus)|267|267|2|0.7%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|231|231|1|0.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7099|7099|1|0.0%|0.0%|
[ciarmy](#ciarmy)|339|339|1|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3202|3202|1|0.0%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt).

The last time downloaded was found to be dated: Mon Jun  1 15:42:00 UTC 2015.

The ipset `openbl_60d` has **7581** entries, **7581** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|178819|178819|7561|4.2%|99.7%|
[openbl_30d](#openbl_30d)|3197|3197|3197|100.0%|42.1%|
[et_compromised](#et_compromised)|2191|2191|1319|60.2%|17.3%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|1306|59.9%|17.2%|
[openbl_7d](#openbl_7d)|901|901|901|100.0%|11.8%|
[blocklist_de](#blocklist_de)|22462|22462|824|3.6%|10.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|1615|1615|755|46.7%|9.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|716|0.0%|9.4%|
[shunlist](#shunlist)|1241|1241|613|49.3%|8.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|342|0.0%|4.5%|
[et_block](#et_block)|997|18338381|245|0.0%|3.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|240|0.0%|3.1%|
[dshield](#dshield)|20|5120|193|3.7%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|172|0.0%|2.2%|
[openbl_1d](#openbl_1d)|141|141|136|96.4%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|54|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|14595|14595|49|0.3%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|620|620|37|5.9%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|27|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|27|16.9%|0.3%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|24|0.3%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7099|7099|21|0.2%|0.2%|
[dm_tor](#dm_tor)|6558|6558|20|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|19|0.0%|0.2%|
[et_tor](#et_tor)|6360|6360|19|0.2%|0.2%|
[bm_tor](#bm_tor)|6535|6535|19|0.2%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3202|3202|15|0.4%|0.1%|
[voipbl](#voipbl)|10350|10759|9|0.0%|0.1%|
[nixspam](#nixspam)|23859|23859|9|0.0%|0.1%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|6|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|6|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|199|199|4|2.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|3|0.0%|0.0%|
[zeus](#zeus)|267|267|2|0.7%|0.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|231|231|1|0.4%|0.0%|
[ciarmy](#ciarmy)|339|339|1|0.2%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt).

The last time downloaded was found to be dated: Mon Jun  1 15:42:00 UTC 2015.

The ipset `openbl_7d` has **901** entries, **901** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7581|7581|901|11.8%|100.0%|
[openbl_30d](#openbl_30d)|3197|3197|901|28.1%|100.0%|
[alienvault_reputation](#alienvault_reputation)|178819|178819|895|0.5%|99.3%|
[blocklist_de](#blocklist_de)|22462|22462|517|2.3%|57.3%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|516|23.6%|57.2%|
[et_compromised](#et_compromised)|2191|2191|515|23.5%|57.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|1615|1615|490|30.3%|54.3%|
[shunlist](#shunlist)|1241|1241|387|31.1%|42.9%|
[openbl_1d](#openbl_1d)|141|141|134|95.0%|14.8%|
[dshield](#dshield)|20|5120|101|1.9%|11.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|90|0.0%|9.9%|
[et_block](#et_block)|997|18338381|89|0.0%|9.8%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|86|0.0%|9.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|41|0.0%|4.5%|
[blocklist_de_mail](#blocklist_de_mail)|14595|14595|26|0.1%|2.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|23|14.4%|2.5%|
[blocklist_de_imap](#blocklist_de_imap)|620|620|19|3.0%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|15|0.0%|1.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|1.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|5|0.0%|0.5%|
[voipbl](#voipbl)|10350|10759|3|0.0%|0.3%|
[zeus](#zeus)|267|267|1|0.3%|0.1%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.1%|
[ciarmy](#ciarmy)|339|339|1|0.2%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|199|199|1|0.5%|0.1%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Mon Jun  1 19:27:11 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|997|18338381|12|0.0%|92.3%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|11|0.1%|84.6%|
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
[stopforumspam_1d](#stopforumspam_1d)|7099|7099|106|1.4%|37.7%|
[blocklist_de](#blocklist_de)|22462|22462|63|0.2%|22.4%|
[blocklist_de_bots](#blocklist_de_bots)|3202|3202|52|1.6%|18.5%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|33|0.5%|11.7%|
[php_spammers](#php_spammers)|417|417|32|7.6%|11.3%|
[et_tor](#et_tor)|6360|6360|29|0.4%|10.3%|
[dm_tor](#dm_tor)|6558|6558|29|0.4%|10.3%|
[bm_tor](#bm_tor)|6535|6535|29|0.4%|10.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|29|18.2%|10.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|28|7.5%|9.9%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|24|0.0%|8.5%|
[et_block](#et_block)|997|18338381|24|0.0%|8.5%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|24|0.1%|8.5%|
[php_dictionary](#php_dictionary)|433|433|22|5.0%|7.8%|
[blocklist_de_mail](#blocklist_de_mail)|14595|14595|17|0.1%|6.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|5.3%|
[alienvault_reputation](#alienvault_reputation)|178819|178819|13|0.0%|4.6%|
[ri_web_proxies](#ri_web_proxies)|5512|5512|11|0.1%|3.9%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.2%|
[openbl_60d](#openbl_60d)|7581|7581|8|0.1%|2.8%|
[nixspam](#nixspam)|23859|23859|8|0.0%|2.8%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|7|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|1.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1437|1437|5|0.3%|1.7%|
[xroxy](#xroxy)|2016|2016|3|0.1%|1.0%|
[proxz](#proxz)|459|459|3|0.6%|1.0%|
[zeus_badips](#zeus_badips)|231|231|1|0.4%|0.3%|
[zeus](#zeus)|267|267|1|0.3%|0.3%|
[proxyrss](#proxyrss)|1596|1596|1|0.0%|0.3%|
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
[nixspam](#nixspam)|23859|23859|79|0.3%|18.2%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|68|0.2%|15.7%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|42|0.6%|9.6%|
[blocklist_de](#blocklist_de)|22462|22462|39|0.1%|9.0%|
[ri_web_proxies](#ri_web_proxies)|5512|5512|33|0.5%|7.6%|
[xroxy](#xroxy)|2016|2016|24|1.1%|5.5%|
[stopforumspam_1d](#stopforumspam_1d)|7099|7099|24|0.3%|5.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|24|0.0%|5.5%|
[php_commenters](#php_commenters)|281|281|22|7.8%|5.0%|
[blocklist_de_bots](#blocklist_de_bots)|3202|3202|22|0.6%|5.0%|
[blocklist_de_mail](#blocklist_de_mail)|14595|14595|17|0.1%|3.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|10|0.0%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|9|0.0%|2.0%|
[proxz](#proxz)|459|459|7|1.5%|1.6%|
[alienvault_reputation](#alienvault_reputation)|178819|178819|7|0.0%|1.6%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|4|0.0%|0.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.9%|
[et_tor](#et_tor)|6360|6360|4|0.0%|0.9%|
[et_block](#et_block)|997|18338381|4|0.0%|0.9%|
[dm_tor](#dm_tor)|6558|6558|4|0.0%|0.9%|
[bm_tor](#bm_tor)|6535|6535|4|0.0%|0.9%|
[ri_connect_proxies](#ri_connect_proxies)|2030|2030|3|0.1%|0.6%|
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
[stopforumspam_1d](#stopforumspam_1d)|7099|7099|32|0.4%|12.4%|
[blocklist_de](#blocklist_de)|22462|22462|25|0.1%|9.7%|
[blocklist_de_bots](#blocklist_de_bots)|3202|3202|20|0.6%|7.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|5.8%|
[php_commenters](#php_commenters)|281|281|9|3.2%|3.5%|
[alienvault_reputation](#alienvault_reputation)|178819|178819|9|0.0%|3.5%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|8|0.1%|3.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|7|0.0%|2.7%|
[dm_tor](#dm_tor)|6558|6558|7|0.1%|2.7%|
[bm_tor](#bm_tor)|6535|6535|7|0.1%|2.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|6|1.6%|2.3%|
[et_tor](#et_tor)|6360|6360|6|0.0%|2.3%|
[nixspam](#nixspam)|23859|23859|4|0.0%|1.5%|
[blocklist_de_ftp](#blocklist_de_ftp)|199|199|3|1.5%|1.1%|
[xroxy](#xroxy)|2016|2016|2|0.0%|0.7%|
[openbl_60d](#openbl_60d)|7581|7581|2|0.0%|0.7%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|14595|14595|2|0.0%|0.7%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|1|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|1|0.0%|0.3%|
[ri_web_proxies](#ri_web_proxies)|5512|5512|1|0.0%|0.3%|
[proxyrss](#proxyrss)|1596|1596|1|0.0%|0.3%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.3%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|
[fullbogons](#fullbogons)|3639|670579672|1|0.0%|0.3%|
[et_block](#et_block)|997|18338381|1|0.0%|0.3%|
[bogons](#bogons)|13|592708608|1|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|1|0.6%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|1|0.0%|0.3%|

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
[nixspam](#nixspam)|23859|23859|62|0.2%|14.8%|
[blocklist_de](#blocklist_de)|22462|22462|41|0.1%|9.8%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|34|0.5%|8.1%|
[php_commenters](#php_commenters)|281|281|32|11.3%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|31|0.0%|7.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|26|0.0%|6.2%|
[ri_web_proxies](#ri_web_proxies)|5512|5512|25|0.4%|5.9%|
[stopforumspam_1d](#stopforumspam_1d)|7099|7099|21|0.2%|5.0%|
[blocklist_de_mail](#blocklist_de_mail)|14595|14595|20|0.1%|4.7%|
[xroxy](#xroxy)|2016|2016|18|0.8%|4.3%|
[blocklist_de_bots](#blocklist_de_bots)|3202|3202|15|0.4%|3.5%|
[proxz](#proxz)|459|459|7|1.5%|1.6%|
[et_tor](#et_tor)|6360|6360|6|0.0%|1.4%|
[dm_tor](#dm_tor)|6558|6558|6|0.0%|1.4%|
[bm_tor](#bm_tor)|6535|6535|6|0.0%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|1.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1437|1437|5|0.3%|1.1%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|5|0.0%|1.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|4|2.5%|0.9%|
[alienvault_reputation](#alienvault_reputation)|178819|178819|3|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|2|0.0%|0.4%|
[ri_connect_proxies](#ri_connect_proxies)|2030|2030|2|0.0%|0.4%|
[proxyrss](#proxyrss)|1596|1596|2|0.1%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[et_block](#et_block)|997|18338381|2|0.0%|0.4%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1615|1615|1|0.0%|0.2%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Mon Jun  1 17:11:22 UTC 2015.

The ipset `proxyrss` has **1596** entries, **1596** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|738|0.8%|46.2%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|630|2.0%|39.4%|
[ri_web_proxies](#ri_web_proxies)|5512|5512|584|10.5%|36.5%|
[xroxy](#xroxy)|2016|2016|456|22.6%|28.5%|
[stopforumspam_1d](#stopforumspam_1d)|7099|7099|428|6.0%|26.8%|
[blocklist_de_bots](#blocklist_de_bots)|3202|3202|234|7.3%|14.6%|
[blocklist_de](#blocklist_de)|22462|22462|234|1.0%|14.6%|
[ri_connect_proxies](#ri_connect_proxies)|2030|2030|172|8.4%|10.7%|
[proxz](#proxz)|459|459|147|32.0%|9.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|64|0.0%|4.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|51|0.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|35|0.0%|2.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|10|1.4%|0.6%|
[nixspam](#nixspam)|23859|23859|6|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|4|2.5%|0.2%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.1%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.0%|
[et_tor](#et_tor)|6360|6360|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6558|6558|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6535|6535|1|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178819|178819|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Mon Jun  1 17:11:28 UTC 2015.

The ipset `proxz` has **459** entries, **459** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|273|0.2%|59.4%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|246|0.7%|53.5%|
[xroxy](#xroxy)|2016|2016|231|11.4%|50.3%|
[ri_web_proxies](#ri_web_proxies)|5512|5512|197|3.5%|42.9%|
[proxyrss](#proxyrss)|1596|1596|147|9.2%|32.0%|
[stopforumspam_1d](#stopforumspam_1d)|7099|7099|93|1.3%|20.2%|
[blocklist_de](#blocklist_de)|22462|22462|93|0.4%|20.2%|
[blocklist_de_bots](#blocklist_de_bots)|3202|3202|82|2.5%|17.8%|
[ri_connect_proxies](#ri_connect_proxies)|2030|2030|70|3.4%|15.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|45|0.0%|9.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|22|0.0%|4.7%|
[nixspam](#nixspam)|23859|23859|18|0.0%|3.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|16|0.0%|3.4%|
[blocklist_de_mail](#blocklist_de_mail)|14595|14595|10|0.0%|2.1%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|7|0.1%|1.5%|
[php_spammers](#php_spammers)|417|417|7|1.6%|1.5%|
[php_dictionary](#php_dictionary)|433|433|7|1.6%|1.5%|
[php_commenters](#php_commenters)|281|281|3|1.0%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|3|1.8%|0.6%|
[et_compromised](#et_compromised)|2191|2191|2|0.0%|0.4%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|2|0.0%|0.4%|
[alienvault_reputation](#alienvault_reputation)|178819|178819|2|0.0%|0.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.2%|
[et_tor](#et_tor)|6360|6360|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1615|1615|1|0.0%|0.2%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Mon Jun  1 14:51:06 UTC 2015.

The ipset `ri_connect_proxies` has **2030** entries, **2030** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|1191|1.2%|58.6%|
[ri_web_proxies](#ri_web_proxies)|5512|5512|827|15.0%|40.7%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|698|2.2%|34.3%|
[xroxy](#xroxy)|2016|2016|317|15.7%|15.6%|
[proxyrss](#proxyrss)|1596|1596|172|10.7%|8.4%|
[stopforumspam_1d](#stopforumspam_1d)|7099|7099|149|2.0%|7.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|82|0.0%|4.0%|
[proxz](#proxz)|459|459|70|15.2%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|68|0.0%|3.3%|
[blocklist_de](#blocklist_de)|22462|22462|59|0.2%|2.9%|
[blocklist_de_bots](#blocklist_de_bots)|3202|3202|57|1.7%|2.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|47|0.0%|2.3%|
[nixspam](#nixspam)|23859|23859|7|0.0%|0.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.2%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|3|0.0%|0.1%|
[php_dictionary](#php_dictionary)|433|433|3|0.6%|0.1%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[et_tor](#et_tor)|6360|6360|2|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178819|178819|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[dm_tor](#dm_tor)|6558|6558|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6535|6535|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14595|14595|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1437|1437|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Mon Jun  1 17:32:46 UTC 2015.

The ipset `ri_web_proxies` has **5512** entries, **5512** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|2683|2.9%|48.6%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|1757|5.6%|31.8%|
[ri_connect_proxies](#ri_connect_proxies)|2030|2030|827|40.7%|15.0%|
[xroxy](#xroxy)|2016|2016|820|40.6%|14.8%|
[proxyrss](#proxyrss)|1596|1596|584|36.5%|10.5%|
[stopforumspam_1d](#stopforumspam_1d)|7099|7099|541|7.6%|9.8%|
[blocklist_de](#blocklist_de)|22462|22462|359|1.5%|6.5%|
[blocklist_de_bots](#blocklist_de_bots)|3202|3202|331|10.3%|6.0%|
[proxz](#proxz)|459|459|197|42.9%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|173|0.0%|3.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|158|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|118|0.0%|2.1%|
[nixspam](#nixspam)|23859|23859|85|0.3%|1.5%|
[php_dictionary](#php_dictionary)|433|433|33|7.6%|0.5%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|31|0.4%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|14595|14595|27|0.1%|0.4%|
[php_spammers](#php_spammers)|417|417|25|5.9%|0.4%|
[php_commenters](#php_commenters)|281|281|11|3.9%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|10|1.4%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.0%|
[et_tor](#et_tor)|6360|6360|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6558|6558|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6535|6535|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|3|1.8%|0.0%|
[alienvault_reputation](#alienvault_reputation)|178819|178819|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1437|1437|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Mon Jun  1 18:30:03 UTC 2015.

The ipset `shunlist` has **1241** entries, **1241** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|178819|178819|1229|0.6%|99.0%|
[openbl_60d](#openbl_60d)|7581|7581|613|8.0%|49.3%|
[openbl_30d](#openbl_30d)|3197|3197|596|18.6%|48.0%|
[et_compromised](#et_compromised)|2191|2191|520|23.7%|41.9%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|519|23.8%|41.8%|
[blocklist_de](#blocklist_de)|22462|22462|409|1.8%|32.9%|
[openbl_7d](#openbl_7d)|901|901|387|42.9%|31.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|1615|1615|374|23.1%|30.1%|
[dshield](#dshield)|20|5120|130|2.5%|10.4%|
[et_block](#et_block)|997|18338381|108|0.0%|8.7%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|102|0.0%|8.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|98|0.0%|7.8%|
[openbl_1d](#openbl_1d)|141|141|71|50.3%|5.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|69|0.0%|5.5%|
[sslbl](#sslbl)|364|364|43|11.8%|3.4%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|28|0.2%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|25|0.0%|2.0%|
[ciarmy](#ciarmy)|339|339|25|7.3%|2.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|18|11.3%|1.4%|
[voipbl](#voipbl)|10350|10759|11|0.1%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|14595|14595|7|0.0%|0.5%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|5|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|620|620|5|0.8%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|4|0.0%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|3|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|3|0.0%|0.2%|
[nixspam](#nixspam)|23859|23859|3|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1437|1437|2|0.1%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7099|7099|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_tor](#et_tor)|6360|6360|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6558|6558|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6535|6535|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|199|199|1|0.5%|0.0%|

## snort_ipfilter

[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)

Source is downloaded from [this link](http://labs.snort.org/feeds/ip-filter.blf).

The last time downloaded was found to be dated: Mon Jun  1 13:30:00 UTC 2015.

The ipset `snort_ipfilter` has **6251** entries, **6251** unique IPs.

The following table shows the overlaps of `snort_ipfilter` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `snort_ipfilter`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `snort_ipfilter`.
- ` this % ` is the percentage **of this ipset (`snort_ipfilter`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_tor](#et_tor)|6360|6360|1073|16.8%|17.1%|
[dm_tor](#dm_tor)|6558|6558|1055|16.0%|16.8%|
[bm_tor](#bm_tor)|6535|6535|1055|16.1%|16.8%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|718|0.7%|11.4%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|562|1.7%|8.9%|
[stopforumspam_1d](#stopforumspam_1d)|7099|7099|326|4.5%|5.2%|
[et_block](#et_block)|997|18338381|297|0.0%|4.7%|
[zeus](#zeus)|267|267|227|85.0%|3.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|211|0.0%|3.3%|
[zeus_badips](#zeus_badips)|231|231|203|87.8%|3.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|176|47.3%|2.8%|
[nixspam](#nixspam)|23859|23859|141|0.5%|2.2%|
[alienvault_reputation](#alienvault_reputation)|178819|178819|115|0.0%|1.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|97|0.0%|1.5%|
[blocklist_de](#blocklist_de)|22462|22462|83|0.3%|1.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|68|0.0%|1.0%|
[feodo](#feodo)|77|77|58|75.3%|0.9%|
[blocklist_de_mail](#blocklist_de_mail)|14595|14595|57|0.3%|0.9%|
[php_dictionary](#php_dictionary)|433|433|42|9.6%|0.6%|
[php_spammers](#php_spammers)|417|417|34|8.1%|0.5%|
[php_commenters](#php_commenters)|281|281|33|11.7%|0.5%|
[ri_web_proxies](#ri_web_proxies)|5512|5512|31|0.5%|0.4%|
[xroxy](#xroxy)|2016|2016|30|1.4%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|26|2.0%|0.4%|
[sslbl](#sslbl)|364|364|24|6.5%|0.3%|
[openbl_60d](#openbl_60d)|7581|7581|24|0.3%|0.3%|
[blocklist_de_bots](#blocklist_de_bots)|3202|3202|21|0.6%|0.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|19|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|13|0.0%|0.2%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|8|3.1%|0.1%|
[proxz](#proxz)|459|459|7|1.5%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|6|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|620|620|6|0.9%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|5|0.0%|0.0%|
[shunlist](#shunlist)|1241|1241|3|0.2%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2030|2030|3|0.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|426|426|3|0.7%|0.0%|
[openbl_30d](#openbl_30d)|3197|3197|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1615|1615|2|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1437|1437|2|0.1%|0.0%|
[openbl_7d](#openbl_7d)|901|901|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2191|2191|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|1|0.6%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|199|199|1|0.5%|0.0%|

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
[et_block](#et_block)|997|18338381|18333440|99.9%|99.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8598042|2.4%|46.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7079936|77.1%|38.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|2272266|0.2%|12.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|195904|0.1%|1.0%|
[fullbogons](#fullbogons)|3639|670579672|20480|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|178819|178819|1628|0.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|971|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|512|0.1%|0.0%|
[dshield](#dshield)|20|5120|512|10.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|342|1.0%|0.0%|
[openbl_60d](#openbl_60d)|7581|7581|240|3.1%|0.0%|
[openbl_30d](#openbl_30d)|3197|3197|201|6.2%|0.0%|
[nixspam](#nixspam)|23859|23859|185|0.7%|0.0%|
[blocklist_de](#blocklist_de)|22462|22462|173|0.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1615|1615|113|6.9%|0.0%|
[shunlist](#shunlist)|1241|1241|102|8.2%|0.0%|
[et_compromised](#et_compromised)|2191|2191|102|4.6%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|101|4.6%|0.0%|
[openbl_7d](#openbl_7d)|901|901|86|9.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7099|7099|82|1.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3202|3202|33|1.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|29|2.2%|0.0%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14595|14595|23|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|19|0.3%|0.0%|
[openbl_1d](#openbl_1d)|141|141|17|12.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|620|620|17|2.7%|0.0%|
[zeus_badips](#zeus_badips)|231|231|16|6.9%|0.0%|
[zeus](#zeus)|267|267|16|5.9%|0.0%|
[voipbl](#voipbl)|10350|10759|14|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|7|4.4%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[malc0de](#malc0de)|397|397|4|1.0%|0.0%|
[sslbl](#sslbl)|364|364|3|0.8%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1437|1437|3|0.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|3|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6360|6360|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6558|6558|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6535|6535|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|426|426|1|0.2%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|97|97|1|1.0%|0.0%|

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
[et_block](#et_block)|997|18338381|517|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|512|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|178819|178819|271|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|103|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|37|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7099|7099|7|0.0%|0.0%|
[php_commenters](#php_commenters)|281|281|7|2.4%|0.0%|
[blocklist_de](#blocklist_de)|22462|22462|7|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|6|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7581|7581|6|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3197|3197|6|0.1%|0.0%|
[zeus_badips](#zeus_badips)|231|231|5|2.1%|0.0%|
[zeus](#zeus)|267|267|5|1.8%|0.0%|
[shunlist](#shunlist)|1241|1241|5|0.4%|0.0%|
[openbl_7d](#openbl_7d)|901|901|5|0.5%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|4|2.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3202|3202|4|0.1%|0.0%|
[nixspam](#nixspam)|23859|23859|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14595|14595|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[malc0de](#malc0de)|397|397|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Mon Jun  1 19:15:06 UTC 2015.

The ipset `sslbl` has **364** entries, **364** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|178819|178819|51|0.0%|14.0%|
[shunlist](#shunlist)|1241|1241|43|3.4%|11.8%|
[feodo](#feodo)|77|77|31|40.2%|8.5%|
[et_block](#et_block)|997|18338381|30|0.0%|8.2%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|24|0.3%|6.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|24|0.0%|6.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|6|0.0%|1.6%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|3|0.0%|0.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Mon Jun  1 19:00:02 UTC 2015.

The ipset `stopforumspam_1d` has **7099** entries, **7099** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|4678|5.0%|65.8%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|4409|14.0%|62.1%|
[blocklist_de](#blocklist_de)|22462|22462|1423|6.3%|20.0%|
[blocklist_de_bots](#blocklist_de_bots)|3202|3202|1372|42.8%|19.3%|
[ri_web_proxies](#ri_web_proxies)|5512|5512|541|9.8%|7.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|498|0.0%|7.0%|
[proxyrss](#proxyrss)|1596|1596|428|26.8%|6.0%|
[xroxy](#xroxy)|2016|2016|341|16.9%|4.8%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|326|5.2%|4.5%|
[et_tor](#et_tor)|6360|6360|293|4.6%|4.1%|
[dm_tor](#dm_tor)|6558|6558|291|4.4%|4.0%|
[bm_tor](#bm_tor)|6535|6535|291|4.4%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|242|0.0%|3.4%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|158|42.4%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|155|0.0%|2.1%|
[ri_connect_proxies](#ri_connect_proxies)|2030|2030|149|7.3%|2.0%|
[php_commenters](#php_commenters)|281|281|106|37.7%|1.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|99|62.2%|1.3%|
[proxz](#proxz)|459|459|93|20.2%|1.3%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|82|0.0%|1.1%|
[et_block](#et_block)|997|18338381|82|0.0%|1.1%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|59|0.4%|0.8%|
[alienvault_reputation](#alienvault_reputation)|178819|178819|57|0.0%|0.8%|
[nixspam](#nixspam)|23859|23859|52|0.2%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|14595|14595|40|0.2%|0.5%|
[php_harvesters](#php_harvesters)|257|257|32|12.4%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|30|0.0%|0.4%|
[php_dictionary](#php_dictionary)|433|433|24|5.5%|0.3%|
[php_spammers](#php_spammers)|417|417|21|5.0%|0.2%|
[openbl_60d](#openbl_60d)|7581|7581|21|0.2%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1437|1437|17|1.1%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|11|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|7|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.0%|
[voipbl](#voipbl)|10350|10759|4|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[et_compromised](#et_compromised)|2191|2191|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|3|0.1%|0.0%|
[zeus_badips](#zeus_badips)|231|231|1|0.4%|0.0%|
[zeus](#zeus)|267|267|1|0.3%|0.0%|
[shunlist](#shunlist)|1241|1241|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3197|3197|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

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
[stopforumspam_1d](#stopforumspam_1d)|7099|7099|4678|65.8%|5.0%|
[ri_web_proxies](#ri_web_proxies)|5512|5512|2683|48.6%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2477|0.0%|2.6%|
[blocklist_de](#blocklist_de)|22462|22462|2155|9.5%|2.3%|
[blocklist_de_bots](#blocklist_de_bots)|3202|3202|1907|59.5%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1523|0.0%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|2030|2030|1191|58.6%|1.2%|
[xroxy](#xroxy)|2016|2016|1181|58.5%|1.2%|
[et_block](#et_block)|997|18338381|975|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|971|0.0%|1.0%|
[proxyrss](#proxyrss)|1596|1596|738|46.2%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|732|0.0%|0.7%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|718|11.4%|0.7%|
[et_tor](#et_tor)|6360|6360|622|9.7%|0.6%|
[dm_tor](#dm_tor)|6558|6558|620|9.4%|0.6%|
[bm_tor](#bm_tor)|6535|6535|620|9.4%|0.6%|
[proxz](#proxz)|459|459|273|59.4%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|234|62.9%|0.2%|
[nixspam](#nixspam)|23859|23859|225|0.9%|0.2%|
[alienvault_reputation](#alienvault_reputation)|178819|178819|219|0.1%|0.2%|
[php_commenters](#php_commenters)|281|281|203|72.2%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|198|1.4%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|14595|14595|196|1.3%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|113|71.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|103|0.0%|0.1%|
[php_spammers](#php_spammers)|417|417|99|23.7%|0.1%|
[php_dictionary](#php_dictionary)|433|433|83|19.1%|0.0%|
[php_harvesters](#php_harvesters)|257|257|63|24.5%|0.0%|
[openbl_60d](#openbl_60d)|7581|7581|54|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|44|0.0%|0.0%|
[voipbl](#voipbl)|10350|10759|40|0.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1437|1437|35|2.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|22|3.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[et_compromised](#et_compromised)|2191|2191|7|0.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|6|0.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|199|199|6|3.0%|0.0%|
[shunlist](#shunlist)|1241|1241|4|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3197|3197|4|0.1%|0.0%|
[zeus_badips](#zeus_badips)|231|231|3|1.2%|0.0%|
[zeus](#zeus)|267|267|3|1.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|3|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1615|1615|3|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3639|670579672|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[sslbl](#sslbl)|364|364|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|620|620|1|0.1%|0.0%|

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
[stopforumspam_1d](#stopforumspam_1d)|7099|7099|4409|62.1%|14.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2107|0.0%|6.7%|
[blocklist_de](#blocklist_de)|22462|22462|1892|8.4%|6.0%|
[ri_web_proxies](#ri_web_proxies)|5512|5512|1757|31.8%|5.6%|
[blocklist_de_bots](#blocklist_de_bots)|3202|3202|1738|54.2%|5.5%|
[xroxy](#xroxy)|2016|2016|990|49.1%|3.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|938|0.0%|2.9%|
[ri_connect_proxies](#ri_connect_proxies)|2030|2030|698|34.3%|2.2%|
[proxyrss](#proxyrss)|1596|1596|630|39.4%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|563|0.0%|1.7%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|562|8.9%|1.7%|
[et_tor](#et_tor)|6360|6360|480|7.5%|1.5%|
[dm_tor](#dm_tor)|6558|6558|479|7.3%|1.5%|
[bm_tor](#bm_tor)|6535|6535|478|7.3%|1.5%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|342|0.0%|1.0%|
[et_block](#et_block)|997|18338381|342|0.0%|1.0%|
[proxz](#proxz)|459|459|246|53.5%|0.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|201|54.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|182|0.0%|0.5%|
[php_commenters](#php_commenters)|281|281|170|60.4%|0.5%|
[nixspam](#nixspam)|23859|23859|132|0.5%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|122|0.8%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|14595|14595|114|0.7%|0.3%|
[alienvault_reputation](#alienvault_reputation)|178819|178819|111|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|104|65.4%|0.3%|
[php_spammers](#php_spammers)|417|417|70|16.7%|0.2%|
[php_dictionary](#php_dictionary)|433|433|68|15.7%|0.2%|
[php_harvesters](#php_harvesters)|257|257|47|18.2%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|37|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1437|1437|30|2.0%|0.0%|
[openbl_60d](#openbl_60d)|7581|7581|27|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|19|0.0%|0.0%|
[voipbl](#voipbl)|10350|10759|12|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|5|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|199|199|5|2.5%|0.0%|
[et_compromised](#et_compromised)|2191|2191|4|0.1%|0.0%|
[shunlist](#shunlist)|1241|1241|3|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|3|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|2|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1615|1615|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|231|231|1|0.4%|0.0%|
[zeus](#zeus)|267|267|1|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3197|3197|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|620|620|1|0.1%|0.0%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Mon Jun  1 17:09:31 UTC 2015.

The ipset `voipbl` has **10350** entries, **10759** unique IPs.

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
[alienvault_reputation](#alienvault_reputation)|178819|178819|209|0.1%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|40|0.0%|0.3%|
[blocklist_de](#blocklist_de)|22462|22462|37|0.1%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|97|97|28|28.8%|0.2%|
[et_block](#et_block)|997|18338381|24|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|14|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|12|0.0%|0.1%|
[shunlist](#shunlist)|1241|1241|11|0.8%|0.1%|
[openbl_60d](#openbl_60d)|7581|7581|9|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|5|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7099|7099|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[openbl_7d](#openbl_7d)|901|901|3|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3197|3197|3|0.0%|0.0%|
[ciarmy](#ciarmy)|339|339|3|0.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[et_tor](#et_tor)|6360|6360|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6558|6558|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6535|6535|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1615|1615|2|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1437|1437|2|0.1%|0.0%|
[nixspam](#nixspam)|23859|23859|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2191|2191|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14595|14595|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|620|620|1|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3202|3202|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Mon Jun  1 18:33:02 UTC 2015.

The ipset `xroxy` has **2016** entries, **2016** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|1181|1.2%|58.5%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|990|3.1%|49.1%|
[ri_web_proxies](#ri_web_proxies)|5512|5512|820|14.8%|40.6%|
[proxyrss](#proxyrss)|1596|1596|456|28.5%|22.6%|
[stopforumspam_1d](#stopforumspam_1d)|7099|7099|341|4.8%|16.9%|
[ri_connect_proxies](#ri_connect_proxies)|2030|2030|317|15.6%|15.7%|
[blocklist_de](#blocklist_de)|22462|22462|237|1.0%|11.7%|
[proxz](#proxz)|459|459|231|50.3%|11.4%|
[blocklist_de_bots](#blocklist_de_bots)|3202|3202|209|6.5%|10.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|99|0.0%|4.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|84|0.0%|4.1%|
[nixspam](#nixspam)|23859|23859|64|0.2%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|57|0.0%|2.8%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|30|0.4%|1.4%|
[blocklist_de_mail](#blocklist_de_mail)|14595|14595|26|0.1%|1.2%|
[php_dictionary](#php_dictionary)|433|433|24|5.5%|1.1%|
[php_spammers](#php_spammers)|417|417|18|4.3%|0.8%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|13|1.9%|0.6%|
[alienvault_reputation](#alienvault_reputation)|178819|178819|5|0.0%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|159|159|4|2.5%|0.1%|
[php_commenters](#php_commenters)|281|281|3|1.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.1%|
[et_tor](#et_tor)|6360|6360|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[dm_tor](#dm_tor)|6558|6558|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6535|6535|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2191|2191|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1615|1615|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1437|1437|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13852|13852|1|0.0%|0.0%|

## zeus

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist).

The last time downloaded was found to be dated: Mon Jun  1 18:18:04 UTC 2015.

The ipset `zeus` has **267** entries, **267** unique IPs.

The following table shows the overlaps of `zeus` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus`.
- ` this % ` is the percentage **of this ipset (`zeus`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|997|18338381|260|0.0%|97.3%|
[zeus_badips](#zeus_badips)|231|231|231|100.0%|86.5%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|227|3.6%|85.0%|
[alienvault_reputation](#alienvault_reputation)|178819|178819|66|0.0%|24.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|19|0.0%|7.1%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|16|0.0%|5.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|7|0.0%|2.6%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|5|0.0%|1.8%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|3|0.0%|1.1%|
[openbl_60d](#openbl_60d)|7581|7581|2|0.0%|0.7%|
[openbl_30d](#openbl_30d)|3197|3197|2|0.0%|0.7%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|1|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7099|7099|1|0.0%|0.3%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.3%|
[openbl_7d](#openbl_7d)|901|901|1|0.1%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|
[et_compromised](#et_compromised)|2191|2191|1|0.0%|0.3%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|1|0.0%|0.3%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Mon Jun  1 19:27:09 UTC 2015.

The ipset `zeus_badips` has **231** entries, **231** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|267|267|231|86.5%|100.0%|
[et_block](#et_block)|997|18338381|229|0.0%|99.1%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|203|3.2%|87.8%|
[alienvault_reputation](#alienvault_reputation)|178819|178819|37|0.0%|16.0%|
[spamhaus_drop](#spamhaus_drop)|652|18338560|16|0.0%|6.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8|0.0%|3.4%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|5|0.0%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4|0.0%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|3|0.0%|1.2%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|7099|7099|1|0.0%|0.4%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.4%|
[openbl_60d](#openbl_60d)|7581|7581|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|3197|3197|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.4%|
[et_compromised](#et_compromised)|2191|2191|1|0.0%|0.4%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|1|0.0%|0.4%|
