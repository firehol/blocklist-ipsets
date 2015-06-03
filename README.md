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

The following list was automatically generated on Wed Jun  3 01:38:27 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|174882 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|32730 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|13974 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|3138 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|2596 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|721 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|1558 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|15540 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|113 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|10351 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|174 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6441 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|2173 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|308 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|11 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6392 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|997 subnets, 18338381 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botcc](#et_botcc)|[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)|ipv4 hash:ip|505 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net compromised hosts](http://doc.emergingthreats.net/bin/view/Main/CompromisedHost) - (this seems to be based on bruteforceblocker)|ipv4 hash:ip|2191 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6360 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[feodo](#feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|80 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
[fullbogons](#fullbogons)|[Team-Cymru.org](http://www.team-cymru.org) IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user - **excellent list - use it only your internet interface**|ipv4 hash:net|3686 subnets, 670534424 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt)
[geolite2_country](https://github.com/ktsaou/blocklist-ipsets/tree/master/geolite2_country)|[MaxMind GeoLite2](http://dev.maxmind.com/geoip/geoip2/geolite2/) databases are free IP geolocation databases comparable to, but less accurate than, MaxMind’s GeoIP2 databases. They include IPs per country, IPs per continent, IPs used by anonymous services (VPNs, Proxies, etc) and Satellite Providers.|ipv4 hash:net|All the world|updated every 7 days  from [this link](http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country-CSV.zip)
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) IPs that have been reported for bad deeds in p2p|ipv4 hash:ip|48134 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=cwworuawihqvocglcoss&fileformat=p2p&archiveformat=gz)
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) hijacked IP-Blocks Hijacked IP space are IP blocks that are being used without permission|ipv4 hash:net|535 subnets, 9177856 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=usrcshglbiilevmyfhse&fileformat=p2p&archiveformat=gz)
[ib_bluetack_level1](#ib_bluetack_level1)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Level 1 (for use in p2p): Companies or organizations who are clearly involved with trying to stop filesharing (e.g. Baytsp, MediaDefender, Mediasentry a.o.). Companies which anti-p2p activity has been seen from. Companies that produce or have a strong financial interest in copyrighted material (e.g. music, movie, software industries a.o.). Government ranges or companies that have a strong financial interest in doing work for governments. Legal industry ranges. IPs or ranges of ISPs from which anti-p2p activity has been observed. Basically this list will block all kinds of internet connections that most people would rather not have during their internet travels.|ipv4 hash:net|218309 subnets, 764987411 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz)
[ib_bluetack_level2](#ib_bluetack_level2)|[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 2 (for use in p2p). General corporate ranges. Ranges used by labs or researchers. Proxies.|ipv4 hash:net|72774 subnets, 348707599 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw&fileformat=p2p&archiveformat=gz)
[ib_bluetack_level3](#ib_bluetack_level3)|[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 3 (for use in p2p). Many portal-type websites. ISP ranges that may be dodgy for some reason. Ranges that belong to an individual, but which have not been determined to be used by a particular company. Ranges for things that are unusual in some way. The L3 list is aka the paranoid list.|ipv4 hash:net|17802 subnets, 139104824 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh&fileformat=p2p&archiveformat=gz)
[ib_bluetack_proxies](#ib_bluetack_proxies)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Open Proxies IPs list (without TOR)|ipv4 hash:ip|673 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=xoebmbyexwuiogmbyprb&fileformat=p2p&archiveformat=gz)
[ib_bluetack_spyware](#ib_bluetack_spyware)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) known malicious SPYWARE and ADWARE IP Address ranges|ipv4 hash:net|3274 subnets, 339192 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=llvtlsjyoyiczbkjsxpf&fileformat=p2p&archiveformat=gz)
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) web server hack and exploit attempts|ipv4 hash:ip|1460 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=ghlzqtqxnzctvvajwwag&fileformat=p2p&archiveformat=gz)
[malc0de](#malc0de)|[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days|ipv4 hash:ip|392 unique IPs|updated every 1 day  from [this link](http://malc0de.com/bl/IP_Blacklist.txt)
[malwaredomainlist](#malwaredomainlist)|[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses|ipv4 hash:ip|1283 unique IPs|updated every 12 hours  from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt)
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.|ipv4 hash:ip|372 unique IPs|updated every 4 hours  from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list)
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|19429 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|303 unique IPs|updated every 1 hour  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|3244 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7653 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|999 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|281 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|433 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|257 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|417 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1973 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|579 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2142 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|5772 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1271 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|8876 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|656 subnets, 18600704 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|57 subnets, 487168 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|360 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|7086 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|92665 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|31339 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
[virbl](#virbl)|[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.|ipv4 hash:ip|12 unique IPs|updated every 1 hour  from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10367 subnets, 10776 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2041 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|266 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|230 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Tue Jun  2 22:01:34 UTC 2015.

The ipset `alienvault_reputation` has **174882** entries, **174882** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14639|0.0%|8.3%|
[openbl_60d](#openbl_60d)|7653|7653|7627|99.6%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7609|0.0%|4.3%|
[et_block](#et_block)|997|18338381|5537|0.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4700|0.0%|2.6%|
[dshield](#dshield)|20|5120|3854|75.2%|2.2%|
[openbl_30d](#openbl_30d)|3244|3244|3224|99.3%|1.8%|
[blocklist_de](#blocklist_de)|32730|32730|2005|6.1%|1.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|10351|10351|1769|17.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|1628|0.0%|0.9%|
[et_compromised](#et_compromised)|2191|2191|1424|64.9%|0.8%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|1403|64.5%|0.8%|
[shunlist](#shunlist)|1271|1271|1261|99.2%|0.7%|
[openbl_7d](#openbl_7d)|999|999|987|98.7%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|518|0.0%|0.2%|
[ciarmy](#ciarmy)|308|308|297|96.4%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|289|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|271|0.0%|0.1%|
[openbl_1d](#openbl_1d)|303|303|253|83.4%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|215|0.2%|0.1%|
[voipbl](#voipbl)|10367|10776|197|1.8%|0.1%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|119|1.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13974|13974|112|0.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|100|0.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15540|15540|78|0.5%|0.0%|
[zeus](#zeus)|266|266|66|24.8%|0.0%|
[sslbl](#sslbl)|360|360|63|17.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7086|7086|57|0.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1558|1558|53|3.4%|0.0%|
[et_tor](#et_tor)|6360|6360|44|0.6%|0.0%|
[dm_tor](#dm_tor)|6392|6392|44|0.6%|0.0%|
[bm_tor](#bm_tor)|6441|6441|44|0.6%|0.0%|
[nixspam](#nixspam)|19429|19429|39|0.2%|0.0%|
[zeus_badips](#zeus_badips)|230|230|37|16.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|37|21.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3138|3138|29|0.9%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|25|6.7%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|113|113|20|17.6%|0.0%|
[php_commenters](#php_commenters)|281|281|14|4.9%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2596|2596|14|0.5%|0.0%|
[malc0de](#malc0de)|392|392|12|3.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|721|721|9|1.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|8|0.5%|0.0%|
[php_dictionary](#php_dictionary)|433|433|7|1.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|6|0.4%|0.0%|
[xroxy](#xroxy)|2041|2041|5|0.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5772|5772|3|0.0%|0.0%|
[proxz](#proxz)|579|579|3|0.5%|0.0%|
[php_spammers](#php_spammers)|417|417|3|0.7%|0.0%|
[et_botcc](#et_botcc)|505|505|3|0.5%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2142|2142|2|0.0%|0.0%|
[proxyrss](#proxyrss)|1973|1973|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[feodo](#feodo)|80|80|1|1.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|11|11|1|9.0%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Wed Jun  3 01:28:02 UTC 2015.

The ipset `blocklist_de` has **32730** entries, **32730** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|15540|15540|15540|100.0%|47.4%|
[blocklist_de_apache](#blocklist_de_apache)|13974|13974|13956|99.8%|42.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|10351|10351|10351|100.0%|31.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|5500|0.0%|16.8%|
[blocklist_de_bots](#blocklist_de_bots)|3138|3138|3138|100.0%|9.5%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|2636|2.8%|8.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2596|2596|2596|100.0%|7.9%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|2005|1.1%|6.1%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|1963|6.2%|5.9%|
[openbl_60d](#openbl_60d)|7653|7653|1665|21.7%|5.0%|
[blocklist_de_imap](#blocklist_de_imap)|1558|1558|1556|99.8%|4.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1554|0.0%|4.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1527|0.0%|4.6%|
[stopforumspam_1d](#stopforumspam_1d)|7086|7086|1401|19.7%|4.2%|
[openbl_30d](#openbl_30d)|3244|3244|877|27.0%|2.6%|
[blocklist_de_ftp](#blocklist_de_ftp)|721|721|721|100.0%|2.2%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|718|33.0%|2.1%|
[et_compromised](#et_compromised)|2191|2191|676|30.8%|2.0%|
[openbl_7d](#openbl_7d)|999|999|584|58.4%|1.7%|
[nixspam](#nixspam)|19429|19429|501|2.5%|1.5%|
[shunlist](#shunlist)|1271|1271|416|32.7%|1.2%|
[ri_web_proxies](#ri_web_proxies)|5772|5772|355|6.1%|1.0%|
[xroxy](#xroxy)|2041|2041|241|11.8%|0.7%|
[proxyrss](#proxyrss)|1973|1973|241|12.2%|0.7%|
[openbl_1d](#openbl_1d)|303|303|212|69.9%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|174|100.0%|0.5%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|168|1.8%|0.5%|
[et_block](#et_block)|997|18338381|164|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|158|0.0%|0.4%|
[proxz](#proxz)|579|579|114|19.6%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|113|113|94|83.1%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2142|2142|69|3.2%|0.2%|
[php_commenters](#php_commenters)|281|281|62|22.0%|0.1%|
[php_dictionary](#php_dictionary)|433|433|54|12.4%|0.1%|
[php_spammers](#php_spammers)|417|417|47|11.2%|0.1%|
[dshield](#dshield)|20|5120|46|0.8%|0.1%|
[voipbl](#voipbl)|10367|10776|41|0.3%|0.1%|
[ciarmy](#ciarmy)|308|308|38|12.3%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|26|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|24|9.3%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|13|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|9|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[et_tor](#et_tor)|6360|6360|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6392|6392|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6441|6441|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[virbl](#virbl)|12|12|1|8.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Wed Jun  3 01:10:06 UTC 2015.

The ipset `blocklist_de_apache` has **13974** entries, **13974** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|32730|32730|13956|42.6%|99.8%|
[blocklist_de_mail](#blocklist_de_mail)|15540|15540|11059|71.1%|79.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2596|2596|2590|99.7%|18.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2259|0.0%|16.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1321|0.0%|9.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1079|0.0%|7.7%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|204|0.2%|1.4%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|126|0.4%|0.9%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|112|0.0%|0.8%|
[stopforumspam_1d](#stopforumspam_1d)|7086|7086|63|0.8%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|36|20.6%|0.2%|
[shunlist](#shunlist)|1271|1271|33|2.5%|0.2%|
[ciarmy](#ciarmy)|308|308|32|10.3%|0.2%|
[nixspam](#nixspam)|19429|19429|27|0.1%|0.1%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3138|3138|22|0.7%|0.1%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|9|0.1%|0.0%|
[voipbl](#voipbl)|10367|10776|5|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|4|0.9%|0.0%|
[et_block](#et_block)|997|18338381|4|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7653|7653|3|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.0%|
[et_tor](#et_tor)|6360|6360|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6392|6392|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6441|6441|3|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|2|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[openbl_30d](#openbl_30d)|3244|3244|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[et_compromised](#et_compromised)|2191|2191|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[openbl_7d](#openbl_7d)|999|999|1|0.1%|0.0%|
[openbl_1d](#openbl_1d)|303|303|1|0.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Wed Jun  3 01:28:08 UTC 2015.

The ipset `blocklist_de_bots` has **3138** entries, **3138** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|32730|32730|3138|9.5%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|2276|2.4%|72.5%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|1770|5.6%|56.4%|
[stopforumspam_1d](#stopforumspam_1d)|7086|7086|1346|18.9%|42.8%|
[ri_web_proxies](#ri_web_proxies)|5772|5772|314|5.4%|10.0%|
[proxyrss](#proxyrss)|1973|1973|238|12.0%|7.5%|
[xroxy](#xroxy)|2041|2041|199|9.7%|6.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|178|0.0%|5.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|158|0.0%|5.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|127|72.9%|4.0%|
[proxz](#proxz)|579|579|95|16.4%|3.0%|
[ri_connect_proxies](#ri_connect_proxies)|2142|2142|67|3.1%|2.1%|
[php_commenters](#php_commenters)|281|281|48|17.0%|1.5%|
[nixspam](#nixspam)|19429|19429|36|0.1%|1.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|33|0.0%|1.0%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|29|0.0%|0.9%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|26|0.2%|0.8%|
[blocklist_de_apache](#blocklist_de_apache)|13974|13974|22|0.1%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|15540|15540|21|0.1%|0.6%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|18|0.0%|0.5%|
[php_harvesters](#php_harvesters)|257|257|18|7.0%|0.5%|
[et_block](#et_block)|997|18338381|18|0.0%|0.5%|
[php_dictionary](#php_dictionary)|433|433|14|3.2%|0.4%|
[php_spammers](#php_spammers)|417|417|11|2.6%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.3%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|5|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7653|7653|5|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.0%|
[voipbl](#voipbl)|10367|10776|2|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[et_compromised](#et_compromised)|2191|2191|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Wed Jun  3 01:28:10 UTC 2015.

The ipset `blocklist_de_bruteforce` has **2596** entries, **2596** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|32730|32730|2596|7.9%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|13974|13974|2590|18.5%|99.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|165|0.0%|6.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|45|0.0%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|41|0.0%|1.5%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|32|0.1%|1.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|30|0.0%|1.1%|
[nixspam](#nixspam)|19429|19429|27|0.1%|1.0%|
[stopforumspam_1d](#stopforumspam_1d)|7086|7086|17|0.2%|0.6%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|14|0.0%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|11|6.3%|0.4%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|6|0.0%|0.2%|
[php_commenters](#php_commenters)|281|281|5|1.7%|0.1%|
[php_spammers](#php_spammers)|417|417|4|0.9%|0.1%|
[et_block](#et_block)|997|18338381|3|0.0%|0.1%|
[voipbl](#voipbl)|10367|10776|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|2|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[shunlist](#shunlist)|1271|1271|1|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7653|7653|1|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15540|15540|1|0.0%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Wed Jun  3 01:28:07 UTC 2015.

The ipset `blocklist_de_ftp` has **721** entries, **721** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|32730|32730|721|2.2%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|63|0.0%|8.7%|
[nixspam](#nixspam)|19429|19429|14|0.0%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|12|0.0%|1.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|10|0.0%|1.3%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|9|0.0%|1.2%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|6|0.0%|0.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|6|0.0%|0.8%|
[php_harvesters](#php_harvesters)|257|257|5|1.9%|0.6%|
[openbl_60d](#openbl_60d)|7653|7653|3|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|7086|7086|2|0.0%|0.2%|
[openbl_30d](#openbl_30d)|3244|3244|2|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|1|0.0%|0.1%|
[shunlist](#shunlist)|1271|1271|1|0.0%|0.1%|
[openbl_7d](#openbl_7d)|999|999|1|0.1%|0.1%|
[et_compromised](#et_compromised)|2191|2191|1|0.0%|0.1%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|1|0.0%|0.1%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Wed Jun  3 01:10:08 UTC 2015.

The ipset `blocklist_de_imap` has **1558** entries, **1558** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|32730|32730|1556|4.7%|99.8%|
[blocklist_de_mail](#blocklist_de_mail)|15540|15540|1555|10.0%|99.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|137|0.0%|8.7%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|53|0.0%|3.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|46|0.0%|2.9%|
[openbl_60d](#openbl_60d)|7653|7653|39|0.5%|2.5%|
[openbl_30d](#openbl_30d)|3244|3244|34|1.0%|2.1%|
[openbl_7d](#openbl_7d)|999|999|17|1.7%|1.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|15|0.0%|0.9%|
[et_block](#et_block)|997|18338381|15|0.0%|0.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|14|0.0%|0.8%|
[et_compromised](#et_compromised)|2191|2191|7|0.3%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|6|0.0%|0.3%|
[nixspam](#nixspam)|19429|19429|6|0.0%|0.3%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|6|0.2%|0.3%|
[openbl_1d](#openbl_1d)|303|303|4|1.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|3|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|3|0.0%|0.1%|
[shunlist](#shunlist)|1271|1271|2|0.1%|0.1%|
[voipbl](#voipbl)|10367|10776|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|1|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|10351|10351|1|0.0%|0.0%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Wed Jun  3 01:28:04 UTC 2015.

The ipset `blocklist_de_mail` has **15540** entries, **15540** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|32730|32730|15540|47.4%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|13974|13974|11059|79.1%|71.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2367|0.0%|15.2%|
[blocklist_de_imap](#blocklist_de_imap)|1558|1558|1555|99.8%|10.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1334|0.0%|8.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1136|0.0%|7.3%|
[nixspam](#nixspam)|19429|19429|375|1.9%|2.4%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|224|0.2%|1.4%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|142|0.4%|0.9%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|133|1.4%|0.8%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|78|0.0%|0.5%|
[openbl_60d](#openbl_60d)|7653|7653|47|0.6%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7086|7086|43|0.6%|0.2%|
[ri_web_proxies](#ri_web_proxies)|5772|5772|41|0.7%|0.2%|
[openbl_30d](#openbl_30d)|3244|3244|41|1.2%|0.2%|
[xroxy](#xroxy)|2041|2041|40|1.9%|0.2%|
[php_dictionary](#php_dictionary)|433|433|38|8.7%|0.2%|
[php_spammers](#php_spammers)|417|417|32|7.6%|0.2%|
[et_block](#et_block)|997|18338381|26|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|25|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3138|3138|21|0.6%|0.1%|
[php_commenters](#php_commenters)|281|281|20|7.1%|0.1%|
[openbl_7d](#openbl_7d)|999|999|20|2.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|20|11.4%|0.1%|
[proxz](#proxz)|579|579|17|2.9%|0.1%|
[et_compromised](#et_compromised)|2191|2191|9|0.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|9|0.4%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.0%|
[shunlist](#shunlist)|1271|1271|5|0.3%|0.0%|
[openbl_1d](#openbl_1d)|303|303|5|1.6%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|4|0.0%|0.0%|
[et_tor](#et_tor)|6360|6360|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6392|6392|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6441|6441|3|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[ciarmy](#ciarmy)|308|308|2|0.6%|0.0%|
[voipbl](#voipbl)|10367|10776|1|0.0%|0.0%|
[virbl](#virbl)|12|12|1|8.3%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2142|2142|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1973|1973|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2596|2596|1|0.0%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Wed Jun  3 01:28:07 UTC 2015.

The ipset `blocklist_de_sip` has **113** entries, **113** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|32730|32730|94|0.2%|83.1%|
[voipbl](#voipbl)|10367|10776|31|0.2%|27.4%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|20|0.0%|17.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|13|0.0%|11.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|6|0.0%|5.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|2.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|1.7%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|1|0.0%|0.8%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.8%|
[et_block](#et_block)|997|18338381|1|0.0%|0.8%|
[ciarmy](#ciarmy)|308|308|1|0.3%|0.8%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Wed Jun  3 01:28:03 UTC 2015.

The ipset `blocklist_de_ssh` has **10351** entries, **10351** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|32730|32730|10351|31.6%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2695|0.0%|26.0%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|1769|1.0%|17.0%|
[openbl_60d](#openbl_60d)|7653|7653|1607|20.9%|15.5%|
[openbl_30d](#openbl_30d)|3244|3244|832|25.6%|8.0%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|705|32.4%|6.8%|
[et_compromised](#et_compromised)|2191|2191|663|30.2%|6.4%|
[openbl_7d](#openbl_7d)|999|999|562|56.2%|5.4%|
[shunlist](#shunlist)|1271|1271|377|29.6%|3.6%|
[openbl_1d](#openbl_1d)|303|303|206|67.9%|1.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|193|0.0%|1.8%|
[et_block](#et_block)|997|18338381|115|0.0%|1.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|113|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|112|0.0%|1.0%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|77|0.0%|0.7%|
[nixspam](#nixspam)|19429|19429|49|0.2%|0.4%|
[dshield](#dshield)|20|5120|43|0.8%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|28|16.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|12|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.0%|
[ciarmy](#ciarmy)|308|308|3|0.9%|0.0%|
[xroxy](#xroxy)|2041|2041|2|0.0%|0.0%|
[voipbl](#voipbl)|10367|10776|2|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|2|0.0%|0.0%|
[proxz](#proxz)|579|579|2|0.3%|0.0%|
[proxyrss](#proxyrss)|1973|1973|2|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7086|7086|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2142|2142|1|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1558|1558|1|0.0%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Wed Jun  3 01:14:10 UTC 2015.

The ipset `blocklist_de_strongips` has **174** entries, **174** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|32730|32730|174|0.5%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|131|0.1%|75.2%|
[blocklist_de_bots](#blocklist_de_bots)|3138|3138|127|4.0%|72.9%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|117|0.3%|67.2%|
[stopforumspam_1d](#stopforumspam_1d)|7086|7086|103|1.4%|59.1%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|37|0.0%|21.2%|
[blocklist_de_apache](#blocklist_de_apache)|13974|13974|36|0.2%|20.6%|
[php_commenters](#php_commenters)|281|281|29|10.3%|16.6%|
[openbl_60d](#openbl_60d)|7653|7653|28|0.3%|16.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|10351|10351|28|0.2%|16.0%|
[openbl_30d](#openbl_30d)|3244|3244|25|0.7%|14.3%|
[openbl_7d](#openbl_7d)|999|999|24|2.4%|13.7%|
[shunlist](#shunlist)|1271|1271|20|1.5%|11.4%|
[blocklist_de_mail](#blocklist_de_mail)|15540|15540|20|0.1%|11.4%|
[openbl_1d](#openbl_1d)|303|303|18|5.9%|10.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|16|0.0%|9.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2596|2596|11|0.4%|6.3%|
[xroxy](#xroxy)|2041|2041|7|0.3%|4.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|7|0.0%|4.0%|
[proxyrss](#proxyrss)|1973|1973|7|0.3%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7|0.0%|4.0%|
[et_block](#et_block)|997|18338381|7|0.0%|4.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|6|0.0%|3.4%|
[ri_web_proxies](#ri_web_proxies)|5772|5772|5|0.0%|2.8%|
[proxz](#proxz)|579|579|3|0.5%|1.7%|
[php_spammers](#php_spammers)|417|417|3|0.7%|1.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.7%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|1.1%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|1.1%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|1|0.0%|0.5%|
[nixspam](#nixspam)|19429|19429|1|0.0%|0.5%|
[dshield](#dshield)|20|5120|1|0.0%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|1558|1558|1|0.0%|0.5%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Wed Jun  3 01:09:07 UTC 2015.

The ipset `bm_tor` has **6441** entries, **6441** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[dm_tor](#dm_tor)|6392|6392|6327|98.9%|98.2%|
[et_tor](#et_tor)|6360|6360|5649|88.8%|87.7%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|1080|12.1%|16.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|637|0.0%|9.8%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|626|0.6%|9.7%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|471|1.5%|7.3%|
[stopforumspam_1d](#stopforumspam_1d)|7086|7086|285|4.0%|4.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|183|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|170|45.6%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|167|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|44|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|28|9.9%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7653|7653|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[et_block](#et_block)|997|18338381|4|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15540|15540|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13974|13974|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|32730|32730|3|0.0%|0.0%|
[xroxy](#xroxy)|2041|2041|2|0.0%|0.0%|
[voipbl](#voipbl)|10367|10776|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|2|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5772|5772|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[shunlist](#shunlist)|1271|1271|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2142|2142|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1973|1973|1|0.0%|0.0%|
[nixspam](#nixspam)|19429|19429|1|0.0%|0.0%|

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
[fullbogons](#fullbogons)|3686|670534424|592708608|88.3%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|4194304|3.0%|0.7%|
[voipbl](#voipbl)|10367|10776|319|2.9%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|1|0.0%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Tue Jun  2 22:54:27 UTC 2015.

The ipset `bruteforceblocker` has **2173** entries, **2173** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_compromised](#et_compromised)|2191|2191|2089|95.3%|96.1%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|1403|0.8%|64.5%|
[openbl_60d](#openbl_60d)|7653|7653|1303|17.0%|59.9%|
[openbl_30d](#openbl_30d)|3244|3244|1222|37.6%|56.2%|
[blocklist_de](#blocklist_de)|32730|32730|718|2.1%|33.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|10351|10351|705|6.8%|32.4%|
[openbl_7d](#openbl_7d)|999|999|519|51.9%|23.8%|
[shunlist](#shunlist)|1271|1271|504|39.6%|23.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|214|0.0%|9.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|115|0.0%|5.2%|
[et_block](#et_block)|997|18338381|102|0.0%|4.6%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|100|0.0%|4.6%|
[openbl_1d](#openbl_1d)|303|303|79|26.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|62|0.0%|2.8%|
[dshield](#dshield)|20|5120|43|0.8%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|10|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|15540|15540|9|0.0%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|6|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|1558|1558|6|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[voipbl](#voipbl)|10367|10776|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|2|0.0%|0.0%|
[proxz](#proxz)|579|579|2|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13974|13974|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[xroxy](#xroxy)|2041|2041|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7086|7086|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5772|5772|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1973|1973|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3686|670534424|1|0.0%|0.0%|
[ciarmy](#ciarmy)|308|308|1|0.3%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|721|721|1|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3138|3138|1|0.0%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Wed Jun  3 01:15:15 UTC 2015.

The ipset `ciarmy` has **308** entries, **308** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|174882|174882|297|0.1%|96.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|51|0.0%|16.5%|
[blocklist_de](#blocklist_de)|32730|32730|38|0.1%|12.3%|
[blocklist_de_apache](#blocklist_de_apache)|13974|13974|32|0.2%|10.3%|
[shunlist](#shunlist)|1271|1271|24|1.8%|7.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|11|0.0%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|9|0.0%|2.9%|
[voipbl](#voipbl)|10367|10776|5|0.0%|1.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|10351|10351|3|0.0%|0.9%|
[et_block](#et_block)|997|18338381|2|0.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|15540|15540|2|0.0%|0.6%|
[openbl_7d](#openbl_7d)|999|999|1|0.1%|0.3%|
[openbl_60d](#openbl_60d)|7653|7653|1|0.0%|0.3%|
[openbl_30d](#openbl_30d)|3244|3244|1|0.0%|0.3%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|1|0.0%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|113|113|1|0.8%|0.3%|

## cleanmx_viruses

[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses

Source is downloaded from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive).

The last time downloaded was found to be dated: Tue Jun  2 18:45:34 UTC 2015.

The ipset `cleanmx_viruses` has **11** entries, **11** unique IPs.

The following table shows the overlaps of `cleanmx_viruses` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `cleanmx_viruses`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `cleanmx_viruses`.
- ` this % ` is the percentage **of this ipset (`cleanmx_viruses`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[malc0de](#malc0de)|392|392|2|0.5%|18.1%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|9.0%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|1|0.0%|9.0%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Wed Jun  3 01:09:06 UTC 2015.

The ipset `dm_tor` has **6392** entries, **6392** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6441|6441|6327|98.2%|98.9%|
[et_tor](#et_tor)|6360|6360|5623|88.4%|87.9%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|1076|12.1%|16.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|634|0.0%|9.9%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|627|0.6%|9.8%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|472|1.5%|7.3%|
[stopforumspam_1d](#stopforumspam_1d)|7086|7086|285|4.0%|4.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|184|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|170|45.6%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|167|0.0%|2.6%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|44|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|28|9.9%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7653|7653|20|0.2%|0.3%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[et_block](#et_block)|997|18338381|4|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15540|15540|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13974|13974|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|32730|32730|3|0.0%|0.0%|
[xroxy](#xroxy)|2041|2041|2|0.0%|0.0%|
[voipbl](#voipbl)|10367|10776|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|2|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5772|5772|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[shunlist](#shunlist)|1271|1271|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2142|2142|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1973|1973|1|0.0%|0.0%|
[nixspam](#nixspam)|19429|19429|1|0.0%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Tue Jun  2 23:23:17 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|174882|174882|3854|2.2%|75.2%|
[et_block](#et_block)|997|18338381|1281|0.0%|25.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|512|0.0%|10.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|512|0.0%|10.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|512|0.0%|10.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|256|0.0%|5.0%|
[openbl_60d](#openbl_60d)|7653|7653|76|0.9%|1.4%|
[openbl_30d](#openbl_30d)|3244|3244|67|2.0%|1.3%|
[blocklist_de](#blocklist_de)|32730|32730|46|0.1%|0.8%|
[et_compromised](#et_compromised)|2191|2191|43|1.9%|0.8%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|43|1.9%|0.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|10351|10351|43|0.4%|0.8%|
[openbl_7d](#openbl_7d)|999|999|42|4.2%|0.8%|
[shunlist](#shunlist)|1271|1271|40|3.1%|0.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|22|0.0%|0.4%|
[openbl_1d](#openbl_1d)|303|303|12|3.9%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|3|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|2|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7086|7086|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|2|0.0%|0.0%|
[et_tor](#et_tor)|6360|6360|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6392|6392|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6441|6441|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13974|13974|2|0.0%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.0%|
[nixspam](#nixspam)|19429|19429|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[malc0de](#malc0de)|392|392|1|0.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|1|0.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15540|15540|1|0.0%|0.0%|

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
[spamhaus_drop](#spamhaus_drop)|656|18600704|18333440|98.5%|99.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8598823|2.4%|46.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7079936|77.1%|38.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|2272672|0.2%|12.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|196186|0.1%|1.0%|
[fullbogons](#fullbogons)|3686|670534424|20480|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|5537|3.1%|0.0%|
[dshield](#dshield)|20|5120|1281|25.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1040|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|1003|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|517|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|341|1.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|299|3.3%|0.0%|
[zeus](#zeus)|266|266|259|97.3%|0.0%|
[openbl_60d](#openbl_60d)|7653|7653|244|3.1%|0.0%|
[zeus_badips](#zeus_badips)|230|230|229|99.5%|0.0%|
[openbl_30d](#openbl_30d)|3244|3244|179|5.5%|0.0%|
[nixspam](#nixspam)|19429|19429|169|0.8%|0.0%|
[blocklist_de](#blocklist_de)|32730|32730|164|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|10351|10351|115|1.1%|0.0%|
[shunlist](#shunlist)|1271|1271|107|8.4%|0.0%|
[et_compromised](#et_compromised)|2191|2191|104|4.7%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7086|7086|103|1.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|102|4.6%|0.0%|
[openbl_7d](#openbl_7d)|999|999|87|8.7%|0.0%|
[feodo](#feodo)|80|80|71|88.7%|0.0%|
[sslbl](#sslbl)|360|360|30|8.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|29|2.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15540|15540|26|0.1%|0.0%|
[voipbl](#voipbl)|10367|10776|24|0.2%|0.0%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3138|3138|18|0.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1558|1558|15|0.9%|0.0%|
[openbl_1d](#openbl_1d)|303|303|13|4.2%|0.0%|
[palevo](#palevo)|13|13|12|92.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|10|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|7|4.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[malc0de](#malc0de)|392|392|4|1.0%|0.0%|
[et_tor](#et_tor)|6360|6360|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6392|6392|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6441|6441|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13974|13974|4|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2596|2596|3|0.1%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[ciarmy](#ciarmy)|308|308|2|0.6%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|113|113|1|0.8%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|174882|174882|3|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[et_block](#et_block)|997|18338381|1|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|113|113|1|0.8%|0.1%|

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
[bruteforceblocker](#bruteforceblocker)|2173|2173|2089|96.1%|95.3%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|1424|0.8%|64.9%|
[openbl_60d](#openbl_60d)|7653|7653|1323|17.2%|60.3%|
[openbl_30d](#openbl_30d)|3244|3244|1227|37.8%|56.0%|
[blocklist_de](#blocklist_de)|32730|32730|676|2.0%|30.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|10351|10351|663|6.4%|30.2%|
[openbl_7d](#openbl_7d)|999|999|509|50.9%|23.2%|
[shunlist](#shunlist)|1271|1271|504|39.6%|23.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|219|0.0%|9.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|116|0.0%|5.2%|
[et_block](#et_block)|997|18338381|104|0.0%|4.7%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|102|0.0%|4.6%|
[openbl_1d](#openbl_1d)|303|303|70|23.1%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|62|0.0%|2.8%|
[dshield](#dshield)|20|5120|43|0.8%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|9|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|15540|15540|9|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|1558|1558|7|0.4%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|5|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|2|0.0%|0.0%|
[proxz](#proxz)|579|579|2|0.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13974|13974|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[xroxy](#xroxy)|2041|2041|1|0.0%|0.0%|
[voipbl](#voipbl)|10367|10776|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7086|7086|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1973|1973|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|721|721|1|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3138|3138|1|0.0%|0.0%|

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
[bm_tor](#bm_tor)|6441|6441|5649|87.7%|88.8%|
[dm_tor](#dm_tor)|6392|6392|5623|87.9%|88.4%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|1078|12.1%|16.9%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|639|0.6%|10.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|628|0.0%|9.8%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|491|1.5%|7.7%|
[stopforumspam_1d](#stopforumspam_1d)|7086|7086|284|4.0%|4.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|191|0.0%|3.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|169|45.4%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|167|0.0%|2.6%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|44|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[openbl_60d](#openbl_60d)|7653|7653|19|0.2%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|19|0.0%|0.2%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[php_harvesters](#php_harvesters)|257|257|6|2.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5772|5772|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[et_block](#et_block)|997|18338381|4|0.0%|0.0%|
[xroxy](#xroxy)|2041|2041|3|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15540|15540|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13974|13974|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|32730|32730|3|0.0%|0.0%|
[voipbl](#voipbl)|10367|10776|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2142|2142|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[shunlist](#shunlist)|1271|1271|1|0.0%|0.0%|
[proxz](#proxz)|579|579|1|0.1%|0.0%|
[proxyrss](#proxyrss)|1973|1973|1|0.0%|0.0%|
[nixspam](#nixspam)|19429|19429|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Wed Jun  3 01:09:25 UTC 2015.

The ipset `feodo` has **80** entries, **80** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|997|18338381|71|0.0%|88.7%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|64|0.7%|80.0%|
[sslbl](#sslbl)|360|360|31|8.6%|38.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|7|0.0%|8.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|3|0.0%|3.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|3.7%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|1.2%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|1|0.0%|1.2%|

## fullbogons

[Team-Cymru.org](http://www.team-cymru.org) IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user - **excellent list - use it only your internet interface**

Source is downloaded from [this link](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt).

The last time downloaded was found to be dated: Tue Jun  2 09:35:08 UTC 2015.

The ipset `fullbogons` has **3686** entries, **670534424** unique IPs.

The following table shows the overlaps of `fullbogons` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `fullbogons`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `fullbogons`.
- ` this % ` is the percentage **of this ipset (`fullbogons`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bogons](#bogons)|13|592708608|592708608|100.0%|88.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|4235823|3.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|565248|6.1%|0.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|248831|0.0%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|235129|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|151552|0.8%|0.0%|
[et_block](#et_block)|997|18338381|20480|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|890|0.2%|0.0%|
[voipbl](#voipbl)|10367|10776|319|2.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|33|2.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|15|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|9|0.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|1|0.0%|0.0%|

## ib_bluetack_badpeers

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) IPs that have been reported for bad deeds in p2p

Source is downloaded from [this link](http://list.iblocklist.com/?list=cwworuawihqvocglcoss&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Tue Jun  2 04:10:47 UTC 2015.

The ipset `ib_bluetack_badpeers` has **48134** entries, **48134** unique IPs.

The following table shows the overlaps of `ib_bluetack_badpeers` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_badpeers`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_badpeers`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_badpeers`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1172|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|406|0.0%|0.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|230|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|15|0.0%|0.0%|
[fullbogons](#fullbogons)|3686|670534424|15|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|14|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.0%|
[et_block](#et_block)|997|18338381|10|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|7|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|6|0.0%|0.0%|
[nixspam](#nixspam)|19429|19429|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|32730|32730|4|0.0%|0.0%|
[xroxy](#xroxy)|2041|2041|3|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|3|0.0%|0.0%|
[voipbl](#voipbl)|10367|10776|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15540|15540|2|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2596|2596|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13974|13974|2|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7086|7086|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5772|5772|1|0.0%|0.0%|
[proxz](#proxz)|579|579|1|0.1%|0.0%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## ib_bluetack_hijacked

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) hijacked IP-Blocks Hijacked IP space are IP blocks that are being used without permission

Source is downloaded from [this link](http://list.iblocklist.com/?list=usrcshglbiilevmyfhse&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Tue Jun  2 04:40:27 UTC 2015.

The ipset `ib_bluetack_hijacked` has **535** entries, **9177856** unique IPs.

The following table shows the overlaps of `ib_bluetack_hijacked` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_hijacked`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_hijacked`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_hijacked`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[spamhaus_drop](#spamhaus_drop)|656|18600704|7079936|38.0%|77.1%|
[et_block](#et_block)|997|18338381|7079936|38.6%|77.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2526625|0.7%|27.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|904796|0.1%|9.8%|
[fullbogons](#fullbogons)|3686|670534424|565248|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|145472|0.1%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1036|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|737|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|518|0.2%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|178|0.5%|0.0%|
[nixspam](#nixspam)|19429|19429|169|0.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7086|7086|37|0.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|27|2.1%|0.0%|
[blocklist_de](#blocklist_de)|32730|32730|26|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7653|7653|18|0.2%|0.0%|
[openbl_30d](#openbl_30d)|3244|3244|13|0.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|11|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3138|3138|11|0.3%|0.0%|
[zeus_badips](#zeus_badips)|230|230|10|4.3%|0.0%|
[zeus](#zeus)|266|266|10|3.7%|0.0%|
[openbl_7d](#openbl_7d)|999|999|9|0.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|10351|10351|7|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15540|15540|7|0.0%|0.0%|
[et_compromised](#et_compromised)|2191|2191|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|5|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1558|1558|4|0.2%|0.0%|
[shunlist](#shunlist)|1271|1271|3|0.2%|0.0%|
[et_tor](#et_tor)|6360|6360|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6392|6392|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6441|6441|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|3|1.7%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[voipbl](#voipbl)|10367|10776|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.0%|
[openbl_1d](#openbl_1d)|303|303|1|0.3%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2596|2596|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13974|13974|1|0.0%|0.0%|

## ib_bluetack_level1

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Level 1 (for use in p2p): Companies or organizations who are clearly involved with trying to stop filesharing (e.g. Baytsp, MediaDefender, Mediasentry a.o.). Companies which anti-p2p activity has been seen from. Companies that produce or have a strong financial interest in copyrighted material (e.g. music, movie, software industries a.o.). Government ranges or companies that have a strong financial interest in doing work for governments. Legal industry ranges. IPs or ranges of ISPs from which anti-p2p activity has been observed. Basically this list will block all kinds of internet connections that most people would rather not have during their internet travels.

Source is downloaded from [this link](http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Tue Jun  2 09:30:13 UTC 2015.

The ipset `ib_bluetack_level1` has **218309** entries, **764987411** unique IPs.

The following table shows the overlaps of `ib_bluetack_level1` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level1`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level1`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level1`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|16300309|4.6%|2.1%|
[et_block](#et_block)|997|18338381|2272672|12.3%|0.2%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|2272266|12.2%|0.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1354348|0.9%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904796|9.8%|0.1%|
[fullbogons](#fullbogons)|3686|670534424|235129|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|33155|6.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|13248|3.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|4700|2.6%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|1545|1.6%|0.0%|
[blocklist_de](#blocklist_de)|32730|32730|1527|4.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15540|15540|1334|8.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13974|13974|1321|9.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|558|1.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|406|0.8%|0.0%|
[nixspam](#nixspam)|19429|19429|402|2.0%|0.0%|
[voipbl](#voipbl)|10367|10776|296|2.7%|0.0%|
[openbl_60d](#openbl_60d)|7653|7653|172|2.2%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7086|7086|171|2.4%|0.0%|
[et_tor](#et_tor)|6360|6360|167|2.6%|0.0%|
[dm_tor](#dm_tor)|6392|6392|167|2.6%|0.0%|
[bm_tor](#bm_tor)|6441|6441|167|2.5%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5772|5772|122|2.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|10351|10351|113|1.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|97|6.6%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|93|1.0%|0.0%|
[openbl_30d](#openbl_30d)|3244|3244|73|2.2%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2142|2142|71|3.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|66|5.1%|0.0%|
[et_compromised](#et_compromised)|2191|2191|62|2.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|62|2.8%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|58|8.6%|0.0%|
[xroxy](#xroxy)|2041|2041|57|2.7%|0.0%|
[et_botcc](#et_botcc)|505|505|41|8.1%|0.0%|
[proxyrss](#proxyrss)|1973|1973|38|1.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3138|3138|33|1.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2596|2596|30|1.1%|0.0%|
[shunlist](#shunlist)|1271|1271|25|1.9%|0.0%|
[proxz](#proxz)|579|579|24|4.1%|0.0%|
[dshield](#dshield)|20|5120|22|0.4%|0.0%|
[openbl_7d](#openbl_7d)|999|999|21|2.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|17|4.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1558|1558|14|0.8%|0.0%|
[malc0de](#malc0de)|392|392|12|3.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|9|2.0%|0.0%|
[ciarmy](#ciarmy)|308|308|9|2.9%|0.0%|
[zeus](#zeus)|266|266|7|2.6%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[openbl_1d](#openbl_1d)|303|303|7|2.3%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|721|721|6|0.8%|0.0%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.0%|
[php_commenters](#php_commenters)|281|281|5|1.7%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[zeus_badips](#zeus_badips)|230|230|4|1.7%|0.0%|
[sslbl](#sslbl)|360|360|3|0.8%|0.0%|
[feodo](#feodo)|80|80|3|3.7%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|113|113|3|2.6%|0.0%|

## ib_bluetack_level2

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 2 (for use in p2p). General corporate ranges. Ranges used by labs or researchers. Proxies.

Source is downloaded from [this link](http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Tue Jun  2 04:40:20 UTC 2015.

The ipset `ib_bluetack_level2` has **72774** entries, **348707599** unique IPs.

The following table shows the overlaps of `ib_bluetack_level2` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level2`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level2`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level2`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|16300309|2.1%|4.6%|
[et_block](#et_block)|997|18338381|8598823|46.8%|2.4%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|8598042|46.2%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2830140|2.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2526625|27.5%|0.7%|
[fullbogons](#fullbogons)|3686|670534424|248831|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|98904|20.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|7733|2.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|7609|4.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|2510|2.7%|0.0%|
[blocklist_de](#blocklist_de)|32730|32730|1554|4.7%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15540|15540|1136|7.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13974|13974|1079|7.7%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|934|2.9%|0.0%|
[nixspam](#nixspam)|19429|19429|606|3.1%|0.0%|
[dshield](#dshield)|20|5120|512|10.0%|0.0%|
[voipbl](#voipbl)|10367|10776|432|4.0%|0.0%|
[openbl_60d](#openbl_60d)|7653|7653|341|4.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7086|7086|259|3.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|230|0.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|10351|10351|193|1.8%|0.0%|
[et_tor](#et_tor)|6360|6360|191|3.0%|0.0%|
[dm_tor](#dm_tor)|6392|6392|184|2.8%|0.0%|
[bm_tor](#bm_tor)|6441|6441|183|2.8%|0.0%|
[openbl_30d](#openbl_30d)|3244|3244|177|5.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5772|5772|175|3.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3138|3138|158|5.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|116|1.3%|0.0%|
[et_compromised](#et_compromised)|2191|2191|116|5.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|115|5.2%|0.0%|
[xroxy](#xroxy)|2041|2041|99|4.8%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2142|2142|85|3.9%|0.0%|
[proxyrss](#proxyrss)|1973|1973|70|3.5%|0.0%|
[shunlist](#shunlist)|1271|1271|69|5.4%|0.0%|
[openbl_7d](#openbl_7d)|999|999|48|4.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1558|1558|46|2.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|45|3.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2596|2596|45|1.7%|0.0%|
[php_spammers](#php_spammers)|417|417|31|7.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|28|4.1%|0.0%|
[proxz](#proxz)|579|579|27|4.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|26|2.0%|0.0%|
[malc0de](#malc0de)|392|392|24|6.1%|0.0%|
[et_botcc](#et_botcc)|505|505|22|4.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|21|5.6%|0.0%|
[openbl_1d](#openbl_1d)|303|303|14|4.6%|0.0%|
[ciarmy](#ciarmy)|308|308|11|3.5%|0.0%|
[php_dictionary](#php_dictionary)|433|433|10|2.3%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|721|721|10|1.3%|0.0%|
[zeus](#zeus)|266|266|9|3.3%|0.0%|
[php_commenters](#php_commenters)|281|281|9|3.2%|0.0%|
[zeus_badips](#zeus_badips)|230|230|8|3.4%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|7|4.0%|0.0%|
[sslbl](#sslbl)|360|360|6|1.6%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|113|113|6|5.3%|0.0%|
[feodo](#feodo)|80|80|3|3.7%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|

## ib_bluetack_level3

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 3 (for use in p2p). Many portal-type websites. ISP ranges that may be dodgy for some reason. Ranges that belong to an individual, but which have not been determined to be used by a particular company. Ranges for things that are unusual in some way. The L3 list is aka the paranoid list.

Source is downloaded from [this link](http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Tue Jun  2 04:40:34 UTC 2015.

The ipset `ib_bluetack_level3` has **17802** entries, **139104824** unique IPs.

The following table shows the overlaps of `ib_bluetack_level3` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level3`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level3`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level3`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[fullbogons](#fullbogons)|3686|670534424|4235823|0.6%|3.0%|
[bogons](#bogons)|13|592708608|4194304|0.7%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2830140|0.8%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1354348|0.1%|0.9%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|270785|55.5%|0.1%|
[et_block](#et_block)|997|18338381|196186|1.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|195904|1.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|14639|8.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|9231|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|5884|6.3%|0.0%|
[blocklist_de](#blocklist_de)|32730|32730|5500|16.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|10351|10351|2695|26.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15540|15540|2367|15.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13974|13974|2259|16.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|2085|6.6%|0.0%|
[voipbl](#voipbl)|10367|10776|1593|14.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1172|2.4%|0.0%|
[nixspam](#nixspam)|19429|19429|1006|5.1%|0.0%|
[openbl_60d](#openbl_60d)|7653|7653|744|9.7%|0.0%|
[bm_tor](#bm_tor)|6441|6441|637|9.8%|0.0%|
[dm_tor](#dm_tor)|6392|6392|634|9.9%|0.0%|
[et_tor](#et_tor)|6360|6360|628|9.8%|0.0%|
[dshield](#dshield)|20|5120|512|10.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7086|7086|486|6.8%|0.0%|
[openbl_30d](#openbl_30d)|3244|3244|313|9.6%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|246|2.7%|0.0%|
[et_compromised](#et_compromised)|2191|2191|219|9.9%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|214|9.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3138|3138|178|5.6%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2596|2596|165|6.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5772|5772|162|2.8%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|146|11.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1558|1558|137|8.7%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|125|33.6%|0.0%|
[openbl_7d](#openbl_7d)|999|999|117|11.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|110|7.5%|0.0%|
[shunlist](#shunlist)|1271|1271|101|7.9%|0.0%|
[xroxy](#xroxy)|2041|2041|87|4.2%|0.0%|
[et_botcc](#et_botcc)|505|505|78|15.4%|0.0%|
[proxyrss](#proxyrss)|1973|1973|68|3.4%|0.0%|
[malc0de](#malc0de)|392|392|67|17.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|721|721|63|8.7%|0.0%|
[proxz](#proxz)|579|579|52|8.9%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|51|7.5%|0.0%|
[ciarmy](#ciarmy)|308|308|51|16.5%|0.0%|
[openbl_1d](#openbl_1d)|303|303|48|15.8%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2142|2142|47|2.1%|0.0%|
[php_spammers](#php_spammers)|417|417|26|6.2%|0.0%|
[php_dictionary](#php_dictionary)|433|433|24|5.5%|0.0%|
[sslbl](#sslbl)|360|360|23|6.3%|0.0%|
[zeus](#zeus)|266|266|19|7.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|16|9.1%|0.0%|
[php_harvesters](#php_harvesters)|257|257|15|5.8%|0.0%|
[php_commenters](#php_commenters)|281|281|15|5.3%|0.0%|
[zeus_badips](#zeus_badips)|230|230|14|6.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|113|113|13|11.5%|0.0%|
[feodo](#feodo)|80|80|7|8.7%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|

## ib_bluetack_proxies

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Open Proxies IPs list (without TOR)

Source is downloaded from [this link](http://list.iblocklist.com/?list=xoebmbyexwuiogmbyprb&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Tue Jun  2 04:40:04 UTC 2015.

The ipset `ib_bluetack_proxies` has **673** entries, **673** unique IPs.

The following table shows the overlaps of `ib_bluetack_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_proxies`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|58|0.0%|8.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|51|0.0%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|28|0.0%|4.1%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|22|0.0%|3.2%|
[xroxy](#xroxy)|2041|2041|13|0.6%|1.9%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|11|0.0%|1.6%|
[ri_web_proxies](#ri_web_proxies)|5772|5772|11|0.1%|1.6%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|11|0.0%|1.6%|
[proxyrss](#proxyrss)|1973|1973|9|0.4%|1.3%|
[stopforumspam_1d](#stopforumspam_1d)|7086|7086|7|0.0%|1.0%|
[ri_connect_proxies](#ri_connect_proxies)|2142|2142|6|0.2%|0.8%|
[proxz](#proxz)|579|579|3|0.5%|0.4%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|2|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|2|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.2%|
[et_block](#et_block)|997|18338381|2|0.0%|0.2%|
[blocklist_de](#blocklist_de)|32730|32730|2|0.0%|0.2%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.1%|
[nixspam](#nixspam)|19429|19429|1|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|15540|15540|1|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3138|3138|1|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|1|0.0%|0.1%|

## ib_bluetack_spyware

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) known malicious SPYWARE and ADWARE IP Address ranges

Source is downloaded from [this link](http://list.iblocklist.com/?list=llvtlsjyoyiczbkjsxpf&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Tue Jun  2 04:10:18 UTC 2015.

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
[spamhaus_drop](#spamhaus_drop)|656|18600704|1037|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1036|0.0%|0.3%|
[fullbogons](#fullbogons)|3686|670534424|890|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|289|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|48|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|26|2.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|21|0.0%|0.0%|
[dm_tor](#dm_tor)|6392|6392|21|0.3%|0.0%|
[bm_tor](#bm_tor)|6441|6441|21|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|19|1.3%|0.0%|
[et_tor](#et_tor)|6360|6360|19|0.2%|0.0%|
[nixspam](#nixspam)|19429|19429|15|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|14|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7086|7086|11|0.1%|0.0%|
[blocklist_de](#blocklist_de)|32730|32730|9|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5772|5772|5|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7653|7653|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|5|1.3%|0.0%|
[voipbl](#voipbl)|10367|10776|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3244|3244|4|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[malc0de](#malc0de)|392|392|3|0.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|10351|10351|3|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3138|3138|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13974|13974|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|2|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|113|113|2|1.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2596|2596|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[xroxy](#xroxy)|2041|2041|1|0.0%|0.0%|
[sslbl](#sslbl)|360|360|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|1|0.0%|0.0%|
[shunlist](#shunlist)|1271|1271|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1973|1973|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|
[openbl_7d](#openbl_7d)|999|999|1|0.1%|0.0%|
[feodo](#feodo)|80|80|1|1.2%|0.0%|
[et_compromised](#et_compromised)|2191|2191|1|0.0%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15540|15540|1|0.0%|0.0%|

## ib_bluetack_webexploit

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) web server hack and exploit attempts

Source is downloaded from [this link](http://list.iblocklist.com/?list=ghlzqtqxnzctvvajwwag&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Tue Jun  2 04:10:03 UTC 2015.

The ipset `ib_bluetack_webexploit` has **1460** entries, **1460** unique IPs.

The following table shows the overlaps of `ib_bluetack_webexploit` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_webexploit`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_webexploit`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_webexploit`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|110|0.0%|7.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|97|0.0%|6.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|45|0.0%|3.0%|
[fullbogons](#fullbogons)|3686|670534424|33|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|19|0.0%|1.3%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|8|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|6|0.0%|0.4%|
[et_block](#et_block)|997|18338381|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|3|0.2%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|2|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7653|7653|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|3244|3244|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7086|7086|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5772|5772|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|999|999|1|0.1%|0.0%|
[nixspam](#nixspam)|19429|19429|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2191|2191|1|0.0%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|10351|10351|1|0.0%|0.0%|
[blocklist_de](#blocklist_de)|32730|32730|1|0.0%|0.0%|

## malc0de

[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days

Source is downloaded from [this link](http://malc0de.com/bl/IP_Blacklist.txt).

The last time downloaded was found to be dated: Tue Jun  2 13:17:02 UTC 2015.

The ipset `malc0de` has **392** entries, **392** unique IPs.

The following table shows the overlaps of `malc0de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `malc0de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `malc0de`.
- ` this % ` is the percentage **of this ipset (`malc0de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|67|0.0%|17.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|24|0.0%|6.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|12|0.0%|3.0%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|12|0.0%|3.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|4|0.0%|1.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|4|0.3%|1.0%|
[et_block](#et_block)|997|18338381|4|0.0%|1.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.7%|
[cleanmx_viruses](#cleanmx_viruses)|11|11|2|18.1%|0.5%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|1|0.0%|0.2%|
[dshield](#dshield)|20|5120|1|0.0%|0.2%|

## malwaredomainlist

[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses

Source is downloaded from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt).

The last time downloaded was found to be dated: Tue Jun  2 07:56:22 UTC 2015.

The ipset `malwaredomainlist` has **1283** entries, **1283** unique IPs.

The following table shows the overlaps of `malwaredomainlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `malwaredomainlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `malwaredomainlist`.
- ` this % ` is the percentage **of this ipset (`malwaredomainlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|146|0.0%|11.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|66|0.0%|5.1%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|29|0.0%|2.2%|
[et_block](#et_block)|997|18338381|29|0.0%|2.2%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|27|0.3%|2.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|26|0.0%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|26|0.0%|2.0%|
[fullbogons](#fullbogons)|3686|670534424|9|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|6|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|4|0.0%|0.3%|
[malc0de](#malc0de)|392|392|4|1.0%|0.3%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7086|7086|1|0.0%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|11|11|1|9.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|10351|10351|1|0.0%|0.0%|
[blocklist_de](#blocklist_de)|32730|32730|1|0.0%|0.0%|

## maxmind_proxy_fraud

[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.

Source is downloaded from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list).

The last time downloaded was found to be dated: Tue Jun  2 23:54:19 UTC 2015.

The ipset `maxmind_proxy_fraud` has **372** entries, **372** unique IPs.

The following table shows the overlaps of `maxmind_proxy_fraud` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `maxmind_proxy_fraud`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `maxmind_proxy_fraud`.
- ` this % ` is the percentage **of this ipset (`maxmind_proxy_fraud`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|232|0.2%|62.3%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|200|0.6%|53.7%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|178|2.0%|47.8%|
[dm_tor](#dm_tor)|6392|6392|170|2.6%|45.6%|
[bm_tor](#bm_tor)|6441|6441|170|2.6%|45.6%|
[et_tor](#et_tor)|6360|6360|169|2.6%|45.4%|
[stopforumspam_1d](#stopforumspam_1d)|7086|7086|153|2.1%|41.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|125|0.0%|33.6%|
[php_commenters](#php_commenters)|281|281|28|9.9%|7.5%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|25|0.0%|6.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|21|0.0%|5.6%|
[openbl_60d](#openbl_60d)|7653|7653|18|0.2%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|17|0.0%|4.5%|
[php_harvesters](#php_harvesters)|257|257|6|2.3%|1.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|1.3%|
[ri_web_proxies](#ri_web_proxies)|5772|5772|4|0.0%|1.0%|
[php_spammers](#php_spammers)|417|417|4|0.9%|1.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|1.0%|
[shunlist](#shunlist)|1271|1271|2|0.1%|0.5%|
[xroxy](#xroxy)|2041|2041|1|0.0%|0.2%|
[voipbl](#voipbl)|10367|10776|1|0.0%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2142|2142|1|0.0%|0.2%|
[dshield](#dshield)|20|5120|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|15540|15540|1|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|13974|13974|1|0.0%|0.2%|
[blocklist_de](#blocklist_de)|32730|32730|1|0.0%|0.2%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Wed Jun  3 01:30:02 UTC 2015.

The ipset `nixspam` has **19429** entries, **19429** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1006|0.0%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|606|0.0%|3.1%|
[blocklist_de](#blocklist_de)|32730|32730|501|1.5%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|402|0.0%|2.0%|
[blocklist_de_mail](#blocklist_de_mail)|15540|15540|375|2.4%|1.9%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|228|2.5%|1.1%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|210|0.2%|1.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|169|0.0%|0.8%|
[et_block](#et_block)|997|18338381|169|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|168|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|125|0.3%|0.6%|
[ri_web_proxies](#ri_web_proxies)|5772|5772|85|1.4%|0.4%|
[xroxy](#xroxy)|2041|2041|70|3.4%|0.3%|
[php_dictionary](#php_dictionary)|433|433|69|15.9%|0.3%|
[php_spammers](#php_spammers)|417|417|57|13.6%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7086|7086|49|0.6%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|10351|10351|49|0.4%|0.2%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|39|0.0%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3138|3138|36|1.1%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2596|2596|27|1.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13974|13974|27|0.1%|0.1%|
[proxz](#proxz)|579|579|24|4.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|15|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|721|721|14|1.9%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2142|2142|13|0.6%|0.0%|
[proxyrss](#proxyrss)|1973|1973|11|0.5%|0.0%|
[openbl_60d](#openbl_60d)|7653|7653|11|0.1%|0.0%|
[php_commenters](#php_commenters)|281|281|10|3.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1558|1558|6|0.3%|0.0%|
[php_harvesters](#php_harvesters)|257|257|5|1.9%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|5|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3244|3244|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[et_tor](#et_tor)|6360|6360|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6392|6392|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6441|6441|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|1|0.5%|0.0%|

## openbl_1d

[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_1days.txt).

The last time downloaded was found to be dated: Wed Jun  3 01:32:00 UTC 2015.

The ipset `openbl_1d` has **303** entries, **303** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7653|7653|260|3.3%|85.8%|
[openbl_30d](#openbl_30d)|3244|3244|253|7.7%|83.4%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|253|0.1%|83.4%|
[openbl_7d](#openbl_7d)|999|999|249|24.9%|82.1%|
[blocklist_de](#blocklist_de)|32730|32730|212|0.6%|69.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|10351|10351|206|1.9%|67.9%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|79|3.6%|26.0%|
[shunlist](#shunlist)|1271|1271|76|5.9%|25.0%|
[et_compromised](#et_compromised)|2191|2191|70|3.1%|23.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|48|0.0%|15.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|18|10.3%|5.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|14|0.0%|4.6%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|13|0.0%|4.2%|
[et_block](#et_block)|997|18338381|13|0.0%|4.2%|
[dshield](#dshield)|20|5120|12|0.2%|3.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|7|0.0%|2.3%|
[blocklist_de_mail](#blocklist_de_mail)|15540|15540|5|0.0%|1.6%|
[blocklist_de_imap](#blocklist_de_imap)|1558|1558|4|0.2%|1.3%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|3|0.0%|0.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|13974|13974|1|0.0%|0.3%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt).

The last time downloaded was found to be dated: Tue Jun  2 23:42:00 UTC 2015.

The ipset `openbl_30d` has **3244** entries, **3244** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7653|7653|3244|42.3%|100.0%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|3224|1.8%|99.3%|
[et_compromised](#et_compromised)|2191|2191|1227|56.0%|37.8%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|1222|56.2%|37.6%|
[openbl_7d](#openbl_7d)|999|999|999|100.0%|30.7%|
[blocklist_de](#blocklist_de)|32730|32730|877|2.6%|27.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|10351|10351|832|8.0%|25.6%|
[shunlist](#shunlist)|1271|1271|585|46.0%|18.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|313|0.0%|9.6%|
[openbl_1d](#openbl_1d)|303|303|253|83.4%|7.7%|
[et_block](#et_block)|997|18338381|179|0.0%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|177|0.0%|5.4%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|174|0.0%|5.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|73|0.0%|2.2%|
[dshield](#dshield)|20|5120|67|1.3%|2.0%|
[blocklist_de_mail](#blocklist_de_mail)|15540|15540|41|0.2%|1.2%|
[blocklist_de_imap](#blocklist_de_imap)|1558|1558|34|2.1%|1.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|25|14.3%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|13|0.0%|0.4%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|6|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.1%|
[voipbl](#voipbl)|10367|10776|3|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|3|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|3|0.0%|0.0%|
[zeus](#zeus)|266|266|2|0.7%|0.0%|
[nixspam](#nixspam)|19429|19429|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|721|721|2|0.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13974|13974|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7086|7086|1|0.0%|0.0%|
[ciarmy](#ciarmy)|308|308|1|0.3%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt).

The last time downloaded was found to be dated: Tue Jun  2 23:42:00 UTC 2015.

The ipset `openbl_60d` has **7653** entries, **7653** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|174882|174882|7627|4.3%|99.6%|
[openbl_30d](#openbl_30d)|3244|3244|3244|100.0%|42.3%|
[blocklist_de](#blocklist_de)|32730|32730|1665|5.0%|21.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|10351|10351|1607|15.5%|20.9%|
[et_compromised](#et_compromised)|2191|2191|1323|60.3%|17.2%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|1303|59.9%|17.0%|
[openbl_7d](#openbl_7d)|999|999|999|100.0%|13.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|744|0.0%|9.7%|
[shunlist](#shunlist)|1271|1271|602|47.3%|7.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|341|0.0%|4.4%|
[openbl_1d](#openbl_1d)|303|303|260|85.8%|3.3%|
[et_block](#et_block)|997|18338381|244|0.0%|3.1%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|239|0.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|172|0.0%|2.2%|
[dshield](#dshield)|20|5120|76|1.4%|0.9%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|54|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|15540|15540|47|0.3%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|1558|1558|39|2.5%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|28|16.0%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|25|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|25|0.2%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7086|7086|22|0.3%|0.2%|
[dm_tor](#dm_tor)|6392|6392|20|0.3%|0.2%|
[bm_tor](#bm_tor)|6441|6441|20|0.3%|0.2%|
[et_tor](#et_tor)|6360|6360|19|0.2%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|18|0.0%|0.2%|
[nixspam](#nixspam)|19429|19429|11|0.0%|0.1%|
[voipbl](#voipbl)|10367|10776|9|0.0%|0.1%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|6|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3138|3138|5|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|721|721|3|0.4%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13974|13974|3|0.0%|0.0%|
[zeus](#zeus)|266|266|2|0.7%|0.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[ciarmy](#ciarmy)|308|308|1|0.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2596|2596|1|0.0%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt).

The last time downloaded was found to be dated: Tue Jun  2 23:42:00 UTC 2015.

The ipset `openbl_7d` has **999** entries, **999** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7653|7653|999|13.0%|100.0%|
[openbl_30d](#openbl_30d)|3244|3244|999|30.7%|100.0%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|987|0.5%|98.7%|
[blocklist_de](#blocklist_de)|32730|32730|584|1.7%|58.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|10351|10351|562|5.4%|56.2%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|519|23.8%|51.9%|
[et_compromised](#et_compromised)|2191|2191|509|23.2%|50.9%|
[shunlist](#shunlist)|1271|1271|399|31.3%|39.9%|
[openbl_1d](#openbl_1d)|303|303|249|82.1%|24.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|117|0.0%|11.7%|
[et_block](#et_block)|997|18338381|87|0.0%|8.7%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|85|0.0%|8.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|48|0.0%|4.8%|
[dshield](#dshield)|20|5120|42|0.8%|4.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|24|13.7%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|21|0.0%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|15540|15540|20|0.1%|2.0%|
[blocklist_de_imap](#blocklist_de_imap)|1558|1558|17|1.0%|1.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|9|0.0%|0.9%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|5|0.0%|0.5%|
[voipbl](#voipbl)|10367|10776|3|0.0%|0.3%|
[zeus](#zeus)|266|266|1|0.3%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|1|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.1%|
[ciarmy](#ciarmy)|308|308|1|0.3%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|721|721|1|0.1%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13974|13974|1|0.0%|0.1%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Wed Jun  3 01:09:22 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|997|18338381|12|0.0%|92.3%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|11|0.1%|84.6%|
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
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|206|0.2%|73.3%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|163|0.5%|58.0%|
[stopforumspam_1d](#stopforumspam_1d)|7086|7086|107|1.5%|38.0%|
[blocklist_de](#blocklist_de)|32730|32730|62|0.1%|22.0%|
[blocklist_de_bots](#blocklist_de_bots)|3138|3138|48|1.5%|17.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|37|0.4%|13.1%|
[php_spammers](#php_spammers)|417|417|32|7.6%|11.3%|
[et_tor](#et_tor)|6360|6360|29|0.4%|10.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|29|16.6%|10.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|28|7.5%|9.9%|
[dm_tor](#dm_tor)|6392|6392|28|0.4%|9.9%|
[bm_tor](#bm_tor)|6441|6441|28|0.4%|9.9%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|24|0.0%|8.5%|
[et_block](#et_block)|997|18338381|24|0.0%|8.5%|
[blocklist_de_apache](#blocklist_de_apache)|13974|13974|24|0.1%|8.5%|
[php_dictionary](#php_dictionary)|433|433|22|5.0%|7.8%|
[blocklist_de_mail](#blocklist_de_mail)|15540|15540|20|0.1%|7.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|5.3%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|14|0.0%|4.9%|
[ri_web_proxies](#ri_web_proxies)|5772|5772|11|0.1%|3.9%|
[nixspam](#nixspam)|19429|19429|10|0.0%|3.5%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.2%|
[openbl_60d](#openbl_60d)|7653|7653|8|0.1%|2.8%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|7|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|1.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2596|2596|5|0.1%|1.7%|
[xroxy](#xroxy)|2041|2041|3|0.1%|1.0%|
[proxz](#proxz)|579|579|3|0.5%|1.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.3%|
[zeus](#zeus)|266|266|1|0.3%|0.3%|
[proxyrss](#proxyrss)|1973|1973|1|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|
[dshield](#dshield)|20|5120|1|0.0%|0.3%|

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
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|85|0.0%|19.6%|
[php_spammers](#php_spammers)|417|417|84|20.1%|19.3%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|69|0.2%|15.9%|
[nixspam](#nixspam)|19429|19429|69|0.3%|15.9%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|63|0.7%|14.5%|
[blocklist_de](#blocklist_de)|32730|32730|54|0.1%|12.4%|
[blocklist_de_mail](#blocklist_de_mail)|15540|15540|38|0.2%|8.7%|
[ri_web_proxies](#ri_web_proxies)|5772|5772|33|0.5%|7.6%|
[xroxy](#xroxy)|2041|2041|24|1.1%|5.5%|
[stopforumspam_1d](#stopforumspam_1d)|7086|7086|24|0.3%|5.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|24|0.0%|5.5%|
[php_commenters](#php_commenters)|281|281|22|7.8%|5.0%|
[blocklist_de_bots](#blocklist_de_bots)|3138|3138|14|0.4%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|10|0.0%|2.3%|
[proxz](#proxz)|579|579|9|1.5%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|9|0.0%|2.0%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|7|0.0%|1.6%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|4|0.0%|0.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.9%|
[et_tor](#et_tor)|6360|6360|4|0.0%|0.9%|
[et_block](#et_block)|997|18338381|4|0.0%|0.9%|
[dm_tor](#dm_tor)|6392|6392|4|0.0%|0.9%|
[bm_tor](#bm_tor)|6441|6441|4|0.0%|0.9%|
[ri_connect_proxies](#ri_connect_proxies)|2142|2142|3|0.1%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|2|1.1%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2596|2596|2|0.0%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|13974|13974|2|0.0%|0.4%|
[proxyrss](#proxyrss)|1973|1973|1|0.0%|0.2%|
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
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|62|0.0%|24.1%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|48|0.1%|18.6%|
[stopforumspam_1d](#stopforumspam_1d)|7086|7086|33|0.4%|12.8%|
[blocklist_de](#blocklist_de)|32730|32730|24|0.0%|9.3%|
[blocklist_de_bots](#blocklist_de_bots)|3138|3138|18|0.5%|7.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|5.8%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|9|0.1%|3.5%|
[php_commenters](#php_commenters)|281|281|9|3.2%|3.5%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|9|0.0%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|7|0.0%|2.7%|
[dm_tor](#dm_tor)|6392|6392|7|0.1%|2.7%|
[bm_tor](#bm_tor)|6441|6441|7|0.1%|2.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|6|1.6%|2.3%|
[et_tor](#et_tor)|6360|6360|6|0.0%|2.3%|
[nixspam](#nixspam)|19429|19429|5|0.0%|1.9%|
[blocklist_de_ftp](#blocklist_de_ftp)|721|721|5|0.6%|1.9%|
[xroxy](#xroxy)|2041|2041|2|0.0%|0.7%|
[openbl_60d](#openbl_60d)|7653|7653|2|0.0%|0.7%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|2|1.1%|0.7%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|1|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|1|0.0%|0.3%|
[ri_web_proxies](#ri_web_proxies)|5772|5772|1|0.0%|0.3%|
[proxyrss](#proxyrss)|1973|1973|1|0.0%|0.3%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.3%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|
[fullbogons](#fullbogons)|3686|670534424|1|0.0%|0.3%|
[et_block](#et_block)|997|18338381|1|0.0%|0.3%|
[bogons](#bogons)|13|592708608|1|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|15540|15540|1|0.0%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|13974|13974|1|0.0%|0.3%|

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
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|100|0.1%|23.9%|
[php_dictionary](#php_dictionary)|433|433|84|19.3%|20.1%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|71|0.2%|17.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|59|0.6%|14.1%|
[nixspam](#nixspam)|19429|19429|57|0.2%|13.6%|
[blocklist_de](#blocklist_de)|32730|32730|47|0.1%|11.2%|
[php_commenters](#php_commenters)|281|281|32|11.3%|7.6%|
[blocklist_de_mail](#blocklist_de_mail)|15540|15540|32|0.2%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|31|0.0%|7.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|26|0.0%|6.2%|
[ri_web_proxies](#ri_web_proxies)|5772|5772|25|0.4%|5.9%|
[xroxy](#xroxy)|2041|2041|20|0.9%|4.7%|
[stopforumspam_1d](#stopforumspam_1d)|7086|7086|20|0.2%|4.7%|
[blocklist_de_bots](#blocklist_de_bots)|3138|3138|11|0.3%|2.6%|
[proxz](#proxz)|579|579|9|1.5%|2.1%|
[et_tor](#et_tor)|6360|6360|6|0.0%|1.4%|
[dm_tor](#dm_tor)|6392|6392|6|0.0%|1.4%|
[bm_tor](#bm_tor)|6441|6441|6|0.0%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|1.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.9%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2596|2596|4|0.1%|0.9%|
[blocklist_de_apache](#blocklist_de_apache)|13974|13974|4|0.0%|0.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|3|1.7%|0.7%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|3|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|2|0.0%|0.4%|
[ri_connect_proxies](#ri_connect_proxies)|2142|2142|2|0.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[et_block](#et_block)|997|18338381|2|0.0%|0.4%|
[proxyrss](#proxyrss)|1973|1973|1|0.0%|0.2%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.2%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Tue Jun  2 23:31:35 UTC 2015.

The ipset `proxyrss` has **1973** entries, **1973** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|974|1.0%|49.3%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|700|2.2%|35.4%|
[ri_web_proxies](#ri_web_proxies)|5772|5772|696|12.0%|35.2%|
[stopforumspam_1d](#stopforumspam_1d)|7086|7086|502|7.0%|25.4%|
[xroxy](#xroxy)|2041|2041|480|23.5%|24.3%|
[ri_connect_proxies](#ri_connect_proxies)|2142|2142|269|12.5%|13.6%|
[blocklist_de](#blocklist_de)|32730|32730|241|0.7%|12.2%|
[blocklist_de_bots](#blocklist_de_bots)|3138|3138|238|7.5%|12.0%|
[proxz](#proxz)|579|579|198|34.1%|10.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|70|0.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|68|0.0%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|38|0.0%|1.9%|
[nixspam](#nixspam)|19429|19429|11|0.0%|0.5%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|9|1.3%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|7|4.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|4|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|10351|10351|2|0.0%|0.1%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.0%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_tor](#et_tor)|6360|6360|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2191|2191|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6392|6392|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6441|6441|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15540|15540|1|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Tue Jun  2 23:31:41 UTC 2015.

The ipset `proxz` has **579** entries, **579** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|357|0.3%|61.6%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|295|0.9%|50.9%|
[xroxy](#xroxy)|2041|2041|261|12.7%|45.0%|
[ri_web_proxies](#ri_web_proxies)|5772|5772|247|4.2%|42.6%|
[proxyrss](#proxyrss)|1973|1973|198|10.0%|34.1%|
[stopforumspam_1d](#stopforumspam_1d)|7086|7086|136|1.9%|23.4%|
[blocklist_de](#blocklist_de)|32730|32730|114|0.3%|19.6%|
[blocklist_de_bots](#blocklist_de_bots)|3138|3138|95|3.0%|16.4%|
[ri_connect_proxies](#ri_connect_proxies)|2142|2142|85|3.9%|14.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|52|0.0%|8.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|27|0.0%|4.6%|
[nixspam](#nixspam)|19429|19429|24|0.1%|4.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|24|0.0%|4.1%|
[blocklist_de_mail](#blocklist_de_mail)|15540|15540|17|0.1%|2.9%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|15|0.1%|2.5%|
[php_spammers](#php_spammers)|417|417|9|2.1%|1.5%|
[php_dictionary](#php_dictionary)|433|433|9|2.0%|1.5%|
[php_commenters](#php_commenters)|281|281|3|1.0%|0.5%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|3|0.4%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|3|1.7%|0.5%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|3|0.0%|0.5%|
[et_compromised](#et_compromised)|2191|2191|2|0.0%|0.3%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|2|0.0%|0.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|10351|10351|2|0.0%|0.3%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.1%|
[et_tor](#et_tor)|6360|6360|1|0.0%|0.1%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Tue Jun  2 21:12:27 UTC 2015.

The ipset `ri_connect_proxies` has **2142** entries, **2142** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|1266|1.3%|59.1%|
[ri_web_proxies](#ri_web_proxies)|5772|5772|884|15.3%|41.2%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|689|2.1%|32.1%|
[xroxy](#xroxy)|2041|2041|332|16.2%|15.4%|
[proxyrss](#proxyrss)|1973|1973|269|13.6%|12.5%|
[stopforumspam_1d](#stopforumspam_1d)|7086|7086|158|2.2%|7.3%|
[proxz](#proxz)|579|579|85|14.6%|3.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|85|0.0%|3.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|71|0.0%|3.3%|
[blocklist_de](#blocklist_de)|32730|32730|69|0.2%|3.2%|
[blocklist_de_bots](#blocklist_de_bots)|3138|3138|67|2.1%|3.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|47|0.0%|2.1%|
[nixspam](#nixspam)|19429|19429|13|0.0%|0.6%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.2%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|4|0.0%|0.1%|
[php_dictionary](#php_dictionary)|433|433|3|0.6%|0.1%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[et_tor](#et_tor)|6360|6360|2|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[dm_tor](#dm_tor)|6392|6392|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6441|6441|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|10351|10351|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15540|15540|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Tue Jun  2 21:10:52 UTC 2015.

The ipset `ri_web_proxies` has **5772** entries, **5772** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|2855|3.0%|49.4%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|1755|5.6%|30.4%|
[ri_connect_proxies](#ri_connect_proxies)|2142|2142|884|41.2%|15.3%|
[xroxy](#xroxy)|2041|2041|848|41.5%|14.6%|
[proxyrss](#proxyrss)|1973|1973|696|35.2%|12.0%|
[stopforumspam_1d](#stopforumspam_1d)|7086|7086|526|7.4%|9.1%|
[blocklist_de](#blocklist_de)|32730|32730|355|1.0%|6.1%|
[blocklist_de_bots](#blocklist_de_bots)|3138|3138|314|10.0%|5.4%|
[proxz](#proxz)|579|579|247|42.6%|4.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|175|0.0%|3.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|162|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|122|0.0%|2.1%|
[nixspam](#nixspam)|19429|19429|85|0.4%|1.4%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|59|0.6%|1.0%|
[blocklist_de_mail](#blocklist_de_mail)|15540|15540|41|0.2%|0.7%|
[php_dictionary](#php_dictionary)|433|433|33|7.6%|0.5%|
[php_spammers](#php_spammers)|417|417|25|5.9%|0.4%|
[php_commenters](#php_commenters)|281|281|11|3.9%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|5|2.8%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.0%|
[et_tor](#et_tor)|6360|6360|4|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6392|6392|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6441|6441|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Tue Jun  2 22:30:03 UTC 2015.

The ipset `shunlist` has **1271** entries, **1271** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|174882|174882|1261|0.7%|99.2%|
[openbl_60d](#openbl_60d)|7653|7653|602|7.8%|47.3%|
[openbl_30d](#openbl_30d)|3244|3244|585|18.0%|46.0%|
[et_compromised](#et_compromised)|2191|2191|504|23.0%|39.6%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|504|23.1%|39.6%|
[blocklist_de](#blocklist_de)|32730|32730|416|1.2%|32.7%|
[openbl_7d](#openbl_7d)|999|999|399|39.9%|31.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|10351|10351|377|3.6%|29.6%|
[et_block](#et_block)|997|18338381|107|0.0%|8.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|101|0.0%|7.9%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|99|0.0%|7.7%|
[openbl_1d](#openbl_1d)|303|303|76|25.0%|5.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|69|0.0%|5.4%|
[sslbl](#sslbl)|360|360|55|15.2%|4.3%|
[dshield](#dshield)|20|5120|40|0.7%|3.1%|
[blocklist_de_apache](#blocklist_de_apache)|13974|13974|33|0.2%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|25|0.0%|1.9%|
[ciarmy](#ciarmy)|308|308|24|7.7%|1.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|20|11.4%|1.5%|
[voipbl](#voipbl)|10367|10776|12|0.1%|0.9%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|5|0.0%|0.3%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|5|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|15540|15540|5|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|4|0.0%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|3|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7086|7086|2|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|1558|1558|2|0.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_tor](#et_tor)|6360|6360|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6392|6392|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6441|6441|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|721|721|1|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2596|2596|1|0.0%|0.0%|

## snort_ipfilter

[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)

Source is downloaded from [this link](http://labs.snort.org/feeds/ip-filter.blf).

The last time downloaded was found to be dated: Wed Jun  3 01:30:00 UTC 2015.

The ipset `snort_ipfilter` has **8876** entries, **8876** unique IPs.

The following table shows the overlaps of `snort_ipfilter` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `snort_ipfilter`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `snort_ipfilter`.
- ` this % ` is the percentage **of this ipset (`snort_ipfilter`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6441|6441|1080|16.7%|12.1%|
[et_tor](#et_tor)|6360|6360|1078|16.9%|12.1%|
[dm_tor](#dm_tor)|6392|6392|1076|16.8%|12.1%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|814|0.8%|9.1%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|614|1.9%|6.9%|
[stopforumspam_1d](#stopforumspam_1d)|7086|7086|327|4.6%|3.6%|
[et_block](#et_block)|997|18338381|299|0.0%|3.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|246|0.0%|2.7%|
[nixspam](#nixspam)|19429|19429|228|1.1%|2.5%|
[zeus](#zeus)|266|266|227|85.3%|2.5%|
[zeus_badips](#zeus_badips)|230|230|202|87.8%|2.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|178|47.8%|2.0%|
[blocklist_de](#blocklist_de)|32730|32730|168|0.5%|1.8%|
[blocklist_de_mail](#blocklist_de_mail)|15540|15540|133|0.8%|1.4%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|119|0.0%|1.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|116|0.0%|1.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|93|0.0%|1.0%|
[feodo](#feodo)|80|80|64|80.0%|0.7%|
[php_dictionary](#php_dictionary)|433|433|63|14.5%|0.7%|
[ri_web_proxies](#ri_web_proxies)|5772|5772|59|1.0%|0.6%|
[php_spammers](#php_spammers)|417|417|59|14.1%|0.6%|
[xroxy](#xroxy)|2041|2041|50|2.4%|0.5%|
[php_commenters](#php_commenters)|281|281|37|13.1%|0.4%|
[sslbl](#sslbl)|360|360|27|7.5%|0.3%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|27|2.1%|0.3%|
[blocklist_de_bots](#blocklist_de_bots)|3138|3138|26|0.8%|0.2%|
[openbl_60d](#openbl_60d)|7653|7653|25|0.3%|0.2%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|20|0.0%|0.2%|
[proxz](#proxz)|579|579|15|2.5%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|14|0.0%|0.1%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13974|13974|9|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|6|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2596|2596|6|0.2%|0.0%|
[shunlist](#shunlist)|1271|1271|4|0.3%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2142|2142|4|0.1%|0.0%|
[proxyrss](#proxyrss)|1973|1973|4|0.2%|0.0%|
[openbl_30d](#openbl_30d)|3244|3244|3|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1558|1558|3|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_compromised](#et_compromised)|2191|2191|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|10351|10351|2|0.0%|0.0%|
[openbl_7d](#openbl_7d)|999|999|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|1|0.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|721|721|1|0.1%|0.0%|

## spamhaus_drop

[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**

Source is downloaded from [this link](http://www.spamhaus.org/drop/drop.txt).

The last time downloaded was found to be dated: Mon Jun  1 19:29:21 UTC 2015.

The ipset `spamhaus_drop` has **656** entries, **18600704** unique IPs.

The following table shows the overlaps of `spamhaus_drop` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `spamhaus_drop`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `spamhaus_drop`.
- ` this % ` is the percentage **of this ipset (`spamhaus_drop`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|997|18338381|18333440|99.9%|98.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8598042|2.4%|46.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7079936|77.1%|38.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|2272266|0.2%|12.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|195904|0.1%|1.0%|
[fullbogons](#fullbogons)|3686|670534424|151552|0.0%|0.8%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|1628|0.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|998|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|512|0.1%|0.0%|
[dshield](#dshield)|20|5120|512|10.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|340|1.0%|0.0%|
[openbl_60d](#openbl_60d)|7653|7653|239|3.1%|0.0%|
[openbl_30d](#openbl_30d)|3244|3244|174|5.3%|0.0%|
[nixspam](#nixspam)|19429|19429|168|0.8%|0.0%|
[blocklist_de](#blocklist_de)|32730|32730|158|0.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|10351|10351|112|1.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7086|7086|103|1.4%|0.0%|
[et_compromised](#et_compromised)|2191|2191|102|4.6%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|100|4.6%|0.0%|
[shunlist](#shunlist)|1271|1271|99|7.7%|0.0%|
[openbl_7d](#openbl_7d)|999|999|85|8.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|29|2.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15540|15540|25|0.1%|0.0%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|20|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3138|3138|18|0.5%|0.0%|
[zeus_badips](#zeus_badips)|230|230|16|6.9%|0.0%|
[zeus](#zeus)|266|266|16|6.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1558|1558|15|0.9%|0.0%|
[voipbl](#voipbl)|10367|10776|14|0.1%|0.0%|
[openbl_1d](#openbl_1d)|303|303|13|4.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|7|4.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[malc0de](#malc0de)|392|392|4|1.0%|0.0%|
[sslbl](#sslbl)|360|360|3|0.8%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6360|6360|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6392|6392|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6441|6441|2|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2596|2596|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13974|13974|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|113|113|1|0.8%|0.0%|

## spamhaus_edrop

[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**

Source is downloaded from [this link](http://www.spamhaus.org/drop/edrop.txt).

The last time downloaded was found to be dated: Mon Jun  1 16:15:11 UTC 2015.

The ipset `spamhaus_edrop` has **57** entries, **487168** unique IPs.

The following table shows the overlaps of `spamhaus_edrop` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `spamhaus_edrop`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `spamhaus_edrop`.
- ` this % ` is the percentage **of this ipset (`spamhaus_edrop`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|270785|0.1%|55.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|98904|0.0%|20.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|33155|0.0%|6.8%|
[et_block](#et_block)|997|18338381|517|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|512|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|271|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|98|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|27|0.0%|0.0%|
[blocklist_de](#blocklist_de)|32730|32730|13|0.0%|0.0%|
[php_commenters](#php_commenters)|281|281|7|2.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|6|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7653|7653|6|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3244|3244|6|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|6|3.4%|0.0%|
[zeus_badips](#zeus_badips)|230|230|5|2.1%|0.0%|
[zeus](#zeus)|266|266|5|1.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7086|7086|5|0.0%|0.0%|
[shunlist](#shunlist)|1271|1271|5|0.3%|0.0%|
[openbl_7d](#openbl_7d)|999|999|5|0.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3138|3138|5|0.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15540|15540|4|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|10351|10351|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13974|13974|2|0.0%|0.0%|
[virbl](#virbl)|12|12|1|8.3%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[nixspam](#nixspam)|19429|19429|1|0.0%|0.0%|
[malc0de](#malc0de)|392|392|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Wed Jun  3 01:15:07 UTC 2015.

The ipset `sslbl` has **360** entries, **360** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|174882|174882|63|0.0%|17.5%|
[shunlist](#shunlist)|1271|1271|55|4.3%|15.2%|
[feodo](#feodo)|80|80|31|38.7%|8.6%|
[et_block](#et_block)|997|18338381|30|0.0%|8.3%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|27|0.3%|7.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|23|0.0%|6.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|6|0.0%|1.6%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|3|0.0%|0.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Wed Jun  3 01:00:02 UTC 2015.

The ipset `stopforumspam_1d` has **7086** entries, **7086** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|7005|7.5%|98.8%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|3937|12.5%|55.5%|
[blocklist_de](#blocklist_de)|32730|32730|1401|4.2%|19.7%|
[blocklist_de_bots](#blocklist_de_bots)|3138|3138|1346|42.8%|18.9%|
[ri_web_proxies](#ri_web_proxies)|5772|5772|526|9.1%|7.4%|
[proxyrss](#proxyrss)|1973|1973|502|25.4%|7.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|486|0.0%|6.8%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|327|3.6%|4.6%|
[xroxy](#xroxy)|2041|2041|322|15.7%|4.5%|
[dm_tor](#dm_tor)|6392|6392|285|4.4%|4.0%|
[bm_tor](#bm_tor)|6441|6441|285|4.4%|4.0%|
[et_tor](#et_tor)|6360|6360|284|4.4%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|259|0.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|171|0.0%|2.4%|
[ri_connect_proxies](#ri_connect_proxies)|2142|2142|158|7.3%|2.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|153|41.1%|2.1%|
[proxz](#proxz)|579|579|136|23.4%|1.9%|
[php_commenters](#php_commenters)|281|281|107|38.0%|1.5%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|103|0.0%|1.4%|
[et_block](#et_block)|997|18338381|103|0.0%|1.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|103|59.1%|1.4%|
[blocklist_de_apache](#blocklist_de_apache)|13974|13974|63|0.4%|0.8%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|57|0.0%|0.8%|
[nixspam](#nixspam)|19429|19429|49|0.2%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|15540|15540|43|0.2%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|37|0.0%|0.5%|
[php_harvesters](#php_harvesters)|257|257|33|12.8%|0.4%|
[php_dictionary](#php_dictionary)|433|433|24|5.5%|0.3%|
[openbl_60d](#openbl_60d)|7653|7653|22|0.2%|0.3%|
[php_spammers](#php_spammers)|417|417|20|4.7%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2596|2596|17|0.6%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|11|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|7|1.0%|0.0%|
[voipbl](#voipbl)|10367|10776|5|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|5|0.0%|0.0%|
[shunlist](#shunlist)|1271|1271|2|0.1%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|721|721|2|0.2%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3244|3244|1|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2191|2191|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|10351|10351|1|0.0%|0.0%|

## stopforumspam_30d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip).

The last time downloaded was found to be dated: Wed Jun  3 00:00:42 UTC 2015.

The ipset `stopforumspam_30d` has **92665** entries, **92665** unique IPs.

The following table shows the overlaps of `stopforumspam_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_30d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|31339|100.0%|33.8%|
[stopforumspam_1d](#stopforumspam_1d)|7086|7086|7005|98.8%|7.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|5884|0.0%|6.3%|
[ri_web_proxies](#ri_web_proxies)|5772|5772|2855|49.4%|3.0%|
[blocklist_de](#blocklist_de)|32730|32730|2636|8.0%|2.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2510|0.0%|2.7%|
[blocklist_de_bots](#blocklist_de_bots)|3138|3138|2276|72.5%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1545|0.0%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|2142|2142|1266|59.1%|1.3%|
[xroxy](#xroxy)|2041|2041|1200|58.7%|1.2%|
[et_block](#et_block)|997|18338381|1003|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|998|0.0%|1.0%|
[proxyrss](#proxyrss)|1973|1973|974|49.3%|1.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|814|9.1%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|737|0.0%|0.7%|
[et_tor](#et_tor)|6360|6360|639|10.0%|0.6%|
[dm_tor](#dm_tor)|6392|6392|627|9.8%|0.6%|
[bm_tor](#bm_tor)|6441|6441|626|9.7%|0.6%|
[proxz](#proxz)|579|579|357|61.6%|0.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|232|62.3%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|15540|15540|224|1.4%|0.2%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|215|0.1%|0.2%|
[nixspam](#nixspam)|19429|19429|210|1.0%|0.2%|
[php_commenters](#php_commenters)|281|281|206|73.3%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|13974|13974|204|1.4%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|131|75.2%|0.1%|
[php_spammers](#php_spammers)|417|417|100|23.9%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|98|0.0%|0.1%|
[php_dictionary](#php_dictionary)|433|433|85|19.6%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|10351|10351|77|0.7%|0.0%|
[php_harvesters](#php_harvesters)|257|257|62|24.1%|0.0%|
[openbl_60d](#openbl_60d)|7653|7653|54|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|48|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2596|2596|41|1.5%|0.0%|
[voipbl](#voipbl)|10367|10776|39|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|22|3.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|15|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|721|721|12|1.6%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|10|0.4%|0.0%|
[et_compromised](#et_compromised)|2191|2191|9|0.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1558|1558|6|0.3%|0.0%|
[shunlist](#shunlist)|1271|1271|5|0.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|4|0.3%|0.0%|
[zeus_badips](#zeus_badips)|230|230|3|1.3%|0.0%|
[zeus](#zeus)|266|266|3|1.1%|0.0%|
[openbl_30d](#openbl_30d)|3244|3244|3|0.0%|0.0%|
[openbl_1d](#openbl_1d)|303|303|3|0.9%|0.0%|
[dshield](#dshield)|20|5120|3|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3686|670534424|2|0.0%|0.0%|
[sslbl](#sslbl)|360|360|1|0.2%|0.0%|
[openbl_7d](#openbl_7d)|999|999|1|0.1%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|

## stopforumspam_7d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip).

The last time downloaded was found to be dated: Tue Jun  2 02:00:08 UTC 2015.

The ipset `stopforumspam_7d` has **31339** entries, **31339** unique IPs.

The following table shows the overlaps of `stopforumspam_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_7d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|31339|33.8%|100.0%|
[stopforumspam_1d](#stopforumspam_1d)|7086|7086|3937|55.5%|12.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2085|0.0%|6.6%|
[blocklist_de](#blocklist_de)|32730|32730|1963|5.9%|6.2%|
[blocklist_de_bots](#blocklist_de_bots)|3138|3138|1770|56.4%|5.6%|
[ri_web_proxies](#ri_web_proxies)|5772|5772|1755|30.4%|5.6%|
[xroxy](#xroxy)|2041|2041|982|48.1%|3.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|934|0.0%|2.9%|
[proxyrss](#proxyrss)|1973|1973|700|35.4%|2.2%|
[ri_connect_proxies](#ri_connect_proxies)|2142|2142|689|32.1%|2.1%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|614|6.9%|1.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|558|0.0%|1.7%|
[et_tor](#et_tor)|6360|6360|491|7.7%|1.5%|
[dm_tor](#dm_tor)|6392|6392|472|7.3%|1.5%|
[bm_tor](#bm_tor)|6441|6441|471|7.3%|1.5%|
[et_block](#et_block)|997|18338381|341|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|340|0.0%|1.0%|
[proxz](#proxz)|579|579|295|50.9%|0.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|200|53.7%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|178|0.0%|0.5%|
[php_commenters](#php_commenters)|281|281|163|58.0%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|15540|15540|142|0.9%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|13974|13974|126|0.9%|0.4%|
[nixspam](#nixspam)|19429|19429|125|0.6%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|117|67.2%|0.3%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|100|0.0%|0.3%|
[php_spammers](#php_spammers)|417|417|71|17.0%|0.2%|
[php_dictionary](#php_dictionary)|433|433|69|15.9%|0.2%|
[php_harvesters](#php_harvesters)|257|257|48|18.6%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2596|2596|32|1.2%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|27|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7653|7653|25|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.0%|
[voipbl](#voipbl)|10367|10776|12|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|10351|10351|12|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|7|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|6|0.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|721|721|6|0.8%|0.0%|
[et_compromised](#et_compromised)|2191|2191|5|0.2%|0.0%|
[shunlist](#shunlist)|1271|1271|3|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1558|1558|3|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|2|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3244|3244|1|0.0%|0.0%|

## virbl

[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.

Source is downloaded from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt).

The last time downloaded was found to be dated: Wed Jun  3 00:42:04 UTC 2015.

The ipset `virbl` has **12** entries, **12** unique IPs.

The following table shows the overlaps of `virbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `virbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `virbl`.
- ` this % ` is the percentage **of this ipset (`virbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|1|0.0%|8.3%|
[blocklist_de_mail](#blocklist_de_mail)|15540|15540|1|0.0%|8.3%|
[blocklist_de](#blocklist_de)|32730|32730|1|0.0%|8.3%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Tue Jun  2 22:09:50 UTC 2015.

The ipset `voipbl` has **10367** entries, **10776** unique IPs.

The following table shows the overlaps of `voipbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `voipbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `voipbl`.
- ` this % ` is the percentage **of this ipset (`voipbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1593|0.0%|14.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|432|0.0%|4.0%|
[fullbogons](#fullbogons)|3686|670534424|319|0.0%|2.9%|
[bogons](#bogons)|13|592708608|319|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|296|0.0%|2.7%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|197|0.1%|1.8%|
[blocklist_de](#blocklist_de)|32730|32730|41|0.1%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|39|0.0%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|113|113|31|27.4%|0.2%|
[et_block](#et_block)|997|18338381|24|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|14|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|12|0.0%|0.1%|
[shunlist](#shunlist)|1271|1271|12|0.9%|0.1%|
[openbl_60d](#openbl_60d)|7653|7653|9|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7086|7086|5|0.0%|0.0%|
[ciarmy](#ciarmy)|308|308|5|1.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13974|13974|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[openbl_7d](#openbl_7d)|999|999|3|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3244|3244|3|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[et_tor](#et_tor)|6360|6360|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6392|6392|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6441|6441|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|10351|10351|2|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2596|2596|2|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3138|3138|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2191|2191|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15540|15540|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1558|1558|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Wed Jun  3 01:33:01 UTC 2015.

The ipset `xroxy` has **2041** entries, **2041** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|1200|1.2%|58.7%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|982|3.1%|48.1%|
[ri_web_proxies](#ri_web_proxies)|5772|5772|848|14.6%|41.5%|
[proxyrss](#proxyrss)|1973|1973|480|24.3%|23.5%|
[ri_connect_proxies](#ri_connect_proxies)|2142|2142|332|15.4%|16.2%|
[stopforumspam_1d](#stopforumspam_1d)|7086|7086|322|4.5%|15.7%|
[proxz](#proxz)|579|579|261|45.0%|12.7%|
[blocklist_de](#blocklist_de)|32730|32730|241|0.7%|11.8%|
[blocklist_de_bots](#blocklist_de_bots)|3138|3138|199|6.3%|9.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|99|0.0%|4.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|87|0.0%|4.2%|
[nixspam](#nixspam)|19429|19429|70|0.3%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|57|0.0%|2.7%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|50|0.5%|2.4%|
[blocklist_de_mail](#blocklist_de_mail)|15540|15540|40|0.2%|1.9%|
[php_dictionary](#php_dictionary)|433|433|24|5.5%|1.1%|
[php_spammers](#php_spammers)|417|417|20|4.7%|0.9%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|13|1.9%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|174|174|7|4.0%|0.3%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|5|0.0%|0.2%|
[php_commenters](#php_commenters)|281|281|3|1.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.1%|
[et_tor](#et_tor)|6360|6360|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[dm_tor](#dm_tor)|6392|6392|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6441|6441|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|10351|10351|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2191|2191|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|1|0.0%|0.0%|

## zeus

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist).

The last time downloaded was found to be dated: Tue Jun  2 14:00:03 UTC 2015.

The ipset `zeus` has **266** entries, **266** unique IPs.

The following table shows the overlaps of `zeus` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus`.
- ` this % ` is the percentage **of this ipset (`zeus`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|997|18338381|259|0.0%|97.3%|
[zeus_badips](#zeus_badips)|230|230|230|100.0%|86.4%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|227|2.5%|85.3%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|66|0.0%|24.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|19|0.0%|7.1%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|16|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|7|0.0%|2.6%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|5|0.0%|1.8%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|3|0.0%|1.1%|
[openbl_60d](#openbl_60d)|7653|7653|2|0.0%|0.7%|
[openbl_30d](#openbl_30d)|3244|3244|2|0.0%|0.7%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|1|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7086|7086|1|0.0%|0.3%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.3%|
[openbl_7d](#openbl_7d)|999|999|1|0.1%|0.3%|
[nixspam](#nixspam)|19429|19429|1|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|
[et_compromised](#et_compromised)|2191|2191|1|0.0%|0.3%|
[dshield](#dshield)|20|5120|1|0.0%|0.3%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|1|0.0%|0.3%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Wed Jun  3 01:09:20 UTC 2015.

The ipset `zeus_badips` has **230** entries, **230** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|266|266|230|86.4%|100.0%|
[et_block](#et_block)|997|18338381|229|0.0%|99.5%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|202|2.2%|87.8%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|37|0.0%|16.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|16|0.0%|6.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8|0.0%|3.4%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|5|0.0%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4|0.0%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|3|0.0%|1.3%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|7086|7086|1|0.0%|0.4%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.4%|
[openbl_60d](#openbl_60d)|7653|7653|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|3244|3244|1|0.0%|0.4%|
[nixspam](#nixspam)|19429|19429|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.4%|
[et_compromised](#et_compromised)|2191|2191|1|0.0%|0.4%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|1|0.0%|0.4%|
