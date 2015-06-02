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

The following list was automatically generated on Tue Jun  2 19:28:00 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|179050 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|29355 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|14003 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|3175 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|2619 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|626 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|1495 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|15563 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|108 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|7144 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|172 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6525 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|2174 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|346 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|11 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6554 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
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
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|24694 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|202 unique IPs|updated every 1 hour  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|3183 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7594 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|931 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|281 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|433 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|257 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|417 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1942 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|559 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2116 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|5735 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1256 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|9012 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|656 subnets, 18600704 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|57 subnets, 487168 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|361 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|7074 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|92372 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|31339 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
[virbl](#virbl)|[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.|ipv4 hash:ip|13 unique IPs|updated every 1 hour  from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10367 subnets, 10776 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2039 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|266 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|230 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Tue Jun  2 16:00:20 UTC 2015.

The ipset `alienvault_reputation` has **179050** entries, **179050** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14633|0.0%|8.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7623|0.0%|4.2%|
[openbl_60d](#openbl_60d)|7594|7594|7569|99.6%|4.2%|
[et_block](#et_block)|997|18338381|5285|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4659|0.0%|2.6%|
[dshield](#dshield)|20|5120|4099|80.0%|2.2%|
[openbl_30d](#openbl_30d)|3183|3183|3164|99.4%|1.7%|
[blocklist_de](#blocklist_de)|29355|29355|1659|5.6%|0.9%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|1628|0.0%|0.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|7144|7144|1444|20.2%|0.8%|
[et_compromised](#et_compromised)|2191|2191|1425|65.0%|0.7%|
[bruteforceblocker](#bruteforceblocker)|2174|2174|1404|64.5%|0.7%|
[shunlist](#shunlist)|1256|1256|1242|98.8%|0.6%|
[openbl_7d](#openbl_7d)|931|931|920|98.8%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|518|0.0%|0.2%|
[ciarmy](#ciarmy)|346|346|331|95.6%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|288|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|271|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|215|0.2%|0.1%|
[voipbl](#voipbl)|10367|10776|210|1.9%|0.1%|
[openbl_1d](#openbl_1d)|202|202|161|79.7%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|121|1.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14003|14003|114|0.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|100|0.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15563|15563|78|0.5%|0.0%|
[zeus](#zeus)|266|266|66|24.8%|0.0%|
[sslbl](#sslbl)|361|361|63|17.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1495|1495|58|3.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|57|0.8%|0.0%|
[dm_tor](#dm_tor)|6554|6554|46|0.7%|0.0%|
[bm_tor](#bm_tor)|6525|6525|46|0.7%|0.0%|
[et_tor](#et_tor)|6360|6360|45|0.7%|0.0%|
[zeus_badips](#zeus_badips)|230|230|37|16.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|37|21.5%|0.0%|
[nixspam](#nixspam)|24694|24694|32|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3175|3175|30|0.9%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|25|6.7%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|108|108|18|16.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|15|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2619|2619|15|0.5%|0.0%|
[php_commenters](#php_commenters)|281|281|14|4.9%|0.0%|
[malc0de](#malc0de)|392|392|12|3.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|8|0.5%|0.0%|
[php_dictionary](#php_dictionary)|433|433|7|1.6%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|626|626|7|1.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|6|0.4%|0.0%|
[xroxy](#xroxy)|2039|2039|5|0.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5735|5735|3|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|3|0.7%|0.0%|
[et_botcc](#et_botcc)|505|505|3|0.5%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2116|2116|2|0.0%|0.0%|
[proxz](#proxz)|559|559|2|0.3%|0.0%|
[proxyrss](#proxyrss)|1942|1942|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[feodo](#feodo)|80|80|1|1.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|11|11|1|9.0%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Tue Jun  2 18:56:05 UTC 2015.

The ipset `blocklist_de` has **29355** entries, **29355** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|15563|15563|15538|99.8%|52.9%|
[blocklist_de_apache](#blocklist_de_apache)|14003|14003|14003|100.0%|47.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|7144|7144|6981|97.7%|23.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|4558|0.0%|15.5%|
[blocklist_de_bots](#blocklist_de_bots)|3175|3175|3167|99.7%|10.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2619|2619|2598|99.1%|8.8%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|2337|2.5%|7.9%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|2023|6.4%|6.8%|
[alienvault_reputation](#alienvault_reputation)|179050|179050|1659|0.9%|5.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1526|0.0%|5.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1487|0.0%|5.0%|
[blocklist_de_imap](#blocklist_de_imap)|1495|1495|1484|99.2%|5.0%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|1428|20.1%|4.8%|
[openbl_60d](#openbl_60d)|7594|7594|1339|17.6%|4.5%|
[openbl_30d](#openbl_30d)|3183|3183|809|25.4%|2.7%|
[bruteforceblocker](#bruteforceblocker)|2174|2174|723|33.2%|2.4%|
[et_compromised](#et_compromised)|2191|2191|686|31.3%|2.3%|
[nixspam](#nixspam)|24694|24694|634|2.5%|2.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|626|626|618|98.7%|2.1%|
[openbl_7d](#openbl_7d)|931|931|532|57.1%|1.8%|
[shunlist](#shunlist)|1256|1256|412|32.8%|1.4%|
[ri_web_proxies](#ri_web_proxies)|5735|5735|366|6.3%|1.2%|
[xroxy](#xroxy)|2039|2039|239|11.7%|0.8%|
[proxyrss](#proxyrss)|1942|1942|231|11.8%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|172|100.0%|0.5%|
[et_block](#et_block)|997|18338381|165|0.0%|0.5%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|163|1.8%|0.5%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|158|0.0%|0.5%|
[openbl_1d](#openbl_1d)|202|202|140|69.3%|0.4%|
[proxz](#proxz)|559|559|108|19.3%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|108|108|89|82.4%|0.3%|
[ri_connect_proxies](#ri_connect_proxies)|2116|2116|69|3.2%|0.2%|
[php_commenters](#php_commenters)|281|281|60|21.3%|0.2%|
[dshield](#dshield)|20|5120|59|1.1%|0.2%|
[php_dictionary](#php_dictionary)|433|433|51|11.7%|0.1%|
[php_spammers](#php_spammers)|417|417|44|10.5%|0.1%|
[voipbl](#voipbl)|10367|10776|39|0.3%|0.1%|
[ciarmy](#ciarmy)|346|346|38|10.9%|0.1%|
[php_harvesters](#php_harvesters)|257|257|25|9.7%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|25|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|13|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|8|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.0%|
[et_tor](#et_tor)|6360|6360|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6554|6554|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6525|6525|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[virbl](#virbl)|13|13|1|7.6%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Tue Jun  2 18:56:08 UTC 2015.

The ipset `blocklist_de_apache` has **14003** entries, **14003** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|29355|29355|14003|47.7%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|15563|15563|11059|71.0%|78.9%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2619|2619|2597|99.1%|18.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2261|0.0%|16.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1322|0.0%|9.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1074|0.0%|7.6%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|193|0.2%|1.3%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|120|0.3%|0.8%|
[alienvault_reputation](#alienvault_reputation)|179050|179050|114|0.0%|0.8%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|60|0.8%|0.4%|
[nixspam](#nixspam)|24694|24694|37|0.1%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|36|20.9%|0.2%|
[ciarmy](#ciarmy)|346|346|34|9.8%|0.2%|
[shunlist](#shunlist)|1256|1256|30|2.3%|0.2%|
[php_commenters](#php_commenters)|281|281|22|7.8%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3175|3175|21|0.6%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|10|0.1%|0.0%|
[voipbl](#voipbl)|10367|10776|6|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|4|0.9%|0.0%|
[et_block](#et_block)|997|18338381|4|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7594|7594|3|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.0%|
[et_tor](#et_tor)|6360|6360|3|0.0%|0.0%|
[et_compromised](#et_compromised)|2191|2191|3|0.1%|0.0%|
[dshield](#dshield)|20|5120|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6554|6554|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2174|2174|3|0.1%|0.0%|
[bm_tor](#bm_tor)|6525|6525|3|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|2|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[openbl_30d](#openbl_30d)|3183|3183|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Tue Jun  2 19:14:18 UTC 2015.

The ipset `blocklist_de_bots` has **3175** entries, **3175** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|29355|29355|3167|10.7%|99.7%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|2024|2.1%|63.7%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|1842|5.8%|58.0%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|1375|19.4%|43.3%|
[ri_web_proxies](#ri_web_proxies)|5735|5735|327|5.7%|10.2%|
[proxyrss](#proxyrss)|1942|1942|226|11.6%|7.1%|
[xroxy](#xroxy)|2039|2039|197|9.6%|6.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|184|0.0%|5.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|179|0.0%|5.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|124|72.0%|3.9%|
[proxz](#proxz)|559|559|90|16.1%|2.8%|
[ri_connect_proxies](#ri_connect_proxies)|2116|2116|67|3.1%|2.1%|
[php_commenters](#php_commenters)|281|281|50|17.7%|1.5%|
[nixspam](#nixspam)|24694|24694|44|0.1%|1.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|33|0.0%|1.0%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|30|0.3%|0.9%|
[alienvault_reputation](#alienvault_reputation)|179050|179050|30|0.0%|0.9%|
[blocklist_de_mail](#blocklist_de_mail)|15563|15563|21|0.1%|0.6%|
[blocklist_de_apache](#blocklist_de_apache)|14003|14003|21|0.1%|0.6%|
[php_harvesters](#php_harvesters)|257|257|18|7.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|17|0.0%|0.5%|
[et_block](#et_block)|997|18338381|17|0.0%|0.5%|
[php_dictionary](#php_dictionary)|433|433|16|3.6%|0.5%|
[php_spammers](#php_spammers)|417|417|10|2.3%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7594|7594|8|0.1%|0.2%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|5|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.0%|
[voipbl](#voipbl)|10367|10776|2|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Tue Jun  2 19:10:12 UTC 2015.

The ipset `blocklist_de_bruteforce` has **2619** entries, **2619** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|29355|29355|2598|8.8%|99.1%|
[blocklist_de_apache](#blocklist_de_apache)|14003|14003|2597|18.5%|99.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|165|0.0%|6.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|41|0.0%|1.5%|
[nixspam](#nixspam)|24694|24694|38|0.1%|1.4%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|35|0.0%|1.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|31|0.0%|1.1%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|28|0.0%|1.0%|
[alienvault_reputation](#alienvault_reputation)|179050|179050|15|0.0%|0.5%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|14|0.1%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|12|6.9%|0.4%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|7|0.0%|0.2%|
[php_spammers](#php_spammers)|417|417|4|0.9%|0.1%|
[php_commenters](#php_commenters)|281|281|4|1.4%|0.1%|
[et_block](#et_block)|997|18338381|3|0.0%|0.1%|
[voipbl](#voipbl)|10367|10776|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|2|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[shunlist](#shunlist)|1256|1256|1|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7594|7594|1|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15563|15563|1|0.0%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Tue Jun  2 19:14:14 UTC 2015.

The ipset `blocklist_de_ftp` has **626** entries, **626** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|29355|29355|618|2.1%|98.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|59|0.0%|9.4%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|10|0.0%|1.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|1.4%|
[nixspam](#nixspam)|24694|24694|8|0.0%|1.2%|
[alienvault_reputation](#alienvault_reputation)|179050|179050|7|0.0%|1.1%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|6|0.0%|0.9%|
[php_harvesters](#php_harvesters)|257|257|5|1.9%|0.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|0.7%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|2|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7594|7594|2|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|1|0.0%|0.1%|
[shunlist](#shunlist)|1256|1256|1|0.0%|0.1%|
[proxyrss](#proxyrss)|1942|1942|1|0.0%|0.1%|
[openbl_30d](#openbl_30d)|3183|3183|1|0.0%|0.1%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Tue Jun  2 19:14:14 UTC 2015.

The ipset `blocklist_de_imap` has **1495** entries, **1495** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|15563|15563|1495|9.6%|100.0%|
[blocklist_de](#blocklist_de)|29355|29355|1484|5.0%|99.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|137|0.0%|9.1%|
[alienvault_reputation](#alienvault_reputation)|179050|179050|58|0.0%|3.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|48|0.0%|3.2%|
[openbl_60d](#openbl_60d)|7594|7594|41|0.5%|2.7%|
[openbl_30d](#openbl_30d)|3183|3183|35|1.0%|2.3%|
[openbl_7d](#openbl_7d)|931|931|17|1.8%|1.1%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|16|0.0%|1.0%|
[et_block](#et_block)|997|18338381|16|0.0%|1.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|11|0.0%|0.7%|
[et_compromised](#et_compromised)|2191|2191|8|0.3%|0.5%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|7|0.0%|0.4%|
[nixspam](#nixspam)|24694|24694|7|0.0%|0.4%|
[bruteforceblocker](#bruteforceblocker)|2174|2174|7|0.3%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|6|0.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6|0.0%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|4|0.0%|0.2%|
[shunlist](#shunlist)|1256|1256|3|0.2%|0.2%|
[openbl_1d](#openbl_1d)|202|202|2|0.9%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|2|1.1%|0.1%|
[voipbl](#voipbl)|10367|10776|1|0.0%|0.0%|
[ciarmy](#ciarmy)|346|346|1|0.2%|0.0%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Tue Jun  2 19:14:13 UTC 2015.

The ipset `blocklist_de_mail` has **15563** entries, **15563** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|29355|29355|15538|52.9%|99.8%|
[blocklist_de_apache](#blocklist_de_apache)|14003|14003|11059|78.9%|71.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2368|0.0%|15.2%|
[blocklist_de_imap](#blocklist_de_imap)|1495|1495|1495|100.0%|9.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1330|0.0%|8.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1135|0.0%|7.2%|
[nixspam](#nixspam)|24694|24694|526|2.1%|3.3%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|216|0.2%|1.3%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|137|0.4%|0.8%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|124|1.3%|0.7%|
[alienvault_reputation](#alienvault_reputation)|179050|179050|78|0.0%|0.5%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|44|0.6%|0.2%|
[openbl_60d](#openbl_60d)|7594|7594|44|0.5%|0.2%|
[xroxy](#xroxy)|2039|2039|39|1.9%|0.2%|
[ri_web_proxies](#ri_web_proxies)|5735|5735|38|0.6%|0.2%|
[openbl_30d](#openbl_30d)|3183|3183|38|1.1%|0.2%|
[php_dictionary](#php_dictionary)|433|433|33|7.6%|0.2%|
[php_spammers](#php_spammers)|417|417|31|7.4%|0.1%|
[et_block](#et_block)|997|18338381|28|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|27|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|21|12.2%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3175|3175|21|0.6%|0.1%|
[php_commenters](#php_commenters)|281|281|18|6.4%|0.1%|
[openbl_7d](#openbl_7d)|931|931|17|1.8%|0.1%|
[proxz](#proxz)|559|559|15|2.6%|0.0%|
[et_compromised](#et_compromised)|2191|2191|10|0.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2174|2174|9|0.4%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|4|0.0%|0.0%|
[shunlist](#shunlist)|1256|1256|4|0.3%|0.0%|
[et_tor](#et_tor)|6360|6360|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6554|6554|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6525|6525|3|0.0%|0.0%|
[proxyrss](#proxyrss)|1942|1942|2|0.1%|0.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[openbl_1d](#openbl_1d)|202|202|2|0.9%|0.0%|
[voipbl](#voipbl)|10367|10776|1|0.0%|0.0%|
[virbl](#virbl)|13|13|1|7.6%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2116|2116|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|346|346|1|0.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2619|2619|1|0.0%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Tue Jun  2 18:56:09 UTC 2015.

The ipset `blocklist_de_sip` has **108** entries, **108** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|29355|29355|89|0.3%|82.4%|
[voipbl](#voipbl)|10367|10776|28|0.2%|25.9%|
[alienvault_reputation](#alienvault_reputation)|179050|179050|18|0.0%|16.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|13|0.0%|12.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8|0.0%|7.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|2|0.0%|1.8%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|1|0.0%|0.9%|
[nixspam](#nixspam)|24694|24694|1|0.0%|0.9%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.9%|
[et_block](#et_block)|997|18338381|1|0.0%|0.9%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Tue Jun  2 19:10:04 UTC 2015.

The ipset `blocklist_de_ssh` has **7144** entries, **7144** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|29355|29355|6981|23.7%|97.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1790|0.0%|25.0%|
[alienvault_reputation](#alienvault_reputation)|179050|179050|1444|0.8%|20.2%|
[openbl_60d](#openbl_60d)|7594|7594|1300|17.1%|18.1%|
[openbl_30d](#openbl_30d)|3183|3183|769|24.1%|10.7%|
[bruteforceblocker](#bruteforceblocker)|2174|2174|710|32.6%|9.9%|
[et_compromised](#et_compromised)|2191|2191|672|30.6%|9.4%|
[openbl_7d](#openbl_7d)|931|931|515|55.3%|7.2%|
[shunlist](#shunlist)|1256|1256|377|30.0%|5.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|148|0.0%|2.0%|
[openbl_1d](#openbl_1d)|202|202|138|68.3%|1.9%|
[et_block](#et_block)|997|18338381|116|0.0%|1.6%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|112|0.0%|1.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|81|0.0%|1.1%|
[dshield](#dshield)|20|5120|55|1.0%|0.7%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|46|0.0%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|27|15.6%|0.3%|
[nixspam](#nixspam)|24694|24694|19|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|5|0.0%|0.0%|
[ciarmy](#ciarmy)|346|346|3|0.8%|0.0%|
[xroxy](#xroxy)|2039|2039|2|0.0%|0.0%|
[voipbl](#voipbl)|10367|10776|2|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|2|0.0%|0.0%|
[proxz](#proxz)|559|559|2|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2116|2116|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1942|1942|1|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Tue Jun  2 18:56:13 UTC 2015.

The ipset `blocklist_de_strongips` has **172** entries, **172** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|29355|29355|172|0.5%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|126|0.1%|73.2%|
[blocklist_de_bots](#blocklist_de_bots)|3175|3175|124|3.9%|72.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|116|0.3%|67.4%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|101|1.4%|58.7%|
[alienvault_reputation](#alienvault_reputation)|179050|179050|37|0.0%|21.5%|
[blocklist_de_apache](#blocklist_de_apache)|14003|14003|36|0.2%|20.9%|
[php_commenters](#php_commenters)|281|281|29|10.3%|16.8%|
[openbl_60d](#openbl_60d)|7594|7594|28|0.3%|16.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|7144|7144|27|0.3%|15.6%|
[openbl_30d](#openbl_30d)|3183|3183|25|0.7%|14.5%|
[openbl_7d](#openbl_7d)|931|931|24|2.5%|13.9%|
[blocklist_de_mail](#blocklist_de_mail)|15563|15563|21|0.1%|12.2%|
[shunlist](#shunlist)|1256|1256|20|1.5%|11.6%|
[openbl_1d](#openbl_1d)|202|202|18|8.9%|10.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|16|0.0%|9.3%|
[dshield](#dshield)|20|5120|12|0.2%|6.9%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2619|2619|12|0.4%|6.9%|
[xroxy](#xroxy)|2039|2039|7|0.3%|4.0%|
[proxyrss](#proxyrss)|1942|1942|7|0.3%|4.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|6|0.0%|3.4%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|6|0.0%|3.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|6|0.0%|3.4%|
[et_block](#et_block)|997|18338381|6|0.0%|3.4%|
[ri_web_proxies](#ri_web_proxies)|5735|5735|5|0.0%|2.9%|
[proxz](#proxz)|559|559|3|0.5%|1.7%|
[php_spammers](#php_spammers)|417|417|3|0.7%|1.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.7%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|1.1%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|1.1%|
[blocklist_de_imap](#blocklist_de_imap)|1495|1495|2|0.1%|1.1%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|1|0.0%|0.5%|
[nixspam](#nixspam)|24694|24694|1|0.0%|0.5%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Tue Jun  2 19:27:07 UTC 2015.

The ipset `bm_tor` has **6525** entries, **6525** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[dm_tor](#dm_tor)|6554|6554|6410|97.8%|98.2%|
[et_tor](#et_tor)|6360|6360|5661|89.0%|86.7%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|1069|11.8%|16.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|632|0.0%|9.6%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|624|0.6%|9.5%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|475|1.5%|7.2%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|302|4.2%|4.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|190|0.0%|2.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|170|45.6%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|166|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|179050|179050|46|0.0%|0.7%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[openbl_60d](#openbl_60d)|7594|7594|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[et_block](#et_block)|997|18338381|4|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5735|5735|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15563|15563|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14003|14003|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|29355|29355|3|0.0%|0.0%|
[xroxy](#xroxy)|2039|2039|2|0.0%|0.0%|
[voipbl](#voipbl)|10367|10776|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|2|0.0%|0.0%|
[shunlist](#shunlist)|1256|1256|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2116|2116|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1942|1942|1|0.0%|0.0%|

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
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2174|2174|1|0.0%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Tue Jun  2 16:36:27 UTC 2015.

The ipset `bruteforceblocker` has **2174** entries, **2174** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_compromised](#et_compromised)|2191|2191|2102|95.9%|96.6%|
[alienvault_reputation](#alienvault_reputation)|179050|179050|1404|0.7%|64.5%|
[openbl_60d](#openbl_60d)|7594|7594|1303|17.1%|59.9%|
[openbl_30d](#openbl_30d)|3183|3183|1228|38.5%|56.4%|
[blocklist_de](#blocklist_de)|29355|29355|723|2.4%|33.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|7144|7144|710|9.9%|32.6%|
[openbl_7d](#openbl_7d)|931|931|526|56.4%|24.1%|
[shunlist](#shunlist)|1256|1256|501|39.8%|23.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|214|0.0%|9.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|112|0.0%|5.1%|
[et_block](#et_block)|997|18338381|102|0.0%|4.6%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|100|0.0%|4.5%|
[openbl_1d](#openbl_1d)|202|202|69|34.1%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|60|0.0%|2.7%|
[dshield](#dshield)|20|5120|35|0.6%|1.6%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|9|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|15563|15563|9|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|1495|1495|7|0.4%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|6|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|3|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|14003|14003|3|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|2|0.0%|0.0%|
[proxz](#proxz)|559|559|2|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[xroxy](#xroxy)|2039|2039|1|0.0%|0.0%|
[voipbl](#voipbl)|10367|10776|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5735|5735|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3686|670534424|1|0.0%|0.0%|
[ciarmy](#ciarmy)|346|346|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Tue Jun  2 19:15:15 UTC 2015.

The ipset `ciarmy` has **346** entries, **346** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|179050|179050|331|0.1%|95.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|55|0.0%|15.8%|
[blocklist_de](#blocklist_de)|29355|29355|38|0.1%|10.9%|
[blocklist_de_apache](#blocklist_de_apache)|14003|14003|34|0.2%|9.8%|
[shunlist](#shunlist)|1256|1256|27|2.1%|7.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|14|0.0%|4.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|11|0.0%|3.1%|
[voipbl](#voipbl)|10367|10776|6|0.0%|1.7%|
[dshield](#dshield)|20|5120|3|0.0%|0.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|7144|7144|3|0.0%|0.8%|
[et_block](#et_block)|997|18338381|2|0.0%|0.5%|
[openbl_7d](#openbl_7d)|931|931|1|0.1%|0.2%|
[openbl_60d](#openbl_60d)|7594|7594|1|0.0%|0.2%|
[openbl_30d](#openbl_30d)|3183|3183|1|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|2174|2174|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|15563|15563|1|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|1495|1495|1|0.0%|0.2%|

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
[alienvault_reputation](#alienvault_reputation)|179050|179050|1|0.0%|9.0%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Tue Jun  2 19:27:05 UTC 2015.

The ipset `dm_tor` has **6554** entries, **6554** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6525|6525|6410|98.2%|97.8%|
[et_tor](#et_tor)|6360|6360|5652|88.8%|86.2%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|1072|11.8%|16.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|633|0.0%|9.6%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|624|0.6%|9.5%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|475|1.5%|7.2%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|301|4.2%|4.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|187|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|170|45.6%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|165|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|179050|179050|46|0.0%|0.7%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[openbl_60d](#openbl_60d)|7594|7594|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[et_block](#et_block)|997|18338381|4|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5735|5735|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15563|15563|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14003|14003|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|29355|29355|3|0.0%|0.0%|
[xroxy](#xroxy)|2039|2039|2|0.0%|0.0%|
[voipbl](#voipbl)|10367|10776|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|2|0.0%|0.0%|
[shunlist](#shunlist)|1256|1256|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2116|2116|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1942|1942|1|0.0%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Tue Jun  2 19:17:02 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|179050|179050|4099|2.2%|80.0%|
[et_block](#et_block)|997|18338381|1281|0.0%|25.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|256|0.0%|5.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|256|0.0%|5.0%|
[openbl_60d](#openbl_60d)|7594|7594|78|1.0%|1.5%|
[openbl_30d](#openbl_30d)|3183|3183|70|2.1%|1.3%|
[blocklist_de](#blocklist_de)|29355|29355|59|0.2%|1.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|7144|7144|55|0.7%|1.0%|
[shunlist](#shunlist)|1256|1256|48|3.8%|0.9%|
[openbl_7d](#openbl_7d)|931|931|48|5.1%|0.9%|
[et_compromised](#et_compromised)|2191|2191|35|1.5%|0.6%|
[bruteforceblocker](#bruteforceblocker)|2174|2174|35|1.6%|0.6%|
[openbl_1d](#openbl_1d)|202|202|17|8.4%|0.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|12|0.0%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|12|6.9%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[ciarmy](#ciarmy)|346|346|3|0.8%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14003|14003|3|0.0%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[malc0de](#malc0de)|392|392|1|0.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15563|15563|1|0.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|179050|179050|5285|2.9%|0.0%|
[dshield](#dshield)|20|5120|1281|25.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1040|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|986|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|517|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|341|1.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|298|3.3%|0.0%|
[zeus](#zeus)|266|266|259|97.3%|0.0%|
[openbl_60d](#openbl_60d)|7594|7594|244|3.2%|0.0%|
[zeus_badips](#zeus_badips)|230|230|229|99.5%|0.0%|
[openbl_30d](#openbl_30d)|3183|3183|193|6.0%|0.0%|
[nixspam](#nixspam)|24694|24694|172|0.6%|0.0%|
[blocklist_de](#blocklist_de)|29355|29355|165|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|7144|7144|116|1.6%|0.0%|
[shunlist](#shunlist)|1256|1256|106|8.4%|0.0%|
[et_compromised](#et_compromised)|2191|2191|104|4.7%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|102|1.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2174|2174|102|4.6%|0.0%|
[openbl_7d](#openbl_7d)|931|931|89|9.5%|0.0%|
[feodo](#feodo)|80|80|71|88.7%|0.0%|
[sslbl](#sslbl)|361|361|30|8.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|29|2.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15563|15563|28|0.1%|0.0%|
[voipbl](#voipbl)|10367|10776|24|0.2%|0.0%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3175|3175|17|0.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1495|1495|16|1.0%|0.0%|
[palevo](#palevo)|13|13|12|92.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|10|0.0%|0.0%|
[openbl_1d](#openbl_1d)|202|202|6|2.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|6|3.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[malc0de](#malc0de)|392|392|4|1.0%|0.0%|
[et_tor](#et_tor)|6360|6360|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6554|6554|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6525|6525|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14003|14003|4|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2619|2619|3|0.1%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[ciarmy](#ciarmy)|346|346|2|0.5%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|108|108|1|0.9%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|179050|179050|3|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[et_block](#et_block)|997|18338381|1|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|108|108|1|0.9%|0.1%|

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
[bruteforceblocker](#bruteforceblocker)|2174|2174|2102|96.6%|95.9%|
[alienvault_reputation](#alienvault_reputation)|179050|179050|1425|0.7%|65.0%|
[openbl_60d](#openbl_60d)|7594|7594|1322|17.4%|60.3%|
[openbl_30d](#openbl_30d)|3183|3183|1230|38.6%|56.1%|
[blocklist_de](#blocklist_de)|29355|29355|686|2.3%|31.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|7144|7144|672|9.4%|30.6%|
[openbl_7d](#openbl_7d)|931|931|517|55.5%|23.5%|
[shunlist](#shunlist)|1256|1256|502|39.9%|22.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|219|0.0%|9.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|116|0.0%|5.2%|
[et_block](#et_block)|997|18338381|104|0.0%|4.7%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|102|0.0%|4.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|62|0.0%|2.8%|
[openbl_1d](#openbl_1d)|202|202|60|29.7%|2.7%|
[dshield](#dshield)|20|5120|35|0.6%|1.5%|
[blocklist_de_mail](#blocklist_de_mail)|15563|15563|10|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|9|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|1495|1495|8|0.5%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|5|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|3|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|14003|14003|3|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|2|0.0%|0.0%|
[proxz](#proxz)|559|559|2|0.3%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[xroxy](#xroxy)|2039|2039|1|0.0%|0.0%|
[voipbl](#voipbl)|10367|10776|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|

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
[bm_tor](#bm_tor)|6525|6525|5661|86.7%|89.0%|
[dm_tor](#dm_tor)|6554|6554|5652|86.2%|88.8%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|1077|11.9%|16.9%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|636|0.6%|10.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|628|0.0%|9.8%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|491|1.5%|7.7%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|304|4.2%|4.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|191|0.0%|3.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|169|45.4%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|167|0.0%|2.6%|
[alienvault_reputation](#alienvault_reputation)|179050|179050|45|0.0%|0.7%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[openbl_60d](#openbl_60d)|7594|7594|19|0.2%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|19|0.0%|0.2%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[php_harvesters](#php_harvesters)|257|257|6|2.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5735|5735|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[et_block](#et_block)|997|18338381|4|0.0%|0.0%|
[xroxy](#xroxy)|2039|2039|3|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15563|15563|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14003|14003|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|29355|29355|3|0.0%|0.0%|
[voipbl](#voipbl)|10367|10776|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2116|2116|2|0.0%|0.0%|
[shunlist](#shunlist)|1256|1256|1|0.0%|0.0%|
[proxz](#proxz)|559|559|1|0.1%|0.0%|
[proxyrss](#proxyrss)|1942|1942|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Tue Jun  2 19:27:20 UTC 2015.

The ipset `feodo` has **80** entries, **80** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|997|18338381|71|0.0%|88.7%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|64|0.7%|80.0%|
[sslbl](#sslbl)|361|361|31|8.5%|38.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|7|0.0%|8.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|3|0.0%|3.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|3.7%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|1.2%|
[alienvault_reputation](#alienvault_reputation)|179050|179050|1|0.0%|1.2%|

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
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2174|2174|1|0.0%|0.0%|

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
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|16|0.0%|0.0%|
[fullbogons](#fullbogons)|3686|670534424|15|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|179050|179050|15|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.0%|
[et_block](#et_block)|997|18338381|10|0.0%|0.0%|
[nixspam](#nixspam)|24694|24694|8|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|7|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|6|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[dshield](#dshield)|20|5120|4|0.0%|0.0%|
[xroxy](#xroxy)|2039|2039|3|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|29355|29355|3|0.0%|0.0%|
[voipbl](#voipbl)|10367|10776|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5735|5735|1|0.0%|0.0%|
[proxz](#proxz)|559|559|1|0.1%|0.0%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15563|15563|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2619|2619|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3175|3175|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14003|14003|1|0.0%|0.0%|

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
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|731|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|179050|179050|518|0.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|178|0.5%|0.0%|
[nixspam](#nixspam)|24694|24694|172|0.6%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|37|0.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|27|2.1%|0.0%|
[blocklist_de](#blocklist_de)|29355|29355|25|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7594|7594|18|0.2%|0.0%|
[openbl_30d](#openbl_30d)|3183|3183|13|0.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|11|0.1%|0.0%|
[zeus_badips](#zeus_badips)|230|230|10|4.3%|0.0%|
[zeus](#zeus)|266|266|10|3.7%|0.0%|
[openbl_7d](#openbl_7d)|931|931|10|1.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3175|3175|10|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|7144|7144|7|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15563|15563|7|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1495|1495|6|0.4%|0.0%|
[et_compromised](#et_compromised)|2191|2191|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2174|2174|5|0.2%|0.0%|
[shunlist](#shunlist)|1256|1256|3|0.2%|0.0%|
[et_tor](#et_tor)|6360|6360|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6554|6554|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6525|6525|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|3|1.7%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[voipbl](#voipbl)|10367|10776|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2619|2619|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14003|14003|1|0.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|179050|179050|4659|2.6%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|1537|1.6%|0.0%|
[blocklist_de](#blocklist_de)|29355|29355|1487|5.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15563|15563|1330|8.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14003|14003|1322|9.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|558|1.7%|0.0%|
[nixspam](#nixspam)|24694|24694|439|1.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|406|0.8%|0.0%|
[voipbl](#voipbl)|10367|10776|296|2.7%|0.0%|
[openbl_60d](#openbl_60d)|7594|7594|170|2.2%|0.0%|
[et_tor](#et_tor)|6360|6360|167|2.6%|0.0%|
[bm_tor](#bm_tor)|6525|6525|166|2.5%|0.0%|
[dm_tor](#dm_tor)|6554|6554|165|2.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|161|2.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5735|5735|121|2.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|97|6.6%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|84|0.9%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|7144|7144|81|1.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2116|2116|70|3.3%|0.0%|
[openbl_30d](#openbl_30d)|3183|3183|69|2.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|66|5.1%|0.0%|
[et_compromised](#et_compromised)|2191|2191|62|2.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2174|2174|60|2.7%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|58|8.6%|0.0%|
[xroxy](#xroxy)|2039|2039|57|2.7%|0.0%|
[proxyrss](#proxyrss)|1942|1942|43|2.2%|0.0%|
[et_botcc](#et_botcc)|505|505|41|8.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3175|3175|33|1.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2619|2619|31|1.1%|0.0%|
[shunlist](#shunlist)|1256|1256|25|1.9%|0.0%|
[proxz](#proxz)|559|559|23|4.1%|0.0%|
[openbl_7d](#openbl_7d)|931|931|17|1.8%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|17|4.5%|0.0%|
[malc0de](#malc0de)|392|392|12|3.0%|0.0%|
[dshield](#dshield)|20|5120|12|0.2%|0.0%|
[ciarmy](#ciarmy)|346|346|11|3.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1495|1495|11|0.7%|0.0%|
[php_dictionary](#php_dictionary)|433|433|9|2.0%|0.0%|
[zeus](#zeus)|266|266|7|2.6%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[openbl_1d](#openbl_1d)|202|202|6|2.9%|0.0%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.0%|
[php_commenters](#php_commenters)|281|281|5|1.7%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|626|626|5|0.7%|0.0%|
[zeus_badips](#zeus_badips)|230|230|4|1.7%|0.0%|
[sslbl](#sslbl)|361|361|3|0.8%|0.0%|
[feodo](#feodo)|80|80|3|3.7%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|108|108|2|1.8%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|179050|179050|7623|4.2%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|2466|2.6%|0.0%|
[blocklist_de](#blocklist_de)|29355|29355|1526|5.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15563|15563|1135|7.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14003|14003|1074|7.6%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|934|2.9%|0.0%|
[nixspam](#nixspam)|24694|24694|719|2.9%|0.0%|
[voipbl](#voipbl)|10367|10776|432|4.0%|0.0%|
[openbl_60d](#openbl_60d)|7594|7594|339|4.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|247|3.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|230|0.4%|0.0%|
[et_tor](#et_tor)|6360|6360|191|3.0%|0.0%|
[bm_tor](#bm_tor)|6525|6525|190|2.9%|0.0%|
[dm_tor](#dm_tor)|6554|6554|187|2.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3175|3175|179|5.6%|0.0%|
[openbl_30d](#openbl_30d)|3183|3183|176|5.5%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5735|5735|175|3.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|7144|7144|148|2.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|122|1.3%|0.0%|
[et_compromised](#et_compromised)|2191|2191|116|5.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2174|2174|112|5.1%|0.0%|
[xroxy](#xroxy)|2039|2039|99|4.8%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2116|2116|83|3.9%|0.0%|
[proxyrss](#proxyrss)|1942|1942|69|3.5%|0.0%|
[shunlist](#shunlist)|1256|1256|68|5.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1495|1495|48|3.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|45|3.0%|0.0%|
[openbl_7d](#openbl_7d)|931|931|44|4.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2619|2619|41|1.5%|0.0%|
[php_spammers](#php_spammers)|417|417|31|7.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|28|4.1%|0.0%|
[proxz](#proxz)|559|559|27|4.8%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|26|2.0%|0.0%|
[malc0de](#malc0de)|392|392|24|6.1%|0.0%|
[et_botcc](#et_botcc)|505|505|22|4.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|21|5.6%|0.0%|
[ciarmy](#ciarmy)|346|346|14|4.0%|0.0%|
[openbl_1d](#openbl_1d)|202|202|11|5.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|10|2.3%|0.0%|
[zeus](#zeus)|266|266|9|3.3%|0.0%|
[php_commenters](#php_commenters)|281|281|9|3.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|626|626|9|1.4%|0.0%|
[zeus_badips](#zeus_badips)|230|230|8|3.4%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|108|108|8|7.4%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[sslbl](#sslbl)|361|361|6|1.6%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|6|3.4%|0.0%|
[palevo](#palevo)|13|13|3|23.0%|0.0%|
[feodo](#feodo)|80|80|3|3.7%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|179050|179050|14633|8.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|9231|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|5888|6.3%|0.0%|
[blocklist_de](#blocklist_de)|29355|29355|4558|15.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15563|15563|2368|15.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14003|14003|2261|16.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|2085|6.6%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|7144|7144|1790|25.0%|0.0%|
[nixspam](#nixspam)|24694|24694|1657|6.7%|0.0%|
[voipbl](#voipbl)|10367|10776|1593|14.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1172|2.4%|0.0%|
[openbl_60d](#openbl_60d)|7594|7594|727|9.5%|0.0%|
[dm_tor](#dm_tor)|6554|6554|633|9.6%|0.0%|
[bm_tor](#bm_tor)|6525|6525|632|9.6%|0.0%|
[et_tor](#et_tor)|6360|6360|628|9.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|501|7.0%|0.0%|
[openbl_30d](#openbl_30d)|3183|3183|292|9.1%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|246|2.7%|0.0%|
[et_compromised](#et_compromised)|2191|2191|219|9.9%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2174|2174|214|9.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3175|3175|184|5.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2619|2619|165|6.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5735|5735|161|2.8%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|146|11.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1495|1495|137|9.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|125|33.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|110|7.5%|0.0%|
[openbl_7d](#openbl_7d)|931|931|101|10.8%|0.0%|
[shunlist](#shunlist)|1256|1256|99|7.8%|0.0%|
[xroxy](#xroxy)|2039|2039|87|4.2%|0.0%|
[et_botcc](#et_botcc)|505|505|78|15.4%|0.0%|
[malc0de](#malc0de)|392|392|67|17.0%|0.0%|
[proxyrss](#proxyrss)|1942|1942|66|3.3%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|626|626|59|9.4%|0.0%|
[ciarmy](#ciarmy)|346|346|55|15.8%|0.0%|
[proxz](#proxz)|559|559|51|9.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|51|7.5%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2116|2116|47|2.2%|0.0%|
[openbl_1d](#openbl_1d)|202|202|33|16.3%|0.0%|
[php_spammers](#php_spammers)|417|417|26|6.2%|0.0%|
[php_dictionary](#php_dictionary)|433|433|24|5.5%|0.0%|
[sslbl](#sslbl)|361|361|23|6.3%|0.0%|
[zeus](#zeus)|266|266|19|7.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|16|9.3%|0.0%|
[php_harvesters](#php_harvesters)|257|257|15|5.8%|0.0%|
[php_commenters](#php_commenters)|281|281|15|5.3%|0.0%|
[zeus_badips](#zeus_badips)|230|230|14|6.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|108|108|13|12.0%|0.0%|
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
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|22|0.0%|3.2%|
[xroxy](#xroxy)|2039|2039|13|0.6%|1.9%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|11|0.0%|1.6%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|11|0.0%|1.6%|
[ri_web_proxies](#ri_web_proxies)|5735|5735|10|0.1%|1.4%|
[proxyrss](#proxyrss)|1942|1942|9|0.4%|1.3%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|7|0.0%|1.0%|
[ri_connect_proxies](#ri_connect_proxies)|2116|2116|6|0.2%|0.8%|
[proxz](#proxz)|559|559|3|0.5%|0.4%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|2|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|2|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.2%|
[et_block](#et_block)|997|18338381|2|0.0%|0.2%|
[blocklist_de](#blocklist_de)|29355|29355|2|0.0%|0.2%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.1%|
[nixspam](#nixspam)|24694|24694|1|0.0%|0.1%|
[dshield](#dshield)|20|5120|1|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|15563|15563|1|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3175|3175|1|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|179050|179050|1|0.0%|0.1%|

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
[alienvault_reputation](#alienvault_reputation)|179050|179050|288|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|45|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|26|2.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|21|0.0%|0.0%|
[dm_tor](#dm_tor)|6554|6554|21|0.3%|0.0%|
[bm_tor](#bm_tor)|6525|6525|21|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|19|1.3%|0.0%|
[et_tor](#et_tor)|6360|6360|19|0.2%|0.0%|
[nixspam](#nixspam)|24694|24694|14|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|13|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|9|0.1%|0.0%|
[blocklist_de](#blocklist_de)|29355|29355|8|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5735|5735|5|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7594|7594|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|5|1.3%|0.0%|
[voipbl](#voipbl)|10367|10776|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3183|3183|4|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[malc0de](#malc0de)|392|392|3|0.7%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3175|3175|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14003|14003|3|0.0%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2174|2174|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|7144|7144|2|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|108|108|2|1.8%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2619|2619|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[xroxy](#xroxy)|2039|2039|1|0.0%|0.0%|
[sslbl](#sslbl)|361|361|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|1|0.0%|0.0%|
[shunlist](#shunlist)|1256|1256|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.0%|
[openbl_7d](#openbl_7d)|931|931|1|0.1%|0.0%|
[feodo](#feodo)|80|80|1|1.2%|0.0%|
[et_compromised](#et_compromised)|2191|2191|1|0.0%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15563|15563|1|0.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|179050|179050|8|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|6|0.0%|0.4%|
[et_block](#et_block)|997|18338381|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|3|0.2%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|2|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7594|7594|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|3183|3183|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5735|5735|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|931|931|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2191|2191|1|0.0%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|7144|7144|1|0.0%|0.0%|
[blocklist_de](#blocklist_de)|29355|29355|1|0.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|179050|179050|12|0.0%|3.0%|
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
[snort_ipfilter](#snort_ipfilter)|9012|9012|27|0.2%|2.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|26|0.0%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|26|0.0%|2.0%|
[fullbogons](#fullbogons)|3686|670534424|9|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|179050|179050|6|0.0%|0.4%|
[malc0de](#malc0de)|392|392|4|1.0%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|3|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|1|0.0%|0.0%|
[nixspam](#nixspam)|24694|24694|1|0.0%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|11|11|1|9.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|7144|7144|1|0.0%|0.0%|
[blocklist_de](#blocklist_de)|29355|29355|1|0.0%|0.0%|

## maxmind_proxy_fraud

[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.

Source is downloaded from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list).

The last time downloaded was found to be dated: Tue Jun  2 15:36:13 UTC 2015.

The ipset `maxmind_proxy_fraud` has **372** entries, **372** unique IPs.

The following table shows the overlaps of `maxmind_proxy_fraud` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `maxmind_proxy_fraud`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `maxmind_proxy_fraud`.
- ` this % ` is the percentage **of this ipset (`maxmind_proxy_fraud`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|234|0.2%|62.9%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|200|0.6%|53.7%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|178|1.9%|47.8%|
[dm_tor](#dm_tor)|6554|6554|170|2.5%|45.6%|
[bm_tor](#bm_tor)|6525|6525|170|2.6%|45.6%|
[et_tor](#et_tor)|6360|6360|169|2.6%|45.4%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|159|2.2%|42.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|125|0.0%|33.6%|
[php_commenters](#php_commenters)|281|281|28|9.9%|7.5%|
[alienvault_reputation](#alienvault_reputation)|179050|179050|25|0.0%|6.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|21|0.0%|5.6%|
[openbl_60d](#openbl_60d)|7594|7594|18|0.2%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|17|0.0%|4.5%|
[php_harvesters](#php_harvesters)|257|257|6|2.3%|1.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|1.3%|
[ri_web_proxies](#ri_web_proxies)|5735|5735|4|0.0%|1.0%|
[php_spammers](#php_spammers)|417|417|4|0.9%|1.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|1.0%|
[shunlist](#shunlist)|1256|1256|2|0.1%|0.5%|
[xroxy](#xroxy)|2039|2039|1|0.0%|0.2%|
[voipbl](#voipbl)|10367|10776|1|0.0%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2116|2116|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|15563|15563|1|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|14003|14003|1|0.0%|0.2%|
[blocklist_de](#blocklist_de)|29355|29355|1|0.0%|0.2%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Tue Jun  2 19:15:02 UTC 2015.

The ipset `nixspam` has **24694** entries, **24694** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1657|0.0%|6.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|719|0.0%|2.9%|
[blocklist_de](#blocklist_de)|29355|29355|634|2.1%|2.5%|
[blocklist_de_mail](#blocklist_de_mail)|15563|15563|526|3.3%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|439|0.0%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|245|0.2%|0.9%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|221|2.4%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|172|0.0%|0.6%|
[et_block](#et_block)|997|18338381|172|0.0%|0.6%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|171|0.0%|0.6%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|145|0.4%|0.5%|
[ri_web_proxies](#ri_web_proxies)|5735|5735|89|1.5%|0.3%|
[xroxy](#xroxy)|2039|2039|73|3.5%|0.2%|
[php_dictionary](#php_dictionary)|433|433|71|16.3%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|62|0.8%|0.2%|
[php_spammers](#php_spammers)|417|417|56|13.4%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3175|3175|44|1.3%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2619|2619|38|1.4%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|14003|14003|37|0.2%|0.1%|
[alienvault_reputation](#alienvault_reputation)|179050|179050|32|0.0%|0.1%|
[proxz](#proxz)|559|559|23|4.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|7144|7144|19|0.2%|0.0%|
[proxyrss](#proxyrss)|1942|1942|14|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|14|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2116|2116|13|0.6%|0.0%|
[php_commenters](#php_commenters)|281|281|9|3.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|8|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|626|626|8|1.2%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[openbl_60d](#openbl_60d)|7594|7594|7|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1495|1495|7|0.4%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|6|0.0%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[voipbl](#voipbl)|10367|10776|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3183|3183|1|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|1|0.5%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|108|108|1|0.9%|0.0%|

## openbl_1d

[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_1days.txt).

The last time downloaded was found to be dated: Tue Jun  2 18:32:00 UTC 2015.

The ipset `openbl_1d` has **202** entries, **202** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7594|7594|169|2.2%|83.6%|
[openbl_7d](#openbl_7d)|931|931|162|17.4%|80.1%|
[openbl_30d](#openbl_30d)|3183|3183|162|5.0%|80.1%|
[alienvault_reputation](#alienvault_reputation)|179050|179050|161|0.0%|79.7%|
[blocklist_de](#blocklist_de)|29355|29355|140|0.4%|69.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|7144|7144|138|1.9%|68.3%|
[bruteforceblocker](#bruteforceblocker)|2174|2174|69|3.1%|34.1%|
[shunlist](#shunlist)|1256|1256|68|5.4%|33.6%|
[et_compromised](#et_compromised)|2191|2191|60|2.7%|29.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|33|0.0%|16.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|18|10.4%|8.9%|
[dshield](#dshield)|20|5120|17|0.3%|8.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|11|0.0%|5.4%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|6|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|6|0.0%|2.9%|
[et_block](#et_block)|997|18338381|6|0.0%|2.9%|
[blocklist_de_mail](#blocklist_de_mail)|15563|15563|2|0.0%|0.9%|
[blocklist_de_imap](#blocklist_de_imap)|1495|1495|2|0.1%|0.9%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt).

The last time downloaded was found to be dated: Tue Jun  2 15:42:00 UTC 2015.

The ipset `openbl_30d` has **3183** entries, **3183** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7594|7594|3183|41.9%|100.0%|
[alienvault_reputation](#alienvault_reputation)|179050|179050|3164|1.7%|99.4%|
[et_compromised](#et_compromised)|2191|2191|1230|56.1%|38.6%|
[bruteforceblocker](#bruteforceblocker)|2174|2174|1228|56.4%|38.5%|
[openbl_7d](#openbl_7d)|931|931|931|100.0%|29.2%|
[blocklist_de](#blocklist_de)|29355|29355|809|2.7%|25.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|7144|7144|769|10.7%|24.1%|
[shunlist](#shunlist)|1256|1256|580|46.1%|18.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|292|0.0%|9.1%|
[et_block](#et_block)|997|18338381|193|0.0%|6.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|188|0.0%|5.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|176|0.0%|5.5%|
[openbl_1d](#openbl_1d)|202|202|162|80.1%|5.0%|
[dshield](#dshield)|20|5120|70|1.3%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|69|0.0%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|15563|15563|38|0.2%|1.1%|
[blocklist_de_imap](#blocklist_de_imap)|1495|1495|35|2.3%|1.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|25|14.5%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|13|0.0%|0.4%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|6|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|5|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|4|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.1%|
[voipbl](#voipbl)|10367|10776|3|0.0%|0.0%|
[zeus](#zeus)|266|266|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14003|14003|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|1|0.0%|0.0%|
[nixspam](#nixspam)|24694|24694|1|0.0%|0.0%|
[ciarmy](#ciarmy)|346|346|1|0.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|626|626|1|0.1%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt).

The last time downloaded was found to be dated: Tue Jun  2 15:42:00 UTC 2015.

The ipset `openbl_60d` has **7594** entries, **7594** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|179050|179050|7569|4.2%|99.6%|
[openbl_30d](#openbl_30d)|3183|3183|3183|100.0%|41.9%|
[blocklist_de](#blocklist_de)|29355|29355|1339|4.5%|17.6%|
[et_compromised](#et_compromised)|2191|2191|1322|60.3%|17.4%|
[bruteforceblocker](#bruteforceblocker)|2174|2174|1303|59.9%|17.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|7144|7144|1300|18.1%|17.1%|
[openbl_7d](#openbl_7d)|931|931|931|100.0%|12.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|727|0.0%|9.5%|
[shunlist](#shunlist)|1256|1256|597|47.5%|7.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|339|0.0%|4.4%|
[et_block](#et_block)|997|18338381|244|0.0%|3.2%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|239|0.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|170|0.0%|2.2%|
[openbl_1d](#openbl_1d)|202|202|169|83.6%|2.2%|
[dshield](#dshield)|20|5120|78|1.5%|1.0%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|54|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|15563|15563|44|0.2%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|1495|1495|41|2.7%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|28|16.2%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|27|0.2%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|25|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|22|0.3%|0.2%|
[dm_tor](#dm_tor)|6554|6554|21|0.3%|0.2%|
[bm_tor](#bm_tor)|6525|6525|21|0.3%|0.2%|
[et_tor](#et_tor)|6360|6360|19|0.2%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|18|0.0%|0.2%|
[voipbl](#voipbl)|10367|10776|9|0.0%|0.1%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3175|3175|8|0.2%|0.1%|
[nixspam](#nixspam)|24694|24694|7|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|6|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14003|14003|3|0.0%|0.0%|
[zeus](#zeus)|266|266|2|0.7%|0.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|626|626|2|0.3%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[ciarmy](#ciarmy)|346|346|1|0.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2619|2619|1|0.0%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt).

The last time downloaded was found to be dated: Tue Jun  2 15:42:00 UTC 2015.

The ipset `openbl_7d` has **931** entries, **931** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7594|7594|931|12.2%|100.0%|
[openbl_30d](#openbl_30d)|3183|3183|931|29.2%|100.0%|
[alienvault_reputation](#alienvault_reputation)|179050|179050|920|0.5%|98.8%|
[blocklist_de](#blocklist_de)|29355|29355|532|1.8%|57.1%|
[bruteforceblocker](#bruteforceblocker)|2174|2174|526|24.1%|56.4%|
[et_compromised](#et_compromised)|2191|2191|517|23.5%|55.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|7144|7144|515|7.2%|55.3%|
[shunlist](#shunlist)|1256|1256|399|31.7%|42.8%|
[openbl_1d](#openbl_1d)|202|202|162|80.1%|17.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|101|0.0%|10.8%|
[et_block](#et_block)|997|18338381|89|0.0%|9.5%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|86|0.0%|9.2%|
[dshield](#dshield)|20|5120|48|0.9%|5.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|44|0.0%|4.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|24|13.9%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|17|0.0%|1.8%|
[blocklist_de_mail](#blocklist_de_mail)|15563|15563|17|0.1%|1.8%|
[blocklist_de_imap](#blocklist_de_imap)|1495|1495|17|1.1%|1.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|1.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|5|0.0%|0.5%|
[voipbl](#voipbl)|10367|10776|3|0.0%|0.3%|
[zeus](#zeus)|266|266|1|0.3%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.1%|
[ciarmy](#ciarmy)|346|346|1|0.2%|0.1%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Tue Jun  2 19:27:15 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|997|18338381|12|0.0%|92.3%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|11|0.1%|84.6%|
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
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|206|0.2%|73.3%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|163|0.5%|58.0%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|112|1.5%|39.8%|
[blocklist_de](#blocklist_de)|29355|29355|60|0.2%|21.3%|
[blocklist_de_bots](#blocklist_de_bots)|3175|3175|50|1.5%|17.7%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|37|0.4%|13.1%|
[php_spammers](#php_spammers)|417|417|32|7.6%|11.3%|
[et_tor](#et_tor)|6360|6360|29|0.4%|10.3%|
[dm_tor](#dm_tor)|6554|6554|29|0.4%|10.3%|
[bm_tor](#bm_tor)|6525|6525|29|0.4%|10.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|29|16.8%|10.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|28|7.5%|9.9%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|24|0.0%|8.5%|
[et_block](#et_block)|997|18338381|24|0.0%|8.5%|
[php_dictionary](#php_dictionary)|433|433|22|5.0%|7.8%|
[blocklist_de_apache](#blocklist_de_apache)|14003|14003|22|0.1%|7.8%|
[blocklist_de_mail](#blocklist_de_mail)|15563|15563|18|0.1%|6.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|5.3%|
[alienvault_reputation](#alienvault_reputation)|179050|179050|14|0.0%|4.9%|
[ri_web_proxies](#ri_web_proxies)|5735|5735|11|0.1%|3.9%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|3.2%|
[nixspam](#nixspam)|24694|24694|9|0.0%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.2%|
[openbl_60d](#openbl_60d)|7594|7594|8|0.1%|2.8%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|7|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|1.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2619|2619|4|0.1%|1.4%|
[xroxy](#xroxy)|2039|2039|3|0.1%|1.0%|
[proxz](#proxz)|559|559|3|0.5%|1.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.3%|
[zeus](#zeus)|266|266|1|0.3%|0.3%|
[proxyrss](#proxyrss)|1942|1942|1|0.0%|0.3%|
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
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|85|0.0%|19.6%|
[php_spammers](#php_spammers)|417|417|84|20.1%|19.3%|
[nixspam](#nixspam)|24694|24694|71|0.2%|16.3%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|69|0.2%|15.9%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|65|0.7%|15.0%|
[blocklist_de](#blocklist_de)|29355|29355|51|0.1%|11.7%|
[ri_web_proxies](#ri_web_proxies)|5735|5735|33|0.5%|7.6%|
[blocklist_de_mail](#blocklist_de_mail)|15563|15563|33|0.2%|7.6%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|26|0.3%|6.0%|
[xroxy](#xroxy)|2039|2039|24|1.1%|5.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|24|0.0%|5.5%|
[php_commenters](#php_commenters)|281|281|22|7.8%|5.0%|
[blocklist_de_bots](#blocklist_de_bots)|3175|3175|16|0.5%|3.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|10|0.0%|2.3%|
[proxz](#proxz)|559|559|9|1.6%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|9|0.0%|2.0%|
[alienvault_reputation](#alienvault_reputation)|179050|179050|7|0.0%|1.6%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|4|0.0%|0.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.9%|
[et_tor](#et_tor)|6360|6360|4|0.0%|0.9%|
[et_block](#et_block)|997|18338381|4|0.0%|0.9%|
[dm_tor](#dm_tor)|6554|6554|4|0.0%|0.9%|
[bm_tor](#bm_tor)|6525|6525|4|0.0%|0.9%|
[ri_connect_proxies](#ri_connect_proxies)|2116|2116|3|0.1%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|2|1.1%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2619|2619|2|0.0%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|14003|14003|2|0.0%|0.4%|
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
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|63|0.0%|24.5%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|48|0.1%|18.6%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|33|0.4%|12.8%|
[blocklist_de](#blocklist_de)|29355|29355|25|0.0%|9.7%|
[blocklist_de_bots](#blocklist_de_bots)|3175|3175|18|0.5%|7.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|5.8%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|9|0.0%|3.5%|
[php_commenters](#php_commenters)|281|281|9|3.2%|3.5%|
[alienvault_reputation](#alienvault_reputation)|179050|179050|9|0.0%|3.5%|
[nixspam](#nixspam)|24694|24694|7|0.0%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|7|0.0%|2.7%|
[dm_tor](#dm_tor)|6554|6554|7|0.1%|2.7%|
[bm_tor](#bm_tor)|6525|6525|7|0.1%|2.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|6|1.6%|2.3%|
[et_tor](#et_tor)|6360|6360|6|0.0%|2.3%|
[blocklist_de_ftp](#blocklist_de_ftp)|626|626|5|0.7%|1.9%|
[xroxy](#xroxy)|2039|2039|2|0.0%|0.7%|
[proxyrss](#proxyrss)|1942|1942|2|0.1%|0.7%|
[openbl_60d](#openbl_60d)|7594|7594|2|0.0%|0.7%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|2|1.1%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|15563|15563|2|0.0%|0.7%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|1|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|1|0.0%|0.3%|
[ri_web_proxies](#ri_web_proxies)|5735|5735|1|0.0%|0.3%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.3%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|
[fullbogons](#fullbogons)|3686|670534424|1|0.0%|0.3%|
[et_block](#et_block)|997|18338381|1|0.0%|0.3%|
[bogons](#bogons)|13|592708608|1|0.0%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|14003|14003|1|0.0%|0.3%|

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
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|100|0.1%|23.9%|
[php_dictionary](#php_dictionary)|433|433|84|19.3%|20.1%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|71|0.2%|17.0%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|58|0.6%|13.9%|
[nixspam](#nixspam)|24694|24694|56|0.2%|13.4%|
[blocklist_de](#blocklist_de)|29355|29355|44|0.1%|10.5%|
[php_commenters](#php_commenters)|281|281|32|11.3%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|31|0.0%|7.4%|
[blocklist_de_mail](#blocklist_de_mail)|15563|15563|31|0.1%|7.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|26|0.0%|6.2%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|25|0.3%|5.9%|
[ri_web_proxies](#ri_web_proxies)|5735|5735|25|0.4%|5.9%|
[xroxy](#xroxy)|2039|2039|20|0.9%|4.7%|
[blocklist_de_bots](#blocklist_de_bots)|3175|3175|10|0.3%|2.3%|
[proxz](#proxz)|559|559|8|1.4%|1.9%|
[et_tor](#et_tor)|6360|6360|6|0.0%|1.4%|
[dm_tor](#dm_tor)|6554|6554|6|0.0%|1.4%|
[bm_tor](#bm_tor)|6525|6525|6|0.0%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|1.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.9%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2619|2619|4|0.1%|0.9%|
[blocklist_de_apache](#blocklist_de_apache)|14003|14003|4|0.0%|0.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|3|1.7%|0.7%|
[alienvault_reputation](#alienvault_reputation)|179050|179050|3|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|2|0.0%|0.4%|
[ri_connect_proxies](#ri_connect_proxies)|2116|2116|2|0.0%|0.4%|
[proxyrss](#proxyrss)|1942|1942|2|0.1%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[et_block](#et_block)|997|18338381|2|0.0%|0.4%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.2%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Tue Jun  2 17:11:32 UTC 2015.

The ipset `proxyrss` has **1942** entries, **1942** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|832|0.9%|42.8%|
[ri_web_proxies](#ri_web_proxies)|5735|5735|709|12.3%|36.5%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|702|2.2%|36.1%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|480|6.7%|24.7%|
[xroxy](#xroxy)|2039|2039|477|23.3%|24.5%|
[ri_connect_proxies](#ri_connect_proxies)|2116|2116|259|12.2%|13.3%|
[blocklist_de](#blocklist_de)|29355|29355|231|0.7%|11.8%|
[blocklist_de_bots](#blocklist_de_bots)|3175|3175|226|7.1%|11.6%|
[proxz](#proxz)|559|559|186|33.2%|9.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|69|0.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|66|0.0%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|43|0.0%|2.2%|
[nixspam](#nixspam)|24694|24694|14|0.0%|0.7%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|9|1.3%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|7|4.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|4|0.0%|0.2%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.1%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|15563|15563|2|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|179050|179050|2|0.0%|0.1%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.0%|
[et_tor](#et_tor)|6360|6360|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6554|6554|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6525|6525|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|7144|7144|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|626|626|1|0.1%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Tue Jun  2 17:11:38 UTC 2015.

The ipset `proxz` has **559** entries, **559** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|331|0.3%|59.2%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|286|0.9%|51.1%|
[xroxy](#xroxy)|2039|2039|256|12.5%|45.7%|
[ri_web_proxies](#ri_web_proxies)|5735|5735|237|4.1%|42.3%|
[proxyrss](#proxyrss)|1942|1942|186|9.5%|33.2%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|130|1.8%|23.2%|
[blocklist_de](#blocklist_de)|29355|29355|108|0.3%|19.3%|
[blocklist_de_bots](#blocklist_de_bots)|3175|3175|90|2.8%|16.1%|
[ri_connect_proxies](#ri_connect_proxies)|2116|2116|84|3.9%|15.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|51|0.0%|9.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|27|0.0%|4.8%|
[nixspam](#nixspam)|24694|24694|23|0.0%|4.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|23|0.0%|4.1%|
[blocklist_de_mail](#blocklist_de_mail)|15563|15563|15|0.0%|2.6%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|13|0.1%|2.3%|
[php_dictionary](#php_dictionary)|433|433|9|2.0%|1.6%|
[php_spammers](#php_spammers)|417|417|8|1.9%|1.4%|
[php_commenters](#php_commenters)|281|281|3|1.0%|0.5%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|3|0.4%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|3|1.7%|0.5%|
[et_compromised](#et_compromised)|2191|2191|2|0.0%|0.3%|
[bruteforceblocker](#bruteforceblocker)|2174|2174|2|0.0%|0.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|7144|7144|2|0.0%|0.3%|
[alienvault_reputation](#alienvault_reputation)|179050|179050|2|0.0%|0.3%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.1%|
[et_tor](#et_tor)|6360|6360|1|0.0%|0.1%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Tue Jun  2 11:14:43 UTC 2015.

The ipset `ri_connect_proxies` has **2116** entries, **2116** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|1236|1.3%|58.4%|
[ri_web_proxies](#ri_web_proxies)|5735|5735|870|15.1%|41.1%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|678|2.1%|32.0%|
[xroxy](#xroxy)|2039|2039|330|16.1%|15.5%|
[proxyrss](#proxyrss)|1942|1942|259|13.3%|12.2%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|137|1.9%|6.4%|
[proxz](#proxz)|559|559|84|15.0%|3.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|83|0.0%|3.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|70|0.0%|3.3%|
[blocklist_de](#blocklist_de)|29355|29355|69|0.2%|3.2%|
[blocklist_de_bots](#blocklist_de_bots)|3175|3175|67|2.1%|3.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|47|0.0%|2.2%|
[nixspam](#nixspam)|24694|24694|13|0.0%|0.6%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|3|0.0%|0.1%|
[php_dictionary](#php_dictionary)|433|433|3|0.6%|0.1%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[et_tor](#et_tor)|6360|6360|2|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|179050|179050|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[dm_tor](#dm_tor)|6554|6554|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6525|6525|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|7144|7144|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15563|15563|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Tue Jun  2 17:27:15 UTC 2015.

The ipset `ri_web_proxies` has **5735** entries, **5735** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|2808|3.0%|48.9%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|1750|5.5%|30.5%|
[ri_connect_proxies](#ri_connect_proxies)|2116|2116|870|41.1%|15.1%|
[xroxy](#xroxy)|2039|2039|845|41.4%|14.7%|
[proxyrss](#proxyrss)|1942|1942|709|36.5%|12.3%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|532|7.5%|9.2%|
[blocklist_de](#blocklist_de)|29355|29355|366|1.2%|6.3%|
[blocklist_de_bots](#blocklist_de_bots)|3175|3175|327|10.2%|5.7%|
[proxz](#proxz)|559|559|237|42.3%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|175|0.0%|3.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|161|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|121|0.0%|2.1%|
[nixspam](#nixspam)|24694|24694|89|0.3%|1.5%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|56|0.6%|0.9%|
[blocklist_de_mail](#blocklist_de_mail)|15563|15563|38|0.2%|0.6%|
[php_dictionary](#php_dictionary)|433|433|33|7.6%|0.5%|
[php_spammers](#php_spammers)|417|417|25|5.9%|0.4%|
[php_commenters](#php_commenters)|281|281|11|3.9%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|10|1.4%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|5|2.9%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.0%|
[et_tor](#et_tor)|6360|6360|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6554|6554|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6525|6525|3|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|179050|179050|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2174|2174|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Tue Jun  2 18:30:03 UTC 2015.

The ipset `shunlist` has **1256** entries, **1256** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|179050|179050|1242|0.6%|98.8%|
[openbl_60d](#openbl_60d)|7594|7594|597|7.8%|47.5%|
[openbl_30d](#openbl_30d)|3183|3183|580|18.2%|46.1%|
[et_compromised](#et_compromised)|2191|2191|502|22.9%|39.9%|
[bruteforceblocker](#bruteforceblocker)|2174|2174|501|23.0%|39.8%|
[blocklist_de](#blocklist_de)|29355|29355|412|1.4%|32.8%|
[openbl_7d](#openbl_7d)|931|931|399|42.8%|31.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|7144|7144|377|5.2%|30.0%|
[et_block](#et_block)|997|18338381|106|0.0%|8.4%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|99|0.0%|7.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|99|0.0%|7.8%|
[openbl_1d](#openbl_1d)|202|202|68|33.6%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|68|0.0%|5.4%|
[sslbl](#sslbl)|361|361|55|15.2%|4.3%|
[dshield](#dshield)|20|5120|48|0.9%|3.8%|
[blocklist_de_apache](#blocklist_de_apache)|14003|14003|30|0.2%|2.3%|
[ciarmy](#ciarmy)|346|346|27|7.8%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|25|0.0%|1.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|20|11.6%|1.5%|
[voipbl](#voipbl)|10367|10776|12|0.1%|0.9%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|5|0.0%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|4|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|4|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|15563|15563|4|0.0%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|3|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|1495|1495|3|0.2%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|2|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_tor](#et_tor)|6360|6360|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6554|6554|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6525|6525|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|626|626|1|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2619|2619|1|0.0%|0.0%|

## snort_ipfilter

[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)

Source is downloaded from [this link](http://labs.snort.org/feeds/ip-filter.blf).

The last time downloaded was found to be dated: Tue Jun  2 13:30:00 UTC 2015.

The ipset `snort_ipfilter` has **9012** entries, **9012** unique IPs.

The following table shows the overlaps of `snort_ipfilter` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `snort_ipfilter`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `snort_ipfilter`.
- ` this % ` is the percentage **of this ipset (`snort_ipfilter`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_tor](#et_tor)|6360|6360|1077|16.9%|11.9%|
[dm_tor](#dm_tor)|6554|6554|1072|16.3%|11.8%|
[bm_tor](#bm_tor)|6525|6525|1069|16.3%|11.8%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|793|0.8%|8.7%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|613|1.9%|6.8%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|353|4.9%|3.9%|
[et_block](#et_block)|997|18338381|298|0.0%|3.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|246|0.0%|2.7%|
[zeus](#zeus)|266|266|227|85.3%|2.5%|
[nixspam](#nixspam)|24694|24694|221|0.8%|2.4%|
[zeus_badips](#zeus_badips)|230|230|202|87.8%|2.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|178|47.8%|1.9%|
[blocklist_de](#blocklist_de)|29355|29355|163|0.5%|1.8%|
[blocklist_de_mail](#blocklist_de_mail)|15563|15563|124|0.7%|1.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|122|0.0%|1.3%|
[alienvault_reputation](#alienvault_reputation)|179050|179050|121|0.0%|1.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|84|0.0%|0.9%|
[php_dictionary](#php_dictionary)|433|433|65|15.0%|0.7%|
[feodo](#feodo)|80|80|64|80.0%|0.7%|
[php_spammers](#php_spammers)|417|417|58|13.9%|0.6%|
[ri_web_proxies](#ri_web_proxies)|5735|5735|56|0.9%|0.6%|
[xroxy](#xroxy)|2039|2039|48|2.3%|0.5%|
[php_commenters](#php_commenters)|281|281|37|13.1%|0.4%|
[blocklist_de_bots](#blocklist_de_bots)|3175|3175|30|0.9%|0.3%|
[sslbl](#sslbl)|361|361|27|7.4%|0.2%|
[openbl_60d](#openbl_60d)|7594|7594|27|0.3%|0.2%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|27|2.1%|0.2%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|19|0.0%|0.2%|
[proxz](#proxz)|559|559|13|2.3%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|13|0.0%|0.1%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|14003|14003|10|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1495|1495|7|0.4%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2619|2619|7|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|6|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3183|3183|5|0.1%|0.0%|
[shunlist](#shunlist)|1256|1256|4|0.3%|0.0%|
[proxyrss](#proxyrss)|1942|1942|4|0.2%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2116|2116|3|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.0%|
[et_compromised](#et_compromised)|2191|2191|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2174|2174|3|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|7144|7144|2|0.0%|0.0%|
[openbl_7d](#openbl_7d)|931|931|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|1|0.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|626|626|1|0.1%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|179050|179050|1628|0.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|981|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|512|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|340|1.0%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[openbl_60d](#openbl_60d)|7594|7594|239|3.1%|0.0%|
[openbl_30d](#openbl_30d)|3183|3183|188|5.9%|0.0%|
[nixspam](#nixspam)|24694|24694|171|0.6%|0.0%|
[blocklist_de](#blocklist_de)|29355|29355|158|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|7144|7144|112|1.5%|0.0%|
[et_compromised](#et_compromised)|2191|2191|102|4.6%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|101|1.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2174|2174|100|4.5%|0.0%|
[shunlist](#shunlist)|1256|1256|99|7.8%|0.0%|
[openbl_7d](#openbl_7d)|931|931|86|9.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|29|2.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15563|15563|27|0.1%|0.0%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|19|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3175|3175|17|0.5%|0.0%|
[zeus_badips](#zeus_badips)|230|230|16|6.9%|0.0%|
[zeus](#zeus)|266|266|16|6.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1495|1495|16|1.0%|0.0%|
[voipbl](#voipbl)|10367|10776|14|0.1%|0.0%|
[openbl_1d](#openbl_1d)|202|202|6|2.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|6|3.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[malc0de](#malc0de)|392|392|4|1.0%|0.0%|
[sslbl](#sslbl)|361|361|3|0.8%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6360|6360|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6554|6554|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6525|6525|2|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2619|2619|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14003|14003|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|108|108|1|0.9%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|179050|179050|271|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|101|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|27|0.0%|0.0%|
[blocklist_de](#blocklist_de)|29355|29355|13|0.0%|0.0%|
[php_commenters](#php_commenters)|281|281|7|2.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|6|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|6|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7594|7594|6|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3183|3183|6|0.1%|0.0%|
[nixspam](#nixspam)|24694|24694|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|6|3.4%|0.0%|
[zeus_badips](#zeus_badips)|230|230|5|2.1%|0.0%|
[zeus](#zeus)|266|266|5|1.8%|0.0%|
[shunlist](#shunlist)|1256|1256|5|0.3%|0.0%|
[openbl_7d](#openbl_7d)|931|931|5|0.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3175|3175|5|0.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15563|15563|4|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|7144|7144|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14003|14003|2|0.0%|0.0%|
[virbl](#virbl)|13|13|1|7.6%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[malc0de](#malc0de)|392|392|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Tue Jun  2 19:15:07 UTC 2015.

The ipset `sslbl` has **361** entries, **361** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|179050|179050|63|0.0%|17.4%|
[shunlist](#shunlist)|1256|1256|55|4.3%|15.2%|
[feodo](#feodo)|80|80|31|38.7%|8.5%|
[et_block](#et_block)|997|18338381|30|0.0%|8.3%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|27|0.2%|7.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|23|0.0%|6.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|6|0.0%|1.6%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|3|0.0%|0.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Tue Jun  2 19:00:02 UTC 2015.

The ipset `stopforumspam_1d` has **7074** entries, **7074** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|4899|5.3%|69.2%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|4603|14.6%|65.0%|
[blocklist_de](#blocklist_de)|29355|29355|1428|4.8%|20.1%|
[blocklist_de_bots](#blocklist_de_bots)|3175|3175|1375|43.3%|19.4%|
[ri_web_proxies](#ri_web_proxies)|5735|5735|532|9.2%|7.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|501|0.0%|7.0%|
[proxyrss](#proxyrss)|1942|1942|480|24.7%|6.7%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|353|3.9%|4.9%|
[xroxy](#xroxy)|2039|2039|328|16.0%|4.6%|
[et_tor](#et_tor)|6360|6360|304|4.7%|4.2%|
[bm_tor](#bm_tor)|6525|6525|302|4.6%|4.2%|
[dm_tor](#dm_tor)|6554|6554|301|4.5%|4.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|247|0.0%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|161|0.0%|2.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|159|42.7%|2.2%|
[ri_connect_proxies](#ri_connect_proxies)|2116|2116|137|6.4%|1.9%|
[proxz](#proxz)|559|559|130|23.2%|1.8%|
[php_commenters](#php_commenters)|281|281|112|39.8%|1.5%|
[et_block](#et_block)|997|18338381|102|0.0%|1.4%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|101|0.0%|1.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|101|58.7%|1.4%|
[nixspam](#nixspam)|24694|24694|62|0.2%|0.8%|
[blocklist_de_apache](#blocklist_de_apache)|14003|14003|60|0.4%|0.8%|
[alienvault_reputation](#alienvault_reputation)|179050|179050|57|0.0%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|15563|15563|44|0.2%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|37|0.0%|0.5%|
[php_harvesters](#php_harvesters)|257|257|33|12.8%|0.4%|
[php_dictionary](#php_dictionary)|433|433|26|6.0%|0.3%|
[php_spammers](#php_spammers)|417|417|25|5.9%|0.3%|
[openbl_60d](#openbl_60d)|7594|7594|22|0.2%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2619|2619|14|0.5%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|9|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|7|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|6|0.0%|0.0%|
[voipbl](#voipbl)|10367|10776|4|0.0%|0.0%|
[shunlist](#shunlist)|1256|1256|2|0.1%|0.0%|
[et_compromised](#et_compromised)|2191|2191|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2174|2174|2|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|626|626|2|0.3%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3183|3183|1|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|

## stopforumspam_30d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip).

The last time downloaded was found to be dated: Tue Jun  2 00:00:38 UTC 2015.

The ipset `stopforumspam_30d` has **92372** entries, **92372** unique IPs.

The following table shows the overlaps of `stopforumspam_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_30d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|31205|99.5%|33.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|5888|0.0%|6.3%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|4899|69.2%|5.3%|
[ri_web_proxies](#ri_web_proxies)|5735|5735|2808|48.9%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2466|0.0%|2.6%|
[blocklist_de](#blocklist_de)|29355|29355|2337|7.9%|2.5%|
[blocklist_de_bots](#blocklist_de_bots)|3175|3175|2024|63.7%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1537|0.0%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|2116|2116|1236|58.4%|1.3%|
[xroxy](#xroxy)|2039|2039|1192|58.4%|1.2%|
[et_block](#et_block)|997|18338381|986|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|981|0.0%|1.0%|
[proxyrss](#proxyrss)|1942|1942|832|42.8%|0.9%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|793|8.7%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|731|0.0%|0.7%|
[et_tor](#et_tor)|6360|6360|636|10.0%|0.6%|
[dm_tor](#dm_tor)|6554|6554|624|9.5%|0.6%|
[bm_tor](#bm_tor)|6525|6525|624|9.5%|0.6%|
[proxz](#proxz)|559|559|331|59.2%|0.3%|
[nixspam](#nixspam)|24694|24694|245|0.9%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|234|62.9%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|15563|15563|216|1.3%|0.2%|
[alienvault_reputation](#alienvault_reputation)|179050|179050|215|0.1%|0.2%|
[php_commenters](#php_commenters)|281|281|206|73.3%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|14003|14003|193|1.3%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|126|73.2%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|101|0.0%|0.1%|
[php_spammers](#php_spammers)|417|417|100|23.9%|0.1%|
[php_dictionary](#php_dictionary)|433|433|85|19.6%|0.0%|
[php_harvesters](#php_harvesters)|257|257|63|24.5%|0.0%|
[openbl_60d](#openbl_60d)|7594|7594|54|0.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|7144|7144|46|0.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|45|0.0%|0.0%|
[voipbl](#voipbl)|10367|10776|39|0.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2619|2619|35|1.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|22|3.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|16|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|626|626|10|1.5%|0.0%|
[et_compromised](#et_compromised)|2191|2191|9|0.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2174|2174|9|0.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1495|1495|6|0.4%|0.0%|
[shunlist](#shunlist)|1256|1256|4|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3183|3183|4|0.1%|0.0%|
[zeus_badips](#zeus_badips)|230|230|3|1.3%|0.0%|
[zeus](#zeus)|266|266|3|1.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|3|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3686|670534424|2|0.0%|0.0%|
[sslbl](#sslbl)|361|361|1|0.2%|0.0%|
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
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|31205|33.7%|99.5%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|4603|65.0%|14.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2085|0.0%|6.6%|
[blocklist_de](#blocklist_de)|29355|29355|2023|6.8%|6.4%|
[blocklist_de_bots](#blocklist_de_bots)|3175|3175|1842|58.0%|5.8%|
[ri_web_proxies](#ri_web_proxies)|5735|5735|1750|30.5%|5.5%|
[xroxy](#xroxy)|2039|2039|981|48.1%|3.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|934|0.0%|2.9%|
[proxyrss](#proxyrss)|1942|1942|702|36.1%|2.2%|
[ri_connect_proxies](#ri_connect_proxies)|2116|2116|678|32.0%|2.1%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|613|6.8%|1.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|558|0.0%|1.7%|
[et_tor](#et_tor)|6360|6360|491|7.7%|1.5%|
[dm_tor](#dm_tor)|6554|6554|475|7.2%|1.5%|
[bm_tor](#bm_tor)|6525|6525|475|7.2%|1.5%|
[et_block](#et_block)|997|18338381|341|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|340|0.0%|1.0%|
[proxz](#proxz)|559|559|286|51.1%|0.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|200|53.7%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|178|0.0%|0.5%|
[php_commenters](#php_commenters)|281|281|163|58.0%|0.5%|
[nixspam](#nixspam)|24694|24694|145|0.5%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|15563|15563|137|0.8%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|14003|14003|120|0.8%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|116|67.4%|0.3%|
[alienvault_reputation](#alienvault_reputation)|179050|179050|100|0.0%|0.3%|
[php_spammers](#php_spammers)|417|417|71|17.0%|0.2%|
[php_dictionary](#php_dictionary)|433|433|69|15.9%|0.2%|
[php_harvesters](#php_harvesters)|257|257|48|18.6%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2619|2619|28|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|27|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7594|7594|25|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.0%|
[voipbl](#voipbl)|10367|10776|12|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|7|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2174|2174|6|0.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|626|626|6|0.9%|0.0%|
[et_compromised](#et_compromised)|2191|2191|5|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|7144|7144|5|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1495|1495|4|0.2%|0.0%|
[shunlist](#shunlist)|1256|1256|3|0.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|2|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3183|3183|1|0.0%|0.0%|

## virbl

[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.

Source is downloaded from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt).

The last time downloaded was found to be dated: Tue Jun  2 18:42:03 UTC 2015.

The ipset `virbl` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `virbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `virbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `virbl`.
- ` this % ` is the percentage **of this ipset (`virbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|1|0.0%|7.6%|
[blocklist_de_mail](#blocklist_de_mail)|15563|15563|1|0.0%|7.6%|
[blocklist_de](#blocklist_de)|29355|29355|1|0.0%|7.6%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Tue Jun  2 18:00:14 UTC 2015.

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
[alienvault_reputation](#alienvault_reputation)|179050|179050|210|0.1%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|39|0.0%|0.3%|
[blocklist_de](#blocklist_de)|29355|29355|39|0.1%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|108|108|28|25.9%|0.2%|
[et_block](#et_block)|997|18338381|24|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|14|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|12|0.0%|0.1%|
[shunlist](#shunlist)|1256|1256|12|0.9%|0.1%|
[openbl_60d](#openbl_60d)|7594|7594|9|0.1%|0.0%|
[ciarmy](#ciarmy)|346|346|6|1.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14003|14003|6|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[openbl_7d](#openbl_7d)|931|931|3|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3183|3183|3|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[et_tor](#et_tor)|6360|6360|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6554|6554|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6525|6525|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|7144|7144|2|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2619|2619|2|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3175|3175|2|0.0%|0.0%|
[nixspam](#nixspam)|24694|24694|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2191|2191|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2174|2174|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15563|15563|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1495|1495|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Tue Jun  2 18:33:01 UTC 2015.

The ipset `xroxy` has **2039** entries, **2039** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|1192|1.2%|58.4%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|981|3.1%|48.1%|
[ri_web_proxies](#ri_web_proxies)|5735|5735|845|14.7%|41.4%|
[proxyrss](#proxyrss)|1942|1942|477|24.5%|23.3%|
[ri_connect_proxies](#ri_connect_proxies)|2116|2116|330|15.5%|16.1%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|328|4.6%|16.0%|
[proxz](#proxz)|559|559|256|45.7%|12.5%|
[blocklist_de](#blocklist_de)|29355|29355|239|0.8%|11.7%|
[blocklist_de_bots](#blocklist_de_bots)|3175|3175|197|6.2%|9.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|99|0.0%|4.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|87|0.0%|4.2%|
[nixspam](#nixspam)|24694|24694|73|0.2%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|57|0.0%|2.7%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|48|0.5%|2.3%|
[blocklist_de_mail](#blocklist_de_mail)|15563|15563|39|0.2%|1.9%|
[php_dictionary](#php_dictionary)|433|433|24|5.5%|1.1%|
[php_spammers](#php_spammers)|417|417|20|4.7%|0.9%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|13|1.9%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|7|4.0%|0.3%|
[alienvault_reputation](#alienvault_reputation)|179050|179050|5|0.0%|0.2%|
[php_commenters](#php_commenters)|281|281|3|1.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.1%|
[et_tor](#et_tor)|6360|6360|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[dm_tor](#dm_tor)|6554|6554|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6525|6525|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|7144|7144|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2191|2191|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2174|2174|1|0.0%|0.0%|

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
[snort_ipfilter](#snort_ipfilter)|9012|9012|227|2.5%|85.3%|
[alienvault_reputation](#alienvault_reputation)|179050|179050|66|0.0%|24.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|19|0.0%|7.1%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|16|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|7|0.0%|2.6%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|5|0.0%|1.8%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|3|0.0%|1.1%|
[openbl_60d](#openbl_60d)|7594|7594|2|0.0%|0.7%|
[openbl_30d](#openbl_30d)|3183|3183|2|0.0%|0.7%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|1|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|1|0.0%|0.3%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.3%|
[openbl_7d](#openbl_7d)|931|931|1|0.1%|0.3%|
[nixspam](#nixspam)|24694|24694|1|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|
[et_compromised](#et_compromised)|2191|2191|1|0.0%|0.3%|
[dshield](#dshield)|20|5120|1|0.0%|0.3%|
[bruteforceblocker](#bruteforceblocker)|2174|2174|1|0.0%|0.3%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Tue Jun  2 19:27:13 UTC 2015.

The ipset `zeus_badips` has **230** entries, **230** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|266|266|230|86.4%|100.0%|
[et_block](#et_block)|997|18338381|229|0.0%|99.5%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|202|2.2%|87.8%|
[alienvault_reputation](#alienvault_reputation)|179050|179050|37|0.0%|16.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|16|0.0%|6.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8|0.0%|3.4%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|5|0.0%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4|0.0%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|3|0.0%|1.3%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|7074|7074|1|0.0%|0.4%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.4%|
[openbl_60d](#openbl_60d)|7594|7594|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|3183|3183|1|0.0%|0.4%|
[nixspam](#nixspam)|24694|24694|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.4%|
[et_compromised](#et_compromised)|2191|2191|1|0.0%|0.4%|
[dshield](#dshield)|20|5120|1|0.0%|0.4%|
[bruteforceblocker](#bruteforceblocker)|2174|2174|1|0.0%|0.4%|
