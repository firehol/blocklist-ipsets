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

The following list was automatically generated on Mon Jun  1 23:46:22 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|173822 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|23053 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|14034 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|3177 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|1614 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|268 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|670 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|14733 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|102 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|1831 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|160 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6513 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|2178 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|345 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|426 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6510 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
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
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|23154 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|146 unique IPs|updated every 1 hour  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|3180 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7583 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|913 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|281 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|433 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|257 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|417 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1713 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|480 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2051 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|5560 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1253 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|6251 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|656 subnets, 18600704 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|56 subnets, 421632 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|363 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|7144 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|92062 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|31333 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10350 subnets, 10759 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2019 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|267 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|231 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Mon Jun  1 22:00:48 UTC 2015.

The ipset `alienvault_reputation` has **173822** entries, **173822** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14365|0.0%|8.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7617|0.0%|4.3%|
[openbl_60d](#openbl_60d)|7583|7583|7556|99.6%|4.3%|
[et_block](#et_block)|997|18338381|5028|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4396|0.0%|2.5%|
[dshield](#dshield)|20|5120|3849|75.1%|2.2%|
[openbl_30d](#openbl_30d)|3180|3180|3159|99.3%|1.8%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|1628|0.0%|0.9%|
[et_compromised](#et_compromised)|2191|2191|1420|64.8%|0.8%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|1406|64.5%|0.8%|
[shunlist](#shunlist)|1253|1253|1239|98.8%|0.7%|
[blocklist_de](#blocklist_de)|23053|23053|1124|4.8%|0.6%|
[openbl_7d](#openbl_7d)|913|913|898|98.3%|0.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|1831|1831|875|47.7%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|518|0.0%|0.2%|
[ciarmy](#ciarmy)|345|345|340|98.5%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|288|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|271|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|210|0.2%|0.1%|
[voipbl](#voipbl)|10350|10759|200|1.8%|0.1%|
[openbl_1d](#openbl_1d)|146|146|136|93.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|114|1.8%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14034|14034|111|0.7%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|107|0.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|86|0.5%|0.0%|
[zeus](#zeus)|267|267|66|24.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|670|670|60|8.9%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7144|7144|54|0.7%|0.0%|
[sslbl](#sslbl)|363|363|51|14.0%|0.0%|
[dm_tor](#dm_tor)|6510|6510|46|0.7%|0.0%|
[bm_tor](#bm_tor)|6513|6513|46|0.7%|0.0%|
[nixspam](#nixspam)|23154|23154|45|0.1%|0.0%|
[et_tor](#et_tor)|6360|6360|44|0.6%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3177|3177|40|1.2%|0.0%|
[zeus_badips](#zeus_badips)|231|231|37|16.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|160|160|36|22.5%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|25|6.7%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|102|102|18|17.6%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1614|1614|15|0.9%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[php_commenters](#php_commenters)|281|281|13|4.6%|0.0%|
[malc0de](#malc0de)|397|397|12|3.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|8|3.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|8|0.5%|0.0%|
[php_dictionary](#php_dictionary)|433|433|7|1.6%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|268|268|7|2.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|6|0.4%|0.0%|
[xroxy](#xroxy)|2019|2019|5|0.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|426|426|4|0.9%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5560|5560|3|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|3|0.7%|0.0%|
[et_botcc](#et_botcc)|505|505|3|0.5%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2051|2051|2|0.0%|0.0%|
[proxz](#proxz)|480|480|2|0.4%|0.0%|
[proxyrss](#proxyrss)|1713|1713|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[feodo](#feodo)|77|77|1|1.2%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Mon Jun  1 23:14:02 UTC 2015.

The ipset `blocklist_de` has **23053** entries, **23053** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|14733|100.0%|63.9%|
[blocklist_de_apache](#blocklist_de_apache)|14034|14034|14034|100.0%|60.8%|
[blocklist_de_bots](#blocklist_de_bots)|3177|3177|3169|99.7%|13.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2895|0.0%|12.5%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|2087|2.2%|9.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1831|1831|1829|99.8%|7.9%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|1815|5.7%|7.8%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1614|1614|1614|100.0%|7.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1468|0.0%|6.3%|
[stopforumspam_1d](#stopforumspam_1d)|7144|7144|1443|20.1%|6.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1431|0.0%|6.2%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|1124|0.6%|4.8%|
[openbl_60d](#openbl_60d)|7583|7583|847|11.1%|3.6%|
[openbl_30d](#openbl_30d)|3180|3180|759|23.8%|3.2%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|697|32.0%|3.0%|
[et_compromised](#et_compromised)|2191|2191|689|31.4%|2.9%|
[blocklist_de_imap](#blocklist_de_imap)|670|670|664|99.1%|2.8%|
[nixspam](#nixspam)|23154|23154|556|2.4%|2.4%|
[openbl_7d](#openbl_7d)|913|913|528|57.8%|2.2%|
[shunlist](#shunlist)|1253|1253|408|32.5%|1.7%|
[ri_web_proxies](#ri_web_proxies)|5560|5560|359|6.4%|1.5%|
[blocklist_de_ftp](#blocklist_de_ftp)|268|268|268|100.0%|1.1%|
[proxyrss](#proxyrss)|1713|1713|247|14.4%|1.0%|
[xroxy](#xroxy)|2019|2019|233|11.5%|1.0%|
[et_block](#et_block)|997|18338381|181|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|172|0.0%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|160|160|160|100.0%|0.6%|
[openbl_1d](#openbl_1d)|146|146|124|84.9%|0.5%|
[proxz](#proxz)|480|480|97|20.2%|0.4%|
[blocklist_de_sip](#blocklist_de_sip)|102|102|83|81.3%|0.3%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|82|1.3%|0.3%|
[php_commenters](#php_commenters)|281|281|63|22.4%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2051|2051|59|2.8%|0.2%|
[dshield](#dshield)|20|5120|55|1.0%|0.2%|
[php_spammers](#php_spammers)|417|417|43|10.3%|0.1%|
[voipbl](#voipbl)|10350|10759|40|0.3%|0.1%|
[php_dictionary](#php_dictionary)|433|433|40|9.2%|0.1%|
[ciarmy](#ciarmy)|345|345|38|11.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|34|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|26|10.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|9|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|7|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.0%|
[et_tor](#et_tor)|6360|6360|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6510|6510|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6513|6513|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Mon Jun  1 23:28:25 UTC 2015.

The ipset `blocklist_de_apache` has **14034** entries, **14034** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|23053|23053|14034|60.8%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|11059|75.0%|78.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2205|0.0%|15.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1614|1614|1614|100.0%|11.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1319|0.0%|9.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1061|0.0%|7.5%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|202|0.2%|1.4%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|124|0.3%|0.8%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|111|0.0%|0.7%|
[stopforumspam_1d](#stopforumspam_1d)|7144|7144|64|0.8%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|160|160|36|22.5%|0.2%|
[ciarmy](#ciarmy)|345|345|31|8.9%|0.2%|
[shunlist](#shunlist)|1253|1253|29|2.3%|0.2%|
[php_commenters](#php_commenters)|281|281|25|8.8%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3177|3177|21|0.6%|0.1%|
[nixspam](#nixspam)|23154|23154|12|0.0%|0.0%|
[et_block](#et_block)|997|18338381|6|0.0%|0.0%|
[voipbl](#voipbl)|10350|10759|5|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|5|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|3|0.0%|0.0%|
[et_tor](#et_tor)|6360|6360|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6510|6510|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6513|6513|3|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|2|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7583|7583|2|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3180|3180|2|0.0%|0.0%|
[et_compromised](#et_compromised)|2191|2191|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[openbl_7d](#openbl_7d)|913|913|1|0.1%|0.0%|
[openbl_1d](#openbl_1d)|146|146|1|0.6%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Mon Jun  1 23:28:26 UTC 2015.

The ipset `blocklist_de_bots` has **3177** entries, **3177** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|23053|23053|3169|13.7%|99.7%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|1832|1.9%|57.6%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|1658|5.2%|52.1%|
[stopforumspam_1d](#stopforumspam_1d)|7144|7144|1388|19.4%|43.6%|
[ri_web_proxies](#ri_web_proxies)|5560|5560|332|5.9%|10.4%|
[proxyrss](#proxyrss)|1713|1713|247|14.4%|7.7%|
[xroxy](#xroxy)|2019|2019|207|10.2%|6.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|203|0.0%|6.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|197|0.0%|6.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|160|160|112|70.0%|3.5%|
[proxz](#proxz)|480|480|83|17.2%|2.6%|
[ri_connect_proxies](#ri_connect_proxies)|2051|2051|58|2.8%|1.8%|
[php_commenters](#php_commenters)|281|281|51|18.1%|1.6%|
[nixspam](#nixspam)|23154|23154|46|0.1%|1.4%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|40|0.0%|1.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|32|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|30|0.0%|0.9%|
[et_block](#et_block)|997|18338381|30|0.0%|0.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|24|0.0%|0.7%|
[php_dictionary](#php_dictionary)|433|433|22|5.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|21|0.1%|0.6%|
[blocklist_de_apache](#blocklist_de_apache)|14034|14034|21|0.1%|0.6%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|20|0.3%|0.6%|
[php_harvesters](#php_harvesters)|257|257|20|7.7%|0.6%|
[php_spammers](#php_spammers)|417|417|15|3.5%|0.4%|
[openbl_60d](#openbl_60d)|7583|7583|15|0.1%|0.4%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|3|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[voipbl](#voipbl)|10350|10759|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3180|3180|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2191|2191|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Mon Jun  1 23:42:17 UTC 2015.

The ipset `blocklist_de_bruteforce` has **1614** entries, **1614** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_apache](#blocklist_de_apache)|14034|14034|1614|11.5%|100.0%|
[blocklist_de](#blocklist_de)|23053|23053|1614|7.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|111|0.0%|6.8%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|39|0.0%|2.4%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|32|0.1%|1.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|30|0.0%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|28|0.0%|1.7%|
[stopforumspam_1d](#stopforumspam_1d)|7144|7144|19|0.2%|1.1%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|15|0.0%|0.9%|
[nixspam](#nixspam)|23154|23154|12|0.0%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|160|160|12|7.5%|0.7%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.3%|
[php_commenters](#php_commenters)|281|281|5|1.7%|0.3%|
[et_block](#et_block)|997|18338381|4|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|3|0.0%|0.1%|
[shunlist](#shunlist)|1253|1253|3|0.2%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.1%|
[voipbl](#voipbl)|10350|10759|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|2|0.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Mon Jun  1 23:14:07 UTC 2015.

The ipset `blocklist_de_ftp` has **268** entries, **268** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|23053|23053|268|1.1%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|21|0.0%|7.8%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|7|0.0%|2.6%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|6|0.0%|2.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|5|0.0%|1.8%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|4|0.0%|1.4%|
[php_harvesters](#php_harvesters)|257|257|4|1.5%|1.4%|
[openbl_60d](#openbl_60d)|7583|7583|4|0.0%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4|0.0%|1.4%|
[openbl_30d](#openbl_30d)|3180|3180|3|0.0%|1.1%|
[nixspam](#nixspam)|23154|23154|2|0.0%|0.7%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|1|0.0%|0.3%|
[shunlist](#shunlist)|1253|1253|1|0.0%|0.3%|
[openbl_7d](#openbl_7d)|913|913|1|0.1%|0.3%|
[et_compromised](#et_compromised)|2191|2191|1|0.0%|0.3%|
[dshield](#dshield)|20|5120|1|0.0%|0.3%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|1|0.0%|0.3%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Mon Jun  1 23:28:25 UTC 2015.

The ipset `blocklist_de_imap` has **670** entries, **670** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|664|4.5%|99.1%|
[blocklist_de](#blocklist_de)|23053|23053|664|2.8%|99.1%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|60|0.0%|8.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|43|0.0%|6.4%|
[openbl_60d](#openbl_60d)|7583|7583|41|0.5%|6.1%|
[openbl_30d](#openbl_30d)|3180|3180|37|1.1%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|36|0.0%|5.3%|
[openbl_7d](#openbl_7d)|913|913|23|2.5%|3.4%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|18|0.0%|2.6%|
[et_block](#et_block)|997|18338381|18|0.0%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|9|0.0%|1.3%|
[et_compromised](#et_compromised)|2191|2191|8|0.3%|1.1%|
[nixspam](#nixspam)|23154|23154|7|0.0%|1.0%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|7|0.3%|1.0%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|5|0.0%|0.7%|
[shunlist](#shunlist)|1253|1253|4|0.3%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|2|0.0%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|2|0.0%|0.2%|
[openbl_1d](#openbl_1d)|146|146|2|1.3%|0.2%|
[ciarmy](#ciarmy)|345|345|2|0.5%|0.2%|
[voipbl](#voipbl)|10350|10759|1|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|160|160|1|0.6%|0.1%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Mon Jun  1 23:14:04 UTC 2015.

The ipset `blocklist_de_mail` has **14733** entries, **14733** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|23053|23053|14733|63.9%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|14034|14034|11059|78.8%|75.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2266|0.0%|15.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1326|0.0%|9.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1123|0.0%|7.6%|
[blocklist_de_imap](#blocklist_de_imap)|670|670|664|99.1%|4.5%|
[nixspam](#nixspam)|23154|23154|493|2.1%|3.3%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|195|0.2%|1.3%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|113|0.3%|0.7%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|86|0.0%|0.5%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|57|0.9%|0.3%|
[openbl_60d](#openbl_60d)|7583|7583|52|0.6%|0.3%|
[openbl_30d](#openbl_30d)|3180|3180|45|1.4%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7144|7144|40|0.5%|0.2%|
[ri_web_proxies](#ri_web_proxies)|5560|5560|28|0.5%|0.1%|
[openbl_7d](#openbl_7d)|913|913|27|2.9%|0.1%|
[xroxy](#xroxy)|2019|2019|26|1.2%|0.1%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|25|0.0%|0.1%|
[et_block](#et_block)|997|18338381|25|0.0%|0.1%|
[php_spammers](#php_spammers)|417|417|22|5.2%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3177|3177|21|0.6%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|160|160|20|12.5%|0.1%|
[php_dictionary](#php_dictionary)|433|433|18|4.1%|0.1%|
[php_commenters](#php_commenters)|281|281|17|6.0%|0.1%|
[proxz](#proxz)|480|480|12|2.5%|0.0%|
[et_compromised](#et_compromised)|2191|2191|11|0.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|10|0.4%|0.0%|
[shunlist](#shunlist)|1253|1253|5|0.3%|0.0%|
[openbl_1d](#openbl_1d)|146|146|4|2.7%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.0%|
[et_tor](#et_tor)|6360|6360|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6510|6510|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6513|6513|3|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[ciarmy](#ciarmy)|345|345|2|0.5%|0.0%|
[voipbl](#voipbl)|10350|10759|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2051|2051|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Mon Jun  1 23:14:07 UTC 2015.

The ipset `blocklist_de_sip` has **102** entries, **102** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|23053|23053|83|0.3%|81.3%|
[voipbl](#voipbl)|10350|10759|31|0.2%|30.3%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|18|0.0%|17.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14|0.0%|13.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|10|0.0%|9.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|1.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|2|0.0%|1.9%|
[et_block](#et_block)|997|18338381|2|0.0%|1.9%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|1|0.0%|0.9%|
[nixspam](#nixspam)|23154|23154|1|0.0%|0.9%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.9%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Mon Jun  1 23:28:22 UTC 2015.

The ipset `blocklist_de_ssh` has **1831** entries, **1831** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|23053|23053|1829|7.9%|99.8%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|875|0.5%|47.7%|
[openbl_60d](#openbl_60d)|7583|7583|773|10.1%|42.2%|
[openbl_30d](#openbl_30d)|3180|3180|707|22.2%|38.6%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|683|31.3%|37.3%|
[et_compromised](#et_compromised)|2191|2191|674|30.7%|36.8%|
[openbl_7d](#openbl_7d)|913|913|498|54.5%|27.1%|
[shunlist](#shunlist)|1253|1253|372|29.6%|20.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|267|0.0%|14.5%|
[et_block](#et_block)|997|18338381|119|0.0%|6.4%|
[openbl_1d](#openbl_1d)|146|146|118|80.8%|6.4%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|114|0.0%|6.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|91|0.0%|4.9%|
[dshield](#dshield)|20|5120|52|1.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|30|0.0%|1.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|160|160|25|15.6%|1.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|5|0.0%|0.2%|
[ciarmy](#ciarmy)|345|345|5|1.4%|0.2%|
[voipbl](#voipbl)|10350|10759|2|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|2|0.0%|0.1%|
[nixspam](#nixspam)|23154|23154|2|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.1%|
[xroxy](#xroxy)|2019|2019|1|0.0%|0.0%|
[proxz](#proxz)|480|480|1|0.2%|0.0%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Mon Jun  1 23:14:10 UTC 2015.

The ipset `blocklist_de_strongips` has **160** entries, **160** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|23053|23053|160|0.6%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|114|0.1%|71.2%|
[blocklist_de_bots](#blocklist_de_bots)|3177|3177|112|3.5%|70.0%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|104|0.3%|65.0%|
[stopforumspam_1d](#stopforumspam_1d)|7144|7144|102|1.4%|63.7%|
[blocklist_de_apache](#blocklist_de_apache)|14034|14034|36|0.2%|22.5%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|36|0.0%|22.5%|
[php_commenters](#php_commenters)|281|281|29|10.3%|18.1%|
[openbl_60d](#openbl_60d)|7583|7583|27|0.3%|16.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|1831|1831|25|1.3%|15.6%|
[openbl_30d](#openbl_30d)|3180|3180|24|0.7%|15.0%|
[openbl_7d](#openbl_7d)|913|913|23|2.5%|14.3%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|20|0.1%|12.5%|
[shunlist](#shunlist)|1253|1253|18|1.4%|11.2%|
[openbl_1d](#openbl_1d)|146|146|17|11.6%|10.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|16|0.0%|10.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1614|1614|12|0.7%|7.5%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|6|0.0%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|6|0.0%|3.7%|
[et_block](#et_block)|997|18338381|6|0.0%|3.7%|
[xroxy](#xroxy)|2019|2019|5|0.2%|3.1%|
[proxyrss](#proxyrss)|1713|1713|5|0.2%|3.1%|
[dshield](#dshield)|20|5120|5|0.0%|3.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|4|0.0%|2.5%|
[php_spammers](#php_spammers)|417|417|4|0.9%|2.5%|
[ri_web_proxies](#ri_web_proxies)|5560|5560|3|0.0%|1.8%|
[proxz](#proxz)|480|480|3|0.6%|1.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.8%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|1.2%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|1.2%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|1|0.0%|0.6%|
[nixspam](#nixspam)|23154|23154|1|0.0%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|670|670|1|0.1%|0.6%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Mon Jun  1 23:27:09 UTC 2015.

The ipset `bm_tor` has **6513** entries, **6513** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[dm_tor](#dm_tor)|6510|6510|6510|100.0%|99.9%|
[et_tor](#et_tor)|6360|6360|5927|93.1%|91.0%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|1052|16.8%|16.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|635|0.0%|9.7%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|619|0.6%|9.5%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|481|1.5%|7.3%|
[stopforumspam_1d](#stopforumspam_1d)|7144|7144|289|4.0%|4.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|185|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|170|45.6%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|169|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|46|0.0%|0.7%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[openbl_60d](#openbl_60d)|7583|7583|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[et_block](#et_block)|997|18338381|4|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5560|5560|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14034|14034|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|23053|23053|3|0.0%|0.0%|
[xroxy](#xroxy)|2019|2019|2|0.0%|0.0%|
[voipbl](#voipbl)|10350|10759|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|2|0.0%|0.0%|
[nixspam](#nixspam)|23154|23154|2|0.0%|0.0%|
[shunlist](#shunlist)|1253|1253|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2051|2051|1|0.0%|0.0%|

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

The last time downloaded was found to be dated: Mon Jun  1 21:45:30 UTC 2015.

The ipset `bruteforceblocker` has **2178** entries, **2178** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_compromised](#et_compromised)|2191|2191|2154|98.3%|98.8%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|1406|0.8%|64.5%|
[openbl_60d](#openbl_60d)|7583|7583|1307|17.2%|60.0%|
[openbl_30d](#openbl_30d)|3180|3180|1233|38.7%|56.6%|
[blocklist_de](#blocklist_de)|23053|23053|697|3.0%|32.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1831|1831|683|37.3%|31.3%|
[shunlist](#shunlist)|1253|1253|521|41.5%|23.9%|
[openbl_7d](#openbl_7d)|913|913|520|56.9%|23.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|219|0.0%|10.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|116|0.0%|5.3%|
[et_block](#et_block)|997|18338381|103|0.0%|4.7%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|101|0.0%|4.6%|
[openbl_1d](#openbl_1d)|146|146|75|51.3%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|62|0.0%|2.8%|
[dshield](#dshield)|20|5120|60|1.1%|2.7%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|10|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|670|670|7|1.0%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|6|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7144|7144|4|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|3|0.0%|0.1%|
[proxz](#proxz)|480|480|2|0.4%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14034|14034|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|231|231|1|0.4%|0.0%|
[zeus](#zeus)|267|267|1|0.3%|0.0%|
[xroxy](#xroxy)|2019|2019|1|0.0%|0.0%|
[voipbl](#voipbl)|10350|10759|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3639|670579672|1|0.0%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|268|268|1|0.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3177|3177|1|0.0%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Mon Jun  1 22:15:16 UTC 2015.

The ipset `ciarmy` has **345** entries, **345** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|173822|173822|340|0.1%|98.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|55|0.0%|15.9%|
[blocklist_de](#blocklist_de)|23053|23053|38|0.1%|11.0%|
[blocklist_de_apache](#blocklist_de_apache)|14034|14034|31|0.2%|8.9%|
[shunlist](#shunlist)|1253|1253|25|1.9%|7.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|16|0.0%|4.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|10|0.0%|2.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|1831|1831|5|0.2%|1.4%|
[voipbl](#voipbl)|10350|10759|3|0.0%|0.8%|
[et_block](#et_block)|997|18338381|2|0.0%|0.5%|
[dshield](#dshield)|20|5120|2|0.0%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|2|0.0%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|670|670|2|0.2%|0.5%|
[openbl_7d](#openbl_7d)|913|913|1|0.1%|0.2%|
[openbl_60d](#openbl_60d)|7583|7583|1|0.0%|0.2%|
[openbl_30d](#openbl_30d)|3180|3180|1|0.0%|0.2%|
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
[alienvault_reputation](#alienvault_reputation)|173822|173822|4|0.0%|0.9%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|3|0.0%|0.7%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|2|0.1%|0.4%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|1|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.2%|
[et_block](#et_block)|997|18338381|1|0.0%|0.2%|
[ciarmy](#ciarmy)|345|345|1|0.2%|0.2%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Mon Jun  1 23:27:08 UTC 2015.

The ipset `dm_tor` has **6510** entries, **6510** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6513|6513|6510|99.9%|100.0%|
[et_tor](#et_tor)|6360|6360|5924|93.1%|90.9%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|1052|16.8%|16.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|635|0.0%|9.7%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|619|0.6%|9.5%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|481|1.5%|7.3%|
[stopforumspam_1d](#stopforumspam_1d)|7144|7144|289|4.0%|4.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|185|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|170|45.6%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|169|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|46|0.0%|0.7%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[openbl_60d](#openbl_60d)|7583|7583|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[et_block](#et_block)|997|18338381|4|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5560|5560|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14034|14034|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|23053|23053|3|0.0%|0.0%|
[xroxy](#xroxy)|2019|2019|2|0.0%|0.0%|
[voipbl](#voipbl)|10350|10759|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|2|0.0%|0.0%|
[nixspam](#nixspam)|23154|23154|2|0.0%|0.0%|
[shunlist](#shunlist)|1253|1253|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2051|2051|1|0.0%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Mon Jun  1 23:13:01 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|173822|173822|3849|2.2%|75.1%|
[et_block](#et_block)|997|18338381|1280|0.0%|25.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|512|0.0%|10.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|256|0.0%|5.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|256|0.0%|5.0%|
[openbl_60d](#openbl_60d)|7583|7583|116|1.5%|2.2%|
[openbl_30d](#openbl_30d)|3180|3180|98|3.0%|1.9%|
[shunlist](#shunlist)|1253|1253|67|5.3%|1.3%|
[openbl_7d](#openbl_7d)|913|913|64|7.0%|1.2%|
[et_compromised](#et_compromised)|2191|2191|60|2.7%|1.1%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|60|2.7%|1.1%|
[blocklist_de](#blocklist_de)|23053|23053|55|0.2%|1.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1831|1831|52|2.8%|1.0%|
[openbl_1d](#openbl_1d)|146|146|17|11.6%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|6|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|160|160|5|3.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|3|0.0%|0.0%|
[malc0de](#malc0de)|397|397|2|0.5%|0.0%|
[ciarmy](#ciarmy)|345|345|2|0.5%|0.0%|
[voipbl](#voipbl)|10350|10759|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7144|7144|1|0.0%|0.0%|
[nixspam](#nixspam)|23154|23154|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|268|268|1|0.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1614|1614|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3177|3177|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14034|14034|1|0.0%|0.0%|

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
[fullbogons](#fullbogons)|3639|670579672|20480|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|5028|2.8%|0.0%|
[dshield](#dshield)|20|5120|1280|25.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1040|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|975|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|517|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|342|1.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|297|4.7%|0.0%|
[nixspam](#nixspam)|23154|23154|279|1.2%|0.0%|
[zeus](#zeus)|267|267|261|97.7%|0.0%|
[openbl_60d](#openbl_60d)|7583|7583|245|3.2%|0.0%|
[zeus_badips](#zeus_badips)|231|231|229|99.1%|0.0%|
[openbl_30d](#openbl_30d)|3180|3180|204|6.4%|0.0%|
[blocklist_de](#blocklist_de)|23053|23053|181|0.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1831|1831|119|6.4%|0.0%|
[shunlist](#shunlist)|1253|1253|108|8.6%|0.0%|
[et_compromised](#et_compromised)|2191|2191|104|4.7%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|103|4.7%|0.0%|
[openbl_7d](#openbl_7d)|913|913|89|9.7%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7144|7144|81|1.1%|0.0%|
[feodo](#feodo)|77|77|71|92.2%|0.0%|
[sslbl](#sslbl)|363|363|30|8.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3177|3177|30|0.9%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|29|2.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|25|0.1%|0.0%|
[voipbl](#voipbl)|10350|10759|24|0.2%|0.0%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|670|670|18|2.6%|0.0%|
[openbl_1d](#openbl_1d)|146|146|16|10.9%|0.0%|
[palevo](#palevo)|13|13|12|92.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|10|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|160|160|6|3.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14034|14034|6|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[malc0de](#malc0de)|397|397|4|1.0%|0.0%|
[et_tor](#et_tor)|6360|6360|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6510|6510|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6513|6513|4|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1614|1614|4|0.2%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[ciarmy](#ciarmy)|345|345|2|0.5%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|102|102|2|1.9%|0.0%|
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
[alienvault_reputation](#alienvault_reputation)|173822|173822|3|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[et_block](#et_block)|997|18338381|1|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|102|102|1|0.9%|0.1%|

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
[bruteforceblocker](#bruteforceblocker)|2178|2178|2154|98.8%|98.3%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|1420|0.8%|64.8%|
[openbl_60d](#openbl_60d)|7583|7583|1319|17.3%|60.2%|
[openbl_30d](#openbl_30d)|3180|3180|1236|38.8%|56.4%|
[blocklist_de](#blocklist_de)|23053|23053|689|2.9%|31.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|1831|1831|674|36.8%|30.7%|
[shunlist](#shunlist)|1253|1253|523|41.7%|23.8%|
[openbl_7d](#openbl_7d)|913|913|516|56.5%|23.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|219|0.0%|9.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|116|0.0%|5.2%|
[et_block](#et_block)|997|18338381|104|0.0%|4.7%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|102|0.0%|4.6%|
[openbl_1d](#openbl_1d)|146|146|72|49.3%|3.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|62|0.0%|2.8%|
[dshield](#dshield)|20|5120|60|1.1%|2.7%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|11|0.0%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|670|670|8|1.1%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|7|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|4|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7144|7144|4|0.0%|0.1%|
[proxz](#proxz)|480|480|2|0.4%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14034|14034|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|231|231|1|0.4%|0.0%|
[zeus](#zeus)|267|267|1|0.3%|0.0%|
[xroxy](#xroxy)|2019|2019|1|0.0%|0.0%|
[voipbl](#voipbl)|10350|10759|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|268|268|1|0.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3177|3177|1|0.0%|0.0%|

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
[bm_tor](#bm_tor)|6513|6513|5927|91.0%|93.1%|
[dm_tor](#dm_tor)|6510|6510|5924|90.9%|93.1%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|1073|17.1%|16.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|628|0.0%|9.8%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|622|0.6%|9.7%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|480|1.5%|7.5%|
[stopforumspam_1d](#stopforumspam_1d)|7144|7144|293|4.1%|4.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|191|0.0%|3.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|169|45.4%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|167|0.0%|2.6%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|44|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[openbl_60d](#openbl_60d)|7583|7583|19|0.2%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|19|0.0%|0.2%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[php_harvesters](#php_harvesters)|257|257|6|2.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5560|5560|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[et_block](#et_block)|997|18338381|4|0.0%|0.0%|
[xroxy](#xroxy)|2019|2019|3|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14034|14034|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|23053|23053|3|0.0%|0.0%|
[voipbl](#voipbl)|10350|10759|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2051|2051|2|0.0%|0.0%|
[shunlist](#shunlist)|1253|1253|1|0.0%|0.0%|
[proxz](#proxz)|480|480|1|0.2%|0.0%|
[nixspam](#nixspam)|23154|23154|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Mon Jun  1 23:27:17 UTC 2015.

The ipset `feodo` has **77** entries, **77** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|997|18338381|71|0.0%|92.2%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|58|0.9%|75.3%|
[sslbl](#sslbl)|363|363|31|8.5%|40.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|7|0.0%|9.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|3|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|3.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|1.2%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|1|0.0%|1.2%|

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
[spamhaus_drop](#spamhaus_drop)|656|18600704|151552|0.8%|0.0%|
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
[alienvault_reputation](#alienvault_reputation)|173822|173822|14|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.0%|
[et_block](#et_block)|997|18338381|10|0.0%|0.0%|
[nixspam](#nixspam)|23154|23154|9|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|6|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|5|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7144|7144|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[xroxy](#xroxy)|2019|2019|3|0.1%|0.0%|
[blocklist_de](#blocklist_de)|23053|23053|3|0.0%|0.0%|
[voipbl](#voipbl)|10350|10759|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5560|5560|1|0.0%|0.0%|
[proxz](#proxz)|480|480|1|0.2%|0.0%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1614|1614|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3177|3177|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14034|14034|1|0.0%|0.0%|

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
[spamhaus_drop](#spamhaus_drop)|656|18600704|7079936|38.0%|77.1%|
[et_block](#et_block)|997|18338381|7079936|38.6%|77.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2526625|0.7%|27.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|904796|0.1%|9.8%|
[fullbogons](#fullbogons)|3639|670579672|565248|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|145472|0.1%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1036|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|732|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|518|0.2%|0.0%|
[nixspam](#nixspam)|23154|23154|277|1.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|182|0.5%|0.0%|
[blocklist_de](#blocklist_de)|23053|23053|34|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7144|7144|28|0.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|27|2.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3177|3177|24|0.7%|0.0%|
[openbl_60d](#openbl_60d)|7583|7583|19|0.2%|0.0%|
[openbl_30d](#openbl_30d)|3180|3180|13|0.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|11|0.1%|0.0%|
[zeus_badips](#zeus_badips)|231|231|10|4.3%|0.0%|
[zeus](#zeus)|267|267|10|3.7%|0.0%|
[openbl_7d](#openbl_7d)|913|913|10|1.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1831|1831|7|0.3%|0.0%|
[et_compromised](#et_compromised)|2191|2191|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|5|0.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|4|0.0%|0.0%|
[shunlist](#shunlist)|1253|1253|3|0.2%|0.0%|
[et_tor](#et_tor)|6360|6360|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6510|6510|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6513|6513|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|160|160|3|1.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|670|670|3|0.4%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[voipbl](#voipbl)|10350|10759|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.0%|
[openbl_1d](#openbl_1d)|146|146|1|0.6%|0.0%|
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
[spamhaus_drop](#spamhaus_drop)|656|18600704|2272266|12.2%|0.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1354348|0.9%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904796|9.8%|0.1%|
[fullbogons](#fullbogons)|3639|670579672|234359|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|33155|7.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|13248|3.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|4396|2.5%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|1523|1.6%|0.0%|
[blocklist_de](#blocklist_de)|23053|23053|1431|6.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|1326|9.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14034|14034|1319|9.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|563|1.7%|0.0%|
[nixspam](#nixspam)|23154|23154|469|2.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|406|0.8%|0.0%|
[voipbl](#voipbl)|10350|10759|295|2.7%|0.0%|
[openbl_60d](#openbl_60d)|7583|7583|171|2.2%|0.0%|
[dm_tor](#dm_tor)|6510|6510|169|2.5%|0.0%|
[bm_tor](#bm_tor)|6513|6513|169|2.5%|0.0%|
[et_tor](#et_tor)|6360|6360|167|2.6%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7144|7144|157|2.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5560|5560|119|2.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|97|6.6%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2051|2051|69|3.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|68|1.0%|0.0%|
[openbl_30d](#openbl_30d)|3180|3180|67|2.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|66|5.1%|0.0%|
[et_compromised](#et_compromised)|2191|2191|62|2.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|62|2.8%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|58|8.6%|0.0%|
[xroxy](#xroxy)|2019|2019|57|2.8%|0.0%|
[et_botcc](#et_botcc)|505|505|41|8.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3177|3177|32|1.0%|0.0%|
[proxyrss](#proxyrss)|1713|1713|31|1.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1831|1831|30|1.6%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1614|1614|28|1.7%|0.0%|
[shunlist](#shunlist)|1253|1253|25|1.9%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|17|4.5%|0.0%|
[proxz](#proxz)|480|480|16|3.3%|0.0%|
[openbl_7d](#openbl_7d)|913|913|16|1.7%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|426|426|15|3.5%|0.0%|
[malc0de](#malc0de)|397|397|12|3.0%|0.0%|
[ciarmy](#ciarmy)|345|345|10|2.8%|0.0%|
[php_dictionary](#php_dictionary)|433|433|9|2.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|670|670|9|1.3%|0.0%|
[zeus](#zeus)|267|267|7|2.6%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.0%|
[php_commenters](#php_commenters)|281|281|5|1.7%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[zeus_badips](#zeus_badips)|231|231|4|1.7%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|268|268|4|1.4%|0.0%|
[sslbl](#sslbl)|363|363|3|0.8%|0.0%|
[feodo](#feodo)|77|77|3|3.8%|0.0%|
[openbl_1d](#openbl_1d)|146|146|2|1.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|102|102|2|1.9%|0.0%|

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
[spamhaus_drop](#spamhaus_drop)|656|18600704|8598042|46.2%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2830140|2.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2526625|27.5%|0.7%|
[fullbogons](#fullbogons)|3639|670579672|248319|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|33368|7.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|7733|2.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|7617|4.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|2477|2.6%|0.0%|
[blocklist_de](#blocklist_de)|23053|23053|1468|6.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|1123|7.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14034|14034|1061|7.5%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|938|2.9%|0.0%|
[nixspam](#nixspam)|23154|23154|566|2.4%|0.0%|
[dshield](#dshield)|20|5120|512|10.0%|0.0%|
[voipbl](#voipbl)|10350|10759|431|4.0%|0.0%|
[openbl_60d](#openbl_60d)|7583|7583|343|4.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7144|7144|235|3.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|230|0.4%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3177|3177|203|6.3%|0.0%|
[et_tor](#et_tor)|6360|6360|191|3.0%|0.0%|
[dm_tor](#dm_tor)|6510|6510|185|2.8%|0.0%|
[bm_tor](#bm_tor)|6513|6513|185|2.8%|0.0%|
[openbl_30d](#openbl_30d)|3180|3180|176|5.5%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5560|5560|173|3.1%|0.0%|
[et_compromised](#et_compromised)|2191|2191|116|5.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|116|5.3%|0.0%|
[xroxy](#xroxy)|2019|2019|99|4.9%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|97|1.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1831|1831|91|4.9%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2051|2051|82|3.9%|0.0%|
[shunlist](#shunlist)|1253|1253|69|5.5%|0.0%|
[proxyrss](#proxyrss)|1713|1713|64|3.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|45|3.0%|0.0%|
[openbl_7d](#openbl_7d)|913|913|42|4.6%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|670|670|36|5.3%|0.0%|
[php_spammers](#php_spammers)|417|417|31|7.4%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1614|1614|30|1.8%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|28|4.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|26|2.0%|0.0%|
[malc0de](#malc0de)|397|397|25|6.2%|0.0%|
[proxz](#proxz)|480|480|23|4.7%|0.0%|
[et_botcc](#et_botcc)|505|505|22|4.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|21|5.6%|0.0%|
[ciarmy](#ciarmy)|345|345|16|4.6%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|426|426|13|3.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|10|2.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|102|102|10|9.8%|0.0%|
[zeus](#zeus)|267|267|9|3.3%|0.0%|
[php_commenters](#php_commenters)|281|281|9|3.2%|0.0%|
[zeus_badips](#zeus_badips)|231|231|8|3.4%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[openbl_1d](#openbl_1d)|146|146|7|4.7%|0.0%|
[sslbl](#sslbl)|363|363|6|1.6%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|160|160|6|3.7%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|268|268|5|1.8%|0.0%|
[palevo](#palevo)|13|13|3|23.0%|0.0%|
[feodo](#feodo)|77|77|3|3.8%|0.0%|

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
[spamhaus_drop](#spamhaus_drop)|656|18600704|195904|1.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|14365|8.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|9231|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|5946|6.4%|0.0%|
[blocklist_de](#blocklist_de)|23053|23053|2895|12.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|2266|15.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14034|14034|2205|15.7%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|2107|6.7%|0.0%|
[voipbl](#voipbl)|10350|10759|1591|14.7%|0.0%|
[nixspam](#nixspam)|23154|23154|1241|5.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1172|2.4%|0.0%|
[openbl_60d](#openbl_60d)|7583|7583|719|9.4%|0.0%|
[dm_tor](#dm_tor)|6510|6510|635|9.7%|0.0%|
[bm_tor](#bm_tor)|6513|6513|635|9.7%|0.0%|
[et_tor](#et_tor)|6360|6360|628|9.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7144|7144|494|6.9%|0.0%|
[openbl_30d](#openbl_30d)|3180|3180|283|8.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1831|1831|267|14.5%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[et_compromised](#et_compromised)|2191|2191|219|9.9%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|219|10.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|211|3.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3177|3177|197|6.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5560|5560|159|2.8%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|146|11.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|125|33.6%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1614|1614|111|6.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|110|7.5%|0.0%|
[shunlist](#shunlist)|1253|1253|100|7.9%|0.0%|
[openbl_7d](#openbl_7d)|913|913|94|10.2%|0.0%|
[xroxy](#xroxy)|2019|2019|84|4.1%|0.0%|
[et_botcc](#et_botcc)|505|505|78|15.4%|0.0%|
[malc0de](#malc0de)|397|397|68|17.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|426|426|59|13.8%|0.0%|
[ciarmy](#ciarmy)|345|345|55|15.9%|0.0%|
[proxyrss](#proxyrss)|1713|1713|52|3.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|51|7.5%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2051|2051|47|2.2%|0.0%|
[proxz](#proxz)|480|480|45|9.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|670|670|43|6.4%|0.0%|
[php_spammers](#php_spammers)|417|417|26|6.2%|0.0%|
[php_dictionary](#php_dictionary)|433|433|24|5.5%|0.0%|
[sslbl](#sslbl)|363|363|23|6.3%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|268|268|21|7.8%|0.0%|
[zeus](#zeus)|267|267|19|7.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|160|160|16|10.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|15|5.8%|0.0%|
[php_commenters](#php_commenters)|281|281|15|5.3%|0.0%|
[zeus_badips](#zeus_badips)|231|231|14|6.0%|0.0%|
[openbl_1d](#openbl_1d)|146|146|14|9.5%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|102|102|14|13.7%|0.0%|
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
[xroxy](#xroxy)|2019|2019|13|0.6%|1.9%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|11|0.0%|1.6%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|11|0.0%|1.6%|
[ri_web_proxies](#ri_web_proxies)|5560|5560|10|0.1%|1.4%|
[proxyrss](#proxyrss)|1713|1713|9|0.5%|1.3%|
[stopforumspam_1d](#stopforumspam_1d)|7144|7144|6|0.0%|0.8%|
[ri_connect_proxies](#ri_connect_proxies)|2051|2051|6|0.2%|0.8%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|2|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.2%|
[et_block](#et_block)|997|18338381|2|0.0%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3177|3177|2|0.0%|0.2%|
[blocklist_de](#blocklist_de)|23053|23053|2|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|1|0.0%|0.1%|
[proxz](#proxz)|480|480|1|0.2%|0.1%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.1%|
[nixspam](#nixspam)|23154|23154|1|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|1|0.0%|0.1%|

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
[spamhaus_drop](#spamhaus_drop)|656|18600704|1037|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1036|0.0%|0.3%|
[fullbogons](#fullbogons)|3639|670579672|890|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|288|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|44|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|25|1.9%|0.0%|
[dm_tor](#dm_tor)|6510|6510|21|0.3%|0.0%|
[bm_tor](#bm_tor)|6513|6513|21|0.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|19|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|19|1.3%|0.0%|
[et_tor](#et_tor)|6360|6360|19|0.2%|0.0%|
[nixspam](#nixspam)|23154|23154|14|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|13|0.2%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7144|7144|10|0.1%|0.0%|
[blocklist_de](#blocklist_de)|23053|23053|9|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5560|5560|5|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7583|7583|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|5|1.3%|0.0%|
[voipbl](#voipbl)|10350|10759|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3180|3180|4|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14034|14034|4|0.0%|0.0%|
[malc0de](#malc0de)|397|397|3|0.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1614|1614|3|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3177|3177|3|0.0%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1831|1831|2|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|102|102|2|1.9%|0.0%|
[zeus_badips](#zeus_badips)|231|231|1|0.4%|0.0%|
[zeus](#zeus)|267|267|1|0.3%|0.0%|
[xroxy](#xroxy)|2019|2019|1|0.0%|0.0%|
[sslbl](#sslbl)|363|363|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|1|0.0%|0.0%|
[shunlist](#shunlist)|1253|1253|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.0%|
[openbl_7d](#openbl_7d)|913|913|1|0.1%|0.0%|
[feodo](#feodo)|77|77|1|1.2%|0.0%|
[et_compromised](#et_compromised)|2191|2191|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|426|426|1|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|1|0.0%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|1|0.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|173822|173822|8|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|6|0.0%|0.4%|
[et_block](#et_block)|997|18338381|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|3|0.2%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|2|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7583|7583|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|3180|3180|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7144|7144|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5560|5560|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|913|913|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2191|2191|1|0.0%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|426|426|1|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1831|1831|1|0.0%|0.0%|
[blocklist_de](#blocklist_de)|23053|23053|1|0.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|173822|173822|12|0.0%|3.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|4|0.0%|1.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|4|0.3%|1.0%|
[et_block](#et_block)|997|18338381|4|0.0%|1.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.7%|
[dshield](#dshield)|20|5120|2|0.0%|0.5%|
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
[spamhaus_drop](#spamhaus_drop)|656|18600704|29|0.0%|2.2%|
[et_block](#et_block)|997|18338381|29|0.0%|2.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.1%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|26|0.4%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|26|0.0%|2.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|25|0.0%|1.9%|
[fullbogons](#fullbogons)|3639|670579672|9|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|6|0.0%|0.4%|
[malc0de](#malc0de)|397|397|4|1.0%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|3|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|2|0.0%|0.1%|
[cleanmx_viruses](#cleanmx_viruses)|426|426|2|0.4%|0.1%|
[nixspam](#nixspam)|23154|23154|1|0.0%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|

## maxmind_proxy_fraud

[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.

Source is downloaded from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list).

The last time downloaded was found to be dated: Mon Jun  1 23:00:08 UTC 2015.

The ipset `maxmind_proxy_fraud` has **372** entries, **372** unique IPs.

The following table shows the overlaps of `maxmind_proxy_fraud` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `maxmind_proxy_fraud`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `maxmind_proxy_fraud`.
- ` this % ` is the percentage **of this ipset (`maxmind_proxy_fraud`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|234|0.2%|62.9%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|201|0.6%|54.0%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|176|2.8%|47.3%|
[dm_tor](#dm_tor)|6510|6510|170|2.6%|45.6%|
[bm_tor](#bm_tor)|6513|6513|170|2.6%|45.6%|
[et_tor](#et_tor)|6360|6360|169|2.6%|45.4%|
[stopforumspam_1d](#stopforumspam_1d)|7144|7144|158|2.2%|42.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|125|0.0%|33.6%|
[php_commenters](#php_commenters)|281|281|28|9.9%|7.5%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|25|0.0%|6.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|21|0.0%|5.6%|
[openbl_60d](#openbl_60d)|7583|7583|18|0.2%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|17|0.0%|4.5%|
[php_harvesters](#php_harvesters)|257|257|6|2.3%|1.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|1.3%|
[ri_web_proxies](#ri_web_proxies)|5560|5560|4|0.0%|1.0%|
[php_spammers](#php_spammers)|417|417|4|0.9%|1.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|1.0%|
[shunlist](#shunlist)|1253|1253|2|0.1%|0.5%|
[xroxy](#xroxy)|2019|2019|1|0.0%|0.2%|
[voipbl](#voipbl)|10350|10759|1|0.0%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2051|2051|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|1|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|14034|14034|1|0.0%|0.2%|
[blocklist_de](#blocklist_de)|23053|23053|1|0.0%|0.2%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Mon Jun  1 23:30:02 UTC 2015.

The ipset `nixspam` has **23154** entries, **23154** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1241|0.0%|5.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|566|0.0%|2.4%|
[blocklist_de](#blocklist_de)|23053|23053|556|2.4%|2.4%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|493|3.3%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|469|0.0%|2.0%|
[et_block](#et_block)|997|18338381|279|0.0%|1.2%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|278|0.0%|1.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|277|0.0%|1.1%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|237|0.2%|1.0%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|138|0.4%|0.5%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|122|1.9%|0.5%|
[ri_web_proxies](#ri_web_proxies)|5560|5560|87|1.5%|0.3%|
[php_dictionary](#php_dictionary)|433|433|81|18.7%|0.3%|
[xroxy](#xroxy)|2019|2019|72|3.5%|0.3%|
[php_spammers](#php_spammers)|417|417|67|16.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7144|7144|61|0.8%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3177|3177|46|1.4%|0.1%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|45|0.0%|0.1%|
[proxz](#proxz)|480|480|23|4.7%|0.0%|
[proxyrss](#proxyrss)|1713|1713|19|1.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|14|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1614|1614|12|0.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14034|14034|12|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2051|2051|10|0.4%|0.0%|
[openbl_60d](#openbl_60d)|7583|7583|9|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|9|0.0%|0.0%|
[php_commenters](#php_commenters)|281|281|7|2.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|670|670|7|1.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|3|1.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6510|6510|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6513|6513|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1831|1831|2|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|268|268|2|0.7%|0.0%|
[zeus_badips](#zeus_badips)|231|231|1|0.4%|0.0%|
[zeus](#zeus)|267|267|1|0.3%|0.0%|
[shunlist](#shunlist)|1253|1253|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3180|3180|1|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[et_tor](#et_tor)|6360|6360|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|160|160|1|0.6%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|102|102|1|0.9%|0.0%|

## openbl_1d

[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_1days.txt).

The last time downloaded was found to be dated: Mon Jun  1 23:32:00 UTC 2015.

The ipset `openbl_1d` has **146** entries, **146** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_7d](#openbl_7d)|913|913|146|15.9%|100.0%|
[openbl_60d](#openbl_60d)|7583|7583|146|1.9%|100.0%|
[openbl_30d](#openbl_30d)|3180|3180|146|4.5%|100.0%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|136|0.0%|93.1%|
[blocklist_de](#blocklist_de)|23053|23053|124|0.5%|84.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|1831|1831|118|6.4%|80.8%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|75|3.4%|51.3%|
[shunlist](#shunlist)|1253|1253|73|5.8%|50.0%|
[et_compromised](#et_compromised)|2191|2191|72|3.2%|49.3%|
[dshield](#dshield)|20|5120|17|0.3%|11.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|160|160|17|10.6%|11.6%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|16|0.0%|10.9%|
[et_block](#et_block)|997|18338381|16|0.0%|10.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14|0.0%|9.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7|0.0%|4.7%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|4|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|2|0.0%|1.3%|
[blocklist_de_imap](#blocklist_de_imap)|670|670|2|0.2%|1.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.6%|
[blocklist_de_apache](#blocklist_de_apache)|14034|14034|1|0.0%|0.6%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt).

The last time downloaded was found to be dated: Mon Jun  1 23:42:00 UTC 2015.

The ipset `openbl_30d` has **3180** entries, **3180** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7583|7583|3180|41.9%|100.0%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|3159|1.8%|99.3%|
[et_compromised](#et_compromised)|2191|2191|1236|56.4%|38.8%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|1233|56.6%|38.7%|
[openbl_7d](#openbl_7d)|913|913|913|100.0%|28.7%|
[blocklist_de](#blocklist_de)|23053|23053|759|3.2%|23.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|1831|1831|707|38.6%|22.2%|
[shunlist](#shunlist)|1253|1253|597|47.6%|18.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|283|0.0%|8.8%|
[et_block](#et_block)|997|18338381|204|0.0%|6.4%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|199|0.0%|6.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|176|0.0%|5.5%|
[openbl_1d](#openbl_1d)|146|146|146|100.0%|4.5%|
[dshield](#dshield)|20|5120|98|1.9%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|67|0.0%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|45|0.3%|1.4%|
[blocklist_de_imap](#blocklist_de_imap)|670|670|37|5.5%|1.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|160|160|24|15.0%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|13|0.0%|0.4%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|6|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|4|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.1%|
[voipbl](#voipbl)|10350|10759|3|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|268|268|3|1.1%|0.0%|
[zeus](#zeus)|267|267|2|0.7%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14034|14034|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|231|231|1|0.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7144|7144|1|0.0%|0.0%|
[nixspam](#nixspam)|23154|23154|1|0.0%|0.0%|
[ciarmy](#ciarmy)|345|345|1|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3177|3177|1|0.0%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt).

The last time downloaded was found to be dated: Mon Jun  1 23:42:00 UTC 2015.

The ipset `openbl_60d` has **7583** entries, **7583** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|173822|173822|7556|4.3%|99.6%|
[openbl_30d](#openbl_30d)|3180|3180|3180|100.0%|41.9%|
[et_compromised](#et_compromised)|2191|2191|1319|60.2%|17.3%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|1307|60.0%|17.2%|
[openbl_7d](#openbl_7d)|913|913|913|100.0%|12.0%|
[blocklist_de](#blocklist_de)|23053|23053|847|3.6%|11.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|1831|1831|773|42.2%|10.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|719|0.0%|9.4%|
[shunlist](#shunlist)|1253|1253|616|49.1%|8.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|343|0.0%|4.5%|
[et_block](#et_block)|997|18338381|245|0.0%|3.2%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|240|0.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|171|0.0%|2.2%|
[openbl_1d](#openbl_1d)|146|146|146|100.0%|1.9%|
[dshield](#dshield)|20|5120|116|2.2%|1.5%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|54|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|52|0.3%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|670|670|41|6.1%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|27|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|160|160|27|16.8%|0.3%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|24|0.3%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7144|7144|21|0.2%|0.2%|
[dm_tor](#dm_tor)|6510|6510|21|0.3%|0.2%|
[bm_tor](#bm_tor)|6513|6513|21|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|19|0.0%|0.2%|
[et_tor](#et_tor)|6360|6360|19|0.2%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3177|3177|15|0.4%|0.1%|
[voipbl](#voipbl)|10350|10759|9|0.0%|0.1%|
[nixspam](#nixspam)|23154|23154|9|0.0%|0.1%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|6|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|268|268|4|1.4%|0.0%|
[zeus](#zeus)|267|267|2|0.7%|0.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14034|14034|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|231|231|1|0.4%|0.0%|
[ciarmy](#ciarmy)|345|345|1|0.2%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt).

The last time downloaded was found to be dated: Mon Jun  1 23:42:00 UTC 2015.

The ipset `openbl_7d` has **913** entries, **913** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7583|7583|913|12.0%|100.0%|
[openbl_30d](#openbl_30d)|3180|3180|913|28.7%|100.0%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|898|0.5%|98.3%|
[blocklist_de](#blocklist_de)|23053|23053|528|2.2%|57.8%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|520|23.8%|56.9%|
[et_compromised](#et_compromised)|2191|2191|516|23.5%|56.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|1831|1831|498|27.1%|54.5%|
[shunlist](#shunlist)|1253|1253|393|31.3%|43.0%|
[openbl_1d](#openbl_1d)|146|146|146|100.0%|15.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|94|0.0%|10.2%|
[et_block](#et_block)|997|18338381|89|0.0%|9.7%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|86|0.0%|9.4%|
[dshield](#dshield)|20|5120|64|1.2%|7.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|42|0.0%|4.6%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|27|0.1%|2.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|160|160|23|14.3%|2.5%|
[blocklist_de_imap](#blocklist_de_imap)|670|670|23|3.4%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|16|0.0%|1.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|1.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|5|0.0%|0.5%|
[voipbl](#voipbl)|10350|10759|3|0.0%|0.3%|
[zeus](#zeus)|267|267|1|0.3%|0.1%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.1%|
[ciarmy](#ciarmy)|345|345|1|0.2%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|268|268|1|0.3%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|14034|14034|1|0.0%|0.1%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Mon Jun  1 23:27:15 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|997|18338381|12|0.0%|92.3%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|11|0.1%|84.6%|
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
[stopforumspam_1d](#stopforumspam_1d)|7144|7144|108|1.5%|38.4%|
[blocklist_de](#blocklist_de)|23053|23053|63|0.2%|22.4%|
[blocklist_de_bots](#blocklist_de_bots)|3177|3177|51|1.6%|18.1%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|33|0.5%|11.7%|
[php_spammers](#php_spammers)|417|417|32|7.6%|11.3%|
[et_tor](#et_tor)|6360|6360|29|0.4%|10.3%|
[dm_tor](#dm_tor)|6510|6510|29|0.4%|10.3%|
[bm_tor](#bm_tor)|6513|6513|29|0.4%|10.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|160|160|29|18.1%|10.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|28|7.5%|9.9%|
[blocklist_de_apache](#blocklist_de_apache)|14034|14034|25|0.1%|8.8%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|24|0.0%|8.5%|
[et_block](#et_block)|997|18338381|24|0.0%|8.5%|
[php_dictionary](#php_dictionary)|433|433|22|5.0%|7.8%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|17|0.1%|6.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|5.3%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|13|0.0%|4.6%|
[ri_web_proxies](#ri_web_proxies)|5560|5560|11|0.1%|3.9%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.2%|
[openbl_60d](#openbl_60d)|7583|7583|8|0.1%|2.8%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|7|0.0%|2.4%|
[nixspam](#nixspam)|23154|23154|7|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|1.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1614|1614|5|0.3%|1.7%|
[xroxy](#xroxy)|2019|2019|3|0.1%|1.0%|
[proxz](#proxz)|480|480|3|0.6%|1.0%|
[proxyrss](#proxyrss)|1713|1713|2|0.1%|0.7%|
[zeus_badips](#zeus_badips)|231|231|1|0.4%|0.3%|
[zeus](#zeus)|267|267|1|0.3%|0.3%|
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
[nixspam](#nixspam)|23154|23154|81|0.3%|18.7%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|68|0.2%|15.7%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|42|0.6%|9.6%|
[blocklist_de](#blocklist_de)|23053|23053|40|0.1%|9.2%|
[ri_web_proxies](#ri_web_proxies)|5560|5560|33|0.5%|7.6%|
[xroxy](#xroxy)|2019|2019|24|1.1%|5.5%|
[stopforumspam_1d](#stopforumspam_1d)|7144|7144|24|0.3%|5.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|24|0.0%|5.5%|
[php_commenters](#php_commenters)|281|281|22|7.8%|5.0%|
[blocklist_de_bots](#blocklist_de_bots)|3177|3177|22|0.6%|5.0%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|18|0.1%|4.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|10|0.0%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|9|0.0%|2.0%|
[proxz](#proxz)|480|480|7|1.4%|1.6%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|7|0.0%|1.6%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|4|0.0%|0.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.9%|
[et_tor](#et_tor)|6360|6360|4|0.0%|0.9%|
[et_block](#et_block)|997|18338381|4|0.0%|0.9%|
[dm_tor](#dm_tor)|6510|6510|4|0.0%|0.9%|
[bm_tor](#bm_tor)|6513|6513|4|0.0%|0.9%|
[ri_connect_proxies](#ri_connect_proxies)|2051|2051|3|0.1%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|160|160|2|1.2%|0.4%|
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
[stopforumspam_1d](#stopforumspam_1d)|7144|7144|34|0.4%|13.2%|
[blocklist_de](#blocklist_de)|23053|23053|26|0.1%|10.1%|
[blocklist_de_bots](#blocklist_de_bots)|3177|3177|20|0.6%|7.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|5.8%|
[php_commenters](#php_commenters)|281|281|9|3.2%|3.5%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|8|0.1%|3.1%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|8|0.0%|3.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|7|0.0%|2.7%|
[dm_tor](#dm_tor)|6510|6510|7|0.1%|2.7%|
[bm_tor](#bm_tor)|6513|6513|7|0.1%|2.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|6|1.6%|2.3%|
[et_tor](#et_tor)|6360|6360|6|0.0%|2.3%|
[blocklist_de_ftp](#blocklist_de_ftp)|268|268|4|1.4%|1.5%|
[nixspam](#nixspam)|23154|23154|3|0.0%|1.1%|
[xroxy](#xroxy)|2019|2019|2|0.0%|0.7%|
[openbl_60d](#openbl_60d)|7583|7583|2|0.0%|0.7%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|160|160|2|1.2%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|2|0.0%|0.7%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|1|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|1|0.0%|0.3%|
[ri_web_proxies](#ri_web_proxies)|5560|5560|1|0.0%|0.3%|
[proxyrss](#proxyrss)|1713|1713|1|0.0%|0.3%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.3%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|
[fullbogons](#fullbogons)|3639|670579672|1|0.0%|0.3%|
[et_block](#et_block)|997|18338381|1|0.0%|0.3%|
[bogons](#bogons)|13|592708608|1|0.0%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|14034|14034|1|0.0%|0.3%|

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
[nixspam](#nixspam)|23154|23154|67|0.2%|16.0%|
[blocklist_de](#blocklist_de)|23053|23053|43|0.1%|10.3%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|34|0.5%|8.1%|
[php_commenters](#php_commenters)|281|281|32|11.3%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|31|0.0%|7.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|26|0.0%|6.2%|
[ri_web_proxies](#ri_web_proxies)|5560|5560|25|0.4%|5.9%|
[stopforumspam_1d](#stopforumspam_1d)|7144|7144|24|0.3%|5.7%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|22|0.1%|5.2%|
[xroxy](#xroxy)|2019|2019|19|0.9%|4.5%|
[blocklist_de_bots](#blocklist_de_bots)|3177|3177|15|0.4%|3.5%|
[proxz](#proxz)|480|480|7|1.4%|1.6%|
[et_tor](#et_tor)|6360|6360|6|0.0%|1.4%|
[dm_tor](#dm_tor)|6510|6510|6|0.0%|1.4%|
[bm_tor](#bm_tor)|6513|6513|6|0.0%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|1.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1614|1614|5|0.3%|1.1%|
[blocklist_de_apache](#blocklist_de_apache)|14034|14034|5|0.0%|1.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|160|160|4|2.5%|0.9%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|3|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|2|0.0%|0.4%|
[ri_connect_proxies](#ri_connect_proxies)|2051|2051|2|0.0%|0.4%|
[proxyrss](#proxyrss)|1713|1713|2|0.1%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[et_block](#et_block)|997|18338381|2|0.0%|0.4%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1831|1831|1|0.0%|0.2%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Mon Jun  1 22:11:26 UTC 2015.

The ipset `proxyrss` has **1713** entries, **1713** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|790|0.8%|46.1%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|649|2.0%|37.8%|
[ri_web_proxies](#ri_web_proxies)|5560|5560|611|10.9%|35.6%|
[xroxy](#xroxy)|2019|2019|454|22.4%|26.5%|
[stopforumspam_1d](#stopforumspam_1d)|7144|7144|454|6.3%|26.5%|
[blocklist_de_bots](#blocklist_de_bots)|3177|3177|247|7.7%|14.4%|
[blocklist_de](#blocklist_de)|23053|23053|247|1.0%|14.4%|
[ri_connect_proxies](#ri_connect_proxies)|2051|2051|183|8.9%|10.6%|
[proxz](#proxz)|480|480|158|32.9%|9.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|64|0.0%|3.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|52|0.0%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|31|0.0%|1.8%|
[nixspam](#nixspam)|23154|23154|19|0.0%|1.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|9|1.3%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|160|160|5|3.1%|0.2%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.1%|
[php_commenters](#php_commenters)|281|281|2|0.7%|0.1%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Mon Jun  1 22:11:32 UTC 2015.

The ipset `proxz` has **480** entries, **480** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|284|0.3%|59.1%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|256|0.8%|53.3%|
[xroxy](#xroxy)|2019|2019|235|11.6%|48.9%|
[ri_web_proxies](#ri_web_proxies)|5560|5560|204|3.6%|42.5%|
[proxyrss](#proxyrss)|1713|1713|158|9.2%|32.9%|
[stopforumspam_1d](#stopforumspam_1d)|7144|7144|105|1.4%|21.8%|
[blocklist_de](#blocklist_de)|23053|23053|97|0.4%|20.2%|
[blocklist_de_bots](#blocklist_de_bots)|3177|3177|83|2.6%|17.2%|
[ri_connect_proxies](#ri_connect_proxies)|2051|2051|75|3.6%|15.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|45|0.0%|9.3%|
[nixspam](#nixspam)|23154|23154|23|0.0%|4.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|23|0.0%|4.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|16|0.0%|3.3%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|12|0.0%|2.5%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|7|0.1%|1.4%|
[php_spammers](#php_spammers)|417|417|7|1.6%|1.4%|
[php_dictionary](#php_dictionary)|433|433|7|1.6%|1.4%|
[php_commenters](#php_commenters)|281|281|3|1.0%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|160|160|3|1.8%|0.6%|
[et_compromised](#et_compromised)|2191|2191|2|0.0%|0.4%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|2|0.0%|0.4%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|2|0.0%|0.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.2%|
[et_tor](#et_tor)|6360|6360|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1831|1831|1|0.0%|0.2%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Mon Jun  1 21:41:35 UTC 2015.

The ipset `ri_connect_proxies` has **2051** entries, **2051** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|1202|1.3%|58.6%|
[ri_web_proxies](#ri_web_proxies)|5560|5560|835|15.0%|40.7%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|706|2.2%|34.4%|
[xroxy](#xroxy)|2019|2019|319|15.7%|15.5%|
[proxyrss](#proxyrss)|1713|1713|183|10.6%|8.9%|
[stopforumspam_1d](#stopforumspam_1d)|7144|7144|147|2.0%|7.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|82|0.0%|3.9%|
[proxz](#proxz)|480|480|75|15.6%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|69|0.0%|3.3%|
[blocklist_de](#blocklist_de)|23053|23053|59|0.2%|2.8%|
[blocklist_de_bots](#blocklist_de_bots)|3177|3177|58|1.8%|2.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|47|0.0%|2.2%|
[nixspam](#nixspam)|23154|23154|10|0.0%|0.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.2%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|3|0.0%|0.1%|
[php_dictionary](#php_dictionary)|433|433|3|0.6%|0.1%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[et_tor](#et_tor)|6360|6360|2|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[dm_tor](#dm_tor)|6510|6510|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6513|6513|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Mon Jun  1 21:40:03 UTC 2015.

The ipset `ri_web_proxies` has **5560** entries, **5560** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|2697|2.9%|48.5%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|1767|5.6%|31.7%|
[ri_connect_proxies](#ri_connect_proxies)|2051|2051|835|40.7%|15.0%|
[xroxy](#xroxy)|2019|2019|825|40.8%|14.8%|
[proxyrss](#proxyrss)|1713|1713|611|35.6%|10.9%|
[stopforumspam_1d](#stopforumspam_1d)|7144|7144|560|7.8%|10.0%|
[blocklist_de](#blocklist_de)|23053|23053|359|1.5%|6.4%|
[blocklist_de_bots](#blocklist_de_bots)|3177|3177|332|10.4%|5.9%|
[proxz](#proxz)|480|480|204|42.5%|3.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|173|0.0%|3.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|159|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|119|0.0%|2.1%|
[nixspam](#nixspam)|23154|23154|87|0.3%|1.5%|
[php_dictionary](#php_dictionary)|433|433|33|7.6%|0.5%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|31|0.4%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|28|0.1%|0.5%|
[php_spammers](#php_spammers)|417|417|25|5.9%|0.4%|
[php_commenters](#php_commenters)|281|281|11|3.9%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|10|1.4%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.0%|
[et_tor](#et_tor)|6360|6360|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6510|6510|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6513|6513|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|160|160|3|1.8%|0.0%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Mon Jun  1 22:30:03 UTC 2015.

The ipset `shunlist` has **1253** entries, **1253** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|173822|173822|1239|0.7%|98.8%|
[openbl_60d](#openbl_60d)|7583|7583|616|8.1%|49.1%|
[openbl_30d](#openbl_30d)|3180|3180|597|18.7%|47.6%|
[et_compromised](#et_compromised)|2191|2191|523|23.8%|41.7%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|521|23.9%|41.5%|
[blocklist_de](#blocklist_de)|23053|23053|408|1.7%|32.5%|
[openbl_7d](#openbl_7d)|913|913|393|43.0%|31.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|1831|1831|372|20.3%|29.6%|
[et_block](#et_block)|997|18338381|108|0.0%|8.6%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|102|0.0%|8.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|100|0.0%|7.9%|
[openbl_1d](#openbl_1d)|146|146|73|50.0%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|69|0.0%|5.5%|
[dshield](#dshield)|20|5120|67|1.3%|5.3%|
[sslbl](#sslbl)|363|363|43|11.8%|3.4%|
[blocklist_de_apache](#blocklist_de_apache)|14034|14034|29|0.2%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|25|0.0%|1.9%|
[ciarmy](#ciarmy)|345|345|25|7.2%|1.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|160|160|18|11.2%|1.4%|
[voipbl](#voipbl)|10350|10759|11|0.1%|0.8%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|5|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|5|0.0%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|4|0.0%|0.3%|
[blocklist_de_imap](#blocklist_de_imap)|670|670|4|0.5%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|3|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|3|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1614|1614|3|0.1%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7144|7144|1|0.0%|0.0%|
[nixspam](#nixspam)|23154|23154|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_tor](#et_tor)|6360|6360|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6510|6510|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6513|6513|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|268|268|1|0.3%|0.0%|

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
[dm_tor](#dm_tor)|6510|6510|1052|16.1%|16.8%|
[bm_tor](#bm_tor)|6513|6513|1052|16.1%|16.8%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|718|0.7%|11.4%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|562|1.7%|8.9%|
[stopforumspam_1d](#stopforumspam_1d)|7144|7144|323|4.5%|5.1%|
[et_block](#et_block)|997|18338381|297|0.0%|4.7%|
[zeus](#zeus)|267|267|227|85.0%|3.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|211|0.0%|3.3%|
[zeus_badips](#zeus_badips)|231|231|203|87.8%|3.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|176|47.3%|2.8%|
[nixspam](#nixspam)|23154|23154|122|0.5%|1.9%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|114|0.0%|1.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|97|0.0%|1.5%|
[blocklist_de](#blocklist_de)|23053|23053|82|0.3%|1.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|68|0.0%|1.0%|
[feodo](#feodo)|77|77|58|75.3%|0.9%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|57|0.3%|0.9%|
[php_dictionary](#php_dictionary)|433|433|42|9.6%|0.6%|
[php_spammers](#php_spammers)|417|417|34|8.1%|0.5%|
[php_commenters](#php_commenters)|281|281|33|11.7%|0.5%|
[ri_web_proxies](#ri_web_proxies)|5560|5560|31|0.5%|0.4%|
[xroxy](#xroxy)|2019|2019|30|1.4%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|26|2.0%|0.4%|
[sslbl](#sslbl)|363|363|24|6.6%|0.3%|
[openbl_60d](#openbl_60d)|7583|7583|24|0.3%|0.3%|
[blocklist_de_bots](#blocklist_de_bots)|3177|3177|20|0.6%|0.3%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|19|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|13|0.0%|0.2%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|8|3.1%|0.1%|
[proxz](#proxz)|480|480|7|1.4%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|6|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|670|670|5|0.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14034|14034|5|0.0%|0.0%|
[shunlist](#shunlist)|1253|1253|3|0.2%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2051|2051|3|0.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|426|426|3|0.7%|0.0%|
[openbl_30d](#openbl_30d)|3180|3180|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1831|1831|2|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1614|1614|2|0.1%|0.0%|
[proxyrss](#proxyrss)|1713|1713|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|913|913|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2191|2191|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|160|160|1|0.6%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|268|268|1|0.3%|0.0%|

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
[fullbogons](#fullbogons)|3639|670579672|151552|0.0%|0.8%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|1628|0.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|971|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|512|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|342|1.0%|0.0%|
[nixspam](#nixspam)|23154|23154|278|1.2%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[openbl_60d](#openbl_60d)|7583|7583|240|3.1%|0.0%|
[openbl_30d](#openbl_30d)|3180|3180|199|6.2%|0.0%|
[blocklist_de](#blocklist_de)|23053|23053|172|0.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1831|1831|114|6.2%|0.0%|
[shunlist](#shunlist)|1253|1253|102|8.1%|0.0%|
[et_compromised](#et_compromised)|2191|2191|102|4.6%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|101|4.6%|0.0%|
[openbl_7d](#openbl_7d)|913|913|86|9.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7144|7144|80|1.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3177|3177|30|0.9%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|29|2.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|25|0.1%|0.0%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|19|0.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|670|670|18|2.6%|0.0%|
[zeus_badips](#zeus_badips)|231|231|16|6.9%|0.0%|
[zeus](#zeus)|267|267|16|5.9%|0.0%|
[openbl_1d](#openbl_1d)|146|146|16|10.9%|0.0%|
[voipbl](#voipbl)|10350|10759|14|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|160|160|6|3.7%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[malc0de](#malc0de)|397|397|4|1.0%|0.0%|
[sslbl](#sslbl)|363|363|3|0.8%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1614|1614|3|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14034|14034|3|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6360|6360|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6510|6510|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6513|6513|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|426|426|1|0.2%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|102|102|1|0.9%|0.0%|

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
[spamhaus_drop](#spamhaus_drop)|656|18600704|512|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|271|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|103|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|37|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7144|7144|7|0.0%|0.0%|
[php_commenters](#php_commenters)|281|281|7|2.4%|0.0%|
[blocklist_de](#blocklist_de)|23053|23053|7|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|6|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7583|7583|6|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3180|3180|6|0.1%|0.0%|
[zeus_badips](#zeus_badips)|231|231|5|2.1%|0.0%|
[zeus](#zeus)|267|267|5|1.8%|0.0%|
[shunlist](#shunlist)|1253|1253|5|0.3%|0.0%|
[openbl_7d](#openbl_7d)|913|913|5|0.5%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|160|160|4|2.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3177|3177|3|0.0%|0.0%|
[nixspam](#nixspam)|23154|23154|2|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14034|14034|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[malc0de](#malc0de)|397|397|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Mon Jun  1 23:15:06 UTC 2015.

The ipset `sslbl` has **363** entries, **363** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|173822|173822|51|0.0%|14.0%|
[shunlist](#shunlist)|1253|1253|43|3.4%|11.8%|
[feodo](#feodo)|77|77|31|40.2%|8.5%|
[et_block](#et_block)|997|18338381|30|0.0%|8.2%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|24|0.3%|6.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|23|0.0%|6.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|6|0.0%|1.6%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|3|0.0%|0.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Mon Jun  1 23:00:02 UTC 2015.

The ipset `stopforumspam_1d` has **7144** entries, **7144** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|4344|4.7%|60.8%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|3947|12.5%|55.2%|
[blocklist_de](#blocklist_de)|23053|23053|1443|6.2%|20.1%|
[blocklist_de_bots](#blocklist_de_bots)|3177|3177|1388|43.6%|19.4%|
[ri_web_proxies](#ri_web_proxies)|5560|5560|560|10.0%|7.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|494|0.0%|6.9%|
[proxyrss](#proxyrss)|1713|1713|454|26.5%|6.3%|
[xroxy](#xroxy)|2019|2019|355|17.5%|4.9%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|323|5.1%|4.5%|
[et_tor](#et_tor)|6360|6360|293|4.6%|4.1%|
[dm_tor](#dm_tor)|6510|6510|289|4.4%|4.0%|
[bm_tor](#bm_tor)|6513|6513|289|4.4%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|235|0.0%|3.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|158|42.4%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|157|0.0%|2.1%|
[ri_connect_proxies](#ri_connect_proxies)|2051|2051|147|7.1%|2.0%|
[php_commenters](#php_commenters)|281|281|108|38.4%|1.5%|
[proxz](#proxz)|480|480|105|21.8%|1.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|160|160|102|63.7%|1.4%|
[et_block](#et_block)|997|18338381|81|0.0%|1.1%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|80|0.0%|1.1%|
[blocklist_de_apache](#blocklist_de_apache)|14034|14034|64|0.4%|0.8%|
[nixspam](#nixspam)|23154|23154|61|0.2%|0.8%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|54|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|40|0.2%|0.5%|
[php_harvesters](#php_harvesters)|257|257|34|13.2%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|28|0.0%|0.3%|
[php_spammers](#php_spammers)|417|417|24|5.7%|0.3%|
[php_dictionary](#php_dictionary)|433|433|24|5.5%|0.3%|
[openbl_60d](#openbl_60d)|7583|7583|21|0.2%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1614|1614|19|1.1%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|10|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|7|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[et_compromised](#et_compromised)|2191|2191|4|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|4|0.1%|0.0%|
[voipbl](#voipbl)|10350|10759|3|0.0%|0.0%|
[zeus_badips](#zeus_badips)|231|231|1|0.4%|0.0%|
[zeus](#zeus)|267|267|1|0.3%|0.0%|
[shunlist](#shunlist)|1253|1253|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3180|3180|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|

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
[stopforumspam_1d](#stopforumspam_1d)|7144|7144|4344|60.8%|4.7%|
[ri_web_proxies](#ri_web_proxies)|5560|5560|2697|48.5%|2.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2477|0.0%|2.6%|
[blocklist_de](#blocklist_de)|23053|23053|2087|9.0%|2.2%|
[blocklist_de_bots](#blocklist_de_bots)|3177|3177|1832|57.6%|1.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1523|0.0%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|2051|2051|1202|58.6%|1.3%|
[xroxy](#xroxy)|2019|2019|1182|58.5%|1.2%|
[et_block](#et_block)|997|18338381|975|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|971|0.0%|1.0%|
[proxyrss](#proxyrss)|1713|1713|790|46.1%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|732|0.0%|0.7%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|718|11.4%|0.7%|
[et_tor](#et_tor)|6360|6360|622|9.7%|0.6%|
[dm_tor](#dm_tor)|6510|6510|619|9.5%|0.6%|
[bm_tor](#bm_tor)|6513|6513|619|9.5%|0.6%|
[proxz](#proxz)|480|480|284|59.1%|0.3%|
[nixspam](#nixspam)|23154|23154|237|1.0%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|234|62.9%|0.2%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|210|0.1%|0.2%|
[php_commenters](#php_commenters)|281|281|203|72.2%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|14034|14034|202|1.4%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|195|1.3%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|160|160|114|71.2%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|103|0.0%|0.1%|
[php_spammers](#php_spammers)|417|417|99|23.7%|0.1%|
[php_dictionary](#php_dictionary)|433|433|83|19.1%|0.0%|
[php_harvesters](#php_harvesters)|257|257|63|24.5%|0.0%|
[openbl_60d](#openbl_60d)|7583|7583|54|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|44|0.0%|0.0%|
[voipbl](#voipbl)|10350|10759|40|0.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1614|1614|39|2.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|22|3.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[et_compromised](#et_compromised)|2191|2191|7|0.3%|0.0%|
[dshield](#dshield)|20|5120|6|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|6|0.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|268|268|6|2.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1831|1831|5|0.2%|0.0%|
[shunlist](#shunlist)|1253|1253|4|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3180|3180|4|0.1%|0.0%|
[zeus_badips](#zeus_badips)|231|231|3|1.2%|0.0%|
[zeus](#zeus)|267|267|3|1.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|3|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3639|670579672|2|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|670|670|2|0.2%|0.0%|
[sslbl](#sslbl)|363|363|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|

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
[stopforumspam_1d](#stopforumspam_1d)|7144|7144|3947|55.2%|12.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2107|0.0%|6.7%|
[blocklist_de](#blocklist_de)|23053|23053|1815|7.8%|5.7%|
[ri_web_proxies](#ri_web_proxies)|5560|5560|1767|31.7%|5.6%|
[blocklist_de_bots](#blocklist_de_bots)|3177|3177|1658|52.1%|5.2%|
[xroxy](#xroxy)|2019|2019|991|49.0%|3.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|938|0.0%|2.9%|
[ri_connect_proxies](#ri_connect_proxies)|2051|2051|706|34.4%|2.2%|
[proxyrss](#proxyrss)|1713|1713|649|37.8%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|563|0.0%|1.7%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|562|8.9%|1.7%|
[dm_tor](#dm_tor)|6510|6510|481|7.3%|1.5%|
[bm_tor](#bm_tor)|6513|6513|481|7.3%|1.5%|
[et_tor](#et_tor)|6360|6360|480|7.5%|1.5%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|342|0.0%|1.0%|
[et_block](#et_block)|997|18338381|342|0.0%|1.0%|
[proxz](#proxz)|480|480|256|53.3%|0.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|201|54.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|182|0.0%|0.5%|
[php_commenters](#php_commenters)|281|281|170|60.4%|0.5%|
[nixspam](#nixspam)|23154|23154|138|0.5%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|14034|14034|124|0.8%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|113|0.7%|0.3%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|107|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|160|160|104|65.0%|0.3%|
[php_spammers](#php_spammers)|417|417|70|16.7%|0.2%|
[php_dictionary](#php_dictionary)|433|433|68|15.7%|0.2%|
[php_harvesters](#php_harvesters)|257|257|47|18.2%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|37|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1614|1614|32|1.9%|0.1%|
[openbl_60d](#openbl_60d)|7583|7583|27|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|19|0.0%|0.0%|
[voipbl](#voipbl)|10350|10759|12|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|5|0.0%|0.0%|
[et_compromised](#et_compromised)|2191|2191|4|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|268|268|4|1.4%|0.0%|
[shunlist](#shunlist)|1253|1253|3|0.2%|0.0%|
[dshield](#dshield)|20|5120|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|3|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|2|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1831|1831|2|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|670|670|2|0.2%|0.0%|
[zeus_badips](#zeus_badips)|231|231|1|0.4%|0.0%|
[zeus](#zeus)|267|267|1|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3180|3180|1|0.0%|0.0%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Mon Jun  1 21:18:26 UTC 2015.

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
[alienvault_reputation](#alienvault_reputation)|173822|173822|200|0.1%|1.8%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|40|0.0%|0.3%|
[blocklist_de](#blocklist_de)|23053|23053|40|0.1%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|102|102|31|30.3%|0.2%|
[et_block](#et_block)|997|18338381|24|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|14|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|12|0.0%|0.1%|
[shunlist](#shunlist)|1253|1253|11|0.8%|0.1%|
[openbl_60d](#openbl_60d)|7583|7583|9|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14034|14034|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7144|7144|3|0.0%|0.0%|
[openbl_7d](#openbl_7d)|913|913|3|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3180|3180|3|0.0%|0.0%|
[ciarmy](#ciarmy)|345|345|3|0.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[et_tor](#et_tor)|6360|6360|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6510|6510|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6513|6513|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1831|1831|2|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1614|1614|2|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2191|2191|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|670|670|1|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3177|3177|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Mon Jun  1 23:33:02 UTC 2015.

The ipset `xroxy` has **2019** entries, **2019** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|1182|1.2%|58.5%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|991|3.1%|49.0%|
[ri_web_proxies](#ri_web_proxies)|5560|5560|825|14.8%|40.8%|
[proxyrss](#proxyrss)|1713|1713|454|26.5%|22.4%|
[stopforumspam_1d](#stopforumspam_1d)|7144|7144|355|4.9%|17.5%|
[ri_connect_proxies](#ri_connect_proxies)|2051|2051|319|15.5%|15.7%|
[proxz](#proxz)|480|480|235|48.9%|11.6%|
[blocklist_de](#blocklist_de)|23053|23053|233|1.0%|11.5%|
[blocklist_de_bots](#blocklist_de_bots)|3177|3177|207|6.5%|10.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|99|0.0%|4.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|84|0.0%|4.1%|
[nixspam](#nixspam)|23154|23154|72|0.3%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|57|0.0%|2.8%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|30|0.4%|1.4%|
[blocklist_de_mail](#blocklist_de_mail)|14733|14733|26|0.1%|1.2%|
[php_dictionary](#php_dictionary)|433|433|24|5.5%|1.1%|
[php_spammers](#php_spammers)|417|417|19|4.5%|0.9%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|13|1.9%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|160|160|5|3.1%|0.2%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|5|0.0%|0.2%|
[php_commenters](#php_commenters)|281|281|3|1.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.1%|
[et_tor](#et_tor)|6360|6360|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[dm_tor](#dm_tor)|6510|6510|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6513|6513|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2191|2191|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1831|1831|1|0.0%|0.0%|

## zeus

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist).

The last time downloaded was found to be dated: Mon Jun  1 22:50:54 UTC 2015.

The ipset `zeus` has **267** entries, **267** unique IPs.

The following table shows the overlaps of `zeus` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus`.
- ` this % ` is the percentage **of this ipset (`zeus`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|997|18338381|261|0.0%|97.7%|
[zeus_badips](#zeus_badips)|231|231|231|100.0%|86.5%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|227|3.6%|85.0%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|66|0.0%|24.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|19|0.0%|7.1%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|16|0.0%|5.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|7|0.0%|2.6%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|5|0.0%|1.8%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|3|0.0%|1.1%|
[openbl_60d](#openbl_60d)|7583|7583|2|0.0%|0.7%|
[openbl_30d](#openbl_30d)|3180|3180|2|0.0%|0.7%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|1|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7144|7144|1|0.0%|0.3%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.3%|
[openbl_7d](#openbl_7d)|913|913|1|0.1%|0.3%|
[nixspam](#nixspam)|23154|23154|1|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|
[et_compromised](#et_compromised)|2191|2191|1|0.0%|0.3%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|1|0.0%|0.3%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Mon Jun  1 23:27:12 UTC 2015.

The ipset `zeus_badips` has **231** entries, **231** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|267|267|231|86.5%|100.0%|
[et_block](#et_block)|997|18338381|229|0.0%|99.1%|
[snort_ipfilter](#snort_ipfilter)|6251|6251|203|3.2%|87.8%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|37|0.0%|16.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|16|0.0%|6.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8|0.0%|3.4%|
[spamhaus_edrop](#spamhaus_edrop)|56|421632|5|0.0%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4|0.0%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|92062|92062|3|0.0%|1.2%|
[stopforumspam_7d](#stopforumspam_7d)|31333|31333|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|7144|7144|1|0.0%|0.4%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.4%|
[openbl_60d](#openbl_60d)|7583|7583|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|3180|3180|1|0.0%|0.4%|
[nixspam](#nixspam)|23154|23154|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.4%|
[et_compromised](#et_compromised)|2191|2191|1|0.0%|0.4%|
[bruteforceblocker](#bruteforceblocker)|2178|2178|1|0.0%|0.4%|
