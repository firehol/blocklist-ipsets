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

The following list was automatically generated on Wed Jun  3 03:10:01 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|174882 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|33154 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|13929 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|3136 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|2596 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|747 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|1669 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|15694 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|114 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|10677 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|176 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6409 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|2175 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|308 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|11 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6391 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|1007 subnets, 18338646 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botcc](#et_botcc)|[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)|ipv4 hash:ip|511 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net compromised hosts](http://doc.emergingthreats.net/bin/view/Main/CompromisedHost) - (this seems to be based on bruteforceblocker)|ipv4 hash:ip|2174 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6520 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
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
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|18241 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|309 unique IPs|updated every 1 hour  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|3244 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7653 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|999 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|281 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|433 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|257 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|417 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1973 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|586 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2159 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|5828 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1276 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|8876 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|656 subnets, 18600704 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|57 subnets, 487168 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|360 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|7091 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|92665 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|31033 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
[virbl](#virbl)|[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.|ipv4 hash:ip|13 unique IPs|updated every 1 hour  from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt)
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
[et_block](#et_block)|1007|18338646|6557|0.0%|3.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4700|0.0%|2.6%|
[dshield](#dshield)|20|5120|3854|75.2%|2.2%|
[openbl_30d](#openbl_30d)|3244|3244|3224|99.3%|1.8%|
[blocklist_de](#blocklist_de)|33154|33154|2036|6.1%|1.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|10677|10677|1792|16.7%|1.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|1628|0.0%|0.9%|
[et_compromised](#et_compromised)|2174|2174|1408|64.7%|0.8%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|1400|64.3%|0.8%|
[shunlist](#shunlist)|1276|1276|1265|99.1%|0.7%|
[openbl_7d](#openbl_7d)|999|999|987|98.7%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|518|0.0%|0.2%|
[ciarmy](#ciarmy)|308|308|297|96.4%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|289|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|271|0.0%|0.1%|
[openbl_1d](#openbl_1d)|309|309|254|82.2%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|215|0.2%|0.1%|
[voipbl](#voipbl)|10367|10776|197|1.8%|0.1%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|119|1.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13929|13929|115|0.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|102|0.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|83|0.5%|0.0%|
[zeus](#zeus)|266|266|66|24.8%|0.0%|
[sslbl](#sslbl)|360|360|63|17.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7091|7091|55|0.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1669|1669|55|3.2%|0.0%|
[et_tor](#et_tor)|6520|6520|46|0.7%|0.0%|
[dm_tor](#dm_tor)|6391|6391|45|0.7%|0.0%|
[bm_tor](#bm_tor)|6409|6409|45|0.7%|0.0%|
[nixspam](#nixspam)|18241|18241|38|0.2%|0.0%|
[zeus_badips](#zeus_badips)|230|230|37|16.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|37|21.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3136|3136|30|0.9%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|25|6.7%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|114|114|20|17.5%|0.0%|
[php_commenters](#php_commenters)|281|281|14|4.9%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2596|2596|14|0.5%|0.0%|
[malc0de](#malc0de)|392|392|12|3.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|747|747|10|1.3%|0.0%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|8|0.5%|0.0%|
[php_dictionary](#php_dictionary)|433|433|7|1.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|6|0.4%|0.0%|
[xroxy](#xroxy)|2041|2041|5|0.2%|0.0%|
[et_botcc](#et_botcc)|511|511|4|0.7%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5828|5828|3|0.0%|0.0%|
[proxz](#proxz)|586|586|3|0.5%|0.0%|
[php_spammers](#php_spammers)|417|417|3|0.7%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2159|2159|2|0.0%|0.0%|
[proxyrss](#proxyrss)|1973|1973|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[feodo](#feodo)|80|80|1|1.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|11|11|1|9.0%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Wed Jun  3 02:42:05 UTC 2015.

The ipset `blocklist_de` has **33154** entries, **33154** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|15650|99.7%|47.2%|
[blocklist_de_apache](#blocklist_de_apache)|13929|13929|13929|100.0%|42.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|10677|10677|10632|99.5%|32.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|5604|0.0%|16.9%|
[blocklist_de_bots](#blocklist_de_bots)|3136|3136|3122|99.5%|9.4%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|2620|2.8%|7.9%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2596|2596|2596|100.0%|7.8%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|2305|7.4%|6.9%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|2036|1.1%|6.1%|
[openbl_60d](#openbl_60d)|7653|7653|1687|22.0%|5.0%|
[blocklist_de_imap](#blocklist_de_imap)|1669|1669|1669|100.0%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1557|0.0%|4.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1526|0.0%|4.6%|
[stopforumspam_1d](#stopforumspam_1d)|7091|7091|1414|19.9%|4.2%|
[openbl_30d](#openbl_30d)|3244|3244|881|27.1%|2.6%|
[blocklist_de_ftp](#blocklist_de_ftp)|747|747|742|99.3%|2.2%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|723|33.2%|2.1%|
[et_compromised](#et_compromised)|2174|2174|691|31.7%|2.0%|
[openbl_7d](#openbl_7d)|999|999|587|58.7%|1.7%|
[nixspam](#nixspam)|18241|18241|476|2.6%|1.4%|
[shunlist](#shunlist)|1276|1276|421|32.9%|1.2%|
[ri_web_proxies](#ri_web_proxies)|5828|5828|356|6.1%|1.0%|
[xroxy](#xroxy)|2041|2041|238|11.6%|0.7%|
[proxyrss](#proxyrss)|1973|1973|237|12.0%|0.7%|
[openbl_1d](#openbl_1d)|309|309|219|70.8%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|176|100.0%|0.5%|
[et_block](#et_block)|1007|18338646|170|0.0%|0.5%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|167|1.8%|0.5%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|160|0.0%|0.4%|
[proxz](#proxz)|586|586|112|19.1%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|114|114|95|83.3%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2159|2159|67|3.1%|0.2%|
[php_commenters](#php_commenters)|281|281|62|22.0%|0.1%|
[php_dictionary](#php_dictionary)|433|433|53|12.2%|0.1%|
[php_spammers](#php_spammers)|417|417|47|11.2%|0.1%|
[dshield](#dshield)|20|5120|47|0.9%|0.1%|
[voipbl](#voipbl)|10367|10776|42|0.3%|0.1%|
[ciarmy](#ciarmy)|308|308|39|12.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|25|9.7%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|13|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|9|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[et_tor](#et_tor)|6520|6520|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6391|6391|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6409|6409|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[virbl](#virbl)|13|13|1|7.6%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Wed Jun  3 02:42:11 UTC 2015.

The ipset `blocklist_de_apache` has **13929** entries, **13929** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|33154|33154|13929|42.0%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|11059|70.4%|79.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2596|2596|2596|100.0%|18.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2260|0.0%|16.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1320|0.0%|9.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1076|0.0%|7.7%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|202|0.2%|1.4%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|123|0.3%|0.8%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|115|0.0%|0.8%|
[stopforumspam_1d](#stopforumspam_1d)|7091|7091|61|0.8%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|35|19.8%|0.2%|
[shunlist](#shunlist)|1276|1276|33|2.5%|0.2%|
[ciarmy](#ciarmy)|308|308|32|10.3%|0.2%|
[nixspam](#nixspam)|18241|18241|24|0.1%|0.1%|
[php_commenters](#php_commenters)|281|281|23|8.1%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3136|3136|21|0.6%|0.1%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|9|0.1%|0.0%|
[voipbl](#voipbl)|10367|10776|5|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|4|0.9%|0.0%|
[et_block](#et_block)|1007|18338646|4|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7653|7653|3|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.0%|
[et_tor](#et_tor)|6520|6520|3|0.0%|0.0%|
[dshield](#dshield)|20|5120|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6391|6391|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6409|6409|3|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|2|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[openbl_30d](#openbl_30d)|3244|3244|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[et_compromised](#et_compromised)|2174|2174|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|2|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[openbl_7d](#openbl_7d)|999|999|1|0.1%|0.0%|
[openbl_1d](#openbl_1d)|309|309|1|0.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Wed Jun  3 02:56:08 UTC 2015.

The ipset `blocklist_de_bots` has **3136** entries, **3136** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|33154|33154|3122|9.4%|99.5%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|2247|2.4%|71.6%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|2106|6.7%|67.1%|
[stopforumspam_1d](#stopforumspam_1d)|7091|7091|1361|19.1%|43.3%|
[ri_web_proxies](#ri_web_proxies)|5828|5828|311|5.3%|9.9%|
[proxyrss](#proxyrss)|1973|1973|234|11.8%|7.4%|
[xroxy](#xroxy)|2041|2041|195|9.5%|6.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|178|0.0%|5.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|152|0.0%|4.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|129|73.2%|4.1%|
[proxz](#proxz)|586|586|93|15.8%|2.9%|
[ri_connect_proxies](#ri_connect_proxies)|2159|2159|65|3.0%|2.0%|
[php_commenters](#php_commenters)|281|281|49|17.4%|1.5%|
[nixspam](#nixspam)|18241|18241|32|0.1%|1.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|31|0.0%|0.9%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|30|0.0%|0.9%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|23|0.2%|0.7%|
[et_block](#et_block)|1007|18338646|21|0.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|21|0.1%|0.6%|
[blocklist_de_apache](#blocklist_de_apache)|13929|13929|21|0.1%|0.6%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|19|0.0%|0.6%|
[php_harvesters](#php_harvesters)|257|257|19|7.3%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|12|0.0%|0.3%|
[php_dictionary](#php_dictionary)|433|433|11|2.5%|0.3%|
[php_spammers](#php_spammers)|417|417|10|2.3%|0.3%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|6|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7653|7653|5|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.0%|
[voipbl](#voipbl)|10367|10776|2|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[et_compromised](#et_compromised)|2174|2174|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Wed Jun  3 02:42:18 UTC 2015.

The ipset `blocklist_de_bruteforce` has **2596** entries, **2596** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_apache](#blocklist_de_apache)|13929|13929|2596|18.6%|100.0%|
[blocklist_de](#blocklist_de)|33154|33154|2596|7.8%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|165|0.0%|6.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|45|0.0%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|42|0.0%|1.6%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|31|0.0%|1.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|30|0.0%|1.1%|
[nixspam](#nixspam)|18241|18241|24|0.1%|0.9%|
[stopforumspam_1d](#stopforumspam_1d)|7091|7091|18|0.2%|0.6%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|14|0.0%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|12|6.8%|0.4%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|6|0.0%|0.2%|
[php_commenters](#php_commenters)|281|281|5|1.7%|0.1%|
[php_spammers](#php_spammers)|417|417|4|0.9%|0.1%|
[et_block](#et_block)|1007|18338646|3|0.0%|0.1%|
[voipbl](#voipbl)|10367|10776|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|2|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[shunlist](#shunlist)|1276|1276|1|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7653|7653|1|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|1|0.0%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Wed Jun  3 02:56:07 UTC 2015.

The ipset `blocklist_de_ftp` has **747** entries, **747** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|33154|33154|742|2.2%|99.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|67|0.0%|8.9%|
[nixspam](#nixspam)|18241|18241|13|0.0%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|11|0.0%|1.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|10|0.0%|1.3%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|10|0.0%|1.3%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|6|0.0%|0.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|6|0.0%|0.8%|
[php_harvesters](#php_harvesters)|257|257|5|1.9%|0.6%|
[openbl_60d](#openbl_60d)|7653|7653|3|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|7091|7091|2|0.0%|0.2%|
[openbl_30d](#openbl_30d)|3244|3244|2|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|1|0.0%|0.1%|
[shunlist](#shunlist)|1276|1276|1|0.0%|0.1%|
[openbl_7d](#openbl_7d)|999|999|1|0.1%|0.1%|
[et_compromised](#et_compromised)|2174|2174|1|0.0%|0.1%|
[ciarmy](#ciarmy)|308|308|1|0.3%|0.1%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|1|0.0%|0.1%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Wed Jun  3 02:42:11 UTC 2015.

The ipset `blocklist_de_imap` has **1669** entries, **1669** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|33154|33154|1669|5.0%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|1666|10.6%|99.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|146|0.0%|8.7%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|55|0.0%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|50|0.0%|2.9%|
[openbl_60d](#openbl_60d)|7653|7653|40|0.5%|2.3%|
[openbl_30d](#openbl_30d)|3244|3244|36|1.1%|2.1%|
[openbl_7d](#openbl_7d)|999|999|17|1.7%|1.0%|
[et_block](#et_block)|1007|18338646|17|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|16|0.0%|0.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|16|0.0%|0.9%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|6|0.0%|0.3%|
[et_compromised](#et_compromised)|2174|2174|6|0.2%|0.3%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|6|0.2%|0.3%|
[nixspam](#nixspam)|18241|18241|5|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|4|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|3|0.0%|0.1%|
[shunlist](#shunlist)|1276|1276|3|0.2%|0.1%|
[openbl_1d](#openbl_1d)|309|309|3|0.9%|0.1%|
[voipbl](#voipbl)|10367|10776|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|1|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|10677|10677|1|0.0%|0.0%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Wed Jun  3 02:56:07 UTC 2015.

The ipset `blocklist_de_mail` has **15694** entries, **15694** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|33154|33154|15650|47.2%|99.7%|
[blocklist_de_apache](#blocklist_de_apache)|13929|13929|11059|79.3%|70.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2380|0.0%|15.1%|
[blocklist_de_imap](#blocklist_de_imap)|1669|1669|1666|99.8%|10.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1333|0.0%|8.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1142|0.0%|7.2%|
[nixspam](#nixspam)|18241|18241|363|1.9%|2.3%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|227|0.2%|1.4%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|137|0.4%|0.8%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|136|1.5%|0.8%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|83|0.0%|0.5%|
[openbl_60d](#openbl_60d)|7653|7653|50|0.6%|0.3%|
[openbl_30d](#openbl_30d)|3244|3244|45|1.3%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7091|7091|44|0.6%|0.2%|
[ri_web_proxies](#ri_web_proxies)|5828|5828|43|0.7%|0.2%|
[xroxy](#xroxy)|2041|2041|40|1.9%|0.2%|
[php_dictionary](#php_dictionary)|433|433|40|9.2%|0.2%|
[php_spammers](#php_spammers)|417|417|33|7.9%|0.2%|
[et_block](#et_block)|1007|18338646|28|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|26|0.0%|0.1%|
[openbl_7d](#openbl_7d)|999|999|24|2.4%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3136|3136|21|0.6%|0.1%|
[php_commenters](#php_commenters)|281|281|20|7.1%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|20|11.3%|0.1%|
[proxz](#proxz)|586|586|17|2.9%|0.1%|
[et_compromised](#et_compromised)|2174|2174|10|0.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|10|0.4%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.0%|
[shunlist](#shunlist)|1276|1276|5|0.3%|0.0%|
[openbl_1d](#openbl_1d)|309|309|5|1.6%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|4|0.0%|0.0%|
[et_tor](#et_tor)|6520|6520|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6391|6391|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6409|6409|3|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[ciarmy](#ciarmy)|308|308|2|0.6%|0.0%|
[voipbl](#voipbl)|10367|10776|1|0.0%|0.0%|
[virbl](#virbl)|13|13|1|7.6%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2159|2159|1|0.0%|0.0%|
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

The last time downloaded was found to be dated: Wed Jun  3 02:42:14 UTC 2015.

The ipset `blocklist_de_sip` has **114** entries, **114** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|33154|33154|95|0.2%|83.3%|
[voipbl](#voipbl)|10367|10776|32|0.2%|28.0%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|20|0.0%|17.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|13|0.0%|11.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|6|0.0%|5.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|2.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|1.7%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|1|0.0%|0.8%|
[et_botcc](#et_botcc)|511|511|1|0.1%|0.8%|
[et_block](#et_block)|1007|18338646|1|0.0%|0.8%|
[ciarmy](#ciarmy)|308|308|1|0.3%|0.8%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Wed Jun  3 02:56:04 UTC 2015.

The ipset `blocklist_de_ssh` has **10677** entries, **10677** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|33154|33154|10632|32.0%|99.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2794|0.0%|26.1%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|1792|1.0%|16.7%|
[openbl_60d](#openbl_60d)|7653|7653|1628|21.2%|15.2%|
[openbl_30d](#openbl_30d)|3244|3244|832|25.6%|7.7%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|710|32.6%|6.6%|
[et_compromised](#et_compromised)|2174|2174|678|31.1%|6.3%|
[openbl_7d](#openbl_7d)|999|999|561|56.1%|5.2%|
[shunlist](#shunlist)|1276|1276|382|29.9%|3.5%|
[openbl_1d](#openbl_1d)|309|309|213|68.9%|1.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|196|0.0%|1.8%|
[et_block](#et_block)|1007|18338646|116|0.0%|1.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|113|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|112|0.0%|1.0%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|81|0.0%|0.7%|
[nixspam](#nixspam)|18241|18241|49|0.2%|0.4%|
[dshield](#dshield)|20|5120|43|0.8%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|28|15.9%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|14|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.0%|
[ciarmy](#ciarmy)|308|308|3|0.9%|0.0%|
[xroxy](#xroxy)|2041|2041|2|0.0%|0.0%|
[voipbl](#voipbl)|10367|10776|2|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|2|0.0%|0.0%|
[proxz](#proxz)|586|586|2|0.3%|0.0%|
[proxyrss](#proxyrss)|1973|1973|2|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7091|7091|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2159|2159|1|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1669|1669|1|0.0%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Wed Jun  3 02:42:17 UTC 2015.

The ipset `blocklist_de_strongips` has **176** entries, **176** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|33154|33154|176|0.5%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|131|0.1%|74.4%|
[blocklist_de_bots](#blocklist_de_bots)|3136|3136|129|4.1%|73.2%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|121|0.3%|68.7%|
[stopforumspam_1d](#stopforumspam_1d)|7091|7091|103|1.4%|58.5%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|37|0.0%|21.0%|
[blocklist_de_apache](#blocklist_de_apache)|13929|13929|35|0.2%|19.8%|
[php_commenters](#php_commenters)|281|281|29|10.3%|16.4%|
[openbl_60d](#openbl_60d)|7653|7653|28|0.3%|15.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|10677|10677|28|0.2%|15.9%|
[openbl_30d](#openbl_30d)|3244|3244|25|0.7%|14.2%|
[openbl_7d](#openbl_7d)|999|999|24|2.4%|13.6%|
[shunlist](#shunlist)|1276|1276|20|1.5%|11.3%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|20|0.1%|11.3%|
[openbl_1d](#openbl_1d)|309|309|18|5.8%|10.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|16|0.0%|9.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2596|2596|12|0.4%|6.8%|
[xroxy](#xroxy)|2041|2041|7|0.3%|3.9%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|7|0.0%|3.9%|
[proxyrss](#proxyrss)|1973|1973|7|0.3%|3.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7|0.0%|3.9%|
[et_block](#et_block)|1007|18338646|7|0.0%|3.9%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|6|0.0%|3.4%|
[ri_web_proxies](#ri_web_proxies)|5828|5828|5|0.0%|2.8%|
[proxz](#proxz)|586|586|3|0.5%|1.7%|
[php_spammers](#php_spammers)|417|417|3|0.7%|1.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.7%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|1.1%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|1.1%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|1|0.0%|0.5%|
[nixspam](#nixspam)|18241|18241|1|0.0%|0.5%|
[dshield](#dshield)|20|5120|1|0.0%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|1669|1669|1|0.0%|0.5%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Wed Jun  3 02:54:08 UTC 2015.

The ipset `bm_tor` has **6409** entries, **6409** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[dm_tor](#dm_tor)|6391|6391|6296|98.5%|98.2%|
[et_tor](#et_tor)|6520|6520|5959|91.3%|92.9%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|1076|12.1%|16.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|633|0.0%|9.8%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|631|0.6%|9.8%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|482|1.5%|7.5%|
[stopforumspam_1d](#stopforumspam_1d)|7091|7091|289|4.0%|4.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|182|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|171|45.9%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|167|0.0%|2.6%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|45|0.0%|0.7%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[openbl_60d](#openbl_60d)|7653|7653|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13929|13929|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|33154|33154|3|0.0%|0.0%|
[xroxy](#xroxy)|2041|2041|2|0.0%|0.0%|
[voipbl](#voipbl)|10367|10776|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|2|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5828|5828|2|0.0%|0.0%|
[et_block](#et_block)|1007|18338646|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[shunlist](#shunlist)|1276|1276|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2159|2159|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1973|1973|1|0.0%|0.0%|
[nixspam](#nixspam)|18241|18241|1|0.0%|0.0%|

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
[bruteforceblocker](#bruteforceblocker)|2175|2175|1|0.0%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Wed Jun  3 02:01:14 UTC 2015.

The ipset `bruteforceblocker` has **2175** entries, **2175** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_compromised](#et_compromised)|2174|2174|2124|97.7%|97.6%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|1400|0.8%|64.3%|
[openbl_60d](#openbl_60d)|7653|7653|1300|16.9%|59.7%|
[openbl_30d](#openbl_30d)|3244|3244|1221|37.6%|56.1%|
[blocklist_de](#blocklist_de)|33154|33154|723|2.1%|33.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|10677|10677|710|6.6%|32.6%|
[openbl_7d](#openbl_7d)|999|999|519|51.9%|23.8%|
[shunlist](#shunlist)|1276|1276|508|39.8%|23.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|217|0.0%|9.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|116|0.0%|5.3%|
[et_block](#et_block)|1007|18338646|101|0.0%|4.6%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|100|0.0%|4.5%|
[openbl_1d](#openbl_1d)|309|309|80|25.8%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|62|0.0%|2.8%|
[dshield](#dshield)|20|5120|43|0.8%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|10|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|10|0.0%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|6|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|1669|1669|6|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[voipbl](#voipbl)|10367|10776|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|2|0.0%|0.0%|
[proxz](#proxz)|586|586|2|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13929|13929|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[xroxy](#xroxy)|2041|2041|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7091|7091|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5828|5828|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1973|1973|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3686|670534424|1|0.0%|0.0%|
[ciarmy](#ciarmy)|308|308|1|0.3%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|747|747|1|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3136|3136|1|0.0%|0.0%|

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
[blocklist_de](#blocklist_de)|33154|33154|39|0.1%|12.6%|
[blocklist_de_apache](#blocklist_de_apache)|13929|13929|32|0.2%|10.3%|
[shunlist](#shunlist)|1276|1276|24|1.8%|7.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|11|0.0%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|9|0.0%|2.9%|
[voipbl](#voipbl)|10367|10776|5|0.0%|1.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|10677|10677|3|0.0%|0.9%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|2|0.0%|0.6%|
[openbl_7d](#openbl_7d)|999|999|1|0.1%|0.3%|
[openbl_60d](#openbl_60d)|7653|7653|1|0.0%|0.3%|
[openbl_30d](#openbl_30d)|3244|3244|1|0.0%|0.3%|
[et_block](#et_block)|1007|18338646|1|0.0%|0.3%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|1|0.0%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|114|114|1|0.8%|0.3%|
[blocklist_de_ftp](#blocklist_de_ftp)|747|747|1|0.1%|0.3%|

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

The last time downloaded was found to be dated: Wed Jun  3 02:54:05 UTC 2015.

The ipset `dm_tor` has **6391** entries, **6391** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6409|6409|6296|98.2%|98.5%|
[et_tor](#et_tor)|6520|6520|5901|90.5%|92.3%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|1072|12.0%|16.7%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|630|0.6%|9.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|630|0.0%|9.8%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|481|1.5%|7.5%|
[stopforumspam_1d](#stopforumspam_1d)|7091|7091|288|4.0%|4.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|183|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|171|45.9%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|167|0.0%|2.6%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|45|0.0%|0.7%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[openbl_60d](#openbl_60d)|7653|7653|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13929|13929|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|33154|33154|3|0.0%|0.0%|
[xroxy](#xroxy)|2041|2041|2|0.0%|0.0%|
[voipbl](#voipbl)|10367|10776|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|2|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5828|5828|2|0.0%|0.0%|
[et_block](#et_block)|1007|18338646|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[shunlist](#shunlist)|1276|1276|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2159|2159|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1973|1973|1|0.0%|0.0%|
[nixspam](#nixspam)|18241|18241|1|0.0%|0.0%|

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
[et_block](#et_block)|1007|18338646|1281|0.0%|25.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|512|0.0%|10.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|512|0.0%|10.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|512|0.0%|10.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|256|0.0%|5.0%|
[openbl_60d](#openbl_60d)|7653|7653|76|0.9%|1.4%|
[openbl_30d](#openbl_30d)|3244|3244|67|2.0%|1.3%|
[blocklist_de](#blocklist_de)|33154|33154|47|0.1%|0.9%|
[et_compromised](#et_compromised)|2174|2174|43|1.9%|0.8%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|43|1.9%|0.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|10677|10677|43|0.4%|0.8%|
[openbl_7d](#openbl_7d)|999|999|42|4.2%|0.8%|
[shunlist](#shunlist)|1276|1276|40|3.1%|0.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|22|0.0%|0.4%|
[openbl_1d](#openbl_1d)|309|309|12|3.8%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13929|13929|3|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|2|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7091|7091|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|2|0.0%|0.0%|
[et_tor](#et_tor)|6520|6520|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6391|6391|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6409|6409|2|0.0%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.0%|
[nixspam](#nixspam)|18241|18241|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[malc0de](#malc0de)|392|392|1|0.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|1|0.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|1|0.0%|0.0%|

## et_block

[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)

Source is downloaded from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt).

The last time downloaded was found to be dated: Tue Jun  2 04:30:02 UTC 2015.

The ipset `et_block` has **1007** entries, **18338646** unique IPs.

The following table shows the overlaps of `et_block` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_block`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_block`.
- ` this % ` is the percentage **of this ipset (`et_block`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[spamhaus_drop](#spamhaus_drop)|656|18600704|18333440|98.5%|99.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8598568|2.4%|46.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7079936|77.1%|38.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|2272350|0.2%|12.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|196188|0.1%|1.0%|
[fullbogons](#fullbogons)|3686|670534424|20480|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|6557|3.7%|0.0%|
[dshield](#dshield)|20|5120|1281|25.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1041|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|1002|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|517|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|345|1.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|305|3.4%|0.0%|
[zeus](#zeus)|266|266|263|98.8%|0.0%|
[openbl_60d](#openbl_60d)|7653|7653|244|3.1%|0.0%|
[zeus_badips](#zeus_badips)|230|230|230|100.0%|0.0%|
[openbl_30d](#openbl_30d)|3244|3244|179|5.5%|0.0%|
[blocklist_de](#blocklist_de)|33154|33154|170|0.5%|0.0%|
[nixspam](#nixspam)|18241|18241|160|0.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|10677|10677|116|1.0%|0.0%|
[shunlist](#shunlist)|1276|1276|105|8.2%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7091|7091|104|1.4%|0.0%|
[et_compromised](#et_compromised)|2174|2174|102|4.6%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|101|4.6%|0.0%|
[openbl_7d](#openbl_7d)|999|999|87|8.7%|0.0%|
[feodo](#feodo)|80|80|77|96.2%|0.0%|
[sslbl](#sslbl)|360|360|34|9.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|29|2.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|28|0.1%|0.0%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3136|3136|21|0.6%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1669|1669|17|1.0%|0.0%|
[voipbl](#voipbl)|10367|10776|14|0.1%|0.0%|
[palevo](#palevo)|13|13|13|100.0%|0.0%|
[openbl_1d](#openbl_1d)|309|309|13|4.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|11|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|7|3.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[malc0de](#malc0de)|392|392|4|1.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13929|13929|4|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2596|2596|3|0.1%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6520|6520|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6391|6391|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6409|6409|2|0.0%|0.0%|
[xroxy](#xroxy)|2041|2041|1|0.0%|0.0%|
[proxz](#proxz)|586|586|1|0.1%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[et_botcc](#et_botcc)|511|511|1|0.1%|0.0%|
[ciarmy](#ciarmy)|308|308|1|0.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|114|114|1|0.8%|0.0%|

## et_botcc

[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)

Source is downloaded from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules).

The last time downloaded was found to be dated: Tue Jun  2 04:30:01 UTC 2015.

The ipset `et_botcc` has **511** entries, **511** unique IPs.

The following table shows the overlaps of `et_botcc` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_botcc`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_botcc`.
- ` this % ` is the percentage **of this ipset (`et_botcc`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|77|0.0%|15.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|42|0.0%|8.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|22|0.0%|4.3%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|4|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[et_block](#et_block)|1007|18338646|1|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|114|114|1|0.8%|0.1%|

## et_compromised

[EmergingThreats.net compromised hosts](http://doc.emergingthreats.net/bin/view/Main/CompromisedHost) - (this seems to be based on bruteforceblocker)

Source is downloaded from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt).

The last time downloaded was found to be dated: Tue Jun  2 04:30:09 UTC 2015.

The ipset `et_compromised` has **2174** entries, **2174** unique IPs.

The following table shows the overlaps of `et_compromised` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_compromised`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_compromised`.
- ` this % ` is the percentage **of this ipset (`et_compromised`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bruteforceblocker](#bruteforceblocker)|2175|2175|2124|97.6%|97.7%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|1408|0.8%|64.7%|
[openbl_60d](#openbl_60d)|7653|7653|1310|17.1%|60.2%|
[openbl_30d](#openbl_30d)|3244|3244|1226|37.7%|56.3%|
[blocklist_de](#blocklist_de)|33154|33154|691|2.0%|31.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|10677|10677|678|6.3%|31.1%|
[openbl_7d](#openbl_7d)|999|999|518|51.8%|23.8%|
[shunlist](#shunlist)|1276|1276|509|39.8%|23.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|217|0.0%|9.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|112|0.0%|5.1%|
[et_block](#et_block)|1007|18338646|102|0.0%|4.6%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|101|0.0%|4.6%|
[openbl_1d](#openbl_1d)|309|309|78|25.2%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|61|0.0%|2.8%|
[dshield](#dshield)|20|5120|43|0.8%|1.9%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|10|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|8|0.0%|0.3%|
[blocklist_de_imap](#blocklist_de_imap)|1669|1669|6|0.3%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|5|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|2|0.0%|0.0%|
[proxz](#proxz)|586|586|2|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13929|13929|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[xroxy](#xroxy)|2041|2041|1|0.0%|0.0%|
[voipbl](#voipbl)|10367|10776|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7091|7091|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1973|1973|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|747|747|1|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3136|3136|1|0.0%|0.0%|

## et_tor

[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs

Source is downloaded from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules).

The last time downloaded was found to be dated: Tue Jun  2 04:30:09 UTC 2015.

The ipset `et_tor` has **6520** entries, **6520** unique IPs.

The following table shows the overlaps of `et_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `et_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `et_tor`.
- ` this % ` is the percentage **of this ipset (`et_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6409|6409|5959|92.9%|91.3%|
[dm_tor](#dm_tor)|6391|6391|5901|92.3%|90.5%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|1112|12.5%|17.0%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|643|0.6%|9.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|635|0.0%|9.7%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|492|1.5%|7.5%|
[stopforumspam_1d](#stopforumspam_1d)|7091|7091|289|4.0%|4.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|188|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|170|45.6%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|170|0.0%|2.6%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|46|0.0%|0.7%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[openbl_60d](#openbl_60d)|7653|7653|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5828|5828|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13929|13929|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|33154|33154|3|0.0%|0.0%|
[xroxy](#xroxy)|2041|2041|2|0.0%|0.0%|
[voipbl](#voipbl)|10367|10776|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|2|0.0%|0.0%|
[et_block](#et_block)|1007|18338646|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[shunlist](#shunlist)|1276|1276|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2159|2159|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1973|1973|1|0.0%|0.0%|
[nixspam](#nixspam)|18241|18241|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Wed Jun  3 02:54:17 UTC 2015.

The ipset `feodo` has **80** entries, **80** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|1007|18338646|77|0.0%|96.2%|
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
[et_block](#et_block)|1007|18338646|20480|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|890|0.2%|0.0%|
[voipbl](#voipbl)|10367|10776|319|2.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|33|2.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|15|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|9|0.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|1|0.0%|0.0%|

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
[et_block](#et_block)|1007|18338646|11|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|7|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|6|0.0%|0.0%|
[nixspam](#nixspam)|18241|18241|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|33154|33154|4|0.0%|0.0%|
[xroxy](#xroxy)|2041|2041|3|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|3|0.0%|0.0%|
[voipbl](#voipbl)|10367|10776|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|2|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2596|2596|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13929|13929|2|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7091|7091|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5828|5828|1|0.0%|0.0%|
[proxz](#proxz)|586|586|1|0.1%|0.0%|
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
[et_block](#et_block)|1007|18338646|7079936|38.6%|77.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2526625|0.7%|27.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|904796|0.1%|9.8%|
[fullbogons](#fullbogons)|3686|670534424|565248|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|145472|0.1%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1036|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|737|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|518|0.2%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|174|0.5%|0.0%|
[nixspam](#nixspam)|18241|18241|161|0.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7091|7091|37|0.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|27|2.1%|0.0%|
[blocklist_de](#blocklist_de)|33154|33154|27|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7653|7653|18|0.2%|0.0%|
[openbl_30d](#openbl_30d)|3244|3244|13|0.4%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3136|3136|12|0.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|11|0.1%|0.0%|
[zeus_badips](#zeus_badips)|230|230|10|4.3%|0.0%|
[zeus](#zeus)|266|266|10|3.7%|0.0%|
[openbl_7d](#openbl_7d)|999|999|9|0.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|7|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|10677|10677|6|0.0%|0.0%|
[et_compromised](#et_compromised)|2174|2174|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|5|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1669|1669|4|0.2%|0.0%|
[shunlist](#shunlist)|1276|1276|3|0.2%|0.0%|
[et_tor](#et_tor)|6520|6520|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6391|6391|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6409|6409|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|3|1.7%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[voipbl](#voipbl)|10367|10776|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.0%|
[openbl_1d](#openbl_1d)|309|309|1|0.3%|0.0%|
[et_botcc](#et_botcc)|511|511|1|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2596|2596|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13929|13929|1|0.0%|0.0%|

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
[et_block](#et_block)|1007|18338646|2272350|12.3%|0.2%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|2272266|12.2%|0.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1354348|0.9%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904796|9.8%|0.1%|
[fullbogons](#fullbogons)|3686|670534424|235129|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|33155|6.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|13248|3.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|4700|2.6%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|1545|1.6%|0.0%|
[blocklist_de](#blocklist_de)|33154|33154|1526|4.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|1333|8.4%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13929|13929|1320|9.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|581|1.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|406|0.8%|0.0%|
[nixspam](#nixspam)|18241|18241|379|2.0%|0.0%|
[voipbl](#voipbl)|10367|10776|296|2.7%|0.0%|
[openbl_60d](#openbl_60d)|7653|7653|172|2.2%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7091|7091|171|2.4%|0.0%|
[et_tor](#et_tor)|6520|6520|170|2.6%|0.0%|
[dm_tor](#dm_tor)|6391|6391|167|2.6%|0.0%|
[bm_tor](#bm_tor)|6409|6409|167|2.6%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5828|5828|123|2.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|10677|10677|113|1.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|97|6.6%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|93|1.0%|0.0%|
[openbl_30d](#openbl_30d)|3244|3244|73|2.2%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2159|2159|71|3.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|66|5.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|62|2.8%|0.0%|
[et_compromised](#et_compromised)|2174|2174|61|2.8%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|58|8.6%|0.0%|
[xroxy](#xroxy)|2041|2041|57|2.7%|0.0%|
[et_botcc](#et_botcc)|511|511|42|8.2%|0.0%|
[proxyrss](#proxyrss)|1973|1973|38|1.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3136|3136|31|0.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2596|2596|30|1.1%|0.0%|
[shunlist](#shunlist)|1276|1276|25|1.9%|0.0%|
[proxz](#proxz)|586|586|24|4.0%|0.0%|
[dshield](#dshield)|20|5120|22|0.4%|0.0%|
[openbl_7d](#openbl_7d)|999|999|21|2.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|17|4.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1669|1669|16|0.9%|0.0%|
[malc0de](#malc0de)|392|392|12|3.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|9|2.0%|0.0%|
[ciarmy](#ciarmy)|308|308|9|2.9%|0.0%|
[zeus](#zeus)|266|266|7|2.6%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[openbl_1d](#openbl_1d)|309|309|7|2.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|747|747|6|0.8%|0.0%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.0%|
[php_commenters](#php_commenters)|281|281|5|1.7%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[zeus_badips](#zeus_badips)|230|230|4|1.7%|0.0%|
[sslbl](#sslbl)|360|360|3|0.8%|0.0%|
[feodo](#feodo)|80|80|3|3.7%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|114|114|3|2.6%|0.0%|

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
[et_block](#et_block)|1007|18338646|8598568|46.8%|2.4%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|8598042|46.2%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2830140|2.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2526625|27.5%|0.7%|
[fullbogons](#fullbogons)|3686|670534424|248831|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|98904|20.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|7733|2.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|7609|4.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|2510|2.7%|0.0%|
[blocklist_de](#blocklist_de)|33154|33154|1557|4.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|1142|7.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13929|13929|1076|7.7%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|940|3.0%|0.0%|
[nixspam](#nixspam)|18241|18241|549|3.0%|0.0%|
[dshield](#dshield)|20|5120|512|10.0%|0.0%|
[voipbl](#voipbl)|10367|10776|432|4.0%|0.0%|
[openbl_60d](#openbl_60d)|7653|7653|341|4.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7091|7091|260|3.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|230|0.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|10677|10677|196|1.8%|0.0%|
[et_tor](#et_tor)|6520|6520|188|2.8%|0.0%|
[dm_tor](#dm_tor)|6391|6391|183|2.8%|0.0%|
[bm_tor](#bm_tor)|6409|6409|182|2.8%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5828|5828|177|3.0%|0.0%|
[openbl_30d](#openbl_30d)|3244|3244|177|5.4%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3136|3136|152|4.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|116|1.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|116|5.3%|0.0%|
[et_compromised](#et_compromised)|2174|2174|112|5.1%|0.0%|
[xroxy](#xroxy)|2041|2041|99|4.8%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2159|2159|88|4.0%|0.0%|
[shunlist](#shunlist)|1276|1276|70|5.4%|0.0%|
[proxyrss](#proxyrss)|1973|1973|70|3.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1669|1669|50|2.9%|0.0%|
[openbl_7d](#openbl_7d)|999|999|48|4.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|45|3.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2596|2596|45|1.7%|0.0%|
[php_spammers](#php_spammers)|417|417|31|7.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|28|4.1%|0.0%|
[proxz](#proxz)|586|586|27|4.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|26|2.0%|0.0%|
[malc0de](#malc0de)|392|392|24|6.1%|0.0%|
[et_botcc](#et_botcc)|511|511|22|4.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|21|5.6%|0.0%|
[openbl_1d](#openbl_1d)|309|309|14|4.5%|0.0%|
[ciarmy](#ciarmy)|308|308|11|3.5%|0.0%|
[php_dictionary](#php_dictionary)|433|433|10|2.3%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|747|747|10|1.3%|0.0%|
[zeus](#zeus)|266|266|9|3.3%|0.0%|
[php_commenters](#php_commenters)|281|281|9|3.2%|0.0%|
[zeus_badips](#zeus_badips)|230|230|8|3.4%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|7|3.9%|0.0%|
[sslbl](#sslbl)|360|360|6|1.6%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|114|114|6|5.2%|0.0%|
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
[et_block](#et_block)|1007|18338646|196188|1.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|195904|1.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|14639|8.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|9231|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|5884|6.3%|0.0%|
[blocklist_de](#blocklist_de)|33154|33154|5604|16.9%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|10677|10677|2794|26.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|2380|15.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13929|13929|2260|16.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|2017|6.4%|0.0%|
[voipbl](#voipbl)|10367|10776|1593|14.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1172|2.4%|0.0%|
[nixspam](#nixspam)|18241|18241|882|4.8%|0.0%|
[openbl_60d](#openbl_60d)|7653|7653|744|9.7%|0.0%|
[et_tor](#et_tor)|6520|6520|635|9.7%|0.0%|
[bm_tor](#bm_tor)|6409|6409|633|9.8%|0.0%|
[dm_tor](#dm_tor)|6391|6391|630|9.8%|0.0%|
[dshield](#dshield)|20|5120|512|10.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7091|7091|484|6.8%|0.0%|
[openbl_30d](#openbl_30d)|3244|3244|313|9.6%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|246|2.7%|0.0%|
[et_compromised](#et_compromised)|2174|2174|217|9.9%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|217|9.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3136|3136|178|5.6%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2596|2596|165|6.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5828|5828|163|2.7%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|146|11.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1669|1669|146|8.7%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|125|33.6%|0.0%|
[openbl_7d](#openbl_7d)|999|999|117|11.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|110|7.5%|0.0%|
[shunlist](#shunlist)|1276|1276|103|8.0%|0.0%|
[xroxy](#xroxy)|2041|2041|87|4.2%|0.0%|
[et_botcc](#et_botcc)|511|511|77|15.0%|0.0%|
[proxyrss](#proxyrss)|1973|1973|68|3.4%|0.0%|
[malc0de](#malc0de)|392|392|67|17.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|747|747|67|8.9%|0.0%|
[proxz](#proxz)|586|586|53|9.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|51|7.5%|0.0%|
[ciarmy](#ciarmy)|308|308|51|16.5%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2159|2159|48|2.2%|0.0%|
[openbl_1d](#openbl_1d)|309|309|48|15.5%|0.0%|
[php_spammers](#php_spammers)|417|417|26|6.2%|0.0%|
[php_dictionary](#php_dictionary)|433|433|24|5.5%|0.0%|
[sslbl](#sslbl)|360|360|23|6.3%|0.0%|
[zeus](#zeus)|266|266|19|7.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|16|9.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|15|5.8%|0.0%|
[php_commenters](#php_commenters)|281|281|15|5.3%|0.0%|
[zeus_badips](#zeus_badips)|230|230|14|6.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|114|114|13|11.4%|0.0%|
[feodo](#feodo)|80|80|7|8.7%|0.0%|
[virbl](#virbl)|13|13|1|7.6%|0.0%|
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
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|12|0.0%|1.7%|
[ri_web_proxies](#ri_web_proxies)|5828|5828|11|0.1%|1.6%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|11|0.0%|1.6%|
[proxyrss](#proxyrss)|1973|1973|9|0.4%|1.3%|
[stopforumspam_1d](#stopforumspam_1d)|7091|7091|7|0.0%|1.0%|
[ri_connect_proxies](#ri_connect_proxies)|2159|2159|6|0.2%|0.8%|
[proxz](#proxz)|586|586|3|0.5%|0.4%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|2|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|2|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.2%|
[et_block](#et_block)|1007|18338646|2|0.0%|0.2%|
[blocklist_de](#blocklist_de)|33154|33154|2|0.0%|0.2%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.1%|
[nixspam](#nixspam)|18241|18241|1|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|1|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3136|3136|1|0.0%|0.1%|
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
[et_block](#et_block)|1007|18338646|1041|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|1037|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1036|0.0%|0.3%|
[fullbogons](#fullbogons)|3686|670534424|890|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|289|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|48|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|26|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|26|2.0%|0.0%|
[et_tor](#et_tor)|6520|6520|21|0.3%|0.0%|
[dm_tor](#dm_tor)|6391|6391|21|0.3%|0.0%|
[bm_tor](#bm_tor)|6409|6409|21|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|19|1.3%|0.0%|
[nixspam](#nixspam)|18241|18241|15|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|14|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7091|7091|11|0.1%|0.0%|
[blocklist_de](#blocklist_de)|33154|33154|9|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5828|5828|5|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7653|7653|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|5|1.3%|0.0%|
[voipbl](#voipbl)|10367|10776|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3244|3244|4|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[malc0de](#malc0de)|392|392|3|0.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|10677|10677|3|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3136|3136|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13929|13929|3|0.0%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|
[et_compromised](#et_compromised)|2174|2174|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|2|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|114|114|2|1.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2596|2596|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[xroxy](#xroxy)|2041|2041|1|0.0%|0.0%|
[sslbl](#sslbl)|360|360|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|1|0.0%|0.0%|
[shunlist](#shunlist)|1276|1276|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1973|1973|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.0%|
[openbl_7d](#openbl_7d)|999|999|1|0.1%|0.0%|
[feodo](#feodo)|80|80|1|1.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|1|0.0%|0.0%|

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
[et_block](#et_block)|1007|18338646|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|3|0.2%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7653|7653|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|3244|3244|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7091|7091|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5828|5828|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|999|999|1|0.1%|0.0%|
[nixspam](#nixspam)|18241|18241|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_botcc](#et_botcc)|511|511|1|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|10677|10677|1|0.0%|0.0%|
[blocklist_de](#blocklist_de)|33154|33154|1|0.0%|0.0%|

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
[et_block](#et_block)|1007|18338646|4|0.0%|1.0%|
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
[et_block](#et_block)|1007|18338646|29|0.0%|2.2%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|27|0.3%|2.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|26|0.0%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|26|0.0%|2.0%|
[fullbogons](#fullbogons)|3686|670534424|9|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|6|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|4|0.0%|0.3%|
[malc0de](#malc0de)|392|392|4|1.0%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|3|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7091|7091|1|0.0%|0.0%|
[et_botcc](#et_botcc)|511|511|1|0.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|11|11|1|9.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|10677|10677|1|0.0%|0.0%|
[blocklist_de](#blocklist_de)|33154|33154|1|0.0%|0.0%|

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
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|196|0.6%|52.6%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|178|2.0%|47.8%|
[dm_tor](#dm_tor)|6391|6391|171|2.6%|45.9%|
[bm_tor](#bm_tor)|6409|6409|171|2.6%|45.9%|
[et_tor](#et_tor)|6520|6520|170|2.6%|45.6%|
[stopforumspam_1d](#stopforumspam_1d)|7091|7091|152|2.1%|40.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|125|0.0%|33.6%|
[php_commenters](#php_commenters)|281|281|28|9.9%|7.5%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|25|0.0%|6.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|21|0.0%|5.6%|
[openbl_60d](#openbl_60d)|7653|7653|18|0.2%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|17|0.0%|4.5%|
[php_harvesters](#php_harvesters)|257|257|6|2.3%|1.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|1.3%|
[ri_web_proxies](#ri_web_proxies)|5828|5828|4|0.0%|1.0%|
[php_spammers](#php_spammers)|417|417|4|0.9%|1.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|1.0%|
[shunlist](#shunlist)|1276|1276|2|0.1%|0.5%|
[xroxy](#xroxy)|2041|2041|1|0.0%|0.2%|
[voipbl](#voipbl)|10367|10776|1|0.0%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2159|2159|1|0.0%|0.2%|
[dshield](#dshield)|20|5120|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|1|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|13929|13929|1|0.0%|0.2%|
[blocklist_de](#blocklist_de)|33154|33154|1|0.0%|0.2%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Wed Jun  3 03:00:02 UTC 2015.

The ipset `nixspam` has **18241** entries, **18241** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|882|0.0%|4.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|549|0.0%|3.0%|
[blocklist_de](#blocklist_de)|33154|33154|476|1.4%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|379|0.0%|2.0%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|363|2.3%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|226|0.2%|1.2%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|215|2.4%|1.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|161|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|160|0.0%|0.8%|
[et_block](#et_block)|1007|18338646|160|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|139|0.4%|0.7%|
[ri_web_proxies](#ri_web_proxies)|5828|5828|88|1.5%|0.4%|
[xroxy](#xroxy)|2041|2041|74|3.6%|0.4%|
[php_dictionary](#php_dictionary)|433|433|71|16.3%|0.3%|
[php_spammers](#php_spammers)|417|417|57|13.6%|0.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|10677|10677|49|0.4%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7091|7091|46|0.6%|0.2%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|38|0.0%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3136|3136|32|1.0%|0.1%|
[proxz](#proxz)|586|586|27|4.6%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2596|2596|24|0.9%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13929|13929|24|0.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|15|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2159|2159|14|0.6%|0.0%|
[proxyrss](#proxyrss)|1973|1973|13|0.6%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|747|747|13|1.7%|0.0%|
[openbl_60d](#openbl_60d)|7653|7653|12|0.1%|0.0%|
[php_commenters](#php_commenters)|281|281|10|3.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|5|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1669|1669|5|0.2%|0.0%|
[php_harvesters](#php_harvesters)|257|257|4|1.5%|0.0%|
[openbl_30d](#openbl_30d)|3244|3244|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[et_tor](#et_tor)|6520|6520|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6391|6391|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6409|6409|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|1|0.5%|0.0%|

## openbl_1d

[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_1days.txt).

The last time downloaded was found to be dated: Wed Jun  3 02:32:00 UTC 2015.

The ipset `openbl_1d` has **309** entries, **309** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7653|7653|261|3.4%|84.4%|
[openbl_30d](#openbl_30d)|3244|3244|254|7.8%|82.2%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|254|0.1%|82.2%|
[openbl_7d](#openbl_7d)|999|999|249|24.9%|80.5%|
[blocklist_de](#blocklist_de)|33154|33154|219|0.6%|70.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|10677|10677|213|1.9%|68.9%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|80|3.6%|25.8%|
[et_compromised](#et_compromised)|2174|2174|78|3.5%|25.2%|
[shunlist](#shunlist)|1276|1276|77|6.0%|24.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|48|0.0%|15.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|18|10.2%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|14|0.0%|4.5%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|13|0.0%|4.2%|
[et_block](#et_block)|1007|18338646|13|0.0%|4.2%|
[dshield](#dshield)|20|5120|12|0.2%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|7|0.0%|2.2%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|5|0.0%|1.6%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|3|0.0%|0.9%|
[blocklist_de_imap](#blocklist_de_imap)|1669|1669|3|0.1%|0.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|13929|13929|1|0.0%|0.3%|

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
[et_compromised](#et_compromised)|2174|2174|1226|56.3%|37.7%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|1221|56.1%|37.6%|
[openbl_7d](#openbl_7d)|999|999|999|100.0%|30.7%|
[blocklist_de](#blocklist_de)|33154|33154|881|2.6%|27.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|10677|10677|832|7.7%|25.6%|
[shunlist](#shunlist)|1276|1276|588|46.0%|18.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|313|0.0%|9.6%|
[openbl_1d](#openbl_1d)|309|309|254|82.2%|7.8%|
[et_block](#et_block)|1007|18338646|179|0.0%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|177|0.0%|5.4%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|174|0.0%|5.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|73|0.0%|2.2%|
[dshield](#dshield)|20|5120|67|1.3%|2.0%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|45|0.2%|1.3%|
[blocklist_de_imap](#blocklist_de_imap)|1669|1669|36|2.1%|1.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|25|14.2%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|13|0.0%|0.4%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|6|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.1%|
[voipbl](#voipbl)|10367|10776|3|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|3|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|3|0.0%|0.0%|
[zeus](#zeus)|266|266|2|0.7%|0.0%|
[nixspam](#nixspam)|18241|18241|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|747|747|2|0.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13929|13929|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7091|7091|1|0.0%|0.0%|
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
[blocklist_de](#blocklist_de)|33154|33154|1687|5.0%|22.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|10677|10677|1628|15.2%|21.2%|
[et_compromised](#et_compromised)|2174|2174|1310|60.2%|17.1%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|1300|59.7%|16.9%|
[openbl_7d](#openbl_7d)|999|999|999|100.0%|13.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|744|0.0%|9.7%|
[shunlist](#shunlist)|1276|1276|605|47.4%|7.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|341|0.0%|4.4%|
[openbl_1d](#openbl_1d)|309|309|261|84.4%|3.4%|
[et_block](#et_block)|1007|18338646|244|0.0%|3.1%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|239|0.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|172|0.0%|2.2%|
[dshield](#dshield)|20|5120|76|1.4%|0.9%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|54|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|50|0.3%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|1669|1669|40|2.3%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|28|15.9%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|26|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|25|0.2%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7091|7091|22|0.3%|0.2%|
[et_tor](#et_tor)|6520|6520|21|0.3%|0.2%|
[dm_tor](#dm_tor)|6391|6391|21|0.3%|0.2%|
[bm_tor](#bm_tor)|6409|6409|21|0.3%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|18|0.0%|0.2%|
[nixspam](#nixspam)|18241|18241|12|0.0%|0.1%|
[voipbl](#voipbl)|10367|10776|9|0.0%|0.1%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|6|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3136|3136|5|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|747|747|3|0.4%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13929|13929|3|0.0%|0.0%|
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
[blocklist_de](#blocklist_de)|33154|33154|587|1.7%|58.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|10677|10677|561|5.2%|56.1%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|519|23.8%|51.9%|
[et_compromised](#et_compromised)|2174|2174|518|23.8%|51.8%|
[shunlist](#shunlist)|1276|1276|400|31.3%|40.0%|
[openbl_1d](#openbl_1d)|309|309|249|80.5%|24.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|117|0.0%|11.7%|
[et_block](#et_block)|1007|18338646|87|0.0%|8.7%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|85|0.0%|8.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|48|0.0%|4.8%|
[dshield](#dshield)|20|5120|42|0.8%|4.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|24|13.6%|2.4%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|24|0.1%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|21|0.0%|2.1%|
[blocklist_de_imap](#blocklist_de_imap)|1669|1669|17|1.0%|1.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|9|0.0%|0.9%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|5|0.0%|0.5%|
[voipbl](#voipbl)|10367|10776|3|0.0%|0.3%|
[zeus](#zeus)|266|266|1|0.3%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|1|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.1%|
[ciarmy](#ciarmy)|308|308|1|0.3%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|747|747|1|0.1%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13929|13929|1|0.0%|0.1%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Wed Jun  3 02:54:14 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|1007|18338646|13|0.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|11|0.1%|84.6%|
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
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|206|0.2%|73.3%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|151|0.4%|53.7%|
[stopforumspam_1d](#stopforumspam_1d)|7091|7091|106|1.4%|37.7%|
[blocklist_de](#blocklist_de)|33154|33154|62|0.1%|22.0%|
[blocklist_de_bots](#blocklist_de_bots)|3136|3136|49|1.5%|17.4%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|37|0.4%|13.1%|
[php_spammers](#php_spammers)|417|417|32|7.6%|11.3%|
[et_tor](#et_tor)|6520|6520|29|0.4%|10.3%|
[dm_tor](#dm_tor)|6391|6391|29|0.4%|10.3%|
[bm_tor](#bm_tor)|6409|6409|29|0.4%|10.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|29|16.4%|10.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|28|7.5%|9.9%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|24|0.0%|8.5%|
[et_block](#et_block)|1007|18338646|24|0.0%|8.5%|
[blocklist_de_apache](#blocklist_de_apache)|13929|13929|23|0.1%|8.1%|
[php_dictionary](#php_dictionary)|433|433|22|5.0%|7.8%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|20|0.1%|7.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|5.3%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|14|0.0%|4.9%|
[ri_web_proxies](#ri_web_proxies)|5828|5828|11|0.1%|3.9%|
[nixspam](#nixspam)|18241|18241|10|0.0%|3.5%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.2%|
[openbl_60d](#openbl_60d)|7653|7653|8|0.1%|2.8%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|7|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|1.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2596|2596|5|0.1%|1.7%|
[xroxy](#xroxy)|2041|2041|3|0.1%|1.0%|
[proxz](#proxz)|586|586|3|0.5%|1.0%|
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
[nixspam](#nixspam)|18241|18241|71|0.3%|16.3%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|65|0.2%|15.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|63|0.7%|14.5%|
[blocklist_de](#blocklist_de)|33154|33154|53|0.1%|12.2%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|40|0.2%|9.2%|
[ri_web_proxies](#ri_web_proxies)|5828|5828|33|0.5%|7.6%|
[xroxy](#xroxy)|2041|2041|24|1.1%|5.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|24|0.0%|5.5%|
[php_commenters](#php_commenters)|281|281|22|7.8%|5.0%|
[stopforumspam_1d](#stopforumspam_1d)|7091|7091|20|0.2%|4.6%|
[blocklist_de_bots](#blocklist_de_bots)|3136|3136|11|0.3%|2.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|10|0.0%|2.3%|
[proxz](#proxz)|586|586|9|1.5%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|9|0.0%|2.0%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|7|0.0%|1.6%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|4|0.0%|0.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.9%|
[et_tor](#et_tor)|6520|6520|4|0.0%|0.9%|
[et_block](#et_block)|1007|18338646|4|0.0%|0.9%|
[dm_tor](#dm_tor)|6391|6391|4|0.0%|0.9%|
[bm_tor](#bm_tor)|6409|6409|4|0.0%|0.9%|
[ri_connect_proxies](#ri_connect_proxies)|2159|2159|3|0.1%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|2|1.1%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2596|2596|2|0.0%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|13929|13929|2|0.0%|0.4%|
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
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|48|0.1%|18.6%|
[stopforumspam_1d](#stopforumspam_1d)|7091|7091|32|0.4%|12.4%|
[blocklist_de](#blocklist_de)|33154|33154|25|0.0%|9.7%|
[blocklist_de_bots](#blocklist_de_bots)|3136|3136|19|0.6%|7.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|5.8%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|9|0.1%|3.5%|
[php_commenters](#php_commenters)|281|281|9|3.2%|3.5%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|9|0.0%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|7|0.0%|2.7%|
[et_tor](#et_tor)|6520|6520|7|0.1%|2.7%|
[dm_tor](#dm_tor)|6391|6391|7|0.1%|2.7%|
[bm_tor](#bm_tor)|6409|6409|7|0.1%|2.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|6|1.6%|2.3%|
[blocklist_de_ftp](#blocklist_de_ftp)|747|747|5|0.6%|1.9%|
[nixspam](#nixspam)|18241|18241|4|0.0%|1.5%|
[xroxy](#xroxy)|2041|2041|2|0.0%|0.7%|
[openbl_60d](#openbl_60d)|7653|7653|2|0.0%|0.7%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|2|1.1%|0.7%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|1|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|1|0.0%|0.3%|
[ri_web_proxies](#ri_web_proxies)|5828|5828|1|0.0%|0.3%|
[proxyrss](#proxyrss)|1973|1973|1|0.0%|0.3%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.3%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|
[fullbogons](#fullbogons)|3686|670534424|1|0.0%|0.3%|
[et_block](#et_block)|1007|18338646|1|0.0%|0.3%|
[bogons](#bogons)|13|592708608|1|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|1|0.0%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|13929|13929|1|0.0%|0.3%|

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
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|61|0.1%|14.6%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|59|0.6%|14.1%|
[nixspam](#nixspam)|18241|18241|57|0.3%|13.6%|
[blocklist_de](#blocklist_de)|33154|33154|47|0.1%|11.2%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|33|0.2%|7.9%|
[php_commenters](#php_commenters)|281|281|32|11.3%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|31|0.0%|7.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|26|0.0%|6.2%|
[ri_web_proxies](#ri_web_proxies)|5828|5828|25|0.4%|5.9%|
[xroxy](#xroxy)|2041|2041|20|0.9%|4.7%|
[stopforumspam_1d](#stopforumspam_1d)|7091|7091|18|0.2%|4.3%|
[blocklist_de_bots](#blocklist_de_bots)|3136|3136|10|0.3%|2.3%|
[proxz](#proxz)|586|586|9|1.5%|2.1%|
[et_tor](#et_tor)|6520|6520|6|0.0%|1.4%|
[dm_tor](#dm_tor)|6391|6391|6|0.0%|1.4%|
[bm_tor](#bm_tor)|6409|6409|6|0.0%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|1.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.9%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2596|2596|4|0.1%|0.9%|
[blocklist_de_apache](#blocklist_de_apache)|13929|13929|4|0.0%|0.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|3|1.7%|0.7%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|3|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|2|0.0%|0.4%|
[ri_connect_proxies](#ri_connect_proxies)|2159|2159|2|0.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[et_block](#et_block)|1007|18338646|2|0.0%|0.4%|
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
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|814|2.6%|41.2%|
[ri_web_proxies](#ri_web_proxies)|5828|5828|712|12.2%|36.0%|
[stopforumspam_1d](#stopforumspam_1d)|7091|7091|509|7.1%|25.7%|
[xroxy](#xroxy)|2041|2041|480|23.5%|24.3%|
[ri_connect_proxies](#ri_connect_proxies)|2159|2159|274|12.6%|13.8%|
[blocklist_de](#blocklist_de)|33154|33154|237|0.7%|12.0%|
[blocklist_de_bots](#blocklist_de_bots)|3136|3136|234|7.4%|11.8%|
[proxz](#proxz)|586|586|205|34.9%|10.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|70|0.0%|3.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|68|0.0%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|38|0.0%|1.9%|
[nixspam](#nixspam)|18241|18241|13|0.0%|0.6%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|9|1.3%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|7|3.9%|0.3%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|4|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|10677|10677|2|0.0%|0.1%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.0%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_tor](#et_tor)|6520|6520|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2174|2174|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6391|6391|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6409|6409|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|1|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Wed Jun  3 02:21:45 UTC 2015.

The ipset `proxz` has **586** entries, **586** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|361|0.3%|61.6%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|306|0.9%|52.2%|
[xroxy](#xroxy)|2041|2041|263|12.8%|44.8%|
[ri_web_proxies](#ri_web_proxies)|5828|5828|254|4.3%|43.3%|
[proxyrss](#proxyrss)|1973|1973|205|10.3%|34.9%|
[stopforumspam_1d](#stopforumspam_1d)|7091|7091|137|1.9%|23.3%|
[blocklist_de](#blocklist_de)|33154|33154|112|0.3%|19.1%|
[blocklist_de_bots](#blocklist_de_bots)|3136|3136|93|2.9%|15.8%|
[ri_connect_proxies](#ri_connect_proxies)|2159|2159|85|3.9%|14.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|53|0.0%|9.0%|
[nixspam](#nixspam)|18241|18241|27|0.1%|4.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|27|0.0%|4.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|24|0.0%|4.0%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|17|0.1%|2.9%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|15|0.1%|2.5%|
[php_spammers](#php_spammers)|417|417|9|2.1%|1.5%|
[php_dictionary](#php_dictionary)|433|433|9|2.0%|1.5%|
[php_commenters](#php_commenters)|281|281|3|1.0%|0.5%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|3|0.4%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|3|1.7%|0.5%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|3|0.0%|0.5%|
[et_compromised](#et_compromised)|2174|2174|2|0.0%|0.3%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|2|0.0%|0.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|10677|10677|2|0.0%|0.3%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.1%|
[et_block](#et_block)|1007|18338646|1|0.0%|0.1%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Wed Jun  3 01:10:35 UTC 2015.

The ipset `ri_connect_proxies` has **2159** entries, **2159** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|1273|1.3%|58.9%|
[ri_web_proxies](#ri_web_proxies)|5828|5828|885|15.1%|40.9%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|679|2.1%|31.4%|
[xroxy](#xroxy)|2041|2041|333|16.3%|15.4%|
[proxyrss](#proxyrss)|1973|1973|274|13.8%|12.6%|
[stopforumspam_1d](#stopforumspam_1d)|7091|7091|163|2.2%|7.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|88|0.0%|4.0%|
[proxz](#proxz)|586|586|85|14.5%|3.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|71|0.0%|3.2%|
[blocklist_de](#blocklist_de)|33154|33154|67|0.2%|3.1%|
[blocklist_de_bots](#blocklist_de_bots)|3136|3136|65|2.0%|3.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|48|0.0%|2.2%|
[nixspam](#nixspam)|18241|18241|14|0.0%|0.6%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.2%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|4|0.0%|0.1%|
[php_dictionary](#php_dictionary)|433|433|3|0.6%|0.1%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[et_tor](#et_tor)|6520|6520|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6391|6391|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6409|6409|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|10677|10677|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Wed Jun  3 01:10:28 UTC 2015.

The ipset `ri_web_proxies` has **5828** entries, **5828** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|2875|3.1%|49.3%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|1703|5.4%|29.2%|
[ri_connect_proxies](#ri_connect_proxies)|2159|2159|885|40.9%|15.1%|
[xroxy](#xroxy)|2041|2041|852|41.7%|14.6%|
[proxyrss](#proxyrss)|1973|1973|712|36.0%|12.2%|
[stopforumspam_1d](#stopforumspam_1d)|7091|7091|538|7.5%|9.2%|
[blocklist_de](#blocklist_de)|33154|33154|356|1.0%|6.1%|
[blocklist_de_bots](#blocklist_de_bots)|3136|3136|311|9.9%|5.3%|
[proxz](#proxz)|586|586|254|43.3%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|177|0.0%|3.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|163|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|123|0.0%|2.1%|
[nixspam](#nixspam)|18241|18241|88|0.4%|1.5%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|59|0.6%|1.0%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|43|0.2%|0.7%|
[php_dictionary](#php_dictionary)|433|433|33|7.6%|0.5%|
[php_spammers](#php_spammers)|417|417|25|5.9%|0.4%|
[php_commenters](#php_commenters)|281|281|11|3.9%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|5|2.8%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.0%|
[et_tor](#et_tor)|6520|6520|3|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6391|6391|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6409|6409|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Wed Jun  3 02:30:03 UTC 2015.

The ipset `shunlist` has **1276** entries, **1276** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|174882|174882|1265|0.7%|99.1%|
[openbl_60d](#openbl_60d)|7653|7653|605|7.9%|47.4%|
[openbl_30d](#openbl_30d)|3244|3244|588|18.1%|46.0%|
[et_compromised](#et_compromised)|2174|2174|509|23.4%|39.8%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|508|23.3%|39.8%|
[blocklist_de](#blocklist_de)|33154|33154|421|1.2%|32.9%|
[openbl_7d](#openbl_7d)|999|999|400|40.0%|31.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|10677|10677|382|3.5%|29.9%|
[et_block](#et_block)|1007|18338646|105|0.0%|8.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|103|0.0%|8.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|99|0.0%|7.7%|
[openbl_1d](#openbl_1d)|309|309|77|24.9%|6.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|70|0.0%|5.4%|
[sslbl](#sslbl)|360|360|55|15.2%|4.3%|
[dshield](#dshield)|20|5120|40|0.7%|3.1%|
[blocklist_de_apache](#blocklist_de_apache)|13929|13929|33|0.2%|2.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|25|0.0%|1.9%|
[ciarmy](#ciarmy)|308|308|24|7.7%|1.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|20|11.3%|1.5%|
[voipbl](#voipbl)|10367|10776|12|0.1%|0.9%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|5|0.0%|0.3%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|5|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|5|0.0%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|4|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|4|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|1669|1669|3|0.1%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7091|7091|2|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_tor](#et_tor)|6520|6520|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6391|6391|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6409|6409|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|747|747|1|0.1%|0.0%|
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
[et_tor](#et_tor)|6520|6520|1112|17.0%|12.5%|
[bm_tor](#bm_tor)|6409|6409|1076|16.7%|12.1%|
[dm_tor](#dm_tor)|6391|6391|1072|16.7%|12.0%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|814|0.8%|9.1%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|618|1.9%|6.9%|
[stopforumspam_1d](#stopforumspam_1d)|7091|7091|325|4.5%|3.6%|
[et_block](#et_block)|1007|18338646|305|0.0%|3.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|246|0.0%|2.7%|
[zeus](#zeus)|266|266|227|85.3%|2.5%|
[nixspam](#nixspam)|18241|18241|215|1.1%|2.4%|
[zeus_badips](#zeus_badips)|230|230|202|87.8%|2.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|178|47.8%|2.0%|
[blocklist_de](#blocklist_de)|33154|33154|167|0.5%|1.8%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|136|0.8%|1.5%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|119|0.0%|1.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|116|0.0%|1.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|93|0.0%|1.0%|
[feodo](#feodo)|80|80|64|80.0%|0.7%|
[php_dictionary](#php_dictionary)|433|433|63|14.5%|0.7%|
[ri_web_proxies](#ri_web_proxies)|5828|5828|59|1.0%|0.6%|
[php_spammers](#php_spammers)|417|417|59|14.1%|0.6%|
[xroxy](#xroxy)|2041|2041|50|2.4%|0.5%|
[php_commenters](#php_commenters)|281|281|37|13.1%|0.4%|
[sslbl](#sslbl)|360|360|27|7.5%|0.3%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|27|2.1%|0.3%|
[openbl_60d](#openbl_60d)|7653|7653|25|0.3%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3136|3136|23|0.7%|0.2%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|20|0.0%|0.2%|
[proxz](#proxz)|586|586|15|2.5%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|14|0.0%|0.1%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13929|13929|9|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|6|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2596|2596|6|0.2%|0.0%|
[shunlist](#shunlist)|1276|1276|4|0.3%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2159|2159|4|0.1%|0.0%|
[proxyrss](#proxyrss)|1973|1973|4|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1669|1669|4|0.2%|0.0%|
[openbl_30d](#openbl_30d)|3244|3244|3|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_compromised](#et_compromised)|2174|2174|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|10677|10677|2|0.0%|0.0%|
[openbl_7d](#openbl_7d)|999|999|1|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|1|0.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|747|747|1|0.1%|0.0%|

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
[et_block](#et_block)|1007|18338646|18333440|99.9%|98.5%|
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
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|343|1.1%|0.0%|
[openbl_60d](#openbl_60d)|7653|7653|239|3.1%|0.0%|
[openbl_30d](#openbl_30d)|3244|3244|174|5.3%|0.0%|
[nixspam](#nixspam)|18241|18241|160|0.8%|0.0%|
[blocklist_de](#blocklist_de)|33154|33154|160|0.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|10677|10677|112|1.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7091|7091|103|1.4%|0.0%|
[et_compromised](#et_compromised)|2174|2174|101|4.6%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|100|4.5%|0.0%|
[shunlist](#shunlist)|1276|1276|99|7.7%|0.0%|
[openbl_7d](#openbl_7d)|999|999|85|8.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|29|2.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|26|0.1%|0.0%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|20|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3136|3136|19|0.6%|0.0%|
[zeus_badips](#zeus_badips)|230|230|16|6.9%|0.0%|
[zeus](#zeus)|266|266|16|6.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1669|1669|16|0.9%|0.0%|
[voipbl](#voipbl)|10367|10776|14|0.1%|0.0%|
[openbl_1d](#openbl_1d)|309|309|13|4.2%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|7|3.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[malc0de](#malc0de)|392|392|4|1.0%|0.0%|
[sslbl](#sslbl)|360|360|3|0.8%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6520|6520|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6391|6391|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6409|6409|2|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2596|2596|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13929|13929|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[et_botcc](#et_botcc)|511|511|1|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|114|114|1|0.8%|0.0%|

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
[et_block](#et_block)|1007|18338646|517|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|512|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|271|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|98|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|23|0.0%|0.0%|
[blocklist_de](#blocklist_de)|33154|33154|13|0.0%|0.0%|
[php_commenters](#php_commenters)|281|281|7|2.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|6|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7653|7653|6|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3244|3244|6|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|6|3.4%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3136|3136|6|0.1%|0.0%|
[zeus_badips](#zeus_badips)|230|230|5|2.1%|0.0%|
[zeus](#zeus)|266|266|5|1.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7091|7091|5|0.0%|0.0%|
[shunlist](#shunlist)|1276|1276|5|0.3%|0.0%|
[openbl_7d](#openbl_7d)|999|999|5|0.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|4|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|10677|10677|2|0.0%|0.0%|
[virbl](#virbl)|13|13|1|7.6%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[malc0de](#malc0de)|392|392|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13929|13929|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Wed Jun  3 02:45:07 UTC 2015.

The ipset `sslbl` has **360** entries, **360** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|174882|174882|63|0.0%|17.5%|
[shunlist](#shunlist)|1276|1276|55|4.3%|15.2%|
[et_block](#et_block)|1007|18338646|34|0.0%|9.4%|
[feodo](#feodo)|80|80|31|38.7%|8.6%|
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

The last time downloaded was found to be dated: Wed Jun  3 03:00:02 UTC 2015.

The ipset `stopforumspam_1d` has **7091** entries, **7091** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|6992|22.5%|98.6%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|6844|7.3%|96.5%|
[blocklist_de](#blocklist_de)|33154|33154|1414|4.2%|19.9%|
[blocklist_de_bots](#blocklist_de_bots)|3136|3136|1361|43.3%|19.1%|
[ri_web_proxies](#ri_web_proxies)|5828|5828|538|9.2%|7.5%|
[proxyrss](#proxyrss)|1973|1973|509|25.7%|7.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|484|0.0%|6.8%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|325|3.6%|4.5%|
[xroxy](#xroxy)|2041|2041|322|15.7%|4.5%|
[et_tor](#et_tor)|6520|6520|289|4.4%|4.0%|
[bm_tor](#bm_tor)|6409|6409|289|4.5%|4.0%|
[dm_tor](#dm_tor)|6391|6391|288|4.5%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|260|0.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|171|0.0%|2.4%|
[ri_connect_proxies](#ri_connect_proxies)|2159|2159|163|7.5%|2.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|152|40.8%|2.1%|
[proxz](#proxz)|586|586|137|23.3%|1.9%|
[php_commenters](#php_commenters)|281|281|106|37.7%|1.4%|
[et_block](#et_block)|1007|18338646|104|0.0%|1.4%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|103|0.0%|1.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|103|58.5%|1.4%|
[blocklist_de_apache](#blocklist_de_apache)|13929|13929|61|0.4%|0.8%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|55|0.0%|0.7%|
[nixspam](#nixspam)|18241|18241|46|0.2%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|44|0.2%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|37|0.0%|0.5%|
[php_harvesters](#php_harvesters)|257|257|32|12.4%|0.4%|
[openbl_60d](#openbl_60d)|7653|7653|22|0.2%|0.3%|
[php_dictionary](#php_dictionary)|433|433|20|4.6%|0.2%|
[php_spammers](#php_spammers)|417|417|18|4.3%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2596|2596|18|0.6%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|11|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|7|1.0%|0.0%|
[voipbl](#voipbl)|10367|10776|5|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|5|0.0%|0.0%|
[shunlist](#shunlist)|1276|1276|2|0.1%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|747|747|2|0.2%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3244|3244|1|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2174|2174|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|10677|10677|1|0.0%|0.0%|

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
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|30866|99.4%|33.3%|
[stopforumspam_1d](#stopforumspam_1d)|7091|7091|6844|96.5%|7.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|5884|0.0%|6.3%|
[ri_web_proxies](#ri_web_proxies)|5828|5828|2875|49.3%|3.1%|
[blocklist_de](#blocklist_de)|33154|33154|2620|7.9%|2.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2510|0.0%|2.7%|
[blocklist_de_bots](#blocklist_de_bots)|3136|3136|2247|71.6%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1545|0.0%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|2159|2159|1273|58.9%|1.3%|
[xroxy](#xroxy)|2041|2041|1200|58.7%|1.2%|
[et_block](#et_block)|1007|18338646|1002|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|998|0.0%|1.0%|
[proxyrss](#proxyrss)|1973|1973|974|49.3%|1.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|814|9.1%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|737|0.0%|0.7%|
[et_tor](#et_tor)|6520|6520|643|9.8%|0.6%|
[bm_tor](#bm_tor)|6409|6409|631|9.8%|0.6%|
[dm_tor](#dm_tor)|6391|6391|630|9.8%|0.6%|
[proxz](#proxz)|586|586|361|61.6%|0.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|232|62.3%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|227|1.4%|0.2%|
[nixspam](#nixspam)|18241|18241|226|1.2%|0.2%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|215|0.1%|0.2%|
[php_commenters](#php_commenters)|281|281|206|73.3%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|13929|13929|202|1.4%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|131|74.4%|0.1%|
[php_spammers](#php_spammers)|417|417|100|23.9%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|98|0.0%|0.1%|
[php_dictionary](#php_dictionary)|433|433|85|19.6%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|10677|10677|81|0.7%|0.0%|
[php_harvesters](#php_harvesters)|257|257|62|24.1%|0.0%|
[openbl_60d](#openbl_60d)|7653|7653|54|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|48|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2596|2596|42|1.6%|0.0%|
[voipbl](#voipbl)|10367|10776|39|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|22|3.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|15|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|747|747|11|1.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|10|0.4%|0.0%|
[et_compromised](#et_compromised)|2174|2174|8|0.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1669|1669|6|0.3%|0.0%|
[shunlist](#shunlist)|1276|1276|5|0.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|4|0.3%|0.0%|
[zeus_badips](#zeus_badips)|230|230|3|1.3%|0.0%|
[zeus](#zeus)|266|266|3|1.1%|0.0%|
[openbl_30d](#openbl_30d)|3244|3244|3|0.0%|0.0%|
[openbl_1d](#openbl_1d)|309|309|3|0.9%|0.0%|
[dshield](#dshield)|20|5120|3|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3686|670534424|2|0.0%|0.0%|
[sslbl](#sslbl)|360|360|1|0.2%|0.0%|
[openbl_7d](#openbl_7d)|999|999|1|0.1%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|

## stopforumspam_7d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip).

The last time downloaded was found to be dated: Wed Jun  3 02:00:09 UTC 2015.

The ipset `stopforumspam_7d` has **31033** entries, **31033** unique IPs.

The following table shows the overlaps of `stopforumspam_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_7d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|30866|33.3%|99.4%|
[stopforumspam_1d](#stopforumspam_1d)|7091|7091|6992|98.6%|22.5%|
[blocklist_de](#blocklist_de)|33154|33154|2305|6.9%|7.4%|
[blocklist_de_bots](#blocklist_de_bots)|3136|3136|2106|67.1%|6.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2017|0.0%|6.4%|
[ri_web_proxies](#ri_web_proxies)|5828|5828|1703|29.2%|5.4%|
[xroxy](#xroxy)|2041|2041|963|47.1%|3.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|940|0.0%|3.0%|
[proxyrss](#proxyrss)|1973|1973|814|41.2%|2.6%|
[ri_connect_proxies](#ri_connect_proxies)|2159|2159|679|31.4%|2.1%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|618|6.9%|1.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|581|0.0%|1.8%|
[et_tor](#et_tor)|6520|6520|492|7.5%|1.5%|
[bm_tor](#bm_tor)|6409|6409|482|7.5%|1.5%|
[dm_tor](#dm_tor)|6391|6391|481|7.5%|1.5%|
[et_block](#et_block)|1007|18338646|345|0.0%|1.1%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|343|0.0%|1.1%|
[proxz](#proxz)|586|586|306|52.2%|0.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|196|52.6%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|174|0.0%|0.5%|
[php_commenters](#php_commenters)|281|281|151|53.7%|0.4%|
[nixspam](#nixspam)|18241|18241|139|0.7%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|137|0.8%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|13929|13929|123|0.8%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|121|68.7%|0.3%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|102|0.0%|0.3%|
[php_dictionary](#php_dictionary)|433|433|65|15.0%|0.2%|
[php_spammers](#php_spammers)|417|417|61|14.6%|0.1%|
[php_harvesters](#php_harvesters)|257|257|48|18.6%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2596|2596|31|1.1%|0.0%|
[openbl_60d](#openbl_60d)|7653|7653|26|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|26|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|23|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|10677|10677|14|0.1%|0.0%|
[voipbl](#voipbl)|10367|10776|13|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|12|1.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|7|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|6|0.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|747|747|6|0.8%|0.0%|
[et_compromised](#et_compromised)|2174|2174|5|0.2%|0.0%|
[shunlist](#shunlist)|1276|1276|4|0.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|3|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1669|1669|3|0.1%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3244|3244|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## virbl

[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.

Source is downloaded from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt).

The last time downloaded was found to be dated: Wed Jun  3 02:42:04 UTC 2015.

The ipset `virbl` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `virbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `virbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `virbl`.
- ` this % ` is the percentage **of this ipset (`virbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|1|0.0%|7.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1|0.0%|7.6%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|1|0.0%|7.6%|
[blocklist_de](#blocklist_de)|33154|33154|1|0.0%|7.6%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Wed Jun  3 02:18:34 UTC 2015.

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
[blocklist_de](#blocklist_de)|33154|33154|42|0.1%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|39|0.0%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|114|114|32|28.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|14|0.0%|0.1%|
[et_block](#et_block)|1007|18338646|14|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|13|0.0%|0.1%|
[shunlist](#shunlist)|1276|1276|12|0.9%|0.1%|
[openbl_60d](#openbl_60d)|7653|7653|9|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7091|7091|5|0.0%|0.0%|
[ciarmy](#ciarmy)|308|308|5|1.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13929|13929|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[openbl_7d](#openbl_7d)|999|999|3|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3244|3244|3|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[et_tor](#et_tor)|6520|6520|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6391|6391|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6409|6409|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|10677|10677|2|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2596|2596|2|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3136|3136|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2174|2174|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1669|1669|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Wed Jun  3 02:33:01 UTC 2015.

The ipset `xroxy` has **2041** entries, **2041** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|1200|1.2%|58.7%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|963|3.1%|47.1%|
[ri_web_proxies](#ri_web_proxies)|5828|5828|852|14.6%|41.7%|
[proxyrss](#proxyrss)|1973|1973|480|24.3%|23.5%|
[ri_connect_proxies](#ri_connect_proxies)|2159|2159|333|15.4%|16.3%|
[stopforumspam_1d](#stopforumspam_1d)|7091|7091|322|4.5%|15.7%|
[proxz](#proxz)|586|586|263|44.8%|12.8%|
[blocklist_de](#blocklist_de)|33154|33154|238|0.7%|11.6%|
[blocklist_de_bots](#blocklist_de_bots)|3136|3136|195|6.2%|9.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|99|0.0%|4.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|87|0.0%|4.2%|
[nixspam](#nixspam)|18241|18241|74|0.4%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|57|0.0%|2.7%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|50|0.5%|2.4%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|40|0.2%|1.9%|
[php_dictionary](#php_dictionary)|433|433|24|5.5%|1.1%|
[php_spammers](#php_spammers)|417|417|20|4.7%|0.9%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|13|1.9%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|176|176|7|3.9%|0.3%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|5|0.0%|0.2%|
[php_commenters](#php_commenters)|281|281|3|1.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[et_tor](#et_tor)|6520|6520|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6391|6391|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6409|6409|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|10677|10677|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2174|2174|1|0.0%|0.0%|
[et_block](#et_block)|1007|18338646|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|1|0.0%|0.0%|

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
[et_block](#et_block)|1007|18338646|263|0.0%|98.8%|
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
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|1|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7091|7091|1|0.0%|0.3%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.3%|
[openbl_7d](#openbl_7d)|999|999|1|0.1%|0.3%|
[nixspam](#nixspam)|18241|18241|1|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|
[et_compromised](#et_compromised)|2174|2174|1|0.0%|0.3%|
[dshield](#dshield)|20|5120|1|0.0%|0.3%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|1|0.0%|0.3%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Wed Jun  3 02:54:12 UTC 2015.

The ipset `zeus_badips` has **230** entries, **230** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|266|266|230|86.4%|100.0%|
[et_block](#et_block)|1007|18338646|230|0.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|202|2.2%|87.8%|
[alienvault_reputation](#alienvault_reputation)|174882|174882|37|0.0%|16.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|16|0.0%|6.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8|0.0%|3.4%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|5|0.0%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4|0.0%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|3|0.0%|1.3%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|7091|7091|1|0.0%|0.4%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.4%|
[openbl_60d](#openbl_60d)|7653|7653|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|3244|3244|1|0.0%|0.4%|
[nixspam](#nixspam)|18241|18241|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.4%|
[et_compromised](#et_compromised)|2174|2174|1|0.0%|0.4%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|1|0.0%|0.4%|
