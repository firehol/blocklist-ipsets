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

The following list was automatically generated on Tue Jun  2 15:37:33 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|177988 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|25681 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|13962 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|3204 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|2566 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|561 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|987 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|15029 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|107 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|3843 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|168 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6505 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|2181 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|331 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|356 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6480 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
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
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|25790 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|166 unique IPs|updated every 1 hour  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|3179 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7586 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|912 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|12 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|281 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|433 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|257 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|417 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1573 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|546 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2116 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|5720 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1301 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|9012 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|656 subnets, 18600704 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|57 subnets, 487168 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|362 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|7053 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|92372 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|31339 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
[virbl](#virbl)|[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.|ipv4 hash:ip|18 unique IPs|updated every 1 hour  from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10350 subnets, 10759 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2032 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|266 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|230 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Tue Jun  2 10:00:45 UTC 2015.

The ipset `alienvault_reputation` has **177988** entries, **177988** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14369|0.0%|8.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7621|0.0%|4.2%|
[openbl_60d](#openbl_60d)|7586|7586|7549|99.5%|4.2%|
[et_block](#et_block)|997|18338381|5284|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4658|0.0%|2.6%|
[dshield](#dshield)|20|5120|3842|75.0%|2.1%|
[openbl_30d](#openbl_30d)|3179|3179|3148|99.0%|1.7%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|1628|0.0%|0.9%|
[et_compromised](#et_compromised)|2191|2191|1423|64.9%|0.7%|
[bruteforceblocker](#bruteforceblocker)|2181|2181|1405|64.4%|0.7%|
[blocklist_de](#blocklist_de)|25681|25681|1324|5.1%|0.7%|
[shunlist](#shunlist)|1301|1301|1290|99.1%|0.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|3843|3843|1077|28.0%|0.6%|
[openbl_7d](#openbl_7d)|912|912|889|97.4%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|518|0.0%|0.2%|
[ciarmy](#ciarmy)|331|331|315|95.1%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|288|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|271|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|214|0.2%|0.1%|
[voipbl](#voipbl)|10350|10759|209|1.9%|0.1%|
[openbl_1d](#openbl_1d)|166|166|132|79.5%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|121|1.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13962|13962|110|0.7%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|100|0.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15029|15029|77|0.5%|0.0%|
[zeus](#zeus)|266|266|66|24.8%|0.0%|
[sslbl](#sslbl)|362|362|63|17.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7053|7053|57|0.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|987|987|54|5.4%|0.0%|
[dm_tor](#dm_tor)|6480|6480|46|0.7%|0.0%|
[bm_tor](#bm_tor)|6505|6505|46|0.7%|0.0%|
[et_tor](#et_tor)|6360|6360|45|0.7%|0.0%|
[zeus_badips](#zeus_badips)|230|230|37|16.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|37|22.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3204|3204|34|1.0%|0.0%|
[nixspam](#nixspam)|25790|25790|32|0.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|25|6.7%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|107|107|18|16.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|15|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2566|2566|15|0.5%|0.0%|
[php_commenters](#php_commenters)|281|281|13|4.6%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|356|356|13|3.6%|0.0%|
[malc0de](#malc0de)|392|392|12|3.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|8|3.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|8|0.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|561|561|8|1.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|7|1.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|6|0.4%|0.0%|
[xroxy](#xroxy)|2032|2032|5|0.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5720|5720|3|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|3|0.7%|0.0%|
[et_botcc](#et_botcc)|505|505|3|0.5%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2116|2116|2|0.0%|0.0%|
[proxz](#proxz)|546|546|2|0.3%|0.0%|
[proxyrss](#proxyrss)|1573|1573|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[feodo](#feodo)|80|80|1|1.2%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Tue Jun  2 15:14:03 UTC 2015.

The ipset `blocklist_de` has **25681** entries, **25681** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|15029|15029|15029|100.0%|58.5%|
[blocklist_de_apache](#blocklist_de_apache)|13962|13962|13961|99.9%|54.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|3843|3843|3843|100.0%|14.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|3684|0.0%|14.3%|
[blocklist_de_bots](#blocklist_de_bots)|3204|3204|3204|100.0%|12.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2566|2566|2566|100.0%|9.9%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|2318|2.5%|9.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|2035|6.4%|7.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1488|0.0%|5.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1453|0.0%|5.6%|
[stopforumspam_1d](#stopforumspam_1d)|7053|7053|1416|20.0%|5.5%|
[alienvault_reputation](#alienvault_reputation)|177988|177988|1324|0.7%|5.1%|
[openbl_60d](#openbl_60d)|7586|7586|1030|13.5%|4.0%|
[blocklist_de_imap](#blocklist_de_imap)|987|987|981|99.3%|3.8%|
[openbl_30d](#openbl_30d)|3179|3179|780|24.5%|3.0%|
[bruteforceblocker](#bruteforceblocker)|2181|2181|723|33.1%|2.8%|
[et_compromised](#et_compromised)|2191|2191|687|31.3%|2.6%|
[nixspam](#nixspam)|25790|25790|626|2.4%|2.4%|
[blocklist_de_ftp](#blocklist_de_ftp)|561|561|561|100.0%|2.1%|
[openbl_7d](#openbl_7d)|912|912|520|57.0%|2.0%|
[shunlist](#shunlist)|1301|1301|416|31.9%|1.6%|
[ri_web_proxies](#ri_web_proxies)|5720|5720|357|6.2%|1.3%|
[xroxy](#xroxy)|2032|2032|229|11.2%|0.8%|
[proxyrss](#proxyrss)|1573|1573|225|14.3%|0.8%|
[et_block](#et_block)|997|18338381|168|0.0%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|168|100.0%|0.6%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|161|0.0%|0.6%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|154|1.7%|0.5%|
[openbl_1d](#openbl_1d)|166|166|123|74.0%|0.4%|
[proxz](#proxz)|546|546|107|19.5%|0.4%|
[blocklist_de_sip](#blocklist_de_sip)|107|107|88|82.2%|0.3%|
[ri_connect_proxies](#ri_connect_proxies)|2116|2116|67|3.1%|0.2%|
[php_commenters](#php_commenters)|281|281|59|20.9%|0.2%|
[dshield](#dshield)|20|5120|59|1.1%|0.2%|
[php_dictionary](#php_dictionary)|433|433|50|11.5%|0.1%|
[php_spammers](#php_spammers)|417|417|45|10.7%|0.1%|
[voipbl](#voipbl)|10350|10759|38|0.3%|0.1%|
[ciarmy](#ciarmy)|331|331|32|9.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|28|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|26|10.1%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|11|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|8|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[et_tor](#et_tor)|6360|6360|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6480|6480|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6505|6505|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[virbl](#virbl)|18|18|1|5.5%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Tue Jun  2 15:28:08 UTC 2015.

The ipset `blocklist_de_apache` has **13962** entries, **13962** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|25681|25681|13961|54.3%|99.9%|
[blocklist_de_mail](#blocklist_de_mail)|15029|15029|11059|73.5%|79.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2566|2566|2564|99.9%|18.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2252|0.0%|16.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1323|0.0%|9.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1071|0.0%|7.6%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|198|0.2%|1.4%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|125|0.3%|0.8%|
[alienvault_reputation](#alienvault_reputation)|177988|177988|110|0.0%|0.7%|
[stopforumspam_1d](#stopforumspam_1d)|7053|7053|63|0.8%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|36|21.4%|0.2%|
[nixspam](#nixspam)|25790|25790|31|0.1%|0.2%|
[ciarmy](#ciarmy)|331|331|28|8.4%|0.2%|
[shunlist](#shunlist)|1301|1301|26|1.9%|0.1%|
[php_commenters](#php_commenters)|281|281|23|8.1%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3204|3204|21|0.6%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|10|0.1%|0.0%|
[voipbl](#voipbl)|10350|10759|5|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.0%|
[et_block](#et_block)|997|18338381|4|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7586|7586|3|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.0%|
[et_tor](#et_tor)|6360|6360|3|0.0%|0.0%|
[et_compromised](#et_compromised)|2191|2191|3|0.1%|0.0%|
[dshield](#dshield)|20|5120|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6480|6480|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2181|2181|3|0.1%|0.0%|
[bm_tor](#bm_tor)|6505|6505|3|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|2|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[openbl_30d](#openbl_30d)|3179|3179|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Tue Jun  2 15:14:09 UTC 2015.

The ipset `blocklist_de_bots` has **3204** entries, **3204** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|25681|25681|3204|12.4%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|2036|2.2%|63.5%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|1862|5.9%|58.1%|
[stopforumspam_1d](#stopforumspam_1d)|7053|7053|1361|19.2%|42.4%|
[ri_web_proxies](#ri_web_proxies)|5720|5720|320|5.5%|9.9%|
[proxyrss](#proxyrss)|1573|1573|224|14.2%|6.9%|
[xroxy](#xroxy)|2032|2032|192|9.4%|5.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|188|0.0%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|186|0.0%|5.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|120|71.4%|3.7%|
[proxz](#proxz)|546|546|91|16.6%|2.8%|
[ri_connect_proxies](#ri_connect_proxies)|2116|2116|66|3.1%|2.0%|
[php_commenters](#php_commenters)|281|281|48|17.0%|1.4%|
[nixspam](#nixspam)|25790|25790|41|0.1%|1.2%|
[alienvault_reputation](#alienvault_reputation)|177988|177988|34|0.0%|1.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|32|0.0%|0.9%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|30|0.3%|0.9%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|21|0.0%|0.6%|
[et_block](#et_block)|997|18338381|21|0.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|15029|15029|21|0.1%|0.6%|
[blocklist_de_apache](#blocklist_de_apache)|13962|13962|21|0.1%|0.6%|
[php_harvesters](#php_harvesters)|257|257|19|7.3%|0.5%|
[php_dictionary](#php_dictionary)|433|433|15|3.4%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|14|0.0%|0.4%|
[openbl_60d](#openbl_60d)|7586|7586|11|0.1%|0.3%|
[php_spammers](#php_spammers)|417|417|10|2.3%|0.3%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|5|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.0%|
[voipbl](#voipbl)|10350|10759|2|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2191|2191|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2181|2181|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Tue Jun  2 15:14:11 UTC 2015.

The ipset `blocklist_de_bruteforce` has **2566** entries, **2566** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|25681|25681|2566|9.9%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|13962|13962|2564|18.3%|99.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|160|0.0%|6.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|41|0.0%|1.5%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|39|0.0%|1.5%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|32|0.1%|1.2%|
[nixspam](#nixspam)|25790|25790|31|0.1%|1.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|31|0.0%|1.2%|
[stopforumspam_1d](#stopforumspam_1d)|7053|7053|18|0.2%|0.7%|
[alienvault_reputation](#alienvault_reputation)|177988|177988|15|0.0%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|12|7.1%|0.4%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|7|0.0%|0.2%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.1%|
[php_commenters](#php_commenters)|281|281|5|1.7%|0.1%|
[et_block](#et_block)|997|18338381|3|0.0%|0.1%|
[voipbl](#voipbl)|10350|10759|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|2|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[shunlist](#shunlist)|1301|1301|1|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7586|7586|1|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15029|15029|1|0.0%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Tue Jun  2 15:14:08 UTC 2015.

The ipset `blocklist_de_ftp` has **561** entries, **561** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|25681|25681|561|2.1%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|54|0.0%|9.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|10|0.0%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|8|0.0%|1.4%|
[alienvault_reputation](#alienvault_reputation)|177988|177988|8|0.0%|1.4%|
[nixspam](#nixspam)|25790|25790|7|0.0%|1.2%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|5|0.0%|0.8%|
[php_harvesters](#php_harvesters)|257|257|5|1.9%|0.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|0.8%|
[openbl_60d](#openbl_60d)|7586|7586|3|0.0%|0.5%|
[openbl_30d](#openbl_30d)|3179|3179|2|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7053|7053|1|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|1|0.0%|0.1%|
[shunlist](#shunlist)|1301|1301|1|0.0%|0.1%|
[proxyrss](#proxyrss)|1573|1573|1|0.0%|0.1%|
[openbl_7d](#openbl_7d)|912|912|1|0.1%|0.1%|
[dshield](#dshield)|20|5120|1|0.0%|0.1%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Tue Jun  2 15:28:08 UTC 2015.

The ipset `blocklist_de_imap` has **987** entries, **987** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|15029|15029|981|6.5%|99.3%|
[blocklist_de](#blocklist_de)|25681|25681|981|3.8%|99.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|95|0.0%|9.6%|
[alienvault_reputation](#alienvault_reputation)|177988|177988|54|0.0%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|40|0.0%|4.0%|
[openbl_60d](#openbl_60d)|7586|7586|38|0.5%|3.8%|
[openbl_30d](#openbl_30d)|3179|3179|33|1.0%|3.3%|
[openbl_7d](#openbl_7d)|912|912|19|2.0%|1.9%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|16|0.0%|1.6%|
[et_block](#et_block)|997|18338381|16|0.0%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|10|0.0%|1.0%|
[et_compromised](#et_compromised)|2191|2191|10|0.4%|1.0%|
[bruteforceblocker](#bruteforceblocker)|2181|2181|9|0.4%|0.9%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|6|0.0%|0.6%|
[nixspam](#nixspam)|25790|25790|6|0.0%|0.6%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|5|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.5%|
[shunlist](#shunlist)|1301|1301|4|0.3%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|3|0.0%|0.3%|
[openbl_1d](#openbl_1d)|166|166|2|1.2%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|2|1.1%|0.2%|
[voipbl](#voipbl)|10350|10759|1|0.0%|0.1%|
[ciarmy](#ciarmy)|331|331|1|0.3%|0.1%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Tue Jun  2 15:14:04 UTC 2015.

The ipset `blocklist_de_mail` has **15029** entries, **15029** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|25681|25681|15029|58.5%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|13962|13962|11059|79.2%|73.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2323|0.0%|15.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1326|0.0%|8.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1126|0.0%|7.4%|
[blocklist_de_imap](#blocklist_de_imap)|987|987|981|99.3%|6.5%|
[nixspam](#nixspam)|25790|25790|542|2.1%|3.6%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|209|0.2%|1.3%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|133|0.4%|0.8%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|114|1.2%|0.7%|
[alienvault_reputation](#alienvault_reputation)|177988|177988|77|0.0%|0.5%|
[stopforumspam_1d](#stopforumspam_1d)|7053|7053|45|0.6%|0.2%|
[openbl_60d](#openbl_60d)|7586|7586|43|0.5%|0.2%|
[openbl_30d](#openbl_30d)|3179|3179|38|1.1%|0.2%|
[ri_web_proxies](#ri_web_proxies)|5720|5720|37|0.6%|0.2%|
[xroxy](#xroxy)|2032|2032|36|1.7%|0.2%|
[php_dictionary](#php_dictionary)|433|433|33|7.6%|0.2%|
[php_spammers](#php_spammers)|417|417|30|7.1%|0.1%|
[et_block](#et_block)|997|18338381|26|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|25|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|21|12.5%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3204|3204|21|0.6%|0.1%|
[openbl_7d](#openbl_7d)|912|912|19|2.0%|0.1%|
[php_commenters](#php_commenters)|281|281|18|6.4%|0.1%|
[proxz](#proxz)|546|546|15|2.7%|0.0%|
[et_compromised](#et_compromised)|2191|2191|12|0.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2181|2181|11|0.5%|0.0%|
[shunlist](#shunlist)|1301|1301|6|0.4%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6|0.0%|0.0%|
[et_tor](#et_tor)|6360|6360|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6480|6480|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6505|6505|3|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[openbl_1d](#openbl_1d)|166|166|2|1.2%|0.0%|
[voipbl](#voipbl)|10350|10759|1|0.0%|0.0%|
[virbl](#virbl)|18|18|1|5.5%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2116|2116|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[ciarmy](#ciarmy)|331|331|1|0.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2566|2566|1|0.0%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Tue Jun  2 15:10:09 UTC 2015.

The ipset `blocklist_de_sip` has **107** entries, **107** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|25681|25681|88|0.3%|82.2%|
[voipbl](#voipbl)|10350|10759|28|0.2%|26.1%|
[alienvault_reputation](#alienvault_reputation)|177988|177988|18|0.0%|16.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|12|0.0%|11.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8|0.0%|7.4%|
[nixspam](#nixspam)|25790|25790|2|0.0%|1.8%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|2|0.0%|1.8%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|1|0.0%|0.9%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.9%|
[et_block](#et_block)|997|18338381|1|0.0%|0.9%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Tue Jun  2 15:10:05 UTC 2015.

The ipset `blocklist_de_ssh` has **3843** entries, **3843** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|25681|25681|3843|14.9%|100.0%|
[alienvault_reputation](#alienvault_reputation)|177988|177988|1077|0.6%|28.0%|
[openbl_60d](#openbl_60d)|7586|7586|964|12.7%|25.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|911|0.0%|23.7%|
[openbl_30d](#openbl_30d)|3179|3179|735|23.1%|19.1%|
[bruteforceblocker](#bruteforceblocker)|2181|2181|706|32.3%|18.3%|
[et_compromised](#et_compromised)|2191|2191|669|30.5%|17.4%|
[openbl_7d](#openbl_7d)|912|912|499|54.7%|12.9%|
[shunlist](#shunlist)|1301|1301|380|29.2%|9.8%|
[openbl_1d](#openbl_1d)|166|166|121|72.8%|3.1%|
[et_block](#et_block)|997|18338381|116|0.0%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|113|0.0%|2.9%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|112|0.0%|2.9%|
[dshield](#dshield)|20|5120|54|1.0%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|45|0.0%|1.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|27|16.0%|0.7%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|19|0.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.1%|
[nixspam](#nixspam)|25790|25790|3|0.0%|0.0%|
[ciarmy](#ciarmy)|331|331|3|0.9%|0.0%|
[voipbl](#voipbl)|10350|10759|2|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|2|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|2|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[xroxy](#xroxy)|2032|2032|1|0.0%|0.0%|
[proxz](#proxz)|546|546|1|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Tue Jun  2 15:10:12 UTC 2015.

The ipset `blocklist_de_strongips` has **168** entries, **168** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|25681|25681|168|0.6%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|124|0.1%|73.8%|
[blocklist_de_bots](#blocklist_de_bots)|3204|3204|120|3.7%|71.4%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|115|0.3%|68.4%|
[stopforumspam_1d](#stopforumspam_1d)|7053|7053|105|1.4%|62.5%|
[alienvault_reputation](#alienvault_reputation)|177988|177988|37|0.0%|22.0%|
[blocklist_de_apache](#blocklist_de_apache)|13962|13962|36|0.2%|21.4%|
[php_commenters](#php_commenters)|281|281|28|9.9%|16.6%|
[openbl_60d](#openbl_60d)|7586|7586|28|0.3%|16.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|3843|3843|27|0.7%|16.0%|
[openbl_30d](#openbl_30d)|3179|3179|25|0.7%|14.8%|
[openbl_7d](#openbl_7d)|912|912|24|2.6%|14.2%|
[blocklist_de_mail](#blocklist_de_mail)|15029|15029|21|0.1%|12.5%|
[shunlist](#shunlist)|1301|1301|19|1.4%|11.3%|
[openbl_1d](#openbl_1d)|166|166|18|10.8%|10.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|16|0.0%|9.5%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2566|2566|12|0.4%|7.1%|
[xroxy](#xroxy)|2032|2032|7|0.3%|4.1%|
[proxyrss](#proxyrss)|1573|1573|7|0.4%|4.1%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|6|0.0%|3.5%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|6|0.0%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|6|0.0%|3.5%|
[et_block](#et_block)|997|18338381|6|0.0%|3.5%|
[ri_web_proxies](#ri_web_proxies)|5720|5720|5|0.0%|2.9%|
[dshield](#dshield)|20|5120|5|0.0%|2.9%|
[proxz](#proxz)|546|546|3|0.5%|1.7%|
[php_spammers](#php_spammers)|417|417|3|0.7%|1.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.7%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|1.1%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|1.1%|
[blocklist_de_imap](#blocklist_de_imap)|987|987|2|0.2%|1.1%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|1|0.0%|0.5%|
[nixspam](#nixspam)|25790|25790|1|0.0%|0.5%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Tue Jun  2 15:27:08 UTC 2015.

The ipset `bm_tor` has **6505** entries, **6505** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[dm_tor](#dm_tor)|6480|6480|6354|98.0%|97.6%|
[et_tor](#et_tor)|6360|6360|5684|89.3%|87.3%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|1084|12.0%|16.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|630|0.0%|9.6%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|621|0.6%|9.5%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|473|1.5%|7.2%|
[stopforumspam_1d](#stopforumspam_1d)|7053|7053|297|4.2%|4.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|187|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|170|45.6%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|167|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|177988|177988|46|0.0%|0.7%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[openbl_60d](#openbl_60d)|7586|7586|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[et_block](#et_block)|997|18338381|4|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5720|5720|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15029|15029|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13962|13962|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|25681|25681|3|0.0%|0.0%|
[xroxy](#xroxy)|2032|2032|2|0.0%|0.0%|
[voipbl](#voipbl)|10350|10759|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|2|0.0%|0.0%|
[shunlist](#shunlist)|1301|1301|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2116|2116|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1573|1573|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|

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
[voipbl](#voipbl)|10350|10759|319|2.9%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2181|2181|1|0.0%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Tue Jun  2 13:27:11 UTC 2015.

The ipset `bruteforceblocker` has **2181** entries, **2181** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_compromised](#et_compromised)|2191|2191|2111|96.3%|96.7%|
[alienvault_reputation](#alienvault_reputation)|177988|177988|1405|0.7%|64.4%|
[openbl_60d](#openbl_60d)|7586|7586|1305|17.2%|59.8%|
[openbl_30d](#openbl_30d)|3179|3179|1230|38.6%|56.3%|
[blocklist_de](#blocklist_de)|25681|25681|723|2.8%|33.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|3843|3843|706|18.3%|32.3%|
[shunlist](#shunlist)|1301|1301|530|40.7%|24.3%|
[openbl_7d](#openbl_7d)|912|912|520|57.0%|23.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|214|0.0%|9.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|113|0.0%|5.1%|
[et_block](#et_block)|997|18338381|103|0.0%|4.7%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|101|0.0%|4.6%|
[openbl_1d](#openbl_1d)|166|166|72|43.3%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|60|0.0%|2.7%|
[dshield](#dshield)|20|5120|58|1.1%|2.6%|
[blocklist_de_mail](#blocklist_de_mail)|15029|15029|11|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|9|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|987|987|9|0.9%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|6|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7053|7053|4|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|3|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13962|13962|3|0.0%|0.1%|
[proxz](#proxz)|546|546|2|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[xroxy](#xroxy)|2032|2032|1|0.0%|0.0%|
[voipbl](#voipbl)|10350|10759|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5720|5720|1|0.0%|0.0%|
[nixspam](#nixspam)|25790|25790|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3686|670534424|1|0.0%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3204|3204|1|0.0%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Tue Jun  2 13:15:14 UTC 2015.

The ipset `ciarmy` has **331** entries, **331** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|177988|177988|315|0.1%|95.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|53|0.0%|16.0%|
[blocklist_de](#blocklist_de)|25681|25681|32|0.1%|9.6%|
[blocklist_de_apache](#blocklist_de_apache)|13962|13962|28|0.2%|8.4%|
[shunlist](#shunlist)|1301|1301|24|1.8%|7.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|13|0.0%|3.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|11|0.0%|3.3%|
[voipbl](#voipbl)|10350|10759|4|0.0%|1.2%|
[dshield](#dshield)|20|5120|4|0.0%|1.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|3843|3843|3|0.0%|0.9%|
[et_block](#et_block)|997|18338381|2|0.0%|0.6%|
[openbl_7d](#openbl_7d)|912|912|1|0.1%|0.3%|
[openbl_60d](#openbl_60d)|7586|7586|1|0.0%|0.3%|
[openbl_30d](#openbl_30d)|3179|3179|1|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|15029|15029|1|0.0%|0.3%|
[blocklist_de_imap](#blocklist_de_imap)|987|987|1|0.1%|0.3%|

## cleanmx_viruses

[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses

Source is downloaded from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive).

The last time downloaded was found to be dated: Tue Jun  2 06:38:55 UTC 2015.

The ipset `cleanmx_viruses` has **356** entries, **356** unique IPs.

The following table shows the overlaps of `cleanmx_viruses` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `cleanmx_viruses`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `cleanmx_viruses`.
- ` this % ` is the percentage **of this ipset (`cleanmx_viruses`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|49|0.0%|13.7%|
[malc0de](#malc0de)|392|392|24|6.1%|6.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|23|0.0%|6.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|14|0.0%|3.9%|
[alienvault_reputation](#alienvault_reputation)|177988|177988|13|0.0%|3.6%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|6|0.0%|1.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.8%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|2|0.1%|0.5%|
[voipbl](#voipbl)|10350|10759|1|0.0%|0.2%|
[openbl_60d](#openbl_60d)|7586|7586|1|0.0%|0.2%|
[openbl_30d](#openbl_30d)|3179|3179|1|0.0%|0.2%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Tue Jun  2 15:27:05 UTC 2015.

The ipset `dm_tor` has **6480** entries, **6480** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6505|6505|6354|97.6%|98.0%|
[et_tor](#et_tor)|6360|6360|5645|88.7%|87.1%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|1057|11.7%|16.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|633|0.0%|9.7%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|603|0.6%|9.3%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|456|1.4%|7.0%|
[stopforumspam_1d](#stopforumspam_1d)|7053|7053|278|3.9%|4.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|190|0.0%|2.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|170|45.6%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|166|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|177988|177988|46|0.0%|0.7%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[openbl_60d](#openbl_60d)|7586|7586|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[et_block](#et_block)|997|18338381|4|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5720|5720|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15029|15029|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13962|13962|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|25681|25681|3|0.0%|0.0%|
[xroxy](#xroxy)|2032|2032|2|0.0%|0.0%|
[voipbl](#voipbl)|10350|10759|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|2|0.0%|0.0%|
[shunlist](#shunlist)|1301|1301|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2116|2116|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1573|1573|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Tue Jun  2 15:10:59 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|177988|177988|3842|2.1%|75.0%|
[et_block](#et_block)|997|18338381|1024|0.0%|20.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|768|0.0%|15.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|256|0.0%|5.0%|
[openbl_60d](#openbl_60d)|7586|7586|118|1.5%|2.3%|
[openbl_30d](#openbl_30d)|3179|3179|101|3.1%|1.9%|
[shunlist](#shunlist)|1301|1301|74|5.6%|1.4%|
[openbl_7d](#openbl_7d)|912|912|68|7.4%|1.3%|
[blocklist_de](#blocklist_de)|25681|25681|59|0.2%|1.1%|
[et_compromised](#et_compromised)|2191|2191|58|2.6%|1.1%|
[bruteforceblocker](#bruteforceblocker)|2181|2181|58|2.6%|1.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|3843|3843|54|1.4%|1.0%|
[openbl_1d](#openbl_1d)|166|166|15|9.0%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|5|2.9%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4|0.0%|0.0%|
[ciarmy](#ciarmy)|331|331|4|1.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13962|13962|3|0.0%|0.0%|
[voipbl](#voipbl)|10350|10759|2|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|2|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|2|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7053|7053|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|2|0.0%|0.0%|
[et_tor](#et_tor)|6360|6360|2|0.0%|0.0%|
[nixspam](#nixspam)|25790|25790|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[malc0de](#malc0de)|392|392|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6480|6480|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6505|6505|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15029|15029|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|561|561|1|0.1%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|177988|177988|5284|2.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1040|0.3%|0.0%|
[dshield](#dshield)|20|5120|1024|20.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|986|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|517|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|341|1.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|298|3.3%|0.0%|
[zeus](#zeus)|266|266|259|97.3%|0.0%|
[openbl_60d](#openbl_60d)|7586|7586|245|3.2%|0.0%|
[zeus_badips](#zeus_badips)|230|230|229|99.5%|0.0%|
[openbl_30d](#openbl_30d)|3179|3179|196|6.1%|0.0%|
[blocklist_de](#blocklist_de)|25681|25681|168|0.6%|0.0%|
[nixspam](#nixspam)|25790|25790|152|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3843|3843|116|3.0%|0.0%|
[shunlist](#shunlist)|1301|1301|110|8.4%|0.0%|
[et_compromised](#et_compromised)|2191|2191|104|4.7%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2181|2181|103|4.7%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7053|7053|96|1.3%|0.0%|
[openbl_7d](#openbl_7d)|912|912|89|9.7%|0.0%|
[feodo](#feodo)|80|80|71|88.7%|0.0%|
[sslbl](#sslbl)|362|362|30|8.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|29|2.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15029|15029|26|0.1%|0.0%|
[voipbl](#voipbl)|10350|10759|24|0.2%|0.0%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3204|3204|21|0.6%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|987|987|16|1.6%|0.0%|
[palevo](#palevo)|12|12|11|91.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|10|0.0%|0.0%|
[openbl_1d](#openbl_1d)|166|166|6|3.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|6|3.5%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[malc0de](#malc0de)|392|392|4|1.0%|0.0%|
[et_tor](#et_tor)|6360|6360|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6480|6480|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6505|6505|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13962|13962|4|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2566|2566|3|0.1%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[ciarmy](#ciarmy)|331|331|2|0.6%|0.0%|
[virbl](#virbl)|18|18|1|5.5%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|107|107|1|0.9%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|177988|177988|3|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[et_block](#et_block)|997|18338381|1|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|107|107|1|0.9%|0.1%|

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
[bruteforceblocker](#bruteforceblocker)|2181|2181|2111|96.7%|96.3%|
[alienvault_reputation](#alienvault_reputation)|177988|177988|1423|0.7%|64.9%|
[openbl_60d](#openbl_60d)|7586|7586|1321|17.4%|60.2%|
[openbl_30d](#openbl_30d)|3179|3179|1231|38.7%|56.1%|
[blocklist_de](#blocklist_de)|25681|25681|687|2.6%|31.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|3843|3843|669|17.4%|30.5%|
[shunlist](#shunlist)|1301|1301|531|40.8%|24.2%|
[openbl_7d](#openbl_7d)|912|912|511|56.0%|23.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|219|0.0%|9.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|116|0.0%|5.2%|
[et_block](#et_block)|997|18338381|104|0.0%|4.7%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|102|0.0%|4.6%|
[openbl_1d](#openbl_1d)|166|166|64|38.5%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|62|0.0%|2.8%|
[dshield](#dshield)|20|5120|58|1.1%|2.6%|
[blocklist_de_mail](#blocklist_de_mail)|15029|15029|12|0.0%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|987|987|10|1.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|9|0.0%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|5|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7053|7053|4|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|3|0.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13962|13962|3|0.0%|0.1%|
[proxz](#proxz)|546|546|2|0.3%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[xroxy](#xroxy)|2032|2032|1|0.0%|0.0%|
[voipbl](#voipbl)|10350|10759|1|0.0%|0.0%|
[nixspam](#nixspam)|25790|25790|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3204|3204|1|0.0%|0.0%|

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
[bm_tor](#bm_tor)|6505|6505|5684|87.3%|89.3%|
[dm_tor](#dm_tor)|6480|6480|5645|87.1%|88.7%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|1077|11.9%|16.9%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|636|0.6%|10.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|628|0.0%|9.8%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|491|1.5%|7.7%|
[stopforumspam_1d](#stopforumspam_1d)|7053|7053|301|4.2%|4.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|191|0.0%|3.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|169|45.4%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|167|0.0%|2.6%|
[alienvault_reputation](#alienvault_reputation)|177988|177988|45|0.0%|0.7%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[openbl_60d](#openbl_60d)|7586|7586|19|0.2%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|19|0.0%|0.2%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[php_harvesters](#php_harvesters)|257|257|6|2.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5720|5720|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[et_block](#et_block)|997|18338381|4|0.0%|0.0%|
[xroxy](#xroxy)|2032|2032|3|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15029|15029|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13962|13962|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|25681|25681|3|0.0%|0.0%|
[voipbl](#voipbl)|10350|10759|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2116|2116|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[shunlist](#shunlist)|1301|1301|1|0.0%|0.0%|
[proxz](#proxz)|546|546|1|0.1%|0.0%|
[proxyrss](#proxyrss)|1573|1573|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Tue Jun  2 15:27:15 UTC 2015.

The ipset `feodo` has **80** entries, **80** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|997|18338381|71|0.0%|88.7%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|64|0.7%|80.0%|
[sslbl](#sslbl)|362|362|31|8.5%|38.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|7|0.0%|8.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|3|0.0%|3.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|3.7%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|1.2%|
[alienvault_reputation](#alienvault_reputation)|177988|177988|1|0.0%|1.2%|

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
[voipbl](#voipbl)|10350|10759|319|2.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|33|2.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|15|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|9|0.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2181|2181|1|0.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|177988|177988|15|0.0%|0.0%|
[nixspam](#nixspam)|25790|25790|12|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.0%|
[et_block](#et_block)|997|18338381|10|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|7|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|6|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7053|7053|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|25681|25681|4|0.0%|0.0%|
[xroxy](#xroxy)|2032|2032|3|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|3|0.0%|0.0%|
[voipbl](#voipbl)|10350|10759|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2566|2566|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13962|13962|2|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5720|5720|1|0.0%|0.0%|
[proxz](#proxz)|546|546|1|0.1%|0.0%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15029|15029|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3204|3204|1|0.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|177988|177988|518|0.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|178|0.5%|0.0%|
[nixspam](#nixspam)|25790|25790|152|0.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7053|7053|31|0.4%|0.0%|
[blocklist_de](#blocklist_de)|25681|25681|28|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|27|2.1%|0.0%|
[openbl_60d](#openbl_60d)|7586|7586|19|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3204|3204|14|0.4%|0.0%|
[openbl_30d](#openbl_30d)|3179|3179|13|0.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|11|0.1%|0.0%|
[zeus_badips](#zeus_badips)|230|230|10|4.3%|0.0%|
[zeus](#zeus)|266|266|10|3.7%|0.0%|
[openbl_7d](#openbl_7d)|912|912|10|1.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3843|3843|7|0.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15029|15029|6|0.0%|0.0%|
[et_compromised](#et_compromised)|2191|2191|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2181|2181|5|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|987|987|5|0.5%|0.0%|
[shunlist](#shunlist)|1301|1301|3|0.2%|0.0%|
[et_tor](#et_tor)|6360|6360|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6480|6480|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6505|6505|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|3|1.7%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[voipbl](#voipbl)|10350|10759|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2566|2566|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13962|13962|1|0.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|177988|177988|4658|2.6%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|1537|1.6%|0.0%|
[blocklist_de](#blocklist_de)|25681|25681|1453|5.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15029|15029|1326|8.8%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13962|13962|1323|9.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|558|1.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|406|0.8%|0.0%|
[nixspam](#nixspam)|25790|25790|396|1.5%|0.0%|
[voipbl](#voipbl)|10350|10759|295|2.7%|0.0%|
[openbl_60d](#openbl_60d)|7586|7586|170|2.2%|0.0%|
[et_tor](#et_tor)|6360|6360|167|2.6%|0.0%|
[bm_tor](#bm_tor)|6505|6505|167|2.5%|0.0%|
[dm_tor](#dm_tor)|6480|6480|166|2.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7053|7053|158|2.2%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5720|5720|120|2.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|97|6.6%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|84|0.9%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2116|2116|70|3.3%|0.0%|
[openbl_30d](#openbl_30d)|3179|3179|69|2.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|66|5.1%|0.0%|
[et_compromised](#et_compromised)|2191|2191|62|2.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2181|2181|60|2.7%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|58|8.6%|0.0%|
[xroxy](#xroxy)|2032|2032|57|2.8%|0.0%|
[proxyrss](#proxyrss)|1573|1573|48|3.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3843|3843|45|1.1%|0.0%|
[et_botcc](#et_botcc)|505|505|41|8.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3204|3204|32|0.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2566|2566|31|1.2%|0.0%|
[shunlist](#shunlist)|1301|1301|26|1.9%|0.0%|
[proxz](#proxz)|546|546|22|4.0%|0.0%|
[openbl_7d](#openbl_7d)|912|912|17|1.8%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|17|4.5%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|356|356|14|3.9%|0.0%|
[malc0de](#malc0de)|392|392|12|3.0%|0.0%|
[ciarmy](#ciarmy)|331|331|11|3.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|987|987|10|1.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|9|2.0%|0.0%|
[zeus](#zeus)|266|266|7|2.6%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.0%|
[php_commenters](#php_commenters)|281|281|5|1.7%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|561|561|5|0.8%|0.0%|
[zeus_badips](#zeus_badips)|230|230|4|1.7%|0.0%|
[openbl_1d](#openbl_1d)|166|166|4|2.4%|0.0%|
[dshield](#dshield)|20|5120|4|0.0%|0.0%|
[sslbl](#sslbl)|362|362|3|0.8%|0.0%|
[feodo](#feodo)|80|80|3|3.7%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|107|107|2|1.8%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|177988|177988|7621|4.2%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|2466|2.6%|0.0%|
[blocklist_de](#blocklist_de)|25681|25681|1488|5.7%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15029|15029|1126|7.4%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13962|13962|1071|7.6%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|934|2.9%|0.0%|
[nixspam](#nixspam)|25790|25790|682|2.6%|0.0%|
[voipbl](#voipbl)|10350|10759|431|4.0%|0.0%|
[openbl_60d](#openbl_60d)|7586|7586|340|4.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7053|7053|255|3.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|230|0.4%|0.0%|
[et_tor](#et_tor)|6360|6360|191|3.0%|0.0%|
[dm_tor](#dm_tor)|6480|6480|190|2.9%|0.0%|
[bm_tor](#bm_tor)|6505|6505|187|2.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3204|3204|186|5.8%|0.0%|
[openbl_30d](#openbl_30d)|3179|3179|176|5.5%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5720|5720|175|3.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|122|1.3%|0.0%|
[et_compromised](#et_compromised)|2191|2191|116|5.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2181|2181|113|5.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3843|3843|113|2.9%|0.0%|
[xroxy](#xroxy)|2032|2032|99|4.8%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2116|2116|83|3.9%|0.0%|
[shunlist](#shunlist)|1301|1301|72|5.5%|0.0%|
[proxyrss](#proxyrss)|1573|1573|62|3.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|45|3.0%|0.0%|
[openbl_7d](#openbl_7d)|912|912|44|4.8%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2566|2566|41|1.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|987|987|40|4.0%|0.0%|
[php_spammers](#php_spammers)|417|417|31|7.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|28|4.1%|0.0%|
[proxz](#proxz)|546|546|27|4.9%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|26|2.0%|0.0%|
[malc0de](#malc0de)|392|392|24|6.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|356|356|23|6.4%|0.0%|
[et_botcc](#et_botcc)|505|505|22|4.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|21|5.6%|0.0%|
[ciarmy](#ciarmy)|331|331|13|3.9%|0.0%|
[php_dictionary](#php_dictionary)|433|433|10|2.3%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|561|561|10|1.7%|0.0%|
[zeus](#zeus)|266|266|9|3.3%|0.0%|
[php_commenters](#php_commenters)|281|281|9|3.2%|0.0%|
[zeus_badips](#zeus_badips)|230|230|8|3.4%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|107|107|8|7.4%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[openbl_1d](#openbl_1d)|166|166|7|4.2%|0.0%|
[sslbl](#sslbl)|362|362|6|1.6%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|6|3.5%|0.0%|
[feodo](#feodo)|80|80|3|3.7%|0.0%|
[palevo](#palevo)|12|12|2|16.6%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|177988|177988|14369|8.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|9231|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|5888|6.3%|0.0%|
[blocklist_de](#blocklist_de)|25681|25681|3684|14.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15029|15029|2323|15.4%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13962|13962|2252|16.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|2085|6.6%|0.0%|
[nixspam](#nixspam)|25790|25790|1850|7.1%|0.0%|
[voipbl](#voipbl)|10350|10759|1591|14.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1172|2.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3843|3843|911|23.7%|0.0%|
[dshield](#dshield)|20|5120|768|15.0%|0.0%|
[openbl_60d](#openbl_60d)|7586|7586|724|9.5%|0.0%|
[dm_tor](#dm_tor)|6480|6480|633|9.7%|0.0%|
[bm_tor](#bm_tor)|6505|6505|630|9.6%|0.0%|
[et_tor](#et_tor)|6360|6360|628|9.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7053|7053|517|7.3%|0.0%|
[openbl_30d](#openbl_30d)|3179|3179|288|9.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|246|2.7%|0.0%|
[et_compromised](#et_compromised)|2191|2191|219|9.9%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2181|2181|214|9.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3204|3204|188|5.8%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5720|5720|161|2.8%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2566|2566|160|6.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|146|11.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|125|33.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|110|7.5%|0.0%|
[shunlist](#shunlist)|1301|1301|103|7.9%|0.0%|
[openbl_7d](#openbl_7d)|912|912|97|10.6%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|987|987|95|9.6%|0.0%|
[xroxy](#xroxy)|2032|2032|85|4.1%|0.0%|
[et_botcc](#et_botcc)|505|505|78|15.4%|0.0%|
[malc0de](#malc0de)|392|392|67|17.0%|0.0%|
[proxyrss](#proxyrss)|1573|1573|57|3.6%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|561|561|54|9.6%|0.0%|
[ciarmy](#ciarmy)|331|331|53|16.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|51|7.5%|0.0%|
[proxz](#proxz)|546|546|49|8.9%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|356|356|49|13.7%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2116|2116|47|2.2%|0.0%|
[php_spammers](#php_spammers)|417|417|26|6.2%|0.0%|
[php_dictionary](#php_dictionary)|433|433|24|5.5%|0.0%|
[openbl_1d](#openbl_1d)|166|166|24|14.4%|0.0%|
[sslbl](#sslbl)|362|362|23|6.3%|0.0%|
[zeus](#zeus)|266|266|19|7.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|16|9.5%|0.0%|
[php_harvesters](#php_harvesters)|257|257|15|5.8%|0.0%|
[php_commenters](#php_commenters)|281|281|15|5.3%|0.0%|
[zeus_badips](#zeus_badips)|230|230|14|6.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|107|107|12|11.2%|0.0%|
[feodo](#feodo)|80|80|7|8.7%|0.0%|
[virbl](#virbl)|18|18|1|5.5%|0.0%|
[palevo](#palevo)|12|12|1|8.3%|0.0%|

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
[xroxy](#xroxy)|2032|2032|13|0.6%|1.9%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|11|0.0%|1.6%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|11|0.0%|1.6%|
[ri_web_proxies](#ri_web_proxies)|5720|5720|10|0.1%|1.4%|
[stopforumspam_1d](#stopforumspam_1d)|7053|7053|6|0.0%|0.8%|
[ri_connect_proxies](#ri_connect_proxies)|2116|2116|6|0.2%|0.8%|
[proxyrss](#proxyrss)|1573|1573|6|0.3%|0.8%|
[proxz](#proxz)|546|546|3|0.5%|0.4%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|2|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|2|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.2%|
[et_block](#et_block)|997|18338381|2|0.0%|0.2%|
[blocklist_de](#blocklist_de)|25681|25681|2|0.0%|0.2%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.1%|
[nixspam](#nixspam)|25790|25790|1|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|15029|15029|1|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3204|3204|1|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|177988|177988|1|0.0%|0.1%|

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
[alienvault_reputation](#alienvault_reputation)|177988|177988|288|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|45|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|26|2.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|21|0.0%|0.0%|
[dm_tor](#dm_tor)|6480|6480|21|0.3%|0.0%|
[bm_tor](#bm_tor)|6505|6505|21|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|19|1.3%|0.0%|
[et_tor](#et_tor)|6360|6360|19|0.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|13|0.1%|0.0%|
[nixspam](#nixspam)|25790|25790|11|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7053|7053|10|0.1%|0.0%|
[blocklist_de](#blocklist_de)|25681|25681|8|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5720|5720|5|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7586|7586|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|5|1.3%|0.0%|
[voipbl](#voipbl)|10350|10759|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3179|3179|4|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[malc0de](#malc0de)|392|392|3|0.7%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|356|356|3|0.8%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3204|3204|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13962|13962|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2181|2181|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3843|3843|2|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|107|107|2|1.8%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2566|2566|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[xroxy](#xroxy)|2032|2032|1|0.0%|0.0%|
[sslbl](#sslbl)|362|362|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|1|0.0%|0.0%|
[shunlist](#shunlist)|1301|1301|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.0%|
[palevo](#palevo)|12|12|1|8.3%|0.0%|
[openbl_7d](#openbl_7d)|912|912|1|0.1%|0.0%|
[feodo](#feodo)|80|80|1|1.2%|0.0%|
[et_compromised](#et_compromised)|2191|2191|1|0.0%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15029|15029|1|0.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|177988|177988|8|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|6|0.0%|0.4%|
[et_block](#et_block)|997|18338381|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|3|0.2%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|2|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7586|7586|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|3179|3179|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7053|7053|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5720|5720|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|912|912|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2191|2191|1|0.0%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3843|3843|1|0.0%|0.0%|
[blocklist_de](#blocklist_de)|25681|25681|1|0.0%|0.0%|

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
[cleanmx_viruses](#cleanmx_viruses)|356|356|24|6.7%|6.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|12|0.0%|3.0%|
[alienvault_reputation](#alienvault_reputation)|177988|177988|12|0.0%|3.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|4|0.0%|1.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|4|0.3%|1.0%|
[et_block](#et_block)|997|18338381|4|0.0%|1.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.7%|
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
[alienvault_reputation](#alienvault_reputation)|177988|177988|6|0.0%|0.4%|
[malc0de](#malc0de)|392|392|4|1.0%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|3|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|2|0.0%|0.1%|
[cleanmx_viruses](#cleanmx_viruses)|356|356|2|0.5%|0.1%|
[nixspam](#nixspam)|25790|25790|1|0.0%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3843|3843|1|0.0%|0.0%|
[blocklist_de](#blocklist_de)|25681|25681|1|0.0%|0.0%|

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
[dm_tor](#dm_tor)|6480|6480|170|2.6%|45.6%|
[bm_tor](#bm_tor)|6505|6505|170|2.6%|45.6%|
[et_tor](#et_tor)|6360|6360|169|2.6%|45.4%|
[stopforumspam_1d](#stopforumspam_1d)|7053|7053|158|2.2%|42.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|125|0.0%|33.6%|
[php_commenters](#php_commenters)|281|281|28|9.9%|7.5%|
[alienvault_reputation](#alienvault_reputation)|177988|177988|25|0.0%|6.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|21|0.0%|5.6%|
[openbl_60d](#openbl_60d)|7586|7586|18|0.2%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|17|0.0%|4.5%|
[php_harvesters](#php_harvesters)|257|257|6|2.3%|1.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|1.3%|
[ri_web_proxies](#ri_web_proxies)|5720|5720|4|0.0%|1.0%|
[php_spammers](#php_spammers)|417|417|4|0.9%|1.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|1.0%|
[shunlist](#shunlist)|1301|1301|2|0.1%|0.5%|
[xroxy](#xroxy)|2032|2032|1|0.0%|0.2%|
[voipbl](#voipbl)|10350|10759|1|0.0%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2116|2116|1|0.0%|0.2%|
[dshield](#dshield)|20|5120|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|15029|15029|1|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|13962|13962|1|0.0%|0.2%|
[blocklist_de](#blocklist_de)|25681|25681|1|0.0%|0.2%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Tue Jun  2 15:30:02 UTC 2015.

The ipset `nixspam` has **25790** entries, **25790** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1850|0.0%|7.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|682|0.0%|2.6%|
[blocklist_de](#blocklist_de)|25681|25681|626|2.4%|2.4%|
[blocklist_de_mail](#blocklist_de_mail)|15029|15029|542|3.6%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|396|0.0%|1.5%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|250|0.2%|0.9%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|232|2.5%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|152|0.0%|0.5%|
[et_block](#et_block)|997|18338381|152|0.0%|0.5%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|151|0.4%|0.5%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|151|0.0%|0.5%|
[ri_web_proxies](#ri_web_proxies)|5720|5720|86|1.5%|0.3%|
[php_dictionary](#php_dictionary)|433|433|75|17.3%|0.2%|
[xroxy](#xroxy)|2032|2032|72|3.5%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7053|7053|64|0.9%|0.2%|
[php_spammers](#php_spammers)|417|417|56|13.4%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3204|3204|41|1.2%|0.1%|
[alienvault_reputation](#alienvault_reputation)|177988|177988|32|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2566|2566|31|1.2%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13962|13962|31|0.2%|0.1%|
[proxz](#proxz)|546|546|24|4.3%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2116|2116|16|0.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|12|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|11|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|10|3.8%|0.0%|
[proxyrss](#proxyrss)|1573|1573|9|0.5%|0.0%|
[php_commenters](#php_commenters)|281|281|9|3.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|561|561|7|1.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|6|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|987|987|6|0.6%|0.0%|
[openbl_60d](#openbl_60d)|7586|7586|4|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3843|3843|3|0.0%|0.0%|
[voipbl](#voipbl)|10350|10759|2|0.0%|0.0%|
[virbl](#virbl)|18|18|2|11.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|107|107|2|1.8%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3179|3179|1|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[et_compromised](#et_compromised)|2191|2191|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2181|2181|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|1|0.5%|0.0%|

## openbl_1d

[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_1days.txt).

The last time downloaded was found to be dated: Tue Jun  2 15:32:00 UTC 2015.

The ipset `openbl_1d` has **166** entries, **166** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7586|7586|150|1.9%|90.3%|
[openbl_30d](#openbl_30d)|3179|3179|150|4.7%|90.3%|
[openbl_7d](#openbl_7d)|912|912|145|15.8%|87.3%|
[alienvault_reputation](#alienvault_reputation)|177988|177988|132|0.0%|79.5%|
[blocklist_de](#blocklist_de)|25681|25681|123|0.4%|74.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3843|3843|121|3.1%|72.8%|
[bruteforceblocker](#bruteforceblocker)|2181|2181|72|3.3%|43.3%|
[shunlist](#shunlist)|1301|1301|70|5.3%|42.1%|
[et_compromised](#et_compromised)|2191|2191|64|2.9%|38.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|24|0.0%|14.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|18|10.7%|10.8%|
[dshield](#dshield)|20|5120|15|0.2%|9.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7|0.0%|4.2%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|6|0.0%|3.6%|
[et_block](#et_block)|997|18338381|6|0.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4|0.0%|2.4%|
[blocklist_de_mail](#blocklist_de_mail)|15029|15029|2|0.0%|1.2%|
[blocklist_de_imap](#blocklist_de_imap)|987|987|2|0.2%|1.2%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt).

The last time downloaded was found to be dated: Tue Jun  2 11:42:00 UTC 2015.

The ipset `openbl_30d` has **3179** entries, **3179** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7586|7586|3179|41.9%|100.0%|
[alienvault_reputation](#alienvault_reputation)|177988|177988|3148|1.7%|99.0%|
[et_compromised](#et_compromised)|2191|2191|1231|56.1%|38.7%|
[bruteforceblocker](#bruteforceblocker)|2181|2181|1230|56.3%|38.6%|
[openbl_7d](#openbl_7d)|912|912|912|100.0%|28.6%|
[blocklist_de](#blocklist_de)|25681|25681|780|3.0%|24.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|3843|3843|735|19.1%|23.1%|
[shunlist](#shunlist)|1301|1301|610|46.8%|19.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|288|0.0%|9.0%|
[et_block](#et_block)|997|18338381|196|0.0%|6.1%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|191|0.0%|6.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|176|0.0%|5.5%|
[openbl_1d](#openbl_1d)|166|166|150|90.3%|4.7%|
[dshield](#dshield)|20|5120|101|1.9%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|69|0.0%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|15029|15029|38|0.2%|1.1%|
[blocklist_de_imap](#blocklist_de_imap)|987|987|33|3.3%|1.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|25|14.8%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|13|0.0%|0.4%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|6|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|5|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|4|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.1%|
[voipbl](#voipbl)|10350|10759|3|0.0%|0.0%|
[zeus](#zeus)|266|266|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|561|561|2|0.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13962|13962|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7053|7053|1|0.0%|0.0%|
[nixspam](#nixspam)|25790|25790|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|356|356|1|0.2%|0.0%|
[ciarmy](#ciarmy)|331|331|1|0.3%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt).

The last time downloaded was found to be dated: Tue Jun  2 11:42:00 UTC 2015.

The ipset `openbl_60d` has **7586** entries, **7586** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|177988|177988|7549|4.2%|99.5%|
[openbl_30d](#openbl_30d)|3179|3179|3179|100.0%|41.9%|
[et_compromised](#et_compromised)|2191|2191|1321|60.2%|17.4%|
[bruteforceblocker](#bruteforceblocker)|2181|2181|1305|59.8%|17.2%|
[blocklist_de](#blocklist_de)|25681|25681|1030|4.0%|13.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|3843|3843|964|25.0%|12.7%|
[openbl_7d](#openbl_7d)|912|912|912|100.0%|12.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|724|0.0%|9.5%|
[shunlist](#shunlist)|1301|1301|629|48.3%|8.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|340|0.0%|4.4%|
[et_block](#et_block)|997|18338381|245|0.0%|3.2%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|240|0.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|170|0.0%|2.2%|
[openbl_1d](#openbl_1d)|166|166|150|90.3%|1.9%|
[dshield](#dshield)|20|5120|118|2.3%|1.5%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|54|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|15029|15029|43|0.2%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|987|987|38|3.8%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|28|16.6%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|27|0.2%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|25|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7053|7053|22|0.3%|0.2%|
[dm_tor](#dm_tor)|6480|6480|21|0.3%|0.2%|
[bm_tor](#bm_tor)|6505|6505|21|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|19|0.0%|0.2%|
[et_tor](#et_tor)|6360|6360|19|0.2%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3204|3204|11|0.3%|0.1%|
[voipbl](#voipbl)|10350|10759|9|0.0%|0.1%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|6|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.0%|
[nixspam](#nixspam)|25790|25790|4|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|561|561|3|0.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13962|13962|3|0.0%|0.0%|
[zeus](#zeus)|266|266|2|0.7%|0.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|356|356|1|0.2%|0.0%|
[ciarmy](#ciarmy)|331|331|1|0.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2566|2566|1|0.0%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt).

The last time downloaded was found to be dated: Tue Jun  2 11:42:00 UTC 2015.

The ipset `openbl_7d` has **912** entries, **912** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7586|7586|912|12.0%|100.0%|
[openbl_30d](#openbl_30d)|3179|3179|912|28.6%|100.0%|
[alienvault_reputation](#alienvault_reputation)|177988|177988|889|0.4%|97.4%|
[bruteforceblocker](#bruteforceblocker)|2181|2181|520|23.8%|57.0%|
[blocklist_de](#blocklist_de)|25681|25681|520|2.0%|57.0%|
[et_compromised](#et_compromised)|2191|2191|511|23.3%|56.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3843|3843|499|12.9%|54.7%|
[shunlist](#shunlist)|1301|1301|404|31.0%|44.2%|
[openbl_1d](#openbl_1d)|166|166|145|87.3%|15.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|97|0.0%|10.6%|
[et_block](#et_block)|997|18338381|89|0.0%|9.7%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|86|0.0%|9.4%|
[dshield](#dshield)|20|5120|68|1.3%|7.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|44|0.0%|4.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|24|14.2%|2.6%|
[blocklist_de_mail](#blocklist_de_mail)|15029|15029|19|0.1%|2.0%|
[blocklist_de_imap](#blocklist_de_imap)|987|987|19|1.9%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|17|0.0%|1.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|1.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|5|0.0%|0.5%|
[voipbl](#voipbl)|10350|10759|3|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|2|0.0%|0.2%|
[zeus](#zeus)|266|266|1|0.3%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.1%|
[ciarmy](#ciarmy)|331|331|1|0.3%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|561|561|1|0.1%|0.1%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Tue Jun  2 15:27:12 UTC 2015.

The ipset `palevo` has **12** entries, **12** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|997|18338381|11|0.0%|91.6%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|10|0.1%|83.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2|0.0%|16.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|8.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1|0.0%|8.3%|

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
[stopforumspam_1d](#stopforumspam_1d)|7053|7053|111|1.5%|39.5%|
[blocklist_de](#blocklist_de)|25681|25681|59|0.2%|20.9%|
[blocklist_de_bots](#blocklist_de_bots)|3204|3204|48|1.4%|17.0%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|37|0.4%|13.1%|
[php_spammers](#php_spammers)|417|417|32|7.6%|11.3%|
[et_tor](#et_tor)|6360|6360|29|0.4%|10.3%|
[dm_tor](#dm_tor)|6480|6480|29|0.4%|10.3%|
[bm_tor](#bm_tor)|6505|6505|29|0.4%|10.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|28|7.5%|9.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|28|16.6%|9.9%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|24|0.0%|8.5%|
[et_block](#et_block)|997|18338381|24|0.0%|8.5%|
[blocklist_de_apache](#blocklist_de_apache)|13962|13962|23|0.1%|8.1%|
[php_dictionary](#php_dictionary)|433|433|22|5.0%|7.8%|
[blocklist_de_mail](#blocklist_de_mail)|15029|15029|18|0.1%|6.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|5.3%|
[alienvault_reputation](#alienvault_reputation)|177988|177988|13|0.0%|4.6%|
[ri_web_proxies](#ri_web_proxies)|5720|5720|11|0.1%|3.9%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|3.2%|
[nixspam](#nixspam)|25790|25790|9|0.0%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.2%|
[openbl_60d](#openbl_60d)|7586|7586|8|0.1%|2.8%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|7|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|1.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2566|2566|5|0.1%|1.7%|
[xroxy](#xroxy)|2032|2032|3|0.1%|1.0%|
[proxz](#proxz)|546|546|3|0.5%|1.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.3%|
[zeus](#zeus)|266|266|1|0.3%|0.3%|
[proxyrss](#proxyrss)|1573|1573|1|0.0%|0.3%|
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
[nixspam](#nixspam)|25790|25790|75|0.2%|17.3%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|69|0.2%|15.9%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|65|0.7%|15.0%|
[blocklist_de](#blocklist_de)|25681|25681|50|0.1%|11.5%|
[ri_web_proxies](#ri_web_proxies)|5720|5720|33|0.5%|7.6%|
[blocklist_de_mail](#blocklist_de_mail)|15029|15029|33|0.2%|7.6%|
[stopforumspam_1d](#stopforumspam_1d)|7053|7053|26|0.3%|6.0%|
[xroxy](#xroxy)|2032|2032|24|1.1%|5.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|24|0.0%|5.5%|
[php_commenters](#php_commenters)|281|281|22|7.8%|5.0%|
[blocklist_de_bots](#blocklist_de_bots)|3204|3204|15|0.4%|3.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|10|0.0%|2.3%|
[proxz](#proxz)|546|546|9|1.6%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|9|0.0%|2.0%|
[alienvault_reputation](#alienvault_reputation)|177988|177988|7|0.0%|1.6%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|4|0.0%|0.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.9%|
[et_tor](#et_tor)|6360|6360|4|0.0%|0.9%|
[et_block](#et_block)|997|18338381|4|0.0%|0.9%|
[dm_tor](#dm_tor)|6480|6480|4|0.0%|0.9%|
[bm_tor](#bm_tor)|6505|6505|4|0.0%|0.9%|
[ri_connect_proxies](#ri_connect_proxies)|2116|2116|3|0.1%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|2|1.1%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2566|2566|2|0.0%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|13962|13962|2|0.0%|0.4%|
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
[stopforumspam_1d](#stopforumspam_1d)|7053|7053|32|0.4%|12.4%|
[blocklist_de](#blocklist_de)|25681|25681|26|0.1%|10.1%|
[blocklist_de_bots](#blocklist_de_bots)|3204|3204|19|0.5%|7.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|5.8%|
[nixspam](#nixspam)|25790|25790|10|0.0%|3.8%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|9|0.0%|3.5%|
[php_commenters](#php_commenters)|281|281|9|3.2%|3.5%|
[alienvault_reputation](#alienvault_reputation)|177988|177988|8|0.0%|3.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|7|0.0%|2.7%|
[dm_tor](#dm_tor)|6480|6480|7|0.1%|2.7%|
[bm_tor](#bm_tor)|6505|6505|7|0.1%|2.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|6|1.6%|2.3%|
[et_tor](#et_tor)|6360|6360|6|0.0%|2.3%|
[blocklist_de_ftp](#blocklist_de_ftp)|561|561|5|0.8%|1.9%|
[xroxy](#xroxy)|2032|2032|2|0.0%|0.7%|
[openbl_60d](#openbl_60d)|7586|7586|2|0.0%|0.7%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|2|1.1%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|15029|15029|2|0.0%|0.7%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|1|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|1|0.0%|0.3%|
[ri_web_proxies](#ri_web_proxies)|5720|5720|1|0.0%|0.3%|
[proxyrss](#proxyrss)|1573|1573|1|0.0%|0.3%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.3%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|
[fullbogons](#fullbogons)|3686|670534424|1|0.0%|0.3%|
[et_block](#et_block)|997|18338381|1|0.0%|0.3%|
[bogons](#bogons)|13|592708608|1|0.0%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|13962|13962|1|0.0%|0.3%|

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
[nixspam](#nixspam)|25790|25790|56|0.2%|13.4%|
[blocklist_de](#blocklist_de)|25681|25681|45|0.1%|10.7%|
[php_commenters](#php_commenters)|281|281|32|11.3%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|31|0.0%|7.4%|
[blocklist_de_mail](#blocklist_de_mail)|15029|15029|30|0.1%|7.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|26|0.0%|6.2%|
[ri_web_proxies](#ri_web_proxies)|5720|5720|25|0.4%|5.9%|
[stopforumspam_1d](#stopforumspam_1d)|7053|7053|24|0.3%|5.7%|
[xroxy](#xroxy)|2032|2032|20|0.9%|4.7%|
[blocklist_de_bots](#blocklist_de_bots)|3204|3204|10|0.3%|2.3%|
[proxz](#proxz)|546|546|8|1.4%|1.9%|
[et_tor](#et_tor)|6360|6360|6|0.0%|1.4%|
[dm_tor](#dm_tor)|6480|6480|6|0.0%|1.4%|
[bm_tor](#bm_tor)|6505|6505|6|0.0%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|1.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2566|2566|5|0.1%|1.1%|
[blocklist_de_apache](#blocklist_de_apache)|13962|13962|5|0.0%|1.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|3|1.7%|0.7%|
[alienvault_reputation](#alienvault_reputation)|177988|177988|3|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|2|0.0%|0.4%|
[ri_connect_proxies](#ri_connect_proxies)|2116|2116|2|0.0%|0.4%|
[proxyrss](#proxyrss)|1573|1573|2|0.1%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[et_block](#et_block)|997|18338381|2|0.0%|0.4%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.2%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Tue Jun  2 12:41:26 UTC 2015.

The ipset `proxyrss` has **1573** entries, **1573** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|788|0.8%|50.0%|
[ri_web_proxies](#ri_web_proxies)|5720|5720|668|11.6%|42.4%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|659|2.1%|41.8%|
[xroxy](#xroxy)|2032|2032|483|23.7%|30.7%|
[stopforumspam_1d](#stopforumspam_1d)|7053|7053|425|6.0%|27.0%|
[ri_connect_proxies](#ri_connect_proxies)|2116|2116|231|10.9%|14.6%|
[blocklist_de](#blocklist_de)|25681|25681|225|0.8%|14.3%|
[blocklist_de_bots](#blocklist_de_bots)|3204|3204|224|6.9%|14.2%|
[proxz](#proxz)|546|546|177|32.4%|11.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|62|0.0%|3.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|57|0.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|48|0.0%|3.0%|
[nixspam](#nixspam)|25790|25790|9|0.0%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|7|4.1%|0.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|2|0.0%|0.1%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.1%|
[alienvault_reputation](#alienvault_reputation)|177988|177988|2|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.0%|
[et_tor](#et_tor)|6360|6360|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6480|6480|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6505|6505|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|561|561|1|0.1%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Tue Jun  2 15:01:42 UTC 2015.

The ipset `proxz` has **546** entries, **546** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|328|0.3%|60.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|284|0.9%|52.0%|
[xroxy](#xroxy)|2032|2032|254|12.5%|46.5%|
[ri_web_proxies](#ri_web_proxies)|5720|5720|234|4.0%|42.8%|
[proxyrss](#proxyrss)|1573|1573|177|11.2%|32.4%|
[stopforumspam_1d](#stopforumspam_1d)|7053|7053|126|1.7%|23.0%|
[blocklist_de](#blocklist_de)|25681|25681|107|0.4%|19.5%|
[blocklist_de_bots](#blocklist_de_bots)|3204|3204|91|2.8%|16.6%|
[ri_connect_proxies](#ri_connect_proxies)|2116|2116|83|3.9%|15.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|49|0.0%|8.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|27|0.0%|4.9%|
[nixspam](#nixspam)|25790|25790|24|0.0%|4.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|22|0.0%|4.0%|
[blocklist_de_mail](#blocklist_de_mail)|15029|15029|15|0.0%|2.7%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|13|0.1%|2.3%|
[php_dictionary](#php_dictionary)|433|433|9|2.0%|1.6%|
[php_spammers](#php_spammers)|417|417|8|1.9%|1.4%|
[php_commenters](#php_commenters)|281|281|3|1.0%|0.5%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|3|0.4%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|3|1.7%|0.5%|
[et_compromised](#et_compromised)|2191|2191|2|0.0%|0.3%|
[bruteforceblocker](#bruteforceblocker)|2181|2181|2|0.0%|0.3%|
[alienvault_reputation](#alienvault_reputation)|177988|177988|2|0.0%|0.3%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.1%|
[et_tor](#et_tor)|6360|6360|1|0.0%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|3843|3843|1|0.0%|0.1%|

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
[ri_web_proxies](#ri_web_proxies)|5720|5720|867|15.1%|40.9%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|678|2.1%|32.0%|
[xroxy](#xroxy)|2032|2032|330|16.2%|15.5%|
[proxyrss](#proxyrss)|1573|1573|231|14.6%|10.9%|
[stopforumspam_1d](#stopforumspam_1d)|7053|7053|138|1.9%|6.5%|
[proxz](#proxz)|546|546|83|15.2%|3.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|83|0.0%|3.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|70|0.0%|3.3%|
[blocklist_de](#blocklist_de)|25681|25681|67|0.2%|3.1%|
[blocklist_de_bots](#blocklist_de_bots)|3204|3204|66|2.0%|3.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|47|0.0%|2.2%|
[nixspam](#nixspam)|25790|25790|16|0.0%|0.7%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|3|0.0%|0.1%|
[php_dictionary](#php_dictionary)|433|433|3|0.6%|0.1%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[et_tor](#et_tor)|6360|6360|2|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|177988|177988|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[dm_tor](#dm_tor)|6480|6480|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6505|6505|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15029|15029|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Tue Jun  2 13:40:52 UTC 2015.

The ipset `ri_web_proxies` has **5720** entries, **5720** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|2805|3.0%|49.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|1748|5.5%|30.5%|
[ri_connect_proxies](#ri_connect_proxies)|2116|2116|867|40.9%|15.1%|
[xroxy](#xroxy)|2032|2032|839|41.2%|14.6%|
[proxyrss](#proxyrss)|1573|1573|668|42.4%|11.6%|
[stopforumspam_1d](#stopforumspam_1d)|7053|7053|534|7.5%|9.3%|
[blocklist_de](#blocklist_de)|25681|25681|357|1.3%|6.2%|
[blocklist_de_bots](#blocklist_de_bots)|3204|3204|320|9.9%|5.5%|
[proxz](#proxz)|546|546|234|42.8%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|175|0.0%|3.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|161|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|120|0.0%|2.0%|
[nixspam](#nixspam)|25790|25790|86|0.3%|1.5%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|56|0.6%|0.9%|
[blocklist_de_mail](#blocklist_de_mail)|15029|15029|37|0.2%|0.6%|
[php_dictionary](#php_dictionary)|433|433|33|7.6%|0.5%|
[php_spammers](#php_spammers)|417|417|25|5.9%|0.4%|
[php_commenters](#php_commenters)|281|281|11|3.9%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|10|1.4%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|5|2.9%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.0%|
[et_tor](#et_tor)|6360|6360|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6480|6480|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6505|6505|3|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|177988|177988|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2181|2181|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Tue Jun  2 14:30:04 UTC 2015.

The ipset `shunlist` has **1301** entries, **1301** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|177988|177988|1290|0.7%|99.1%|
[openbl_60d](#openbl_60d)|7586|7586|629|8.2%|48.3%|
[openbl_30d](#openbl_30d)|3179|3179|610|19.1%|46.8%|
[et_compromised](#et_compromised)|2191|2191|531|24.2%|40.8%|
[bruteforceblocker](#bruteforceblocker)|2181|2181|530|24.3%|40.7%|
[blocklist_de](#blocklist_de)|25681|25681|416|1.6%|31.9%|
[openbl_7d](#openbl_7d)|912|912|404|44.2%|31.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3843|3843|380|9.8%|29.2%|
[et_block](#et_block)|997|18338381|110|0.0%|8.4%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|103|0.0%|7.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|103|0.0%|7.9%|
[dshield](#dshield)|20|5120|74|1.4%|5.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|72|0.0%|5.5%|
[openbl_1d](#openbl_1d)|166|166|70|42.1%|5.3%|
[sslbl](#sslbl)|362|362|55|15.1%|4.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|26|0.0%|1.9%|
[blocklist_de_apache](#blocklist_de_apache)|13962|13962|26|0.1%|1.9%|
[ciarmy](#ciarmy)|331|331|24|7.2%|1.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|19|11.3%|1.4%|
[voipbl](#voipbl)|10350|10759|11|0.1%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|15029|15029|6|0.0%|0.4%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|5|0.0%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|4|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|4|0.0%|0.3%|
[blocklist_de_imap](#blocklist_de_imap)|987|987|4|0.4%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|3|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7053|7053|2|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_tor](#et_tor)|6360|6360|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6480|6480|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6505|6505|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|561|561|1|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2566|2566|1|0.0%|0.0%|

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
[bm_tor](#bm_tor)|6505|6505|1084|16.6%|12.0%|
[et_tor](#et_tor)|6360|6360|1077|16.9%|11.9%|
[dm_tor](#dm_tor)|6480|6480|1057|16.3%|11.7%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|793|0.8%|8.7%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|613|1.9%|6.8%|
[stopforumspam_1d](#stopforumspam_1d)|7053|7053|351|4.9%|3.8%|
[et_block](#et_block)|997|18338381|298|0.0%|3.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|246|0.0%|2.7%|
[nixspam](#nixspam)|25790|25790|232|0.8%|2.5%|
[zeus](#zeus)|266|266|227|85.3%|2.5%|
[zeus_badips](#zeus_badips)|230|230|202|87.8%|2.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|178|47.8%|1.9%|
[blocklist_de](#blocklist_de)|25681|25681|154|0.5%|1.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|122|0.0%|1.3%|
[alienvault_reputation](#alienvault_reputation)|177988|177988|121|0.0%|1.3%|
[blocklist_de_mail](#blocklist_de_mail)|15029|15029|114|0.7%|1.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|84|0.0%|0.9%|
[php_dictionary](#php_dictionary)|433|433|65|15.0%|0.7%|
[feodo](#feodo)|80|80|64|80.0%|0.7%|
[php_spammers](#php_spammers)|417|417|58|13.9%|0.6%|
[ri_web_proxies](#ri_web_proxies)|5720|5720|56|0.9%|0.6%|
[xroxy](#xroxy)|2032|2032|48|2.3%|0.5%|
[php_commenters](#php_commenters)|281|281|37|13.1%|0.4%|
[blocklist_de_bots](#blocklist_de_bots)|3204|3204|30|0.9%|0.3%|
[sslbl](#sslbl)|362|362|27|7.4%|0.2%|
[openbl_60d](#openbl_60d)|7586|7586|27|0.3%|0.2%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|27|2.1%|0.2%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|19|0.0%|0.2%|
[proxz](#proxz)|546|546|13|2.3%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|13|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.1%|
[palevo](#palevo)|12|12|10|83.3%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13962|13962|10|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2566|2566|7|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|6|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|356|356|6|1.6%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|987|987|6|0.6%|0.0%|
[openbl_30d](#openbl_30d)|3179|3179|5|0.1%|0.0%|
[shunlist](#shunlist)|1301|1301|4|0.3%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2116|2116|3|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.0%|
[et_compromised](#et_compromised)|2191|2191|3|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2181|2181|3|0.1%|0.0%|
[proxyrss](#proxyrss)|1573|1573|2|0.1%|0.0%|
[openbl_7d](#openbl_7d)|912|912|2|0.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3843|3843|2|0.0%|0.0%|
[virbl](#virbl)|18|18|1|5.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|1|0.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|561|561|1|0.1%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|177988|177988|1628|0.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|981|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|512|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|340|1.0%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[openbl_60d](#openbl_60d)|7586|7586|240|3.1%|0.0%|
[openbl_30d](#openbl_30d)|3179|3179|191|6.0%|0.0%|
[blocklist_de](#blocklist_de)|25681|25681|161|0.6%|0.0%|
[nixspam](#nixspam)|25790|25790|151|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3843|3843|112|2.9%|0.0%|
[shunlist](#shunlist)|1301|1301|103|7.9%|0.0%|
[et_compromised](#et_compromised)|2191|2191|102|4.6%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2181|2181|101|4.6%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7053|7053|95|1.3%|0.0%|
[openbl_7d](#openbl_7d)|912|912|86|9.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|29|2.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15029|15029|25|0.1%|0.0%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3204|3204|21|0.6%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|19|0.2%|0.0%|
[zeus_badips](#zeus_badips)|230|230|16|6.9%|0.0%|
[zeus](#zeus)|266|266|16|6.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|987|987|16|1.6%|0.0%|
[voipbl](#voipbl)|10350|10759|14|0.1%|0.0%|
[openbl_1d](#openbl_1d)|166|166|6|3.6%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|6|3.5%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[malc0de](#malc0de)|392|392|4|1.0%|0.0%|
[sslbl](#sslbl)|362|362|3|0.8%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6360|6360|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6480|6480|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6505|6505|2|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2566|2566|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13962|13962|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|107|107|1|0.9%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|177988|177988|271|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|101|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|27|0.0%|0.0%|
[blocklist_de](#blocklist_de)|25681|25681|11|0.0%|0.0%|
[php_commenters](#php_commenters)|281|281|7|2.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7053|7053|6|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|6|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7586|7586|6|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3179|3179|6|0.1%|0.0%|
[nixspam](#nixspam)|25790|25790|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|6|3.5%|0.0%|
[zeus_badips](#zeus_badips)|230|230|5|2.1%|0.0%|
[zeus](#zeus)|266|266|5|1.8%|0.0%|
[shunlist](#shunlist)|1301|1301|5|0.3%|0.0%|
[openbl_7d](#openbl_7d)|912|912|5|0.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3204|3204|5|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3843|3843|2|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15029|15029|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13962|13962|2|0.0%|0.0%|
[virbl](#virbl)|18|18|1|5.5%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[malc0de](#malc0de)|392|392|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Tue Jun  2 15:15:06 UTC 2015.

The ipset `sslbl` has **362** entries, **362** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|177988|177988|63|0.0%|17.4%|
[shunlist](#shunlist)|1301|1301|55|4.2%|15.1%|
[feodo](#feodo)|80|80|31|38.7%|8.5%|
[et_block](#et_block)|997|18338381|30|0.0%|8.2%|
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

The last time downloaded was found to be dated: Tue Jun  2 15:00:02 UTC 2015.

The ipset `stopforumspam_1d` has **7053** entries, **7053** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|5421|5.8%|76.8%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|5219|16.6%|73.9%|
[blocklist_de](#blocklist_de)|25681|25681|1416|5.5%|20.0%|
[blocklist_de_bots](#blocklist_de_bots)|3204|3204|1361|42.4%|19.2%|
[ri_web_proxies](#ri_web_proxies)|5720|5720|534|9.3%|7.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|517|0.0%|7.3%|
[proxyrss](#proxyrss)|1573|1573|425|27.0%|6.0%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|351|3.8%|4.9%|
[xroxy](#xroxy)|2032|2032|333|16.3%|4.7%|
[et_tor](#et_tor)|6360|6360|301|4.7%|4.2%|
[bm_tor](#bm_tor)|6505|6505|297|4.5%|4.2%|
[dm_tor](#dm_tor)|6480|6480|278|4.2%|3.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|255|0.0%|3.6%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|158|42.4%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|158|0.0%|2.2%|
[ri_connect_proxies](#ri_connect_proxies)|2116|2116|138|6.5%|1.9%|
[proxz](#proxz)|546|546|126|23.0%|1.7%|
[php_commenters](#php_commenters)|281|281|111|39.5%|1.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|105|62.5%|1.4%|
[et_block](#et_block)|997|18338381|96|0.0%|1.3%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|95|0.0%|1.3%|
[nixspam](#nixspam)|25790|25790|64|0.2%|0.9%|
[blocklist_de_apache](#blocklist_de_apache)|13962|13962|63|0.4%|0.8%|
[alienvault_reputation](#alienvault_reputation)|177988|177988|57|0.0%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|15029|15029|45|0.2%|0.6%|
[php_harvesters](#php_harvesters)|257|257|32|12.4%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|31|0.0%|0.4%|
[php_dictionary](#php_dictionary)|433|433|26|6.0%|0.3%|
[php_spammers](#php_spammers)|417|417|24|5.7%|0.3%|
[openbl_60d](#openbl_60d)|7586|7586|22|0.2%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2566|2566|18|0.7%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|10|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|6|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.0%|
[voipbl](#voipbl)|10350|10759|4|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[et_compromised](#et_compromised)|2191|2191|4|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2181|2181|4|0.1%|0.0%|
[shunlist](#shunlist)|1301|1301|2|0.1%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3179|3179|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|561|561|1|0.1%|0.0%|

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
[stopforumspam_1d](#stopforumspam_1d)|7053|7053|5421|76.8%|5.8%|
[ri_web_proxies](#ri_web_proxies)|5720|5720|2805|49.0%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2466|0.0%|2.6%|
[blocklist_de](#blocklist_de)|25681|25681|2318|9.0%|2.5%|
[blocklist_de_bots](#blocklist_de_bots)|3204|3204|2036|63.5%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1537|0.0%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|2116|2116|1236|58.4%|1.3%|
[xroxy](#xroxy)|2032|2032|1191|58.6%|1.2%|
[et_block](#et_block)|997|18338381|986|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|981|0.0%|1.0%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|793|8.7%|0.8%|
[proxyrss](#proxyrss)|1573|1573|788|50.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|731|0.0%|0.7%|
[et_tor](#et_tor)|6360|6360|636|10.0%|0.6%|
[bm_tor](#bm_tor)|6505|6505|621|9.5%|0.6%|
[dm_tor](#dm_tor)|6480|6480|603|9.3%|0.6%|
[proxz](#proxz)|546|546|328|60.0%|0.3%|
[nixspam](#nixspam)|25790|25790|250|0.9%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|234|62.9%|0.2%|
[alienvault_reputation](#alienvault_reputation)|177988|177988|214|0.1%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|15029|15029|209|1.3%|0.2%|
[php_commenters](#php_commenters)|281|281|206|73.3%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|13962|13962|198|1.4%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|124|73.8%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|101|0.0%|0.1%|
[php_spammers](#php_spammers)|417|417|100|23.9%|0.1%|
[php_dictionary](#php_dictionary)|433|433|85|19.6%|0.0%|
[php_harvesters](#php_harvesters)|257|257|63|24.5%|0.0%|
[openbl_60d](#openbl_60d)|7586|7586|54|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|45|0.0%|0.0%|
[voipbl](#voipbl)|10350|10759|39|0.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2566|2566|39|1.5%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|22|3.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3843|3843|19|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|16|0.0%|0.0%|
[et_compromised](#et_compromised)|2191|2191|9|0.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2181|2181|9|0.4%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|561|561|8|1.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|987|987|5|0.5%|0.0%|
[shunlist](#shunlist)|1301|1301|4|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3179|3179|4|0.1%|0.0%|
[zeus_badips](#zeus_badips)|230|230|3|1.3%|0.0%|
[zeus](#zeus)|266|266|3|1.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|3|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3686|670534424|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[sslbl](#sslbl)|362|362|1|0.2%|0.0%|
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
[stopforumspam_1d](#stopforumspam_1d)|7053|7053|5219|73.9%|16.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2085|0.0%|6.6%|
[blocklist_de](#blocklist_de)|25681|25681|2035|7.9%|6.4%|
[blocklist_de_bots](#blocklist_de_bots)|3204|3204|1862|58.1%|5.9%|
[ri_web_proxies](#ri_web_proxies)|5720|5720|1748|30.5%|5.5%|
[xroxy](#xroxy)|2032|2032|980|48.2%|3.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|934|0.0%|2.9%|
[ri_connect_proxies](#ri_connect_proxies)|2116|2116|678|32.0%|2.1%|
[proxyrss](#proxyrss)|1573|1573|659|41.8%|2.1%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|613|6.8%|1.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|558|0.0%|1.7%|
[et_tor](#et_tor)|6360|6360|491|7.7%|1.5%|
[bm_tor](#bm_tor)|6505|6505|473|7.2%|1.5%|
[dm_tor](#dm_tor)|6480|6480|456|7.0%|1.4%|
[et_block](#et_block)|997|18338381|341|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|340|0.0%|1.0%|
[proxz](#proxz)|546|546|284|52.0%|0.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|200|53.7%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|178|0.0%|0.5%|
[php_commenters](#php_commenters)|281|281|163|58.0%|0.5%|
[nixspam](#nixspam)|25790|25790|151|0.5%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|15029|15029|133|0.8%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|13962|13962|125|0.8%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|115|68.4%|0.3%|
[alienvault_reputation](#alienvault_reputation)|177988|177988|100|0.0%|0.3%|
[php_spammers](#php_spammers)|417|417|71|17.0%|0.2%|
[php_dictionary](#php_dictionary)|433|433|69|15.9%|0.2%|
[php_harvesters](#php_harvesters)|257|257|48|18.6%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2566|2566|32|1.2%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|27|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7586|7586|25|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.0%|
[voipbl](#voipbl)|10350|10759|12|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|7|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2181|2181|6|0.2%|0.0%|
[et_compromised](#et_compromised)|2191|2191|5|0.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|561|561|5|0.8%|0.0%|
[shunlist](#shunlist)|1301|1301|3|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|987|987|3|0.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1283|1283|2|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3843|3843|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|0.0%|
[zeus](#zeus)|266|266|1|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3179|3179|1|0.0%|0.0%|

## virbl

[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.

Source is downloaded from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt).

The last time downloaded was found to be dated: Tue Jun  2 14:37:02 UTC 2015.

The ipset `virbl` has **18** entries, **18** unique IPs.

The following table shows the overlaps of `virbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `virbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `virbl`.
- ` this % ` is the percentage **of this ipset (`virbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[nixspam](#nixspam)|25790|25790|2|0.0%|11.1%|
[zeus_badips](#zeus_badips)|230|230|1|0.4%|5.5%|
[zeus](#zeus)|266|266|1|0.3%|5.5%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|1|0.0%|5.5%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|1|0.0%|5.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1|0.0%|5.5%|
[et_block](#et_block)|997|18338381|1|0.0%|5.5%|
[blocklist_de_mail](#blocklist_de_mail)|15029|15029|1|0.0%|5.5%|
[blocklist_de](#blocklist_de)|25681|25681|1|0.0%|5.5%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Tue Jun  2 13:54:27 UTC 2015.

The ipset `voipbl` has **10350** entries, **10759** unique IPs.

The following table shows the overlaps of `voipbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `voipbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `voipbl`.
- ` this % ` is the percentage **of this ipset (`voipbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1591|0.0%|14.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|431|0.0%|4.0%|
[fullbogons](#fullbogons)|3686|670534424|319|0.0%|2.9%|
[bogons](#bogons)|13|592708608|319|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|295|0.0%|2.7%|
[alienvault_reputation](#alienvault_reputation)|177988|177988|209|0.1%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|39|0.0%|0.3%|
[blocklist_de](#blocklist_de)|25681|25681|38|0.1%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|107|107|28|26.1%|0.2%|
[et_block](#et_block)|997|18338381|24|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|14|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|12|0.0%|0.1%|
[shunlist](#shunlist)|1301|1301|11|0.8%|0.1%|
[openbl_60d](#openbl_60d)|7586|7586|9|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13962|13962|5|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7053|7053|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[ciarmy](#ciarmy)|331|331|4|1.2%|0.0%|
[openbl_7d](#openbl_7d)|912|912|3|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3179|3179|3|0.0%|0.0%|
[nixspam](#nixspam)|25790|25790|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[et_tor](#et_tor)|6360|6360|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6480|6480|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6505|6505|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3843|3843|2|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2566|2566|2|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3204|3204|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2191|2191|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|356|356|1|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2181|2181|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15029|15029|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|987|987|1|0.1%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Tue Jun  2 15:33:01 UTC 2015.

The ipset `xroxy` has **2032** entries, **2032** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|1191|1.2%|58.6%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|980|3.1%|48.2%|
[ri_web_proxies](#ri_web_proxies)|5720|5720|839|14.6%|41.2%|
[proxyrss](#proxyrss)|1573|1573|483|30.7%|23.7%|
[stopforumspam_1d](#stopforumspam_1d)|7053|7053|333|4.7%|16.3%|
[ri_connect_proxies](#ri_connect_proxies)|2116|2116|330|15.5%|16.2%|
[proxz](#proxz)|546|546|254|46.5%|12.5%|
[blocklist_de](#blocklist_de)|25681|25681|229|0.8%|11.2%|
[blocklist_de_bots](#blocklist_de_bots)|3204|3204|192|5.9%|9.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|99|0.0%|4.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|85|0.0%|4.1%|
[nixspam](#nixspam)|25790|25790|72|0.2%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|57|0.0%|2.8%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|48|0.5%|2.3%|
[blocklist_de_mail](#blocklist_de_mail)|15029|15029|36|0.2%|1.7%|
[php_dictionary](#php_dictionary)|433|433|24|5.5%|1.1%|
[php_spammers](#php_spammers)|417|417|20|4.7%|0.9%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|13|1.9%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|168|168|7|4.1%|0.3%|
[alienvault_reputation](#alienvault_reputation)|177988|177988|5|0.0%|0.2%|
[php_commenters](#php_commenters)|281|281|3|1.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.1%|
[et_tor](#et_tor)|6360|6360|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[dm_tor](#dm_tor)|6480|6480|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6505|6505|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2191|2191|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2181|2181|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|3843|3843|1|0.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|177988|177988|66|0.0%|24.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|19|0.0%|7.1%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|16|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|7|0.0%|2.6%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|5|0.0%|1.8%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|3|0.0%|1.1%|
[openbl_60d](#openbl_60d)|7586|7586|2|0.0%|0.7%|
[openbl_30d](#openbl_30d)|3179|3179|2|0.0%|0.7%|
[virbl](#virbl)|18|18|1|5.5%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|1|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7053|7053|1|0.0%|0.3%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.3%|
[openbl_7d](#openbl_7d)|912|912|1|0.1%|0.3%|
[nixspam](#nixspam)|25790|25790|1|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|
[et_compromised](#et_compromised)|2191|2191|1|0.0%|0.3%|
[bruteforceblocker](#bruteforceblocker)|2181|2181|1|0.0%|0.3%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Tue Jun  2 15:27:10 UTC 2015.

The ipset `zeus_badips` has **230** entries, **230** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|266|266|230|86.4%|100.0%|
[et_block](#et_block)|997|18338381|229|0.0%|99.5%|
[snort_ipfilter](#snort_ipfilter)|9012|9012|202|2.2%|87.8%|
[alienvault_reputation](#alienvault_reputation)|177988|177988|37|0.0%|16.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|16|0.0%|6.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8|0.0%|3.4%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|5|0.0%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4|0.0%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|3|0.0%|1.3%|
[virbl](#virbl)|18|18|1|5.5%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|7053|7053|1|0.0%|0.4%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.4%|
[openbl_60d](#openbl_60d)|7586|7586|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|3179|3179|1|0.0%|0.4%|
[nixspam](#nixspam)|25790|25790|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.4%|
[et_compromised](#et_compromised)|2191|2191|1|0.0%|0.4%|
[bruteforceblocker](#bruteforceblocker)|2181|2181|1|0.0%|0.4%|
