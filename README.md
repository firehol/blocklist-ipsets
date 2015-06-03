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

The following list was automatically generated on Wed Jun  3 08:20:27 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|177256 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|33951 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|13782 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|3078 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|2450 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|814 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|1838 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|15694 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|119 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|11565 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|172 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6415 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|2173 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|329 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|46 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6437 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|1007 subnets, 18338646 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botcc](#et_botcc)|[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)|ipv4 hash:ip|511 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net compromised hosts](http://doc.emergingthreats.net/bin/view/Main/CompromisedHost) - (this seems to be based on bruteforceblocker)|ipv4 hash:ip|2174 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6520 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[feodo](#feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|82 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
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
[malwaredomainlist](#malwaredomainlist)|[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses|ipv4 hash:ip|1284 unique IPs|updated every 12 hours  from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt)
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.|ipv4 hash:ip|372 unique IPs|updated every 4 hours  from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list)
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|19336 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|326 unique IPs|updated every 1 hour  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|3284 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7699 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|1035 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|281 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|433 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|257 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|417 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1672 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|593 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2185 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|5867 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1288 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|8876 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|656 subnets, 18600704 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|57 subnets, 487168 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|359 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|7113 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|92665 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|31033 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
[virbl](#virbl)|[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.|ipv4 hash:ip|16 unique IPs|updated every 1 hour  from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10367 subnets, 10776 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2044 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|269 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|234 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Wed Jun  3 04:00:22 UTC 2015.

The ipset `alienvault_reputation` has **177256** entries, **177256** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14646|0.0%|8.2%|
[openbl_60d](#openbl_60d)|7699|7699|7668|99.5%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7609|0.0%|4.2%|
[et_block](#et_block)|1007|18338646|6557|0.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4701|0.0%|2.6%|
[dshield](#dshield)|20|5120|3596|70.2%|2.0%|
[openbl_30d](#openbl_30d)|3284|3284|3259|99.2%|1.8%|
[blocklist_de](#blocklist_de)|33951|33951|2128|6.2%|1.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|11565|11565|1871|16.1%|1.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|1628|0.0%|0.9%|
[et_compromised](#et_compromised)|2174|2174|1409|64.8%|0.7%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|1397|64.2%|0.7%|
[shunlist](#shunlist)|1288|1288|1280|99.3%|0.7%|
[openbl_7d](#openbl_7d)|1035|1035|1019|98.4%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|518|0.0%|0.2%|
[openbl_1d](#openbl_1d)|326|326|314|96.3%|0.1%|
[ciarmy](#ciarmy)|329|329|311|94.5%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|289|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|271|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|217|0.2%|0.1%|
[voipbl](#voipbl)|10367|10776|197|1.8%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13782|13782|124|0.8%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|119|1.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|102|0.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|88|0.5%|0.0%|
[zeus](#zeus)|269|269|65|24.1%|0.0%|
[sslbl](#sslbl)|359|359|63|17.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1838|1838|59|3.2%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7113|7113|56|0.7%|0.0%|
[et_tor](#et_tor)|6520|6520|46|0.7%|0.0%|
[nixspam](#nixspam)|19336|19336|45|0.2%|0.0%|
[dm_tor](#dm_tor)|6437|6437|43|0.6%|0.0%|
[bm_tor](#bm_tor)|6415|6415|43|0.6%|0.0%|
[zeus_badips](#zeus_badips)|234|234|37|15.8%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|36|20.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3078|3078|27|0.8%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|25|6.7%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|119|119|20|16.8%|0.0%|
[php_commenters](#php_commenters)|281|281|14|4.9%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2450|2450|13|0.5%|0.0%|
[malc0de](#malc0de)|392|392|12|3.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|814|814|9|1.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|8|0.5%|0.0%|
[php_dictionary](#php_dictionary)|433|433|7|1.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1284|1284|6|0.4%|0.0%|
[xroxy](#xroxy)|2044|2044|5|0.2%|0.0%|
[et_botcc](#et_botcc)|511|511|4|0.7%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5867|5867|3|0.0%|0.0%|
[proxz](#proxz)|593|593|3|0.5%|0.0%|
[proxyrss](#proxyrss)|1672|1672|3|0.1%|0.0%|
[php_spammers](#php_spammers)|417|417|3|0.7%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|46|46|3|6.5%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2185|2185|2|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[feodo](#feodo)|82|82|1|1.2%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Wed Jun  3 08:10:03 UTC 2015.

The ipset `blocklist_de` has **33951** entries, **33951** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|15674|99.8%|46.1%|
[blocklist_de_apache](#blocklist_de_apache)|13782|13782|13781|99.9%|40.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|11565|11565|11565|100.0%|34.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|5845|0.0%|17.2%|
[blocklist_de_bots](#blocklist_de_bots)|3078|3078|3073|99.8%|9.0%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|2521|2.7%|7.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2450|2450|2450|100.0%|7.2%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|2181|7.0%|6.4%|
[alienvault_reputation](#alienvault_reputation)|177256|177256|2128|1.2%|6.2%|
[blocklist_de_imap](#blocklist_de_imap)|1838|1838|1838|100.0%|5.4%|
[openbl_60d](#openbl_60d)|7699|7699|1771|23.0%|5.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1555|0.0%|4.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1526|0.0%|4.4%|
[stopforumspam_1d](#stopforumspam_1d)|7113|7113|1410|19.8%|4.1%|
[openbl_30d](#openbl_30d)|3284|3284|917|27.9%|2.7%|
[blocklist_de_ftp](#blocklist_de_ftp)|814|814|814|100.0%|2.3%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|715|32.9%|2.1%|
[et_compromised](#et_compromised)|2174|2174|677|31.1%|1.9%|
[openbl_7d](#openbl_7d)|1035|1035|616|59.5%|1.8%|
[nixspam](#nixspam)|19336|19336|516|2.6%|1.5%|
[shunlist](#shunlist)|1288|1288|416|32.2%|1.2%|
[ri_web_proxies](#ri_web_proxies)|5867|5867|359|6.1%|1.0%|
[xroxy](#xroxy)|2044|2044|242|11.8%|0.7%|
[openbl_1d](#openbl_1d)|326|326|236|72.3%|0.6%|
[proxyrss](#proxyrss)|1672|1672|232|13.8%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|172|100.0%|0.5%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|165|1.8%|0.4%|
[et_block](#et_block)|1007|18338646|164|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|156|0.0%|0.4%|
[proxz](#proxz)|593|593|114|19.2%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|119|119|100|84.0%|0.2%|
[dshield](#dshield)|20|5120|79|1.5%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2185|2185|72|3.2%|0.2%|
[php_commenters](#php_commenters)|281|281|64|22.7%|0.1%|
[php_dictionary](#php_dictionary)|433|433|55|12.7%|0.1%|
[php_spammers](#php_spammers)|417|417|49|11.7%|0.1%|
[voipbl](#voipbl)|10367|10776|44|0.4%|0.1%|
[ciarmy](#ciarmy)|329|329|44|13.3%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|26|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|25|9.7%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|13|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|7|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[et_tor](#et_tor)|6520|6520|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6437|6437|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6415|6415|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[virbl](#virbl)|16|16|1|6.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1284|1284|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Wed Jun  3 07:56:08 UTC 2015.

The ipset `blocklist_de_apache` has **13782** entries, **13782** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|33951|33951|13781|40.5%|99.9%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|11059|70.4%|80.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2450|2450|2450|100.0%|17.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2250|0.0%|16.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1321|0.0%|9.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1077|0.0%|7.8%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|198|0.2%|1.4%|
[alienvault_reputation](#alienvault_reputation)|177256|177256|124|0.0%|0.8%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|119|0.3%|0.8%|
[stopforumspam_1d](#stopforumspam_1d)|7113|7113|57|0.8%|0.4%|
[ciarmy](#ciarmy)|329|329|38|11.5%|0.2%|
[shunlist](#shunlist)|1288|1288|32|2.4%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|32|18.6%|0.2%|
[php_commenters](#php_commenters)|281|281|23|8.1%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3078|3078|21|0.6%|0.1%|
[nixspam](#nixspam)|19336|19336|10|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|8|0.0%|0.0%|
[voipbl](#voipbl)|10367|10776|5|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7699|7699|4|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|3|0.7%|0.0%|
[openbl_30d](#openbl_30d)|3284|3284|3|0.0%|0.0%|
[et_tor](#et_tor)|6520|6520|3|0.0%|0.0%|
[et_block](#et_block)|1007|18338646|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6437|6437|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6415|6415|3|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|2|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[et_compromised](#et_compromised)|2174|2174|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[openbl_7d](#openbl_7d)|1035|1035|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|326|326|1|0.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Wed Jun  3 08:14:09 UTC 2015.

The ipset `blocklist_de_bots` has **3078** entries, **3078** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|33951|33951|3073|9.0%|99.8%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|2150|2.3%|69.8%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|1994|6.4%|64.7%|
[stopforumspam_1d](#stopforumspam_1d)|7113|7113|1360|19.1%|44.1%|
[ri_web_proxies](#ri_web_proxies)|5867|5867|313|5.3%|10.1%|
[proxyrss](#proxyrss)|1672|1672|229|13.6%|7.4%|
[xroxy](#xroxy)|2044|2044|201|9.8%|6.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|172|0.0%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|138|0.0%|4.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|129|75.0%|4.1%|
[proxz](#proxz)|593|593|95|16.0%|3.0%|
[ri_connect_proxies](#ri_connect_proxies)|2185|2185|69|3.1%|2.2%|
[php_commenters](#php_commenters)|281|281|49|17.4%|1.5%|
[nixspam](#nixspam)|19336|19336|37|0.1%|1.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|32|0.0%|1.0%|
[alienvault_reputation](#alienvault_reputation)|177256|177256|27|0.0%|0.8%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|23|0.2%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|21|0.1%|0.6%|
[blocklist_de_apache](#blocklist_de_apache)|13782|13782|21|0.1%|0.6%|
[et_block](#et_block)|1007|18338646|20|0.0%|0.6%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|19|0.0%|0.6%|
[php_harvesters](#php_harvesters)|257|257|19|7.3%|0.6%|
[php_dictionary](#php_dictionary)|433|433|14|3.2%|0.4%|
[php_spammers](#php_spammers)|417|417|12|2.8%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|12|0.0%|0.3%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|5|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7699|7699|3|0.0%|0.0%|
[voipbl](#voipbl)|10367|10776|2|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2174|2174|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Wed Jun  3 08:10:11 UTC 2015.

The ipset `blocklist_de_bruteforce` has **2450** entries, **2450** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_apache](#blocklist_de_apache)|13782|13782|2450|17.7%|100.0%|
[blocklist_de](#blocklist_de)|33951|33951|2450|7.2%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|157|0.0%|6.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|43|0.0%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|38|0.0%|1.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|32|0.0%|1.3%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|27|0.0%|1.1%|
[stopforumspam_1d](#stopforumspam_1d)|7113|7113|15|0.2%|0.6%|
[alienvault_reputation](#alienvault_reputation)|177256|177256|13|0.0%|0.5%|
[nixspam](#nixspam)|19336|19336|10|0.0%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|8|4.6%|0.3%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|5|0.0%|0.2%|
[php_commenters](#php_commenters)|281|281|4|1.4%|0.1%|
[php_spammers](#php_spammers)|417|417|3|0.7%|0.1%|
[voipbl](#voipbl)|10367|10776|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|2|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[et_block](#et_block)|1007|18338646|2|0.0%|0.0%|
[shunlist](#shunlist)|1288|1288|1|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7699|7699|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|1|0.0%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Wed Jun  3 07:56:09 UTC 2015.

The ipset `blocklist_de_ftp` has **814** entries, **814** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|33951|33951|814|2.3%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|73|0.0%|8.9%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|11|0.0%|1.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|11|0.0%|1.3%|
[alienvault_reputation](#alienvault_reputation)|177256|177256|9|0.0%|1.1%|
[nixspam](#nixspam)|19336|19336|8|0.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|7|0.0%|0.8%|
[php_harvesters](#php_harvesters)|257|257|5|1.9%|0.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|0.6%|
[stopforumspam_1d](#stopforumspam_1d)|7113|7113|3|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7699|7699|2|0.0%|0.2%|
[shunlist](#shunlist)|1288|1288|1|0.0%|0.1%|
[openbl_7d](#openbl_7d)|1035|1035|1|0.0%|0.1%|
[openbl_30d](#openbl_30d)|3284|3284|1|0.0%|0.1%|
[et_compromised](#et_compromised)|2174|2174|1|0.0%|0.1%|
[dshield](#dshield)|20|5120|1|0.0%|0.1%|
[ciarmy](#ciarmy)|329|329|1|0.3%|0.1%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|1|0.0%|0.1%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Wed Jun  3 07:56:09 UTC 2015.

The ipset `blocklist_de_imap` has **1838** entries, **1838** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|1838|11.7%|100.0%|
[blocklist_de](#blocklist_de)|33951|33951|1838|5.4%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|179|0.0%|9.7%|
[alienvault_reputation](#alienvault_reputation)|177256|177256|59|0.0%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|50|0.0%|2.7%|
[openbl_60d](#openbl_60d)|7699|7699|43|0.5%|2.3%|
[openbl_30d](#openbl_30d)|3284|3284|39|1.1%|2.1%|
[openbl_7d](#openbl_7d)|1035|1035|19|1.8%|1.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|16|0.0%|0.8%|
[et_block](#et_block)|1007|18338646|15|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|14|0.0%|0.7%|
[nixspam](#nixspam)|19336|19336|13|0.0%|0.7%|
[et_compromised](#et_compromised)|2174|2174|7|0.3%|0.3%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|7|0.3%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|6|0.0%|0.3%|
[shunlist](#shunlist)|1288|1288|5|0.3%|0.2%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|4|0.0%|0.2%|
[openbl_1d](#openbl_1d)|326|326|4|1.2%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|3|0.0%|0.1%|
[ciarmy](#ciarmy)|329|329|1|0.3%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|1|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|11565|11565|1|0.0%|0.0%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Wed Jun  3 07:56:06 UTC 2015.

The ipset `blocklist_de_mail` has **15694** entries, **15694** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|33951|33951|15674|46.1%|99.8%|
[blocklist_de_apache](#blocklist_de_apache)|13782|13782|11059|80.2%|70.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2389|0.0%|15.2%|
[blocklist_de_imap](#blocklist_de_imap)|1838|1838|1838|100.0%|11.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1329|0.0%|8.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1140|0.0%|7.2%|
[nixspam](#nixspam)|19336|19336|398|2.0%|2.5%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|231|0.2%|1.4%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|140|0.4%|0.8%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|135|1.5%|0.8%|
[alienvault_reputation](#alienvault_reputation)|177256|177256|88|0.0%|0.5%|
[openbl_60d](#openbl_60d)|7699|7699|54|0.7%|0.3%|
[openbl_30d](#openbl_30d)|3284|3284|48|1.4%|0.3%|
[ri_web_proxies](#ri_web_proxies)|5867|5867|46|0.7%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7113|7113|40|0.5%|0.2%|
[xroxy](#xroxy)|2044|2044|39|1.9%|0.2%|
[php_dictionary](#php_dictionary)|433|433|39|9.0%|0.2%|
[php_spammers](#php_spammers)|417|417|33|7.9%|0.2%|
[et_block](#et_block)|1007|18338646|26|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|24|0.0%|0.1%|
[openbl_7d](#openbl_7d)|1035|1035|22|2.1%|0.1%|
[php_commenters](#php_commenters)|281|281|21|7.4%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3078|3078|21|0.6%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|20|11.6%|0.1%|
[proxz](#proxz)|593|593|16|2.6%|0.1%|
[et_compromised](#et_compromised)|2174|2174|12|0.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|12|0.5%|0.0%|
[shunlist](#shunlist)|1288|1288|7|0.5%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|4|0.0%|0.0%|
[openbl_1d](#openbl_1d)|326|326|4|1.2%|0.0%|
[et_tor](#et_tor)|6520|6520|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6437|6437|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6415|6415|3|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2185|2185|2|0.0%|0.0%|
[proxyrss](#proxyrss)|1672|1672|2|0.1%|0.0%|
[ciarmy](#ciarmy)|329|329|2|0.6%|0.0%|
[voipbl](#voipbl)|10367|10776|1|0.0%|0.0%|
[virbl](#virbl)|16|16|1|6.2%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|11565|11565|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2450|2450|1|0.0%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Wed Jun  3 08:10:08 UTC 2015.

The ipset `blocklist_de_sip` has **119** entries, **119** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|33951|33951|100|0.2%|84.0%|
[voipbl](#voipbl)|10367|10776|33|0.3%|27.7%|
[alienvault_reputation](#alienvault_reputation)|177256|177256|20|0.0%|16.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14|0.0%|11.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|6|0.0%|5.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|2.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|1.6%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|1|0.0%|0.8%|
[et_botcc](#et_botcc)|511|511|1|0.1%|0.8%|
[et_block](#et_block)|1007|18338646|1|0.0%|0.8%|
[ciarmy](#ciarmy)|329|329|1|0.3%|0.8%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Wed Jun  3 08:10:03 UTC 2015.

The ipset `blocklist_de_ssh` has **11565** entries, **11565** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|33951|33951|11565|34.0%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|3021|0.0%|26.1%|
[alienvault_reputation](#alienvault_reputation)|177256|177256|1871|1.0%|16.1%|
[openbl_60d](#openbl_60d)|7699|7699|1709|22.1%|14.7%|
[openbl_30d](#openbl_30d)|3284|3284|866|26.3%|7.4%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|700|32.2%|6.0%|
[et_compromised](#et_compromised)|2174|2174|662|30.4%|5.7%|
[openbl_7d](#openbl_7d)|1035|1035|593|57.2%|5.1%|
[shunlist](#shunlist)|1288|1288|377|29.2%|3.2%|
[openbl_1d](#openbl_1d)|326|326|232|71.1%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|211|0.0%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|118|0.0%|1.0%|
[et_block](#et_block)|1007|18338646|114|0.0%|0.9%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|110|0.0%|0.9%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|90|0.0%|0.7%|
[dshield](#dshield)|20|5120|75|1.4%|0.6%|
[nixspam](#nixspam)|19336|19336|57|0.2%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|27|15.6%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|15|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6|0.0%|0.0%|
[voipbl](#voipbl)|10367|10776|3|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.0%|
[xroxy](#xroxy)|2044|2044|2|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|2|0.0%|0.0%|
[proxz](#proxz)|593|593|2|0.3%|0.0%|
[ciarmy](#ciarmy)|329|329|2|0.6%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7113|7113|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2185|2185|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1672|1672|1|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1284|1284|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1838|1838|1|0.0%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Wed Jun  3 08:10:10 UTC 2015.

The ipset `blocklist_de_strongips` has **172** entries, **172** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|33951|33951|172|0.5%|100.0%|
[blocklist_de_bots](#blocklist_de_bots)|3078|3078|129|4.1%|75.0%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|127|0.1%|73.8%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|117|0.3%|68.0%|
[stopforumspam_1d](#stopforumspam_1d)|7113|7113|102|1.4%|59.3%|
[alienvault_reputation](#alienvault_reputation)|177256|177256|36|0.0%|20.9%|
[blocklist_de_apache](#blocklist_de_apache)|13782|13782|32|0.2%|18.6%|
[php_commenters](#php_commenters)|281|281|29|10.3%|16.8%|
[openbl_60d](#openbl_60d)|7699|7699|27|0.3%|15.6%|
[blocklist_de_ssh](#blocklist_de_ssh)|11565|11565|27|0.2%|15.6%|
[openbl_7d](#openbl_7d)|1035|1035|24|2.3%|13.9%|
[openbl_30d](#openbl_30d)|3284|3284|24|0.7%|13.9%|
[shunlist](#shunlist)|1288|1288|20|1.5%|11.6%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|20|0.1%|11.6%|
[openbl_1d](#openbl_1d)|326|326|18|5.5%|10.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|16|0.0%|9.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2450|2450|8|0.3%|4.6%|
[xroxy](#xroxy)|2044|2044|7|0.3%|4.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|7|0.0%|4.0%|
[proxyrss](#proxyrss)|1672|1672|7|0.4%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7|0.0%|4.0%|
[et_block](#et_block)|1007|18338646|7|0.0%|4.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|6|0.0%|3.4%|
[ri_web_proxies](#ri_web_proxies)|5867|5867|5|0.0%|2.9%|
[proxz](#proxz)|593|593|3|0.5%|1.7%|
[php_spammers](#php_spammers)|417|417|3|0.7%|1.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.7%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|1.1%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|1.1%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|1|0.0%|0.5%|
[nixspam](#nixspam)|19336|19336|1|0.0%|0.5%|
[blocklist_de_imap](#blocklist_de_imap)|1838|1838|1|0.0%|0.5%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Wed Jun  3 08:00:13 UTC 2015.

The ipset `bm_tor` has **6415** entries, **6415** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[dm_tor](#dm_tor)|6437|6437|6339|98.4%|98.8%|
[et_tor](#et_tor)|6520|6520|5804|89.0%|90.4%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|1052|11.8%|16.3%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|626|0.6%|9.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|626|0.0%|9.7%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|478|1.5%|7.4%|
[stopforumspam_1d](#stopforumspam_1d)|7113|7113|291|4.0%|4.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|186|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|171|45.9%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|166|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|177256|177256|43|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[openbl_60d](#openbl_60d)|7699|7699|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13782|13782|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|33951|33951|3|0.0%|0.0%|
[xroxy](#xroxy)|2044|2044|2|0.0%|0.0%|
[voipbl](#voipbl)|10367|10776|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|2|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5867|5867|2|0.0%|0.0%|
[et_block](#et_block)|1007|18338646|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[shunlist](#shunlist)|1288|1288|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2185|2185|1|0.0%|0.0%|
[nixspam](#nixspam)|19336|19336|1|0.0%|0.0%|

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

The last time downloaded was found to be dated: Wed Jun  3 08:18:29 UTC 2015.

The ipset `bruteforceblocker` has **2173** entries, **2173** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_compromised](#et_compromised)|2174|2174|2113|97.1%|97.2%|
[alienvault_reputation](#alienvault_reputation)|177256|177256|1397|0.7%|64.2%|
[openbl_60d](#openbl_60d)|7699|7699|1302|16.9%|59.9%|
[openbl_30d](#openbl_30d)|3284|3284|1226|37.3%|56.4%|
[blocklist_de](#blocklist_de)|33951|33951|715|2.1%|32.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|11565|11565|700|6.0%|32.2%|
[shunlist](#shunlist)|1288|1288|512|39.7%|23.5%|
[openbl_7d](#openbl_7d)|1035|1035|506|48.8%|23.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|218|0.0%|10.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|112|0.0%|5.1%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|100|0.0%|4.6%|
[et_block](#et_block)|1007|18338646|100|0.0%|4.6%|
[openbl_1d](#openbl_1d)|326|326|89|27.3%|4.0%|
[dshield](#dshield)|20|5120|82|1.6%|3.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|62|0.0%|2.8%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|12|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|10|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|1838|1838|7|0.3%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|6|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[voipbl](#voipbl)|10367|10776|2|0.0%|0.0%|
[proxz](#proxz)|593|593|2|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13782|13782|2|0.0%|0.0%|
[xroxy](#xroxy)|2044|2044|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7113|7113|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5867|5867|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3686|670534424|1|0.0%|0.0%|
[ciarmy](#ciarmy)|329|329|1|0.3%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|814|814|1|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3078|3078|1|0.0%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Wed Jun  3 07:15:15 UTC 2015.

The ipset `ciarmy` has **329** entries, **329** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|177256|177256|311|0.1%|94.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|56|0.0%|17.0%|
[blocklist_de](#blocklist_de)|33951|33951|44|0.1%|13.3%|
[blocklist_de_apache](#blocklist_de_apache)|13782|13782|38|0.2%|11.5%|
[shunlist](#shunlist)|1288|1288|24|1.8%|7.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|12|0.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|9|0.0%|2.7%|
[voipbl](#voipbl)|10367|10776|6|0.0%|1.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|11565|11565|2|0.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|2|0.0%|0.6%|
[openbl_7d](#openbl_7d)|1035|1035|1|0.0%|0.3%|
[openbl_60d](#openbl_60d)|7699|7699|1|0.0%|0.3%|
[openbl_30d](#openbl_30d)|3284|3284|1|0.0%|0.3%|
[et_block](#et_block)|1007|18338646|1|0.0%|0.3%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|1|0.0%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|119|119|1|0.8%|0.3%|
[blocklist_de_imap](#blocklist_de_imap)|1838|1838|1|0.0%|0.3%|
[blocklist_de_ftp](#blocklist_de_ftp)|814|814|1|0.1%|0.3%|

## cleanmx_viruses

[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses

Source is downloaded from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive).

The last time downloaded was found to be dated: Wed Jun  3 06:54:47 UTC 2015.

The ipset `cleanmx_viruses` has **46** entries, **46** unique IPs.

The following table shows the overlaps of `cleanmx_viruses` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `cleanmx_viruses`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `cleanmx_viruses`.
- ` this % ` is the percentage **of this ipset (`cleanmx_viruses`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|5|0.0%|10.8%|
[malc0de](#malc0de)|392|392|3|0.7%|6.5%|
[alienvault_reputation](#alienvault_reputation)|177256|177256|3|0.0%|6.5%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|1|0.0%|2.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1|0.0%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1|0.0%|2.1%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Wed Jun  3 08:00:10 UTC 2015.

The ipset `dm_tor` has **6437** entries, **6437** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6415|6415|6339|98.8%|98.4%|
[et_tor](#et_tor)|6520|6520|5788|88.7%|89.9%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|1059|11.9%|16.4%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|629|0.6%|9.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|627|0.0%|9.7%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|479|1.5%|7.4%|
[stopforumspam_1d](#stopforumspam_1d)|7113|7113|290|4.0%|4.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|187|0.0%|2.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|171|45.9%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|166|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|177256|177256|43|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[openbl_60d](#openbl_60d)|7699|7699|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13782|13782|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|33951|33951|3|0.0%|0.0%|
[xroxy](#xroxy)|2044|2044|2|0.0%|0.0%|
[voipbl](#voipbl)|10367|10776|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|2|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5867|5867|2|0.0%|0.0%|
[et_block](#et_block)|1007|18338646|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[shunlist](#shunlist)|1288|1288|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2185|2185|1|0.0%|0.0%|
[nixspam](#nixspam)|19336|19336|1|0.0%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Wed Jun  3 07:23:46 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|177256|177256|3596|2.0%|70.2%|
[et_block](#et_block)|1007|18338646|1536|0.0%|30.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|768|0.0%|15.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|256|0.0%|5.0%|
[openbl_60d](#openbl_60d)|7699|7699|144|1.8%|2.8%|
[openbl_30d](#openbl_30d)|3284|3284|123|3.7%|2.4%|
[shunlist](#shunlist)|1288|1288|94|7.2%|1.8%|
[et_compromised](#et_compromised)|2174|2174|82|3.7%|1.6%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|82|3.7%|1.6%|
[blocklist_de](#blocklist_de)|33951|33951|79|0.2%|1.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|11565|11565|75|0.6%|1.4%|
[openbl_7d](#openbl_7d)|1035|1035|65|6.2%|1.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|11|0.0%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[openbl_1d](#openbl_1d)|326|326|3|0.9%|0.0%|
[malc0de](#malc0de)|392|392|2|0.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[et_tor](#et_tor)|6520|6520|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6437|6437|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6415|6415|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13782|13782|2|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|1|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7113|7113|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|814|814|1|0.1%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|177256|177256|6557|3.6%|0.0%|
[dshield](#dshield)|20|5120|1536|30.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1041|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|1002|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|517|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|345|1.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|305|3.4%|0.0%|
[zeus](#zeus)|269|269|263|97.7%|0.0%|
[openbl_60d](#openbl_60d)|7699|7699|244|3.1%|0.0%|
[zeus_badips](#zeus_badips)|234|234|230|98.2%|0.0%|
[openbl_30d](#openbl_30d)|3284|3284|165|5.0%|0.0%|
[blocklist_de](#blocklist_de)|33951|33951|164|0.4%|0.0%|
[nixspam](#nixspam)|19336|19336|138|0.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|11565|11565|114|0.9%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7113|7113|106|1.4%|0.0%|
[shunlist](#shunlist)|1288|1288|106|8.2%|0.0%|
[et_compromised](#et_compromised)|2174|2174|102|4.6%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|100|4.6%|0.0%|
[openbl_7d](#openbl_7d)|1035|1035|85|8.2%|0.0%|
[feodo](#feodo)|82|82|77|93.9%|0.0%|
[sslbl](#sslbl)|359|359|34|9.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1284|1284|29|2.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|26|0.1%|0.0%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3078|3078|20|0.6%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1838|1838|15|0.8%|0.0%|
[voipbl](#voipbl)|10367|10776|14|0.1%|0.0%|
[palevo](#palevo)|13|13|13|100.0%|0.0%|
[openbl_1d](#openbl_1d)|326|326|13|3.9%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|11|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|7|4.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[malc0de](#malc0de)|392|392|4|1.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13782|13782|3|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6520|6520|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6437|6437|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6415|6415|2|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2450|2450|2|0.0%|0.0%|
[xroxy](#xroxy)|2044|2044|1|0.0%|0.0%|
[proxz](#proxz)|593|593|1|0.1%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[et_botcc](#et_botcc)|511|511|1|0.1%|0.0%|
[ciarmy](#ciarmy)|329|329|1|0.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|119|119|1|0.8%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|177256|177256|4|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1284|1284|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[et_block](#et_block)|1007|18338646|1|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|119|119|1|0.8%|0.1%|

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
[bruteforceblocker](#bruteforceblocker)|2173|2173|2113|97.2%|97.1%|
[alienvault_reputation](#alienvault_reputation)|177256|177256|1409|0.7%|64.8%|
[openbl_60d](#openbl_60d)|7699|7699|1315|17.0%|60.4%|
[openbl_30d](#openbl_30d)|3284|3284|1230|37.4%|56.5%|
[blocklist_de](#blocklist_de)|33951|33951|677|1.9%|31.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|11565|11565|662|5.7%|30.4%|
[shunlist](#shunlist)|1288|1288|512|39.7%|23.5%|
[openbl_7d](#openbl_7d)|1035|1035|503|48.5%|23.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|217|0.0%|9.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|112|0.0%|5.1%|
[et_block](#et_block)|1007|18338646|102|0.0%|4.6%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|101|0.0%|4.6%|
[openbl_1d](#openbl_1d)|326|326|87|26.6%|4.0%|
[dshield](#dshield)|20|5120|82|1.6%|3.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|61|0.0%|2.8%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|12|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|8|0.0%|0.3%|
[blocklist_de_imap](#blocklist_de_imap)|1838|1838|7|0.3%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|5|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|2|0.0%|0.0%|
[proxz](#proxz)|593|593|2|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13782|13782|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|234|234|1|0.4%|0.0%|
[zeus](#zeus)|269|269|1|0.3%|0.0%|
[xroxy](#xroxy)|2044|2044|1|0.0%|0.0%|
[voipbl](#voipbl)|10367|10776|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7113|7113|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|814|814|1|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3078|3078|1|0.0%|0.0%|

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
[bm_tor](#bm_tor)|6415|6415|5804|90.4%|89.0%|
[dm_tor](#dm_tor)|6437|6437|5788|89.9%|88.7%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|1112|12.5%|17.0%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|643|0.6%|9.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|635|0.0%|9.7%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|492|1.5%|7.5%|
[stopforumspam_1d](#stopforumspam_1d)|7113|7113|290|4.0%|4.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|188|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|170|45.6%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|170|0.0%|2.6%|
[alienvault_reputation](#alienvault_reputation)|177256|177256|46|0.0%|0.7%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[openbl_60d](#openbl_60d)|7699|7699|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5867|5867|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13782|13782|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|33951|33951|3|0.0%|0.0%|
[xroxy](#xroxy)|2044|2044|2|0.0%|0.0%|
[voipbl](#voipbl)|10367|10776|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|2|0.0%|0.0%|
[et_block](#et_block)|1007|18338646|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[shunlist](#shunlist)|1288|1288|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2185|2185|1|0.0%|0.0%|
[nixspam](#nixspam)|19336|19336|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Wed Jun  3 08:00:33 UTC 2015.

The ipset `feodo` has **82** entries, **82** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|1007|18338646|77|0.0%|93.9%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|64|0.7%|78.0%|
[sslbl](#sslbl)|359|359|31|8.6%|37.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|7|0.0%|8.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|3|0.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|3.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|1.2%|
[alienvault_reputation](#alienvault_reputation)|177256|177256|1|0.0%|1.2%|

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
[malwaredomainlist](#malwaredomainlist)|1284|1284|9|0.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|1|0.0%|0.0%|

## ib_bluetack_badpeers

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) IPs that have been reported for bad deeds in p2p

Source is downloaded from [this link](http://list.iblocklist.com/?list=cwworuawihqvocglcoss&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Wed Jun  3 04:21:00 UTC 2015.

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
[alienvault_reputation](#alienvault_reputation)|177256|177256|14|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.0%|
[et_block](#et_block)|1007|18338646|11|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|7|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|6|0.0%|0.0%|
[nixspam](#nixspam)|19336|19336|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[dshield](#dshield)|20|5120|4|0.0%|0.0%|
[blocklist_de](#blocklist_de)|33951|33951|4|0.0%|0.0%|
[xroxy](#xroxy)|2044|2044|3|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|3|0.0%|0.0%|
[voipbl](#voipbl)|10367|10776|2|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7113|7113|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2450|2450|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13782|13782|2|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5867|5867|1|0.0%|0.0%|
[proxz](#proxz)|593|593|1|0.1%|0.0%|
[proxyrss](#proxyrss)|1672|1672|1|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3078|3078|1|0.0%|0.0%|

## ib_bluetack_hijacked

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) hijacked IP-Blocks Hijacked IP space are IP blocks that are being used without permission

Source is downloaded from [this link](http://list.iblocklist.com/?list=usrcshglbiilevmyfhse&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Wed Jun  3 04:50:06 UTC 2015.

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
[alienvault_reputation](#alienvault_reputation)|177256|177256|518|0.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|174|0.5%|0.0%|
[nixspam](#nixspam)|19336|19336|138|0.7%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7113|7113|37|0.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1284|1284|27|2.1%|0.0%|
[blocklist_de](#blocklist_de)|33951|33951|26|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7699|7699|18|0.2%|0.0%|
[openbl_30d](#openbl_30d)|3284|3284|13|0.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3078|3078|12|0.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|11|0.1%|0.0%|
[zeus_badips](#zeus_badips)|234|234|10|4.2%|0.0%|
[zeus](#zeus)|269|269|10|3.7%|0.0%|
[openbl_7d](#openbl_7d)|1035|1035|9|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|7|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|11565|11565|6|0.0%|0.0%|
[et_compromised](#et_compromised)|2174|2174|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|5|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1838|1838|4|0.2%|0.0%|
[shunlist](#shunlist)|1288|1288|3|0.2%|0.0%|
[openbl_1d](#openbl_1d)|326|326|3|0.9%|0.0%|
[et_tor](#et_tor)|6520|6520|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6437|6437|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6415|6415|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|3|1.7%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[voipbl](#voipbl)|10367|10776|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.0%|
[et_botcc](#et_botcc)|511|511|1|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2450|2450|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13782|13782|1|0.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|177256|177256|4701|2.6%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|1545|1.6%|0.0%|
[blocklist_de](#blocklist_de)|33951|33951|1526|4.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|1329|8.4%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13782|13782|1321|9.5%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|581|1.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|406|0.8%|0.0%|
[nixspam](#nixspam)|19336|19336|362|1.8%|0.0%|
[voipbl](#voipbl)|10367|10776|296|2.7%|0.0%|
[openbl_60d](#openbl_60d)|7699|7699|172|2.2%|0.0%|
[et_tor](#et_tor)|6520|6520|170|2.6%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7113|7113|168|2.3%|0.0%|
[dm_tor](#dm_tor)|6437|6437|166|2.5%|0.0%|
[bm_tor](#bm_tor)|6415|6415|166|2.5%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5867|5867|125|2.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|11565|11565|118|1.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|97|6.6%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|93|1.0%|0.0%|
[openbl_30d](#openbl_30d)|3284|3284|74|2.2%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2185|2185|72|3.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1284|1284|66|5.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|62|2.8%|0.0%|
[et_compromised](#et_compromised)|2174|2174|61|2.8%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|58|8.6%|0.0%|
[xroxy](#xroxy)|2044|2044|57|2.7%|0.0%|
[proxyrss](#proxyrss)|1672|1672|44|2.6%|0.0%|
[et_botcc](#et_botcc)|511|511|42|8.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2450|2450|32|1.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3078|3078|32|1.0%|0.0%|
[shunlist](#shunlist)|1288|1288|26|2.0%|0.0%|
[proxz](#proxz)|593|593|24|4.0%|0.0%|
[openbl_7d](#openbl_7d)|1035|1035|22|2.1%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|17|4.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1838|1838|16|0.8%|0.0%|
[malc0de](#malc0de)|392|392|12|3.0%|0.0%|
[dshield](#dshield)|20|5120|11|0.2%|0.0%|
[php_dictionary](#php_dictionary)|433|433|9|2.0%|0.0%|
[openbl_1d](#openbl_1d)|326|326|9|2.7%|0.0%|
[ciarmy](#ciarmy)|329|329|9|2.7%|0.0%|
[zeus](#zeus)|269|269|7|2.6%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.0%|
[php_commenters](#php_commenters)|281|281|5|1.7%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|814|814|5|0.6%|0.0%|
[zeus_badips](#zeus_badips)|234|234|4|1.7%|0.0%|
[sslbl](#sslbl)|359|359|3|0.8%|0.0%|
[feodo](#feodo)|82|82|3|3.6%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|119|119|3|2.5%|0.0%|
[virbl](#virbl)|16|16|2|12.5%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|46|46|1|2.1%|0.0%|

## ib_bluetack_level2

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 2 (for use in p2p). General corporate ranges. Ranges used by labs or researchers. Proxies.

Source is downloaded from [this link](http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Wed Jun  3 04:50:23 UTC 2015.

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
[alienvault_reputation](#alienvault_reputation)|177256|177256|7609|4.2%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|2510|2.7%|0.0%|
[blocklist_de](#blocklist_de)|33951|33951|1555|4.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|1140|7.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13782|13782|1077|7.8%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|940|3.0%|0.0%|
[dshield](#dshield)|20|5120|768|15.0%|0.0%|
[nixspam](#nixspam)|19336|19336|521|2.6%|0.0%|
[voipbl](#voipbl)|10367|10776|432|4.0%|0.0%|
[openbl_60d](#openbl_60d)|7699|7699|340|4.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7113|7113|268|3.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|230|0.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|11565|11565|211|1.8%|0.0%|
[et_tor](#et_tor)|6520|6520|188|2.8%|0.0%|
[dm_tor](#dm_tor)|6437|6437|187|2.9%|0.0%|
[bm_tor](#bm_tor)|6415|6415|186|2.8%|0.0%|
[openbl_30d](#openbl_30d)|3284|3284|178|5.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5867|5867|177|3.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3078|3078|138|4.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|116|1.3%|0.0%|
[et_compromised](#et_compromised)|2174|2174|112|5.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|112|5.1%|0.0%|
[xroxy](#xroxy)|2044|2044|99|4.8%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2185|2185|88|4.0%|0.0%|
[shunlist](#shunlist)|1288|1288|71|5.5%|0.0%|
[proxyrss](#proxyrss)|1672|1672|68|4.0%|0.0%|
[openbl_7d](#openbl_7d)|1035|1035|50|4.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1838|1838|50|2.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|45|3.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2450|2450|43|1.7%|0.0%|
[php_spammers](#php_spammers)|417|417|31|7.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|28|4.1%|0.0%|
[proxz](#proxz)|593|593|27|4.5%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1284|1284|26|2.0%|0.0%|
[malc0de](#malc0de)|392|392|24|6.1%|0.0%|
[et_botcc](#et_botcc)|511|511|22|4.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|21|5.6%|0.0%|
[openbl_1d](#openbl_1d)|326|326|14|4.2%|0.0%|
[ciarmy](#ciarmy)|329|329|12|3.6%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|814|814|11|1.3%|0.0%|
[php_dictionary](#php_dictionary)|433|433|10|2.3%|0.0%|
[zeus](#zeus)|269|269|9|3.3%|0.0%|
[php_commenters](#php_commenters)|281|281|9|3.2%|0.0%|
[zeus_badips](#zeus_badips)|234|234|8|3.4%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|7|4.0%|0.0%|
[sslbl](#sslbl)|359|359|6|1.6%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|119|119|6|5.0%|0.0%|
[palevo](#palevo)|13|13|3|23.0%|0.0%|
[feodo](#feodo)|82|82|3|3.6%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|46|46|1|2.1%|0.0%|

## ib_bluetack_level3

[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 3 (for use in p2p). Many portal-type websites. ISP ranges that may be dodgy for some reason. Ranges that belong to an individual, but which have not been determined to be used by a particular company. Ranges for things that are unusual in some way. The L3 list is aka the paranoid list.

Source is downloaded from [this link](http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Wed Jun  3 04:50:33 UTC 2015.

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
[alienvault_reputation](#alienvault_reputation)|177256|177256|14646|8.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|9231|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|5884|6.3%|0.0%|
[blocklist_de](#blocklist_de)|33951|33951|5845|17.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|11565|11565|3021|26.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|2389|15.2%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13782|13782|2250|16.3%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|2017|6.4%|0.0%|
[voipbl](#voipbl)|10367|10776|1593|14.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1172|2.4%|0.0%|
[nixspam](#nixspam)|19336|19336|1125|5.8%|0.0%|
[openbl_60d](#openbl_60d)|7699|7699|748|9.7%|0.0%|
[et_tor](#et_tor)|6520|6520|635|9.7%|0.0%|
[dm_tor](#dm_tor)|6437|6437|627|9.7%|0.0%|
[bm_tor](#bm_tor)|6415|6415|626|9.7%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7113|7113|453|6.3%|0.0%|
[openbl_30d](#openbl_30d)|3284|3284|320|9.7%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|246|2.7%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|218|10.0%|0.0%|
[et_compromised](#et_compromised)|2174|2174|217|9.9%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1838|1838|179|9.7%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3078|3078|172|5.5%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5867|5867|166|2.8%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2450|2450|157|6.4%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1284|1284|146|11.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|125|33.6%|0.0%|
[openbl_7d](#openbl_7d)|1035|1035|116|11.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|110|7.5%|0.0%|
[shunlist](#shunlist)|1288|1288|104|8.0%|0.0%|
[xroxy](#xroxy)|2044|2044|88|4.3%|0.0%|
[et_botcc](#et_botcc)|511|511|77|15.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|814|814|73|8.9%|0.0%|
[malc0de](#malc0de)|392|392|67|17.0%|0.0%|
[proxyrss](#proxyrss)|1672|1672|64|3.8%|0.0%|
[ciarmy](#ciarmy)|329|329|56|17.0%|0.0%|
[proxz](#proxz)|593|593|53|8.9%|0.0%|
[openbl_1d](#openbl_1d)|326|326|51|15.6%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|51|7.5%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2185|2185|48|2.1%|0.0%|
[php_spammers](#php_spammers)|417|417|26|6.2%|0.0%|
[php_dictionary](#php_dictionary)|433|433|24|5.5%|0.0%|
[sslbl](#sslbl)|359|359|23|6.4%|0.0%|
[zeus](#zeus)|269|269|18|6.6%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|16|9.3%|0.0%|
[php_harvesters](#php_harvesters)|257|257|15|5.8%|0.0%|
[php_commenters](#php_commenters)|281|281|15|5.3%|0.0%|
[zeus_badips](#zeus_badips)|234|234|14|5.9%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|119|119|14|11.7%|0.0%|
[feodo](#feodo)|82|82|7|8.5%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|46|46|5|10.8%|0.0%|
[virbl](#virbl)|16|16|3|18.7%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|

## ib_bluetack_proxies

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Open Proxies IPs list (without TOR)

Source is downloaded from [this link](http://list.iblocklist.com/?list=xoebmbyexwuiogmbyprb&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Wed Jun  3 04:50:06 UTC 2015.

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
[xroxy](#xroxy)|2044|2044|13|0.6%|1.9%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|12|0.0%|1.7%|
[ri_web_proxies](#ri_web_proxies)|5867|5867|11|0.1%|1.6%|
[proxyrss](#proxyrss)|1672|1672|11|0.6%|1.6%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|11|0.0%|1.6%|
[stopforumspam_1d](#stopforumspam_1d)|7113|7113|7|0.0%|1.0%|
[ri_connect_proxies](#ri_connect_proxies)|2185|2185|6|0.2%|0.8%|
[proxz](#proxz)|593|593|3|0.5%|0.4%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|2|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|2|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.2%|
[et_block](#et_block)|1007|18338646|2|0.0%|0.2%|
[blocklist_de](#blocklist_de)|33951|33951|2|0.0%|0.2%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.1%|
[nixspam](#nixspam)|19336|19336|1|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|1|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3078|3078|1|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|177256|177256|1|0.0%|0.1%|

## ib_bluetack_spyware

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) known malicious SPYWARE and ADWARE IP Address ranges

Source is downloaded from [this link](http://list.iblocklist.com/?list=llvtlsjyoyiczbkjsxpf&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Wed Jun  3 04:20:04 UTC 2015.

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
[alienvault_reputation](#alienvault_reputation)|177256|177256|289|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|48|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1284|1284|27|2.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|26|0.0%|0.0%|
[et_tor](#et_tor)|6520|6520|21|0.3%|0.0%|
[dm_tor](#dm_tor)|6437|6437|21|0.3%|0.0%|
[bm_tor](#bm_tor)|6415|6415|21|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|19|1.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|14|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7113|7113|13|0.1%|0.0%|
[nixspam](#nixspam)|19336|19336|11|0.0%|0.0%|
[blocklist_de](#blocklist_de)|33951|33951|7|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5867|5867|5|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7699|7699|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|5|1.3%|0.0%|
[voipbl](#voipbl)|10367|10776|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3284|3284|4|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[malc0de](#malc0de)|392|392|3|0.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|11565|11565|3|0.0%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|
[et_compromised](#et_compromised)|2174|2174|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|2|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|119|119|2|1.6%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3078|3078|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13782|13782|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|234|234|1|0.4%|0.0%|
[zeus](#zeus)|269|269|1|0.3%|0.0%|
[xroxy](#xroxy)|2044|2044|1|0.0%|0.0%|
[sslbl](#sslbl)|359|359|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|1|0.0%|0.0%|
[shunlist](#shunlist)|1288|1288|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1672|1672|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.0%|
[openbl_7d](#openbl_7d)|1035|1035|1|0.0%|0.0%|
[feodo](#feodo)|82|82|1|1.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2450|2450|1|0.0%|0.0%|

## ib_bluetack_webexploit

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) web server hack and exploit attempts

Source is downloaded from [this link](http://list.iblocklist.com/?list=ghlzqtqxnzctvvajwwag&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Wed Jun  3 04:20:25 UTC 2015.

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
[alienvault_reputation](#alienvault_reputation)|177256|177256|8|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|6|0.0%|0.4%|
[et_block](#et_block)|1007|18338646|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1284|1284|3|0.2%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7699|7699|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|3284|3284|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7113|7113|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5867|5867|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|1035|1035|1|0.0%|0.0%|
[nixspam](#nixspam)|19336|19336|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_botcc](#et_botcc)|511|511|1|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|11565|11565|1|0.0%|0.0%|
[blocklist_de](#blocklist_de)|33951|33951|1|0.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|177256|177256|12|0.0%|3.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|4|0.0%|1.0%|
[malwaredomainlist](#malwaredomainlist)|1284|1284|4|0.3%|1.0%|
[et_block](#et_block)|1007|18338646|4|0.0%|1.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.7%|
[cleanmx_viruses](#cleanmx_viruses)|46|46|3|6.5%|0.7%|
[dshield](#dshield)|20|5120|2|0.0%|0.5%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|1|0.0%|0.2%|

## malwaredomainlist

[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses

Source is downloaded from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt).

The last time downloaded was found to be dated: Wed Jun  3 07:27:37 UTC 2015.

The ipset `malwaredomainlist` has **1284** entries, **1284** unique IPs.

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
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|27|0.0%|2.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|26|0.0%|2.0%|
[fullbogons](#fullbogons)|3686|670534424|9|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|177256|177256|6|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|4|0.0%|0.3%|
[malc0de](#malc0de)|392|392|4|1.0%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|3|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7113|7113|1|0.0%|0.0%|
[et_botcc](#et_botcc)|511|511|1|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|11565|11565|1|0.0%|0.0%|
[blocklist_de](#blocklist_de)|33951|33951|1|0.0%|0.0%|

## maxmind_proxy_fraud

[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.

Source is downloaded from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list).

The last time downloaded was found to be dated: Wed Jun  3 08:09:08 UTC 2015.

The ipset `maxmind_proxy_fraud` has **372** entries, **372** unique IPs.

The following table shows the overlaps of `maxmind_proxy_fraud` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `maxmind_proxy_fraud`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `maxmind_proxy_fraud`.
- ` this % ` is the percentage **of this ipset (`maxmind_proxy_fraud`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|232|0.2%|62.3%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|196|0.6%|52.6%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|178|2.0%|47.8%|
[dm_tor](#dm_tor)|6437|6437|171|2.6%|45.9%|
[bm_tor](#bm_tor)|6415|6415|171|2.6%|45.9%|
[et_tor](#et_tor)|6520|6520|170|2.6%|45.6%|
[stopforumspam_1d](#stopforumspam_1d)|7113|7113|155|2.1%|41.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|125|0.0%|33.6%|
[php_commenters](#php_commenters)|281|281|28|9.9%|7.5%|
[alienvault_reputation](#alienvault_reputation)|177256|177256|25|0.0%|6.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|21|0.0%|5.6%|
[openbl_60d](#openbl_60d)|7699|7699|18|0.2%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|17|0.0%|4.5%|
[php_harvesters](#php_harvesters)|257|257|6|2.3%|1.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|1.3%|
[ri_web_proxies](#ri_web_proxies)|5867|5867|4|0.0%|1.0%|
[php_spammers](#php_spammers)|417|417|4|0.9%|1.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|1.0%|
[shunlist](#shunlist)|1288|1288|2|0.1%|0.5%|
[xroxy](#xroxy)|2044|2044|1|0.0%|0.2%|
[voipbl](#voipbl)|10367|10776|1|0.0%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2185|2185|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|1|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|13782|13782|1|0.0%|0.2%|
[blocklist_de](#blocklist_de)|33951|33951|1|0.0%|0.2%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Wed Jun  3 08:15:02 UTC 2015.

The ipset `nixspam` has **19336** entries, **19336** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1125|0.0%|5.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|521|0.0%|2.6%|
[blocklist_de](#blocklist_de)|33951|33951|516|1.5%|2.6%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|398|2.5%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|362|0.0%|1.8%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|251|0.2%|1.2%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|209|2.3%|1.0%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|155|0.4%|0.8%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|138|0.0%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|138|0.0%|0.7%|
[et_block](#et_block)|1007|18338646|138|0.0%|0.7%|
[ri_web_proxies](#ri_web_proxies)|5867|5867|103|1.7%|0.5%|
[xroxy](#xroxy)|2044|2044|79|3.8%|0.4%|
[php_dictionary](#php_dictionary)|433|433|72|16.6%|0.3%|
[php_spammers](#php_spammers)|417|417|60|14.3%|0.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|11565|11565|57|0.4%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7113|7113|54|0.7%|0.2%|
[alienvault_reputation](#alienvault_reputation)|177256|177256|45|0.0%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3078|3078|37|1.2%|0.1%|
[proxz](#proxz)|593|593|30|5.0%|0.1%|
[ri_connect_proxies](#ri_connect_proxies)|2185|2185|22|1.0%|0.1%|
[proxyrss](#proxyrss)|1672|1672|20|1.1%|0.1%|
[openbl_60d](#openbl_60d)|7699|7699|19|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1838|1838|13|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|11|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2450|2450|10|0.4%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13782|13782|10|0.0%|0.0%|
[php_commenters](#php_commenters)|281|281|9|3.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|814|814|8|0.9%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3284|3284|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[zeus_badips](#zeus_badips)|234|234|1|0.4%|0.0%|
[zeus](#zeus)|269|269|1|0.3%|0.0%|
[openbl_7d](#openbl_7d)|1035|1035|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|326|326|1|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[et_tor](#et_tor)|6520|6520|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6437|6437|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6415|6415|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|1|0.5%|0.0%|

## openbl_1d

[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_1days.txt).

The last time downloaded was found to be dated: Wed Jun  3 07:32:00 UTC 2015.

The ipset `openbl_1d` has **326** entries, **326** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_7d](#openbl_7d)|1035|1035|326|31.4%|100.0%|
[openbl_60d](#openbl_60d)|7699|7699|326|4.2%|100.0%|
[openbl_30d](#openbl_30d)|3284|3284|326|9.9%|100.0%|
[alienvault_reputation](#alienvault_reputation)|177256|177256|314|0.1%|96.3%|
[blocklist_de](#blocklist_de)|33951|33951|236|0.6%|72.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|11565|11565|232|2.0%|71.1%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|89|4.0%|27.3%|
[et_compromised](#et_compromised)|2174|2174|87|4.0%|26.6%|
[shunlist](#shunlist)|1288|1288|83|6.4%|25.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|51|0.0%|15.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|18|10.4%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|14|0.0%|4.2%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|13|0.0%|3.9%|
[et_block](#et_block)|1007|18338646|13|0.0%|3.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|9|0.0%|2.7%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|4|0.0%|1.2%|
[blocklist_de_imap](#blocklist_de_imap)|1838|1838|4|0.2%|1.2%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|3|0.0%|0.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.9%|
[dshield](#dshield)|20|5120|3|0.0%|0.9%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|1|0.0%|0.3%|
[nixspam](#nixspam)|19336|19336|1|0.0%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|13782|13782|1|0.0%|0.3%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt).

The last time downloaded was found to be dated: Wed Jun  3 07:42:00 UTC 2015.

The ipset `openbl_30d` has **3284** entries, **3284** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7699|7699|3284|42.6%|100.0%|
[alienvault_reputation](#alienvault_reputation)|177256|177256|3259|1.8%|99.2%|
[et_compromised](#et_compromised)|2174|2174|1230|56.5%|37.4%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|1226|56.4%|37.3%|
[openbl_7d](#openbl_7d)|1035|1035|1035|100.0%|31.5%|
[blocklist_de](#blocklist_de)|33951|33951|917|2.7%|27.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|11565|11565|866|7.4%|26.3%|
[shunlist](#shunlist)|1288|1288|596|46.2%|18.1%|
[openbl_1d](#openbl_1d)|326|326|326|100.0%|9.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|320|0.0%|9.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|178|0.0%|5.4%|
[et_block](#et_block)|1007|18338646|165|0.0%|5.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|160|0.0%|4.8%|
[dshield](#dshield)|20|5120|123|2.4%|3.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|74|0.0%|2.2%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|48|0.3%|1.4%|
[blocklist_de_imap](#blocklist_de_imap)|1838|1838|39|2.1%|1.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|24|13.9%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|13|0.0%|0.3%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|6|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|4|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.1%|
[voipbl](#voipbl)|10367|10776|3|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|3|0.0%|0.0%|
[nixspam](#nixspam)|19336|19336|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13782|13782|3|0.0%|0.0%|
[zeus](#zeus)|269|269|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|234|234|1|0.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7113|7113|1|0.0%|0.0%|
[ciarmy](#ciarmy)|329|329|1|0.3%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|814|814|1|0.1%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt).

The last time downloaded was found to be dated: Wed Jun  3 07:42:00 UTC 2015.

The ipset `openbl_60d` has **7699** entries, **7699** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|177256|177256|7668|4.3%|99.5%|
[openbl_30d](#openbl_30d)|3284|3284|3284|100.0%|42.6%|
[blocklist_de](#blocklist_de)|33951|33951|1771|5.2%|23.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|11565|11565|1709|14.7%|22.1%|
[et_compromised](#et_compromised)|2174|2174|1315|60.4%|17.0%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|1302|59.9%|16.9%|
[openbl_7d](#openbl_7d)|1035|1035|1035|100.0%|13.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|748|0.0%|9.7%|
[shunlist](#shunlist)|1288|1288|612|47.5%|7.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|340|0.0%|4.4%|
[openbl_1d](#openbl_1d)|326|326|326|100.0%|4.2%|
[et_block](#et_block)|1007|18338646|244|0.0%|3.1%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|239|0.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|172|0.0%|2.2%|
[dshield](#dshield)|20|5120|144|2.8%|1.8%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|56|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|54|0.3%|0.7%|
[blocklist_de_imap](#blocklist_de_imap)|1838|1838|43|2.3%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|27|15.6%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|26|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|25|0.2%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7113|7113|21|0.2%|0.2%|
[et_tor](#et_tor)|6520|6520|21|0.3%|0.2%|
[dm_tor](#dm_tor)|6437|6437|21|0.3%|0.2%|
[bm_tor](#bm_tor)|6415|6415|21|0.3%|0.2%|
[nixspam](#nixspam)|19336|19336|19|0.0%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|18|0.0%|0.2%|
[voipbl](#voipbl)|10367|10776|8|0.0%|0.1%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|6|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13782|13782|4|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3078|3078|3|0.0%|0.0%|
[zeus](#zeus)|269|269|2|0.7%|0.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|814|814|2|0.2%|0.0%|
[zeus_badips](#zeus_badips)|234|234|1|0.4%|0.0%|
[ciarmy](#ciarmy)|329|329|1|0.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2450|2450|1|0.0%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt).

The last time downloaded was found to be dated: Wed Jun  3 07:42:00 UTC 2015.

The ipset `openbl_7d` has **1035** entries, **1035** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7699|7699|1035|13.4%|100.0%|
[openbl_30d](#openbl_30d)|3284|3284|1035|31.5%|100.0%|
[alienvault_reputation](#alienvault_reputation)|177256|177256|1019|0.5%|98.4%|
[blocklist_de](#blocklist_de)|33951|33951|616|1.8%|59.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|11565|11565|593|5.1%|57.2%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|506|23.2%|48.8%|
[et_compromised](#et_compromised)|2174|2174|503|23.1%|48.5%|
[shunlist](#shunlist)|1288|1288|398|30.9%|38.4%|
[openbl_1d](#openbl_1d)|326|326|326|100.0%|31.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|116|0.0%|11.2%|
[et_block](#et_block)|1007|18338646|85|0.0%|8.2%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|83|0.0%|8.0%|
[dshield](#dshield)|20|5120|65|1.2%|6.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|50|0.0%|4.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|24|13.9%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|22|0.0%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|22|0.1%|2.1%|
[blocklist_de_imap](#blocklist_de_imap)|1838|1838|19|1.0%|1.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|9|0.0%|0.8%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|5|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|3|0.0%|0.2%|
[voipbl](#voipbl)|10367|10776|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|2|0.0%|0.1%|
[zeus](#zeus)|269|269|1|0.3%|0.0%|
[nixspam](#nixspam)|19336|19336|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[ciarmy](#ciarmy)|329|329|1|0.3%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|814|814|1|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13782|13782|1|0.0%|0.0%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Wed Jun  3 08:00:30 UTC 2015.

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
[stopforumspam_1d](#stopforumspam_1d)|7113|7113|108|1.5%|38.4%|
[blocklist_de](#blocklist_de)|33951|33951|64|0.1%|22.7%|
[blocklist_de_bots](#blocklist_de_bots)|3078|3078|49|1.5%|17.4%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|37|0.4%|13.1%|
[php_spammers](#php_spammers)|417|417|32|7.6%|11.3%|
[et_tor](#et_tor)|6520|6520|29|0.4%|10.3%|
[dm_tor](#dm_tor)|6437|6437|29|0.4%|10.3%|
[bm_tor](#bm_tor)|6415|6415|29|0.4%|10.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|29|16.8%|10.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|28|7.5%|9.9%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|24|0.0%|8.5%|
[et_block](#et_block)|1007|18338646|24|0.0%|8.5%|
[blocklist_de_apache](#blocklist_de_apache)|13782|13782|23|0.1%|8.1%|
[php_dictionary](#php_dictionary)|433|433|22|5.0%|7.8%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|21|0.1%|7.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|5.3%|
[alienvault_reputation](#alienvault_reputation)|177256|177256|14|0.0%|4.9%|
[ri_web_proxies](#ri_web_proxies)|5867|5867|11|0.1%|3.9%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|3.2%|
[nixspam](#nixspam)|19336|19336|9|0.0%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.2%|
[openbl_60d](#openbl_60d)|7699|7699|8|0.1%|2.8%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|7|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|1.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2450|2450|4|0.1%|1.4%|
[xroxy](#xroxy)|2044|2044|3|0.1%|1.0%|
[proxz](#proxz)|593|593|3|0.5%|1.0%|
[zeus_badips](#zeus_badips)|234|234|1|0.4%|0.3%|
[zeus](#zeus)|269|269|1|0.3%|0.3%|
[proxyrss](#proxyrss)|1672|1672|1|0.0%|0.3%|
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
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|85|0.0%|19.6%|
[php_spammers](#php_spammers)|417|417|84|20.1%|19.3%|
[nixspam](#nixspam)|19336|19336|72|0.3%|16.6%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|65|0.2%|15.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|63|0.7%|14.5%|
[blocklist_de](#blocklist_de)|33951|33951|55|0.1%|12.7%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|39|0.2%|9.0%|
[ri_web_proxies](#ri_web_proxies)|5867|5867|33|0.5%|7.6%|
[xroxy](#xroxy)|2044|2044|24|1.1%|5.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|24|0.0%|5.5%|
[php_commenters](#php_commenters)|281|281|22|7.8%|5.0%|
[stopforumspam_1d](#stopforumspam_1d)|7113|7113|17|0.2%|3.9%|
[blocklist_de_bots](#blocklist_de_bots)|3078|3078|14|0.4%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|10|0.0%|2.3%|
[proxz](#proxz)|593|593|9|1.5%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|9|0.0%|2.0%|
[alienvault_reputation](#alienvault_reputation)|177256|177256|7|0.0%|1.6%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|4|0.0%|0.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.9%|
[et_tor](#et_tor)|6520|6520|4|0.0%|0.9%|
[et_block](#et_block)|1007|18338646|4|0.0%|0.9%|
[dm_tor](#dm_tor)|6437|6437|4|0.0%|0.9%|
[bm_tor](#bm_tor)|6415|6415|4|0.0%|0.9%|
[ri_connect_proxies](#ri_connect_proxies)|2185|2185|3|0.1%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|2|1.1%|0.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2450|2450|2|0.0%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|13782|13782|2|0.0%|0.4%|
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
[stopforumspam_1d](#stopforumspam_1d)|7113|7113|34|0.4%|13.2%|
[blocklist_de](#blocklist_de)|33951|33951|25|0.0%|9.7%|
[blocklist_de_bots](#blocklist_de_bots)|3078|3078|19|0.6%|7.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|5.8%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|9|0.1%|3.5%|
[php_commenters](#php_commenters)|281|281|9|3.2%|3.5%|
[alienvault_reputation](#alienvault_reputation)|177256|177256|9|0.0%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|7|0.0%|2.7%|
[et_tor](#et_tor)|6520|6520|7|0.1%|2.7%|
[dm_tor](#dm_tor)|6437|6437|7|0.1%|2.7%|
[bm_tor](#bm_tor)|6415|6415|7|0.1%|2.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|6|1.6%|2.3%|
[blocklist_de_ftp](#blocklist_de_ftp)|814|814|5|0.6%|1.9%|
[xroxy](#xroxy)|2044|2044|2|0.0%|0.7%|
[openbl_60d](#openbl_60d)|7699|7699|2|0.0%|0.7%|
[nixspam](#nixspam)|19336|19336|2|0.0%|0.7%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|2|1.1%|0.7%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|1|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|1|0.0%|0.3%|
[ri_web_proxies](#ri_web_proxies)|5867|5867|1|0.0%|0.3%|
[proxyrss](#proxyrss)|1672|1672|1|0.0%|0.3%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.3%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|
[fullbogons](#fullbogons)|3686|670534424|1|0.0%|0.3%|
[et_block](#et_block)|1007|18338646|1|0.0%|0.3%|
[bogons](#bogons)|13|592708608|1|0.0%|0.3%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|1|0.0%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|13782|13782|1|0.0%|0.3%|

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
[nixspam](#nixspam)|19336|19336|60|0.3%|14.3%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|59|0.6%|14.1%|
[blocklist_de](#blocklist_de)|33951|33951|49|0.1%|11.7%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|33|0.2%|7.9%|
[php_commenters](#php_commenters)|281|281|32|11.3%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|31|0.0%|7.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|26|0.0%|6.2%|
[ri_web_proxies](#ri_web_proxies)|5867|5867|25|0.4%|5.9%|
[xroxy](#xroxy)|2044|2044|20|0.9%|4.7%|
[stopforumspam_1d](#stopforumspam_1d)|7113|7113|18|0.2%|4.3%|
[blocklist_de_bots](#blocklist_de_bots)|3078|3078|12|0.3%|2.8%|
[proxz](#proxz)|593|593|9|1.5%|2.1%|
[et_tor](#et_tor)|6520|6520|6|0.0%|1.4%|
[dm_tor](#dm_tor)|6437|6437|6|0.0%|1.4%|
[bm_tor](#bm_tor)|6415|6415|6|0.0%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|1.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|3|1.7%|0.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2450|2450|3|0.1%|0.7%|
[blocklist_de_apache](#blocklist_de_apache)|13782|13782|3|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|177256|177256|3|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|2|0.0%|0.4%|
[ri_connect_proxies](#ri_connect_proxies)|2185|2185|2|0.0%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[et_block](#et_block)|1007|18338646|2|0.0%|0.4%|
[proxyrss](#proxyrss)|1672|1672|1|0.0%|0.2%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.2%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Wed Jun  3 05:11:35 UTC 2015.

The ipset `proxyrss` has **1672** entries, **1672** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|894|0.9%|53.4%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|740|2.3%|44.2%|
[ri_web_proxies](#ri_web_proxies)|5867|5867|666|11.3%|39.8%|
[xroxy](#xroxy)|2044|2044|471|23.0%|28.1%|
[stopforumspam_1d](#stopforumspam_1d)|7113|7113|461|6.4%|27.5%|
[ri_connect_proxies](#ri_connect_proxies)|2185|2185|258|11.8%|15.4%|
[blocklist_de](#blocklist_de)|33951|33951|232|0.6%|13.8%|
[blocklist_de_bots](#blocklist_de_bots)|3078|3078|229|7.4%|13.6%|
[proxz](#proxz)|593|593|188|31.7%|11.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|68|0.0%|4.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|64|0.0%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|44|0.0%|2.6%|
[nixspam](#nixspam)|19336|19336|20|0.1%|1.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|7|4.0%|0.4%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|5|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|177256|177256|3|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|2|0.0%|0.1%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|11565|11565|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Wed Jun  3 05:11:42 UTC 2015.

The ipset `proxz` has **593** entries, **593** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|364|0.3%|61.3%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|309|0.9%|52.1%|
[xroxy](#xroxy)|2044|2044|264|12.9%|44.5%|
[ri_web_proxies](#ri_web_proxies)|5867|5867|255|4.3%|43.0%|
[proxyrss](#proxyrss)|1672|1672|188|11.2%|31.7%|
[stopforumspam_1d](#stopforumspam_1d)|7113|7113|132|1.8%|22.2%|
[blocklist_de](#blocklist_de)|33951|33951|114|0.3%|19.2%|
[blocklist_de_bots](#blocklist_de_bots)|3078|3078|95|3.0%|16.0%|
[ri_connect_proxies](#ri_connect_proxies)|2185|2185|88|4.0%|14.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|53|0.0%|8.9%|
[nixspam](#nixspam)|19336|19336|30|0.1%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|27|0.0%|4.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|24|0.0%|4.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|16|0.1%|2.6%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|16|0.1%|2.6%|
[php_spammers](#php_spammers)|417|417|9|2.1%|1.5%|
[php_dictionary](#php_dictionary)|433|433|9|2.0%|1.5%|
[php_commenters](#php_commenters)|281|281|3|1.0%|0.5%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|3|0.4%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|3|1.7%|0.5%|
[alienvault_reputation](#alienvault_reputation)|177256|177256|3|0.0%|0.5%|
[et_compromised](#et_compromised)|2174|2174|2|0.0%|0.3%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|2|0.0%|0.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|11565|11565|2|0.0%|0.3%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.1%|
[et_block](#et_block)|1007|18338646|1|0.0%|0.1%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Wed Jun  3 04:08:33 UTC 2015.

The ipset `ri_connect_proxies` has **2185** entries, **2185** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|1283|1.3%|58.7%|
[ri_web_proxies](#ri_web_proxies)|5867|5867|895|15.2%|40.9%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|686|2.2%|31.3%|
[xroxy](#xroxy)|2044|2044|333|16.2%|15.2%|
[proxyrss](#proxyrss)|1672|1672|258|15.4%|11.8%|
[stopforumspam_1d](#stopforumspam_1d)|7113|7113|186|2.6%|8.5%|
[proxz](#proxz)|593|593|88|14.8%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|88|0.0%|4.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|72|0.0%|3.2%|
[blocklist_de](#blocklist_de)|33951|33951|72|0.2%|3.2%|
[blocklist_de_bots](#blocklist_de_bots)|3078|3078|69|2.2%|3.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|48|0.0%|2.1%|
[nixspam](#nixspam)|19336|19336|22|0.1%|1.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.2%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|4|0.0%|0.1%|
[php_dictionary](#php_dictionary)|433|433|3|0.6%|0.1%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|2|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|177256|177256|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[et_tor](#et_tor)|6520|6520|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6437|6437|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6415|6415|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|11565|11565|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Wed Jun  3 06:38:52 UTC 2015.

The ipset `ri_web_proxies` has **5867** entries, **5867** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|2889|3.1%|49.2%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|1716|5.5%|29.2%|
[ri_connect_proxies](#ri_connect_proxies)|2185|2185|895|40.9%|15.2%|
[xroxy](#xroxy)|2044|2044|853|41.7%|14.5%|
[proxyrss](#proxyrss)|1672|1672|666|39.8%|11.3%|
[stopforumspam_1d](#stopforumspam_1d)|7113|7113|548|7.7%|9.3%|
[blocklist_de](#blocklist_de)|33951|33951|359|1.0%|6.1%|
[blocklist_de_bots](#blocklist_de_bots)|3078|3078|313|10.1%|5.3%|
[proxz](#proxz)|593|593|255|43.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|177|0.0%|3.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|166|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|125|0.0%|2.1%|
[nixspam](#nixspam)|19336|19336|103|0.5%|1.7%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|59|0.6%|1.0%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|46|0.2%|0.7%|
[php_dictionary](#php_dictionary)|433|433|33|7.6%|0.5%|
[php_spammers](#php_spammers)|417|417|25|5.9%|0.4%|
[php_commenters](#php_commenters)|281|281|11|3.9%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|5|2.9%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.0%|
[et_tor](#et_tor)|6520|6520|3|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|177256|177256|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6437|6437|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6415|6415|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Wed Jun  3 06:30:03 UTC 2015.

The ipset `shunlist` has **1288** entries, **1288** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|177256|177256|1280|0.7%|99.3%|
[openbl_60d](#openbl_60d)|7699|7699|612|7.9%|47.5%|
[openbl_30d](#openbl_30d)|3284|3284|596|18.1%|46.2%|
[et_compromised](#et_compromised)|2174|2174|512|23.5%|39.7%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|512|23.5%|39.7%|
[blocklist_de](#blocklist_de)|33951|33951|416|1.2%|32.2%|
[openbl_7d](#openbl_7d)|1035|1035|398|38.4%|30.9%|
[blocklist_de_ssh](#blocklist_de_ssh)|11565|11565|377|3.2%|29.2%|
[et_block](#et_block)|1007|18338646|106|0.0%|8.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|104|0.0%|8.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|99|0.0%|7.6%|
[dshield](#dshield)|20|5120|94|1.8%|7.2%|
[openbl_1d](#openbl_1d)|326|326|83|25.4%|6.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|71|0.0%|5.5%|
[sslbl](#sslbl)|359|359|55|15.3%|4.2%|
[blocklist_de_apache](#blocklist_de_apache)|13782|13782|32|0.2%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|26|0.0%|2.0%|
[ciarmy](#ciarmy)|329|329|24|7.2%|1.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|20|11.6%|1.5%|
[voipbl](#voipbl)|10367|10776|13|0.1%|1.0%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|7|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|5|0.0%|0.3%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|5|0.0%|0.3%|
[blocklist_de_imap](#blocklist_de_imap)|1838|1838|5|0.2%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|4|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|4|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7113|7113|2|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_tor](#et_tor)|6520|6520|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6437|6437|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6415|6415|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|814|814|1|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2450|2450|1|0.0%|0.0%|

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
[dm_tor](#dm_tor)|6437|6437|1059|16.4%|11.9%|
[bm_tor](#bm_tor)|6415|6415|1052|16.3%|11.8%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|814|0.8%|9.1%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|618|1.9%|6.9%|
[stopforumspam_1d](#stopforumspam_1d)|7113|7113|325|4.5%|3.6%|
[et_block](#et_block)|1007|18338646|305|0.0%|3.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|246|0.0%|2.7%|
[zeus](#zeus)|269|269|227|84.3%|2.5%|
[nixspam](#nixspam)|19336|19336|209|1.0%|2.3%|
[zeus_badips](#zeus_badips)|234|234|202|86.3%|2.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|178|47.8%|2.0%|
[blocklist_de](#blocklist_de)|33951|33951|165|0.4%|1.8%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|135|0.8%|1.5%|
[alienvault_reputation](#alienvault_reputation)|177256|177256|119|0.0%|1.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|116|0.0%|1.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|93|0.0%|1.0%|
[feodo](#feodo)|82|82|64|78.0%|0.7%|
[php_dictionary](#php_dictionary)|433|433|63|14.5%|0.7%|
[ri_web_proxies](#ri_web_proxies)|5867|5867|59|1.0%|0.6%|
[php_spammers](#php_spammers)|417|417|59|14.1%|0.6%|
[xroxy](#xroxy)|2044|2044|50|2.4%|0.5%|
[php_commenters](#php_commenters)|281|281|37|13.1%|0.4%|
[sslbl](#sslbl)|359|359|27|7.5%|0.3%|
[malwaredomainlist](#malwaredomainlist)|1284|1284|27|2.1%|0.3%|
[openbl_60d](#openbl_60d)|7699|7699|25|0.3%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3078|3078|23|0.7%|0.2%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|20|0.0%|0.2%|
[proxz](#proxz)|593|593|16|2.6%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|14|0.0%|0.1%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13782|13782|8|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|6|0.0%|0.0%|
[proxyrss](#proxyrss)|1672|1672|5|0.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2450|2450|5|0.2%|0.0%|
[shunlist](#shunlist)|1288|1288|4|0.3%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2185|2185|4|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1838|1838|4|0.2%|0.0%|
[openbl_30d](#openbl_30d)|3284|3284|3|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.0%|
[openbl_7d](#openbl_7d)|1035|1035|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_compromised](#et_compromised)|2174|2174|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|11565|11565|2|0.0%|0.0%|
[openbl_1d](#openbl_1d)|326|326|1|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|1|0.5%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|177256|177256|1628|0.9%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|998|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|512|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|343|1.1%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[openbl_60d](#openbl_60d)|7699|7699|239|3.1%|0.0%|
[openbl_30d](#openbl_30d)|3284|3284|160|4.8%|0.0%|
[blocklist_de](#blocklist_de)|33951|33951|156|0.4%|0.0%|
[nixspam](#nixspam)|19336|19336|138|0.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|11565|11565|110|0.9%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7113|7113|104|1.4%|0.0%|
[et_compromised](#et_compromised)|2174|2174|101|4.6%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|100|4.6%|0.0%|
[shunlist](#shunlist)|1288|1288|99|7.6%|0.0%|
[openbl_7d](#openbl_7d)|1035|1035|83|8.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1284|1284|29|2.2%|0.0%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|24|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|20|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3078|3078|19|0.6%|0.0%|
[zeus_badips](#zeus_badips)|234|234|16|6.8%|0.0%|
[zeus](#zeus)|269|269|16|5.9%|0.0%|
[voipbl](#voipbl)|10367|10776|14|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1838|1838|14|0.7%|0.0%|
[openbl_1d](#openbl_1d)|326|326|13|3.9%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|7|4.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[malc0de](#malc0de)|392|392|4|1.0%|0.0%|
[sslbl](#sslbl)|359|359|3|0.8%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6520|6520|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6437|6437|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6415|6415|2|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2450|2450|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13782|13782|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[et_botcc](#et_botcc)|511|511|1|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|119|119|1|0.8%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|177256|177256|271|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|98|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|23|0.0%|0.0%|
[blocklist_de](#blocklist_de)|33951|33951|13|0.0%|0.0%|
[php_commenters](#php_commenters)|281|281|7|2.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|6|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7699|7699|6|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3284|3284|6|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|6|3.4%|0.0%|
[zeus_badips](#zeus_badips)|234|234|5|2.1%|0.0%|
[zeus](#zeus)|269|269|5|1.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7113|7113|5|0.0%|0.0%|
[shunlist](#shunlist)|1288|1288|5|0.3%|0.0%|
[openbl_7d](#openbl_7d)|1035|1035|5|0.4%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3078|3078|5|0.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|4|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|11565|11565|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13782|13782|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[malc0de](#malc0de)|392|392|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Wed Jun  3 08:15:06 UTC 2015.

The ipset `sslbl` has **359** entries, **359** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|177256|177256|63|0.0%|17.5%|
[shunlist](#shunlist)|1288|1288|55|4.2%|15.3%|
[et_block](#et_block)|1007|18338646|34|0.0%|9.4%|
[feodo](#feodo)|82|82|31|37.8%|8.6%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|27|0.3%|7.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|23|0.0%|6.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|6|0.0%|1.6%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|3|0.0%|0.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Wed Jun  3 08:00:02 UTC 2015.

The ipset `stopforumspam_1d` has **7113** entries, **7113** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|6395|20.6%|89.9%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|6364|6.8%|89.4%|
[blocklist_de](#blocklist_de)|33951|33951|1410|4.1%|19.8%|
[blocklist_de_bots](#blocklist_de_bots)|3078|3078|1360|44.1%|19.1%|
[ri_web_proxies](#ri_web_proxies)|5867|5867|548|9.3%|7.7%|
[proxyrss](#proxyrss)|1672|1672|461|27.5%|6.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|453|0.0%|6.3%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|325|3.6%|4.5%|
[xroxy](#xroxy)|2044|2044|322|15.7%|4.5%|
[bm_tor](#bm_tor)|6415|6415|291|4.5%|4.0%|
[et_tor](#et_tor)|6520|6520|290|4.4%|4.0%|
[dm_tor](#dm_tor)|6437|6437|290|4.5%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|268|0.0%|3.7%|
[ri_connect_proxies](#ri_connect_proxies)|2185|2185|186|8.5%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|168|0.0%|2.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|155|41.6%|2.1%|
[proxz](#proxz)|593|593|132|22.2%|1.8%|
[php_commenters](#php_commenters)|281|281|108|38.4%|1.5%|
[et_block](#et_block)|1007|18338646|106|0.0%|1.4%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|104|0.0%|1.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|102|59.3%|1.4%|
[blocklist_de_apache](#blocklist_de_apache)|13782|13782|57|0.4%|0.8%|
[alienvault_reputation](#alienvault_reputation)|177256|177256|56|0.0%|0.7%|
[nixspam](#nixspam)|19336|19336|54|0.2%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|40|0.2%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|37|0.0%|0.5%|
[php_harvesters](#php_harvesters)|257|257|34|13.2%|0.4%|
[openbl_60d](#openbl_60d)|7699|7699|21|0.2%|0.2%|
[php_spammers](#php_spammers)|417|417|18|4.3%|0.2%|
[php_dictionary](#php_dictionary)|433|433|17|3.9%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2450|2450|15|0.6%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|13|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|7|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|5|0.0%|0.0%|
[voipbl](#voipbl)|10367|10776|4|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|814|814|3|0.3%|0.0%|
[shunlist](#shunlist)|1288|1288|2|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|234|234|1|0.4%|0.0%|
[zeus](#zeus)|269|269|1|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3284|3284|1|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1284|1284|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2174|2174|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|11565|11565|1|0.0%|0.0%|

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
[stopforumspam_1d](#stopforumspam_1d)|7113|7113|6364|89.4%|6.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|5884|0.0%|6.3%|
[ri_web_proxies](#ri_web_proxies)|5867|5867|2889|49.2%|3.1%|
[blocklist_de](#blocklist_de)|33951|33951|2521|7.4%|2.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2510|0.0%|2.7%|
[blocklist_de_bots](#blocklist_de_bots)|3078|3078|2150|69.8%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1545|0.0%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|2185|2185|1283|58.7%|1.3%|
[xroxy](#xroxy)|2044|2044|1201|58.7%|1.2%|
[et_block](#et_block)|1007|18338646|1002|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|998|0.0%|1.0%|
[proxyrss](#proxyrss)|1672|1672|894|53.4%|0.9%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|814|9.1%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|737|0.0%|0.7%|
[et_tor](#et_tor)|6520|6520|643|9.8%|0.6%|
[dm_tor](#dm_tor)|6437|6437|629|9.7%|0.6%|
[bm_tor](#bm_tor)|6415|6415|626|9.7%|0.6%|
[proxz](#proxz)|593|593|364|61.3%|0.3%|
[nixspam](#nixspam)|19336|19336|251|1.2%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|232|62.3%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|231|1.4%|0.2%|
[alienvault_reputation](#alienvault_reputation)|177256|177256|217|0.1%|0.2%|
[php_commenters](#php_commenters)|281|281|206|73.3%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|13782|13782|198|1.4%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|127|73.8%|0.1%|
[php_spammers](#php_spammers)|417|417|100|23.9%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|98|0.0%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|11565|11565|90|0.7%|0.0%|
[php_dictionary](#php_dictionary)|433|433|85|19.6%|0.0%|
[php_harvesters](#php_harvesters)|257|257|62|24.1%|0.0%|
[openbl_60d](#openbl_60d)|7699|7699|56|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|48|0.0%|0.0%|
[voipbl](#voipbl)|10367|10776|39|0.3%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2450|2450|38|1.5%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|22|3.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|15|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|814|814|11|1.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|10|0.4%|0.0%|
[et_compromised](#et_compromised)|2174|2174|8|0.3%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1838|1838|6|0.3%|0.0%|
[shunlist](#shunlist)|1288|1288|5|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3284|3284|4|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1284|1284|4|0.3%|0.0%|
[zeus_badips](#zeus_badips)|234|234|3|1.2%|0.0%|
[zeus](#zeus)|269|269|3|1.1%|0.0%|
[openbl_7d](#openbl_7d)|1035|1035|3|0.2%|0.0%|
[openbl_1d](#openbl_1d)|326|326|3|0.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3686|670534424|2|0.0%|0.0%|
[sslbl](#sslbl)|359|359|1|0.2%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|46|46|1|2.1%|0.0%|
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
[stopforumspam_1d](#stopforumspam_1d)|7113|7113|6395|89.9%|20.6%|
[blocklist_de](#blocklist_de)|33951|33951|2181|6.4%|7.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2017|0.0%|6.4%|
[blocklist_de_bots](#blocklist_de_bots)|3078|3078|1994|64.7%|6.4%|
[ri_web_proxies](#ri_web_proxies)|5867|5867|1716|29.2%|5.5%|
[xroxy](#xroxy)|2044|2044|964|47.1%|3.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|940|0.0%|3.0%|
[proxyrss](#proxyrss)|1672|1672|740|44.2%|2.3%|
[ri_connect_proxies](#ri_connect_proxies)|2185|2185|686|31.3%|2.2%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|618|6.9%|1.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|581|0.0%|1.8%|
[et_tor](#et_tor)|6520|6520|492|7.5%|1.5%|
[dm_tor](#dm_tor)|6437|6437|479|7.4%|1.5%|
[bm_tor](#bm_tor)|6415|6415|478|7.4%|1.5%|
[et_block](#et_block)|1007|18338646|345|0.0%|1.1%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|343|0.0%|1.1%|
[proxz](#proxz)|593|593|309|52.1%|0.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|196|52.6%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|174|0.0%|0.5%|
[nixspam](#nixspam)|19336|19336|155|0.8%|0.4%|
[php_commenters](#php_commenters)|281|281|151|53.7%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|140|0.8%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|13782|13782|119|0.8%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|117|68.0%|0.3%|
[alienvault_reputation](#alienvault_reputation)|177256|177256|102|0.0%|0.3%|
[php_dictionary](#php_dictionary)|433|433|65|15.0%|0.2%|
[php_spammers](#php_spammers)|417|417|61|14.6%|0.1%|
[php_harvesters](#php_harvesters)|257|257|48|18.6%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2450|2450|27|1.1%|0.0%|
[openbl_60d](#openbl_60d)|7699|7699|26|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|26|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|23|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|11565|11565|15|0.1%|0.0%|
[voipbl](#voipbl)|10367|10776|13|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|12|1.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|7|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|814|814|7|0.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|6|0.2%|0.0%|
[et_compromised](#et_compromised)|2174|2174|5|0.2%|0.0%|
[shunlist](#shunlist)|1288|1288|4|0.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1284|1284|3|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|1838|1838|3|0.1%|0.0%|
[zeus_badips](#zeus_badips)|234|234|1|0.4%|0.0%|
[zeus](#zeus)|269|269|1|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3284|3284|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|

## virbl

[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.

Source is downloaded from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt).

The last time downloaded was found to be dated: Wed Jun  3 07:42:04 UTC 2015.

The ipset `virbl` has **16** entries, **16** unique IPs.

The following table shows the overlaps of `virbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `virbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `virbl`.
- ` this % ` is the percentage **of this ipset (`virbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|3|0.0%|18.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|2|0.0%|12.5%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|1|0.0%|6.2%|
[blocklist_de](#blocklist_de)|33951|33951|1|0.0%|6.2%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Wed Jun  3 06:27:09 UTC 2015.

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
[alienvault_reputation](#alienvault_reputation)|177256|177256|197|0.1%|1.8%|
[blocklist_de](#blocklist_de)|33951|33951|44|0.1%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|39|0.0%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|119|119|33|27.7%|0.3%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|14|0.0%|0.1%|
[et_block](#et_block)|1007|18338646|14|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|13|0.0%|0.1%|
[shunlist](#shunlist)|1288|1288|13|1.0%|0.1%|
[openbl_60d](#openbl_60d)|7699|7699|8|0.1%|0.0%|
[ciarmy](#ciarmy)|329|329|6|1.8%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13782|13782|5|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7113|7113|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3284|3284|3|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|11565|11565|3|0.0%|0.0%|
[openbl_7d](#openbl_7d)|1035|1035|2|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[et_tor](#et_tor)|6520|6520|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6437|6437|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6415|6415|2|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2450|2450|2|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3078|3078|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2174|2174|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Wed Jun  3 07:33:01 UTC 2015.

The ipset `xroxy` has **2044** entries, **2044** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|1201|1.2%|58.7%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|964|3.1%|47.1%|
[ri_web_proxies](#ri_web_proxies)|5867|5867|853|14.5%|41.7%|
[proxyrss](#proxyrss)|1672|1672|471|28.1%|23.0%|
[ri_connect_proxies](#ri_connect_proxies)|2185|2185|333|15.2%|16.2%|
[stopforumspam_1d](#stopforumspam_1d)|7113|7113|322|4.5%|15.7%|
[proxz](#proxz)|593|593|264|44.5%|12.9%|
[blocklist_de](#blocklist_de)|33951|33951|242|0.7%|11.8%|
[blocklist_de_bots](#blocklist_de_bots)|3078|3078|201|6.5%|9.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|99|0.0%|4.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|88|0.0%|4.3%|
[nixspam](#nixspam)|19336|19336|79|0.4%|3.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|57|0.0%|2.7%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|50|0.5%|2.4%|
[blocklist_de_mail](#blocklist_de_mail)|15694|15694|39|0.2%|1.9%|
[php_dictionary](#php_dictionary)|433|433|24|5.5%|1.1%|
[php_spammers](#php_spammers)|417|417|20|4.7%|0.9%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|13|1.9%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|172|172|7|4.0%|0.3%|
[alienvault_reputation](#alienvault_reputation)|177256|177256|5|0.0%|0.2%|
[php_commenters](#php_commenters)|281|281|3|1.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[et_tor](#et_tor)|6520|6520|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6437|6437|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6415|6415|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|11565|11565|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2174|2174|1|0.0%|0.0%|
[et_block](#et_block)|1007|18338646|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2173|2173|1|0.0%|0.0%|

## zeus

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist).

The last time downloaded was found to be dated: Wed Jun  3 08:00:03 UTC 2015.

The ipset `zeus` has **269** entries, **269** unique IPs.

The following table shows the overlaps of `zeus` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus`.
- ` this % ` is the percentage **of this ipset (`zeus`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|1007|18338646|263|0.0%|97.7%|
[zeus_badips](#zeus_badips)|234|234|234|100.0%|86.9%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|227|2.5%|84.3%|
[alienvault_reputation](#alienvault_reputation)|177256|177256|65|0.0%|24.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|18|0.0%|6.6%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|16|0.0%|5.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|7|0.0%|2.6%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|5|0.0%|1.8%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|3|0.0%|1.1%|
[openbl_60d](#openbl_60d)|7699|7699|2|0.0%|0.7%|
[openbl_30d](#openbl_30d)|3284|3284|2|0.0%|0.7%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|1|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7113|7113|1|0.0%|0.3%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.3%|
[openbl_7d](#openbl_7d)|1035|1035|1|0.0%|0.3%|
[nixspam](#nixspam)|19336|19336|1|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|
[et_compromised](#et_compromised)|2174|2174|1|0.0%|0.3%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Wed Jun  3 08:00:27 UTC 2015.

The ipset `zeus_badips` has **234** entries, **234** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|269|269|234|86.9%|100.0%|
[et_block](#et_block)|1007|18338646|230|0.0%|98.2%|
[snort_ipfilter](#snort_ipfilter)|8876|8876|202|2.2%|86.3%|
[alienvault_reputation](#alienvault_reputation)|177256|177256|37|0.0%|15.8%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|16|0.0%|6.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14|0.0%|5.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8|0.0%|3.4%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|5|0.0%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4|0.0%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|3|0.0%|1.2%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|7113|7113|1|0.0%|0.4%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.4%|
[openbl_60d](#openbl_60d)|7699|7699|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|3284|3284|1|0.0%|0.4%|
[nixspam](#nixspam)|19336|19336|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.4%|
[et_compromised](#et_compromised)|2174|2174|1|0.0%|0.4%|
