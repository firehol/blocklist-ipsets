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

The following list was automatically generated on Tue Jun  2 02:20:19 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|173822 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|23464 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|14303 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|3238 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|1883 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|327 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|722 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|14766 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|107 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|1826 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|164 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6427 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|2175 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|294 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|426 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6424 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
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
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|21661 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|151 unique IPs|updated every 1 hour  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|3180 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7583 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|913 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|281 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|433 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|257 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|417 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1722 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|493 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2068 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|5604 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1253 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|8058 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|656 subnets, 18600704 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|57 subnets, 487168 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|363 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|7208 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|92372 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|31339 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10350 subnets, 10759 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2022 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
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
[bruteforceblocker](#bruteforceblocker)|2175|2175|1405|64.5%|0.8%|
[shunlist](#shunlist)|1253|1253|1239|98.8%|0.7%|
[blocklist_de](#blocklist_de)|23464|23464|1121|4.7%|0.6%|
[openbl_7d](#openbl_7d)|913|913|898|98.3%|0.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|1826|1826|869|47.5%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|518|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|288|0.0%|0.1%|
[ciarmy](#ciarmy)|294|294|286|97.2%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|271|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|211|0.2%|0.1%|
[voipbl](#voipbl)|10350|10759|200|1.8%|0.1%|
[openbl_1d](#openbl_1d)|151|151|139|92.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8058|8058|119|1.4%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14303|14303|110|0.7%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|99|0.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14766|14766|82|0.5%|0.0%|
[zeus](#zeus)|267|267|66|24.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|722|722|59|8.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7208|7208|56|0.7%|0.0%|
[sslbl](#sslbl)|363|363|51|14.0%|0.0%|
[dm_tor](#dm_tor)|6424|6424|46|0.7%|0.0%|
[bm_tor](#bm_tor)|6427|6427|46|0.7%|0.0%|
[et_tor](#et_tor)|6360|6360|44|0.6%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|42|1.2%|0.0%|
[nixspam](#nixspam)|21661|21661|40|0.1%|0.0%|
[zeus_badips](#zeus_badips)|231|231|37|16.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|36|21.9%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|25|6.7%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|107|107|19|17.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1883|1883|15|0.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[php_commenters](#php_commenters)|281|281|13|4.6%|0.0%|
[malc0de](#malc0de)|397|397|12|3.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|327|327|9|2.7%|0.0%|
[php_harvesters](#php_harvesters)|257|257|8|3.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|8|0.5%|0.0%|
[php_dictionary](#php_dictionary)|433|433|7|1.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|6|0.4%|0.0%|
[xroxy](#xroxy)|2022|2022|5|0.2%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|426|426|4|0.9%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5604|5604|3|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|3|0.7%|0.0%|
[et_botcc](#et_botcc)|505|505|3|0.5%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2068|2068|2|0.0%|0.0%|
[proxz](#proxz)|493|493|2|0.4%|0.0%|
[proxyrss](#proxyrss)|1722|1722|2|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[feodo](#feodo)|77|77|1|1.2%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Tue Jun  2 01:56:03 UTC 2015.

The ipset `blocklist_de` has **23464** entries, **23464** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|14766|14766|14766|100.0%|62.9%|
[blocklist_de_apache](#blocklist_de_apache)|14303|14303|14302|99.9%|60.9%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|3219|99.4%|13.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2921|0.0%|12.4%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|2476|2.6%|10.5%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|2227|7.1%|9.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1883|1883|1883|100.0%|8.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1826|1826|1825|99.9%|7.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1483|0.0%|6.3%|
[stopforumspam_1d](#stopforumspam_1d)|7208|7208|1470|20.3%|6.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1435|0.0%|6.1%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|1121|0.6%|4.7%|
[openbl_60d](#openbl_60d)|7583|7583|840|11.0%|3.5%|
[openbl_30d](#openbl_30d)|3180|3180|750|23.5%|3.1%|
[blocklist_de_imap](#blocklist_de_imap)|722|722|722|100.0%|3.0%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|701|32.2%|2.9%|
[et_compromised](#et_compromised)|2191|2191|690|31.4%|2.9%|
[openbl_7d](#openbl_7d)|913|913|522|57.1%|2.2%|
[nixspam](#nixspam)|21661|21661|487|2.2%|2.0%|
[shunlist](#shunlist)|1253|1253|405|32.3%|1.7%|
[ri_web_proxies](#ri_web_proxies)|5604|5604|367|6.5%|1.5%|
[blocklist_de_ftp](#blocklist_de_ftp)|327|327|321|98.1%|1.3%|
[proxyrss](#proxyrss)|1722|1722|246|14.2%|1.0%|
[xroxy](#xroxy)|2022|2022|236|11.6%|1.0%|
[et_block](#et_block)|997|18338381|177|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|168|0.0%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|164|100.0%|0.6%|
[snort_ipfilter](#snort_ipfilter)|8058|8058|127|1.5%|0.5%|
[openbl_1d](#openbl_1d)|151|151|127|84.1%|0.5%|
[proxz](#proxz)|493|493|98|19.8%|0.4%|
[blocklist_de_sip](#blocklist_de_sip)|107|107|87|81.3%|0.3%|
[ri_connect_proxies](#ri_connect_proxies)|2068|2068|63|3.0%|0.2%|
[php_commenters](#php_commenters)|281|281|62|22.0%|0.2%|
[dshield](#dshield)|20|5120|54|1.0%|0.2%|
[php_spammers](#php_spammers)|417|417|44|10.5%|0.1%|
[php_dictionary](#php_dictionary)|433|433|42|9.6%|0.1%|
[voipbl](#voipbl)|10350|10759|41|0.3%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|36|0.0%|0.1%|
[ciarmy](#ciarmy)|294|294|35|11.9%|0.1%|
[php_harvesters](#php_harvesters)|257|257|25|9.7%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|9|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|8|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.0%|
[et_tor](#et_tor)|6360|6360|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6424|6424|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6427|6427|3|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Tue Jun  2 02:10:05 UTC 2015.

The ipset `blocklist_de_apache` has **14303** entries, **14303** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|23464|23464|14302|60.9%|99.9%|
[blocklist_de_mail](#blocklist_de_mail)|14766|14766|11059|74.8%|77.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2213|0.0%|15.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1883|1883|1881|99.8%|13.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1320|0.0%|9.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1065|0.0%|7.4%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|207|0.2%|1.4%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|132|0.4%|0.9%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|110|0.0%|0.7%|
[stopforumspam_1d](#stopforumspam_1d)|7208|7208|64|0.8%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|34|20.7%|0.2%|
[ciarmy](#ciarmy)|294|294|30|10.2%|0.2%|
[shunlist](#shunlist)|1253|1253|29|2.3%|0.2%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|21|0.6%|0.1%|
[nixspam](#nixspam)|21661|21661|17|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|8058|8058|8|0.0%|0.0%|
[voipbl](#voipbl)|10350|10759|5|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[et_block](#et_block)|997|18338381|4|0.0%|0.0%|
[et_tor](#et_tor)|6360|6360|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6424|6424|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6427|6427|3|0.0%|0.0%|
[et_compromised](#et_compromised)|2191|2191|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|2|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|1|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[openbl_60d](#openbl_60d)|7583|7583|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3180|3180|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Tue Jun  2 02:14:11 UTC 2015.

The ipset `blocklist_de_bots` has **3238** entries, **3238** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|23464|23464|3219|13.7%|99.4%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|2207|2.3%|68.1%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|2056|6.5%|63.4%|
[stopforumspam_1d](#stopforumspam_1d)|7208|7208|1416|19.6%|43.7%|
[ri_web_proxies](#ri_web_proxies)|5604|5604|332|5.9%|10.2%|
[proxyrss](#proxyrss)|1722|1722|247|14.3%|7.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|208|0.0%|6.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|207|0.0%|6.3%|
[xroxy](#xroxy)|2022|2022|205|10.1%|6.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|118|71.9%|3.6%|
[proxz](#proxz)|493|493|85|17.2%|2.6%|
[ri_connect_proxies](#ri_connect_proxies)|2068|2068|62|2.9%|1.9%|
[php_commenters](#php_commenters)|281|281|50|17.7%|1.5%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|42|0.0%|1.2%|
[nixspam](#nixspam)|21661|21661|39|0.1%|1.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|33|0.0%|1.0%|
[snort_ipfilter](#snort_ipfilter)|8058|8058|29|0.3%|0.8%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|26|0.0%|0.8%|
[et_block](#et_block)|997|18338381|26|0.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|22|0.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|14766|14766|21|0.1%|0.6%|
[blocklist_de_apache](#blocklist_de_apache)|14303|14303|21|0.1%|0.6%|
[php_dictionary](#php_dictionary)|433|433|20|4.6%|0.6%|
[php_harvesters](#php_harvesters)|257|257|19|7.3%|0.5%|
[openbl_60d](#openbl_60d)|7583|7583|16|0.2%|0.4%|
[php_spammers](#php_spammers)|417|417|14|3.3%|0.4%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|4|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.0%|
[voipbl](#voipbl)|10350|10759|2|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1883|1883|2|0.1%|0.0%|
[openbl_30d](#openbl_30d)|3180|3180|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2191|2191|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Tue Jun  2 01:56:13 UTC 2015.

The ipset `blocklist_de_bruteforce` has **1883** entries, **1883** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|23464|23464|1883|8.0%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|14303|14303|1881|13.1%|99.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|120|0.0%|6.3%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|44|0.0%|2.3%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|36|0.1%|1.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|34|0.0%|1.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|30|0.0%|1.5%|
[stopforumspam_1d](#stopforumspam_1d)|7208|7208|22|0.3%|1.1%|
[nixspam](#nixspam)|21661|21661|17|0.0%|0.9%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|15|0.0%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|11|6.7%|0.5%|
[snort_ipfilter](#snort_ipfilter)|8058|8058|5|0.0%|0.2%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.2%|
[php_commenters](#php_commenters)|281|281|5|1.7%|0.2%|
[shunlist](#shunlist)|1253|1253|3|0.2%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.1%|
[voipbl](#voipbl)|10350|10759|2|0.0%|0.1%|
[et_block](#et_block)|997|18338381|2|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|2|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|1|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Tue Jun  2 02:14:09 UTC 2015.

The ipset `blocklist_de_ftp` has **327** entries, **327** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|23464|23464|321|1.3%|98.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|24|0.0%|7.3%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|9|0.0%|2.7%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|6|0.0%|1.8%|
[openbl_60d](#openbl_60d)|7583|7583|5|0.0%|1.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|5|0.0%|1.5%|
[php_harvesters](#php_harvesters)|257|257|4|1.5%|1.2%|
[openbl_30d](#openbl_30d)|3180|3180|4|0.1%|1.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4|0.0%|1.2%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|3|0.0%|0.9%|
[shunlist](#shunlist)|1253|1253|2|0.1%|0.6%|
[openbl_7d](#openbl_7d)|913|913|2|0.2%|0.6%|
[nixspam](#nixspam)|21661|21661|2|0.0%|0.6%|
[snort_ipfilter](#snort_ipfilter)|8058|8058|1|0.0%|0.3%|
[openbl_1d](#openbl_1d)|151|151|1|0.6%|0.3%|
[et_compromised](#et_compromised)|2191|2191|1|0.0%|0.3%|
[dshield](#dshield)|20|5120|1|0.0%|0.3%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|1|0.0%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|1|0.6%|0.3%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Tue Jun  2 01:56:07 UTC 2015.

The ipset `blocklist_de_imap` has **722** entries, **722** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|14766|14766|722|4.8%|100.0%|
[blocklist_de](#blocklist_de)|23464|23464|722|3.0%|100.0%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|59|0.0%|8.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|51|0.0%|7.0%|
[openbl_60d](#openbl_60d)|7583|7583|39|0.5%|5.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|36|0.0%|4.9%|
[openbl_30d](#openbl_30d)|3180|3180|34|1.0%|4.7%|
[openbl_7d](#openbl_7d)|913|913|21|2.3%|2.9%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|20|0.0%|2.7%|
[et_block](#et_block)|997|18338381|20|0.0%|2.7%|
[snort_ipfilter](#snort_ipfilter)|8058|8058|9|0.1%|1.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|9|0.0%|1.2%|
[et_compromised](#et_compromised)|2191|2191|9|0.4%|1.2%|
[nixspam](#nixspam)|21661|21661|8|0.0%|1.1%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|8|0.3%|1.1%|
[shunlist](#shunlist)|1253|1253|4|0.3%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|3|0.0%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|2|0.0%|0.2%|
[ciarmy](#ciarmy)|294|294|2|0.6%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|2|1.2%|0.2%|
[voipbl](#voipbl)|10350|10759|1|0.0%|0.1%|
[openbl_1d](#openbl_1d)|151|151|1|0.6%|0.1%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Tue Jun  2 01:56:06 UTC 2015.

The ipset `blocklist_de_mail` has **14766** entries, **14766** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|23464|23464|14766|62.9%|100.0%|
[blocklist_de_apache](#blocklist_de_apache)|14303|14303|11059|77.3%|74.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2272|0.0%|15.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1328|0.0%|8.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1127|0.0%|7.6%|
[blocklist_de_imap](#blocklist_de_imap)|722|722|722|100.0%|4.8%|
[nixspam](#nixspam)|21661|21661|425|1.9%|2.8%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|201|0.2%|1.3%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|122|0.3%|0.8%|
[snort_ipfilter](#snort_ipfilter)|8058|8058|89|1.1%|0.6%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|82|0.0%|0.5%|
[openbl_60d](#openbl_60d)|7583|7583|49|0.6%|0.3%|
[openbl_30d](#openbl_30d)|3180|3180|42|1.3%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7208|7208|39|0.5%|0.2%|
[ri_web_proxies](#ri_web_proxies)|5604|5604|33|0.5%|0.2%|
[xroxy](#xroxy)|2022|2022|29|1.4%|0.1%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|26|0.0%|0.1%|
[et_block](#et_block)|997|18338381|26|0.0%|0.1%|
[openbl_7d](#openbl_7d)|913|913|25|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|23|5.5%|0.1%|
[php_dictionary](#php_dictionary)|433|433|21|4.8%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|21|0.6%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|20|12.1%|0.1%|
[php_commenters](#php_commenters)|281|281|17|6.0%|0.1%|
[proxz](#proxz)|493|493|12|2.4%|0.0%|
[et_compromised](#et_compromised)|2191|2191|10|0.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|9|0.4%|0.0%|
[shunlist](#shunlist)|1253|1253|6|0.4%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.0%|
[openbl_1d](#openbl_1d)|151|151|3|1.9%|0.0%|
[et_tor](#et_tor)|6360|6360|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6424|6424|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6427|6427|3|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[ciarmy](#ciarmy)|294|294|2|0.6%|0.0%|
[voipbl](#voipbl)|10350|10759|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2068|2068|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Tue Jun  2 02:10:08 UTC 2015.

The ipset `blocklist_de_sip` has **107** entries, **107** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|23464|23464|87|0.3%|81.3%|
[voipbl](#voipbl)|10350|10759|31|0.2%|28.9%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|19|0.0%|17.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14|0.0%|13.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|10|0.0%|9.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|1.8%|
[et_block](#et_block)|997|18338381|2|0.0%|1.8%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|1|0.0%|0.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1|0.0%|0.9%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.9%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Tue Jun  2 02:10:03 UTC 2015.

The ipset `blocklist_de_ssh` has **1826** entries, **1826** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|23464|23464|1825|7.7%|99.9%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|869|0.4%|47.5%|
[openbl_60d](#openbl_60d)|7583|7583|767|10.1%|42.0%|
[openbl_30d](#openbl_30d)|3180|3180|700|22.0%|38.3%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|685|31.4%|37.5%|
[et_compromised](#et_compromised)|2191|2191|674|30.7%|36.9%|
[openbl_7d](#openbl_7d)|913|913|494|54.1%|27.0%|
[shunlist](#shunlist)|1253|1253|367|29.2%|20.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|267|0.0%|14.6%|
[openbl_1d](#openbl_1d)|151|151|123|81.4%|6.7%|
[et_block](#et_block)|997|18338381|118|0.0%|6.4%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|113|0.0%|6.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|94|0.0%|5.1%|
[dshield](#dshield)|20|5120|52|1.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|29|0.0%|1.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|25|15.2%|1.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|6|0.0%|0.3%|
[ciarmy](#ciarmy)|294|294|3|1.0%|0.1%|
[voipbl](#voipbl)|10350|10759|2|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|8058|8058|2|0.0%|0.1%|
[nixspam](#nixspam)|21661|21661|2|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.1%|
[xroxy](#xroxy)|2022|2022|1|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|1|0.0%|0.0%|
[proxz](#proxz)|493|493|1|0.2%|0.0%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Tue Jun  2 02:10:10 UTC 2015.

The ipset `blocklist_de_strongips` has **164** entries, **164** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|23464|23464|164|0.6%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|122|0.1%|74.3%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|118|3.6%|71.9%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|113|0.3%|68.9%|
[stopforumspam_1d](#stopforumspam_1d)|7208|7208|106|1.4%|64.6%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|36|0.0%|21.9%|
[blocklist_de_apache](#blocklist_de_apache)|14303|14303|34|0.2%|20.7%|
[php_commenters](#php_commenters)|281|281|29|10.3%|17.6%|
[openbl_60d](#openbl_60d)|7583|7583|27|0.3%|16.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|1826|1826|25|1.3%|15.2%|
[openbl_30d](#openbl_30d)|3180|3180|24|0.7%|14.6%|
[openbl_7d](#openbl_7d)|913|913|23|2.5%|14.0%|
[blocklist_de_mail](#blocklist_de_mail)|14766|14766|20|0.1%|12.1%|
[shunlist](#shunlist)|1253|1253|18|1.4%|10.9%|
[openbl_1d](#openbl_1d)|151|151|17|11.2%|10.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|16|0.0%|9.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1883|1883|11|0.5%|6.7%|
[xroxy](#xroxy)|2022|2022|6|0.2%|3.6%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|6|0.0%|3.6%|
[proxyrss](#proxyrss)|1722|1722|6|0.3%|3.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|6|0.0%|3.6%|
[et_block](#et_block)|997|18338381|6|0.0%|3.6%|
[dshield](#dshield)|20|5120|5|0.0%|3.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|4|0.0%|2.4%|
[ri_web_proxies](#ri_web_proxies)|5604|5604|4|0.0%|2.4%|
[php_spammers](#php_spammers)|417|417|4|0.9%|2.4%|
[proxz](#proxz)|493|493|3|0.6%|1.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.8%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|1.2%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|1.2%|
[blocklist_de_imap](#blocklist_de_imap)|722|722|2|0.2%|1.2%|
[snort_ipfilter](#snort_ipfilter)|8058|8058|1|0.0%|0.6%|
[nixspam](#nixspam)|21661|21661|1|0.0%|0.6%|
[blocklist_de_ftp](#blocklist_de_ftp)|327|327|1|0.3%|0.6%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Tue Jun  2 02:18:07 UTC 2015.

The ipset `bm_tor` has **6427** entries, **6427** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[dm_tor](#dm_tor)|6424|6424|6424|100.0%|99.9%|
[et_tor](#et_tor)|6360|6360|5903|92.8%|91.8%|
[snort_ipfilter](#snort_ipfilter)|8058|8058|1088|13.5%|16.9%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|637|0.6%|9.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|634|0.0%|9.8%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|493|1.5%|7.6%|
[stopforumspam_1d](#stopforumspam_1d)|7208|7208|295|4.0%|4.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|186|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|170|45.6%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|170|0.0%|2.6%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|46|0.0%|0.7%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[openbl_60d](#openbl_60d)|7583|7583|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[et_block](#et_block)|997|18338381|4|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5604|5604|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14766|14766|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14303|14303|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|23464|23464|3|0.0%|0.0%|
[xroxy](#xroxy)|2022|2022|2|0.0%|0.0%|
[voipbl](#voipbl)|10350|10759|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|2|0.0%|0.0%|
[shunlist](#shunlist)|1253|1253|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2068|2068|1|0.0%|0.0%|

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
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|1|0.0%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Tue Jun  2 00:54:20 UTC 2015.

The ipset `bruteforceblocker` has **2175** entries, **2175** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_compromised](#et_compromised)|2191|2191|2144|97.8%|98.5%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|1405|0.8%|64.5%|
[openbl_60d](#openbl_60d)|7583|7583|1307|17.2%|60.0%|
[openbl_30d](#openbl_30d)|3180|3180|1233|38.7%|56.6%|
[blocklist_de](#blocklist_de)|23464|23464|701|2.9%|32.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1826|1826|685|37.5%|31.4%|
[shunlist](#shunlist)|1253|1253|522|41.6%|24.0%|
[openbl_7d](#openbl_7d)|913|913|520|56.9%|23.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|217|0.0%|9.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|114|0.0%|5.2%|
[et_block](#et_block)|997|18338381|103|0.0%|4.7%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|101|0.0%|4.6%|
[openbl_1d](#openbl_1d)|151|151|78|51.6%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|61|0.0%|2.8%|
[dshield](#dshield)|20|5120|60|1.1%|2.7%|
[blocklist_de_mail](#blocklist_de_mail)|14766|14766|9|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|8|0.0%|0.3%|
[blocklist_de_imap](#blocklist_de_imap)|722|722|8|1.1%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|5|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7208|7208|4|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|8058|8058|2|0.0%|0.0%|
[proxz](#proxz)|493|493|2|0.4%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14303|14303|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|231|231|1|0.4%|0.0%|
[zeus](#zeus)|267|267|1|0.3%|0.0%|
[xroxy](#xroxy)|2022|2022|1|0.0%|0.0%|
[voipbl](#voipbl)|10350|10759|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3639|670579672|1|0.0%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|327|327|1|0.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|1|0.0%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Tue Jun  2 01:15:16 UTC 2015.

The ipset `ciarmy` has **294** entries, **294** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|173822|173822|286|0.1%|97.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|50|0.0%|17.0%|
[blocklist_de](#blocklist_de)|23464|23464|35|0.1%|11.9%|
[blocklist_de_apache](#blocklist_de_apache)|14303|14303|30|0.2%|10.2%|
[shunlist](#shunlist)|1253|1253|23|1.8%|7.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|11|0.0%|3.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|10|0.0%|3.4%|
[voipbl](#voipbl)|10350|10759|3|0.0%|1.0%|
[dshield](#dshield)|20|5120|3|0.0%|1.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1826|1826|3|0.1%|1.0%|
[et_block](#et_block)|997|18338381|2|0.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|14766|14766|2|0.0%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|722|722|2|0.2%|0.6%|
[openbl_7d](#openbl_7d)|913|913|1|0.1%|0.3%|
[openbl_60d](#openbl_60d)|7583|7583|1|0.0%|0.3%|
[openbl_30d](#openbl_30d)|3180|3180|1|0.0%|0.3%|
[cleanmx_viruses](#cleanmx_viruses)|426|426|1|0.2%|0.3%|

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
[snort_ipfilter](#snort_ipfilter)|8058|8058|3|0.0%|0.7%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|2|0.1%|0.4%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|1|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.2%|
[et_block](#et_block)|997|18338381|1|0.0%|0.2%|
[ciarmy](#ciarmy)|294|294|1|0.3%|0.2%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Tue Jun  2 02:18:05 UTC 2015.

The ipset `dm_tor` has **6424** entries, **6424** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6427|6427|6424|99.9%|100.0%|
[et_tor](#et_tor)|6360|6360|5901|92.7%|91.8%|
[snort_ipfilter](#snort_ipfilter)|8058|8058|1088|13.5%|16.9%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|637|0.6%|9.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|634|0.0%|9.8%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|493|1.5%|7.6%|
[stopforumspam_1d](#stopforumspam_1d)|7208|7208|295|4.0%|4.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|186|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|170|45.6%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|170|0.0%|2.6%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|46|0.0%|0.7%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[openbl_60d](#openbl_60d)|7583|7583|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[et_block](#et_block)|997|18338381|4|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5604|5604|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14766|14766|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14303|14303|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|23464|23464|3|0.0%|0.0%|
[xroxy](#xroxy)|2022|2022|2|0.0%|0.0%|
[voipbl](#voipbl)|10350|10759|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|2|0.0%|0.0%|
[shunlist](#shunlist)|1253|1253|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2068|2068|1|0.0%|0.0%|

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
[bruteforceblocker](#bruteforceblocker)|2175|2175|60|2.7%|1.1%|
[blocklist_de](#blocklist_de)|23464|23464|54|0.2%|1.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1826|1826|52|2.8%|1.0%|
[openbl_1d](#openbl_1d)|151|151|14|9.2%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|6|0.0%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|5|3.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|3|0.0%|0.0%|
[ciarmy](#ciarmy)|294|294|3|1.0%|0.0%|
[malc0de](#malc0de)|397|397|2|0.5%|0.0%|
[voipbl](#voipbl)|10350|10759|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7208|7208|1|0.0%|0.0%|
[nixspam](#nixspam)|21661|21661|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|327|327|1|0.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|1|0.0%|0.0%|

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
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|986|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|517|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|341|1.0%|0.0%|
[nixspam](#nixspam)|21661|21661|320|1.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8058|8058|297|3.6%|0.0%|
[zeus](#zeus)|267|267|261|97.7%|0.0%|
[openbl_60d](#openbl_60d)|7583|7583|245|3.2%|0.0%|
[zeus_badips](#zeus_badips)|231|231|229|99.1%|0.0%|
[openbl_30d](#openbl_30d)|3180|3180|204|6.4%|0.0%|
[blocklist_de](#blocklist_de)|23464|23464|177|0.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1826|1826|118|6.4%|0.0%|
[shunlist](#shunlist)|1253|1253|108|8.6%|0.0%|
[et_compromised](#et_compromised)|2191|2191|104|4.7%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|103|4.7%|0.0%|
[openbl_7d](#openbl_7d)|913|913|89|9.7%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7208|7208|79|1.0%|0.0%|
[feodo](#feodo)|77|77|71|92.2%|0.0%|
[sslbl](#sslbl)|363|363|30|8.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|29|2.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14766|14766|26|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|26|0.8%|0.0%|
[voipbl](#voipbl)|10350|10759|24|0.2%|0.0%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|722|722|20|2.7%|0.0%|
[palevo](#palevo)|13|13|12|92.3%|0.0%|
[openbl_1d](#openbl_1d)|151|151|12|7.9%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|10|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|6|3.6%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[malc0de](#malc0de)|397|397|4|1.0%|0.0%|
[et_tor](#et_tor)|6360|6360|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6424|6424|4|0.0%|0.0%|
[bm_tor](#bm_tor)|6427|6427|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14303|14303|4|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[ciarmy](#ciarmy)|294|294|2|0.6%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|107|107|2|1.8%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1883|1883|2|0.1%|0.0%|
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
[bruteforceblocker](#bruteforceblocker)|2175|2175|2144|98.5%|97.8%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|1420|0.8%|64.8%|
[openbl_60d](#openbl_60d)|7583|7583|1319|17.3%|60.2%|
[openbl_30d](#openbl_30d)|3180|3180|1236|38.8%|56.4%|
[blocklist_de](#blocklist_de)|23464|23464|690|2.9%|31.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|1826|1826|674|36.9%|30.7%|
[shunlist](#shunlist)|1253|1253|523|41.7%|23.8%|
[openbl_7d](#openbl_7d)|913|913|516|56.5%|23.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|219|0.0%|9.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|116|0.0%|5.2%|
[et_block](#et_block)|997|18338381|104|0.0%|4.7%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|102|0.0%|4.6%|
[openbl_1d](#openbl_1d)|151|151|74|49.0%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|62|0.0%|2.8%|
[dshield](#dshield)|20|5120|60|1.1%|2.7%|
[blocklist_de_mail](#blocklist_de_mail)|14766|14766|10|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|9|0.0%|0.4%|
[blocklist_de_imap](#blocklist_de_imap)|722|722|9|1.2%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|5|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7208|7208|4|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|8058|8058|2|0.0%|0.0%|
[proxz](#proxz)|493|493|2|0.4%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14303|14303|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|231|231|1|0.4%|0.0%|
[zeus](#zeus)|267|267|1|0.3%|0.0%|
[xroxy](#xroxy)|2022|2022|1|0.0%|0.0%|
[voipbl](#voipbl)|10350|10759|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|327|327|1|0.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|1|0.0%|0.0%|

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
[bm_tor](#bm_tor)|6427|6427|5903|91.8%|92.8%|
[dm_tor](#dm_tor)|6424|6424|5901|91.8%|92.7%|
[snort_ipfilter](#snort_ipfilter)|8058|8058|1078|13.3%|16.9%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|636|0.6%|10.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|628|0.0%|9.8%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|491|1.5%|7.7%|
[stopforumspam_1d](#stopforumspam_1d)|7208|7208|297|4.1%|4.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|191|0.0%|3.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|169|45.4%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|167|0.0%|2.6%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|44|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[openbl_60d](#openbl_60d)|7583|7583|19|0.2%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|19|0.0%|0.2%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[php_harvesters](#php_harvesters)|257|257|6|2.3%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5604|5604|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[et_block](#et_block)|997|18338381|4|0.0%|0.0%|
[xroxy](#xroxy)|2022|2022|3|0.1%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14766|14766|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14303|14303|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|23464|23464|3|0.0%|0.0%|
[voipbl](#voipbl)|10350|10759|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|2|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2068|2068|2|0.0%|0.0%|
[shunlist](#shunlist)|1253|1253|1|0.0%|0.0%|
[proxz](#proxz)|493|493|1|0.2%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Tue Jun  2 02:18:26 UTC 2015.

The ipset `feodo` has **77** entries, **77** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|997|18338381|71|0.0%|92.2%|
[snort_ipfilter](#snort_ipfilter)|8058|8058|61|0.7%|79.2%|
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
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|1|0.0%|0.0%|

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
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|16|0.0%|0.0%|
[fullbogons](#fullbogons)|3639|670579672|14|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|14|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.0%|
[nixspam](#nixspam)|21661|21661|10|0.0%|0.0%|
[et_block](#et_block)|997|18338381|10|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|7|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|6|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7208|7208|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[xroxy](#xroxy)|2022|2022|3|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8058|8058|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|23464|23464|3|0.0%|0.0%|
[voipbl](#voipbl)|10350|10759|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5604|5604|1|0.0%|0.0%|
[proxz](#proxz)|493|493|1|0.2%|0.0%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14766|14766|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1883|1883|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14303|14303|1|0.0%|0.0%|

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
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|731|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|518|0.2%|0.0%|
[nixspam](#nixspam)|21661|21661|318|1.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|178|0.5%|0.0%|
[blocklist_de](#blocklist_de)|23464|23464|36|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|27|2.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7208|7208|26|0.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|22|0.6%|0.0%|
[openbl_60d](#openbl_60d)|7583|7583|19|0.2%|0.0%|
[openbl_30d](#openbl_30d)|3180|3180|13|0.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8058|8058|11|0.1%|0.0%|
[zeus_badips](#zeus_badips)|231|231|10|4.3%|0.0%|
[zeus](#zeus)|267|267|10|3.7%|0.0%|
[openbl_7d](#openbl_7d)|913|913|10|1.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1826|1826|7|0.3%|0.0%|
[et_compromised](#et_compromised)|2191|2191|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|5|0.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14766|14766|5|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|722|722|4|0.5%|0.0%|
[shunlist](#shunlist)|1253|1253|3|0.2%|0.0%|
[et_tor](#et_tor)|6360|6360|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6424|6424|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6427|6427|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|3|1.8%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[voipbl](#voipbl)|10350|10759|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.0%|
[openbl_1d](#openbl_1d)|151|151|1|0.6%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1883|1883|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14303|14303|1|0.0%|0.0%|

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
[spamhaus_edrop](#spamhaus_edrop)|57|487168|33155|6.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|13248|3.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|4396|2.5%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|1537|1.6%|0.0%|
[blocklist_de](#blocklist_de)|23464|23464|1435|6.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14766|14766|1328|8.9%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14303|14303|1320|9.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|558|1.7%|0.0%|
[nixspam](#nixspam)|21661|21661|439|2.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|406|0.8%|0.0%|
[voipbl](#voipbl)|10350|10759|295|2.7%|0.0%|
[openbl_60d](#openbl_60d)|7583|7583|171|2.2%|0.0%|
[dm_tor](#dm_tor)|6424|6424|170|2.6%|0.0%|
[bm_tor](#bm_tor)|6427|6427|170|2.6%|0.0%|
[et_tor](#et_tor)|6360|6360|167|2.6%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7208|7208|157|2.1%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5604|5604|120|2.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|97|6.6%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8058|8058|75|0.9%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2068|2068|69|3.3%|0.0%|
[openbl_30d](#openbl_30d)|3180|3180|67|2.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|66|5.1%|0.0%|
[et_compromised](#et_compromised)|2191|2191|62|2.8%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|61|2.8%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|58|8.6%|0.0%|
[xroxy](#xroxy)|2022|2022|57|2.8%|0.0%|
[et_botcc](#et_botcc)|505|505|41|8.1%|0.0%|
[proxyrss](#proxyrss)|1722|1722|36|2.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|33|1.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1883|1883|30|1.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1826|1826|29|1.5%|0.0%|
[shunlist](#shunlist)|1253|1253|25|1.9%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|17|4.5%|0.0%|
[proxz](#proxz)|493|493|16|3.2%|0.0%|
[openbl_7d](#openbl_7d)|913|913|16|1.7%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|426|426|15|3.5%|0.0%|
[malc0de](#malc0de)|397|397|12|3.0%|0.0%|
[ciarmy](#ciarmy)|294|294|10|3.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|9|2.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|722|722|9|1.2%|0.0%|
[zeus](#zeus)|267|267|7|2.6%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.0%|
[php_commenters](#php_commenters)|281|281|5|1.7%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[zeus_badips](#zeus_badips)|231|231|4|1.7%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|327|327|4|1.2%|0.0%|
[sslbl](#sslbl)|363|363|3|0.8%|0.0%|
[openbl_1d](#openbl_1d)|151|151|3|1.9%|0.0%|
[feodo](#feodo)|77|77|3|3.8%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|107|107|1|0.9%|0.0%|

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
[spamhaus_edrop](#spamhaus_edrop)|57|487168|98904|20.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|7733|2.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|7617|4.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|2466|2.6%|0.0%|
[blocklist_de](#blocklist_de)|23464|23464|1483|6.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14766|14766|1127|7.6%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14303|14303|1065|7.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|934|2.9%|0.0%|
[dshield](#dshield)|20|5120|512|10.0%|0.0%|
[nixspam](#nixspam)|21661|21661|505|2.3%|0.0%|
[voipbl](#voipbl)|10350|10759|431|4.0%|0.0%|
[openbl_60d](#openbl_60d)|7583|7583|343|4.5%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7208|7208|240|3.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|230|0.4%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|207|6.3%|0.0%|
[et_tor](#et_tor)|6360|6360|191|3.0%|0.0%|
[dm_tor](#dm_tor)|6424|6424|186|2.8%|0.0%|
[bm_tor](#bm_tor)|6427|6427|186|2.8%|0.0%|
[openbl_30d](#openbl_30d)|3180|3180|176|5.5%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5604|5604|174|3.1%|0.0%|
[et_compromised](#et_compromised)|2191|2191|116|5.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|114|5.2%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8058|8058|108|1.3%|0.0%|
[xroxy](#xroxy)|2022|2022|99|4.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1826|1826|94|5.1%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2068|2068|82|3.9%|0.0%|
[shunlist](#shunlist)|1253|1253|69|5.5%|0.0%|
[proxyrss](#proxyrss)|1722|1722|56|3.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|45|3.0%|0.0%|
[openbl_7d](#openbl_7d)|913|913|42|4.6%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|722|722|36|4.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1883|1883|34|1.8%|0.0%|
[php_spammers](#php_spammers)|417|417|31|7.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|28|4.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|26|2.0%|0.0%|
[malc0de](#malc0de)|397|397|25|6.2%|0.0%|
[proxz](#proxz)|493|493|24|4.8%|0.0%|
[et_botcc](#et_botcc)|505|505|22|4.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|21|5.6%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|426|426|13|3.0%|0.0%|
[ciarmy](#ciarmy)|294|294|11|3.7%|0.0%|
[php_dictionary](#php_dictionary)|433|433|10|2.3%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|107|107|10|9.3%|0.0%|
[zeus](#zeus)|267|267|9|3.3%|0.0%|
[php_commenters](#php_commenters)|281|281|9|3.2%|0.0%|
[zeus_badips](#zeus_badips)|231|231|8|3.4%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[openbl_1d](#openbl_1d)|151|151|7|4.6%|0.0%|
[sslbl](#sslbl)|363|363|6|1.6%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|6|3.6%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|327|327|5|1.5%|0.0%|
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
[spamhaus_edrop](#spamhaus_edrop)|57|487168|270785|55.5%|0.1%|
[et_block](#et_block)|997|18338381|196186|1.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|195904|1.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|14365|8.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|9231|2.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|5888|6.3%|0.0%|
[blocklist_de](#blocklist_de)|23464|23464|2921|12.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14766|14766|2272|15.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14303|14303|2213|15.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|2085|6.6%|0.0%|
[voipbl](#voipbl)|10350|10759|1591|14.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1172|2.4%|0.0%|
[nixspam](#nixspam)|21661|21661|1018|4.6%|0.0%|
[openbl_60d](#openbl_60d)|7583|7583|719|9.4%|0.0%|
[dm_tor](#dm_tor)|6424|6424|634|9.8%|0.0%|
[bm_tor](#bm_tor)|6427|6427|634|9.8%|0.0%|
[et_tor](#et_tor)|6360|6360|628|9.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7208|7208|512|7.1%|0.0%|
[openbl_30d](#openbl_30d)|3180|3180|283|8.8%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1826|1826|267|14.6%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8058|8058|238|2.9%|0.0%|
[et_compromised](#et_compromised)|2191|2191|219|9.9%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|217|9.9%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|208|6.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5604|5604|160|2.8%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|146|11.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|125|33.6%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1883|1883|120|6.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|110|7.5%|0.0%|
[shunlist](#shunlist)|1253|1253|100|7.9%|0.0%|
[openbl_7d](#openbl_7d)|913|913|94|10.2%|0.0%|
[xroxy](#xroxy)|2022|2022|84|4.1%|0.0%|
[et_botcc](#et_botcc)|505|505|78|15.4%|0.0%|
[malc0de](#malc0de)|397|397|68|17.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|426|426|59|13.8%|0.0%|
[proxyrss](#proxyrss)|1722|1722|58|3.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|51|7.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|722|722|51|7.0%|0.0%|
[ciarmy](#ciarmy)|294|294|50|17.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2068|2068|47|2.2%|0.0%|
[proxz](#proxz)|493|493|46|9.3%|0.0%|
[php_spammers](#php_spammers)|417|417|26|6.2%|0.0%|
[php_dictionary](#php_dictionary)|433|433|24|5.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|327|327|24|7.3%|0.0%|
[sslbl](#sslbl)|363|363|23|6.3%|0.0%|
[zeus](#zeus)|267|267|19|7.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|16|9.7%|0.0%|
[php_harvesters](#php_harvesters)|257|257|15|5.8%|0.0%|
[php_commenters](#php_commenters)|281|281|15|5.3%|0.0%|
[openbl_1d](#openbl_1d)|151|151|15|9.9%|0.0%|
[zeus_badips](#zeus_badips)|231|231|14|6.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|107|107|14|13.0%|0.0%|
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
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|22|0.0%|3.2%|
[xroxy](#xroxy)|2022|2022|13|0.6%|1.9%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|11|0.0%|1.6%|
[proxyrss](#proxyrss)|1722|1722|11|0.6%|1.6%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|11|0.0%|1.6%|
[ri_web_proxies](#ri_web_proxies)|5604|5604|10|0.1%|1.4%|
[stopforumspam_1d](#stopforumspam_1d)|7208|7208|6|0.0%|0.8%|
[ri_connect_proxies](#ri_connect_proxies)|2068|2068|6|0.2%|0.8%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|2|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|8058|8058|2|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.2%|
[et_block](#et_block)|997|18338381|2|0.0%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|2|0.0%|0.2%|
[blocklist_de](#blocklist_de)|23464|23464|2|0.0%|0.2%|
[proxz](#proxz)|493|493|1|0.2%|0.1%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.1%|
[nixspam](#nixspam)|21661|21661|1|0.0%|0.1%|
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
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|45|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|25|1.9%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|21|0.0%|0.0%|
[dm_tor](#dm_tor)|6424|6424|21|0.3%|0.0%|
[bm_tor](#bm_tor)|6427|6427|21|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|19|1.3%|0.0%|
[et_tor](#et_tor)|6360|6360|19|0.2%|0.0%|
[nixspam](#nixspam)|21661|21661|15|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8058|8058|13|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7208|7208|10|0.1%|0.0%|
[blocklist_de](#blocklist_de)|23464|23464|9|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5604|5604|5|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7583|7583|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|5|1.3%|0.0%|
[voipbl](#voipbl)|10350|10759|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3180|3180|4|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14303|14303|4|0.0%|0.0%|
[malc0de](#malc0de)|397|397|3|0.7%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1883|1883|3|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|3|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1826|1826|2|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|107|107|2|1.8%|0.0%|
[zeus_badips](#zeus_badips)|231|231|1|0.4%|0.0%|
[zeus](#zeus)|267|267|1|0.3%|0.0%|
[xroxy](#xroxy)|2022|2022|1|0.0%|0.0%|
[sslbl](#sslbl)|363|363|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|1|0.0%|0.0%|
[shunlist](#shunlist)|1253|1253|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.0%|
[palevo](#palevo)|13|13|1|7.6%|0.0%|
[openbl_7d](#openbl_7d)|913|913|1|0.1%|0.0%|
[feodo](#feodo)|77|77|1|1.2%|0.0%|
[et_compromised](#et_compromised)|2191|2191|1|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|426|426|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14766|14766|1|0.0%|0.0%|

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
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|2|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7583|7583|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|3180|3180|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7208|7208|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8058|8058|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5604|5604|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|913|913|1|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2191|2191|1|0.0%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|426|426|1|0.2%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1826|1826|1|0.0%|0.0%|
[blocklist_de](#blocklist_de)|23464|23464|1|0.0%|0.0%|

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
[spamhaus_edrop](#spamhaus_edrop)|57|487168|1|0.0%|0.2%|

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
[snort_ipfilter](#snort_ipfilter)|8058|8058|26|0.3%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|26|0.0%|2.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|25|0.0%|1.9%|
[fullbogons](#fullbogons)|3639|670579672|9|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|6|0.0%|0.4%|
[malc0de](#malc0de)|397|397|4|1.0%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|3|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|2|0.0%|0.1%|
[cleanmx_viruses](#cleanmx_viruses)|426|426|2|0.4%|0.1%|
[nixspam](#nixspam)|21661|21661|1|0.0%|0.0%|
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
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|234|0.2%|62.9%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|200|0.6%|53.7%|
[snort_ipfilter](#snort_ipfilter)|8058|8058|178|2.2%|47.8%|
[dm_tor](#dm_tor)|6424|6424|170|2.6%|45.6%|
[bm_tor](#bm_tor)|6427|6427|170|2.6%|45.6%|
[et_tor](#et_tor)|6360|6360|169|2.6%|45.4%|
[stopforumspam_1d](#stopforumspam_1d)|7208|7208|157|2.1%|42.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|125|0.0%|33.6%|
[php_commenters](#php_commenters)|281|281|28|9.9%|7.5%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|25|0.0%|6.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|21|0.0%|5.6%|
[openbl_60d](#openbl_60d)|7583|7583|18|0.2%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|17|0.0%|4.5%|
[php_harvesters](#php_harvesters)|257|257|6|2.3%|1.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|1.3%|
[ri_web_proxies](#ri_web_proxies)|5604|5604|4|0.0%|1.0%|
[php_spammers](#php_spammers)|417|417|4|0.9%|1.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|1.0%|
[shunlist](#shunlist)|1253|1253|2|0.1%|0.5%|
[xroxy](#xroxy)|2022|2022|1|0.0%|0.2%|
[voipbl](#voipbl)|10350|10759|1|0.0%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2068|2068|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|14766|14766|1|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|14303|14303|1|0.0%|0.2%|
[blocklist_de](#blocklist_de)|23464|23464|1|0.0%|0.2%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Tue Jun  2 02:15:02 UTC 2015.

The ipset `nixspam` has **21661** entries, **21661** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1018|0.0%|4.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|505|0.0%|2.3%|
[blocklist_de](#blocklist_de)|23464|23464|487|2.0%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|439|0.0%|2.0%|
[blocklist_de_mail](#blocklist_de_mail)|14766|14766|425|2.8%|1.9%|
[et_block](#et_block)|997|18338381|320|0.0%|1.4%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|319|0.0%|1.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|318|0.0%|1.4%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|241|0.2%|1.1%|
[snort_ipfilter](#snort_ipfilter)|8058|8058|225|2.7%|1.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|151|0.4%|0.6%|
[ri_web_proxies](#ri_web_proxies)|5604|5604|86|1.5%|0.3%|
[xroxy](#xroxy)|2022|2022|74|3.6%|0.3%|
[php_dictionary](#php_dictionary)|433|433|71|16.3%|0.3%|
[php_spammers](#php_spammers)|417|417|62|14.8%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7208|7208|58|0.8%|0.2%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|40|0.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|39|1.2%|0.1%|
[proxz](#proxz)|493|493|25|5.0%|0.1%|
[proxyrss](#proxyrss)|1722|1722|19|1.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1883|1883|17|0.9%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14303|14303|17|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|15|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2068|2068|12|0.5%|0.0%|
[php_commenters](#php_commenters)|281|281|10|3.5%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|10|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|722|722|8|1.1%|0.0%|
[openbl_60d](#openbl_60d)|7583|7583|5|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1826|1826|2|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|327|327|2|0.6%|0.0%|
[zeus_badips](#zeus_badips)|231|231|1|0.4%|0.0%|
[zeus](#zeus)|267|267|1|0.3%|0.0%|
[shunlist](#shunlist)|1253|1253|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3180|3180|1|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|1|0.6%|0.0%|

## openbl_1d

[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_1days.txt).

The last time downloaded was found to be dated: Tue Jun  2 01:32:00 UTC 2015.

The ipset `openbl_1d` has **151** entries, **151** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7583|7583|148|1.9%|98.0%|
[openbl_30d](#openbl_30d)|3180|3180|148|4.6%|98.0%|
[openbl_7d](#openbl_7d)|913|913|147|16.1%|97.3%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|139|0.0%|92.0%|
[blocklist_de](#blocklist_de)|23464|23464|127|0.5%|84.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|1826|1826|123|6.7%|81.4%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|78|3.5%|51.6%|
[et_compromised](#et_compromised)|2191|2191|74|3.3%|49.0%|
[shunlist](#shunlist)|1253|1253|72|5.7%|47.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|17|10.3%|11.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|9.9%|
[dshield](#dshield)|20|5120|14|0.2%|9.2%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|12|0.0%|7.9%|
[et_block](#et_block)|997|18338381|12|0.0%|7.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7|0.0%|4.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|1.9%|
[blocklist_de_mail](#blocklist_de_mail)|14766|14766|3|0.0%|1.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|722|722|1|0.1%|0.6%|
[blocklist_de_ftp](#blocklist_de_ftp)|327|327|1|0.3%|0.6%|

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
[bruteforceblocker](#bruteforceblocker)|2175|2175|1233|56.6%|38.7%|
[openbl_7d](#openbl_7d)|913|913|913|100.0%|28.7%|
[blocklist_de](#blocklist_de)|23464|23464|750|3.1%|23.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|1826|1826|700|38.3%|22.0%|
[shunlist](#shunlist)|1253|1253|597|47.6%|18.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|283|0.0%|8.8%|
[et_block](#et_block)|997|18338381|204|0.0%|6.4%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|199|0.0%|6.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|176|0.0%|5.5%|
[openbl_1d](#openbl_1d)|151|151|148|98.0%|4.6%|
[dshield](#dshield)|20|5120|98|1.9%|3.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|67|0.0%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|14766|14766|42|0.2%|1.3%|
[blocklist_de_imap](#blocklist_de_imap)|722|722|34|4.7%|1.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|24|14.6%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|13|0.0%|0.4%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|6|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|4|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|8058|8058|4|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|327|327|4|1.2%|0.1%|
[voipbl](#voipbl)|10350|10759|3|0.0%|0.0%|
[zeus](#zeus)|267|267|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|231|231|1|0.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7208|7208|1|0.0%|0.0%|
[nixspam](#nixspam)|21661|21661|1|0.0%|0.0%|
[ciarmy](#ciarmy)|294|294|1|0.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14303|14303|1|0.0%|0.0%|

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
[bruteforceblocker](#bruteforceblocker)|2175|2175|1307|60.0%|17.2%|
[openbl_7d](#openbl_7d)|913|913|913|100.0%|12.0%|
[blocklist_de](#blocklist_de)|23464|23464|840|3.5%|11.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1826|1826|767|42.0%|10.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|719|0.0%|9.4%|
[shunlist](#shunlist)|1253|1253|616|49.1%|8.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|343|0.0%|4.5%|
[et_block](#et_block)|997|18338381|245|0.0%|3.2%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|240|0.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|171|0.0%|2.2%|
[openbl_1d](#openbl_1d)|151|151|148|98.0%|1.9%|
[dshield](#dshield)|20|5120|116|2.2%|1.5%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|54|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|14766|14766|49|0.3%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|722|722|39|5.4%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|27|16.4%|0.3%|
[snort_ipfilter](#snort_ipfilter)|8058|8058|26|0.3%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|25|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7208|7208|21|0.2%|0.2%|
[dm_tor](#dm_tor)|6424|6424|21|0.3%|0.2%|
[bm_tor](#bm_tor)|6427|6427|21|0.3%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|19|0.0%|0.2%|
[et_tor](#et_tor)|6360|6360|19|0.2%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|16|0.4%|0.2%|
[voipbl](#voipbl)|10350|10759|9|0.0%|0.1%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|6|0.0%|0.0%|
[nixspam](#nixspam)|21661|21661|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|327|327|5|1.5%|0.0%|
[zeus](#zeus)|267|267|2|0.7%|0.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|231|231|1|0.4%|0.0%|
[ciarmy](#ciarmy)|294|294|1|0.3%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14303|14303|1|0.0%|0.0%|

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
[blocklist_de](#blocklist_de)|23464|23464|522|2.2%|57.1%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|520|23.9%|56.9%|
[et_compromised](#et_compromised)|2191|2191|516|23.5%|56.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|1826|1826|494|27.0%|54.1%|
[shunlist](#shunlist)|1253|1253|393|31.3%|43.0%|
[openbl_1d](#openbl_1d)|151|151|147|97.3%|16.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|94|0.0%|10.2%|
[et_block](#et_block)|997|18338381|89|0.0%|9.7%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|86|0.0%|9.4%|
[dshield](#dshield)|20|5120|64|1.2%|7.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|42|0.0%|4.6%|
[blocklist_de_mail](#blocklist_de_mail)|14766|14766|25|0.1%|2.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|23|14.0%|2.5%|
[blocklist_de_imap](#blocklist_de_imap)|722|722|21|2.9%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|16|0.0%|1.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|1.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|5|0.0%|0.5%|
[voipbl](#voipbl)|10350|10759|3|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|8058|8058|2|0.0%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|327|327|2|0.6%|0.2%|
[zeus](#zeus)|267|267|1|0.3%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.1%|
[ciarmy](#ciarmy)|294|294|1|0.3%|0.1%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Tue Jun  2 02:18:22 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|997|18338381|12|0.0%|92.3%|
[snort_ipfilter](#snort_ipfilter)|8058|8058|11|0.1%|84.6%|
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
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|206|0.2%|73.3%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|163|0.5%|58.0%|
[stopforumspam_1d](#stopforumspam_1d)|7208|7208|108|1.4%|38.4%|
[blocklist_de](#blocklist_de)|23464|23464|62|0.2%|22.0%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|50|1.5%|17.7%|
[snort_ipfilter](#snort_ipfilter)|8058|8058|37|0.4%|13.1%|
[php_spammers](#php_spammers)|417|417|32|7.6%|11.3%|
[et_tor](#et_tor)|6360|6360|29|0.4%|10.3%|
[dm_tor](#dm_tor)|6424|6424|29|0.4%|10.3%|
[bm_tor](#bm_tor)|6427|6427|29|0.4%|10.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|29|17.6%|10.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|28|7.5%|9.9%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|24|0.0%|8.5%|
[et_block](#et_block)|997|18338381|24|0.0%|8.5%|
[blocklist_de_apache](#blocklist_de_apache)|14303|14303|24|0.1%|8.5%|
[php_dictionary](#php_dictionary)|433|433|22|5.0%|7.8%|
[blocklist_de_mail](#blocklist_de_mail)|14766|14766|17|0.1%|6.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|5.3%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|13|0.0%|4.6%|
[ri_web_proxies](#ri_web_proxies)|5604|5604|11|0.1%|3.9%|
[nixspam](#nixspam)|21661|21661|10|0.0%|3.5%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.2%|
[openbl_60d](#openbl_60d)|7583|7583|8|0.1%|2.8%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|7|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|1.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1883|1883|5|0.2%|1.7%|
[xroxy](#xroxy)|2022|2022|3|0.1%|1.0%|
[proxz](#proxz)|493|493|3|0.6%|1.0%|
[proxyrss](#proxyrss)|1722|1722|2|0.1%|0.7%|
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
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|85|0.0%|19.6%|
[php_spammers](#php_spammers)|417|417|84|20.1%|19.3%|
[nixspam](#nixspam)|21661|21661|71|0.3%|16.3%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|69|0.2%|15.9%|
[snort_ipfilter](#snort_ipfilter)|8058|8058|60|0.7%|13.8%|
[blocklist_de](#blocklist_de)|23464|23464|42|0.1%|9.6%|
[ri_web_proxies](#ri_web_proxies)|5604|5604|33|0.5%|7.6%|
[xroxy](#xroxy)|2022|2022|24|1.1%|5.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|24|0.0%|5.5%|
[stopforumspam_1d](#stopforumspam_1d)|7208|7208|23|0.3%|5.3%|
[php_commenters](#php_commenters)|281|281|22|7.8%|5.0%|
[blocklist_de_mail](#blocklist_de_mail)|14766|14766|21|0.1%|4.8%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|20|0.6%|4.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|10|0.0%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|9|0.0%|2.0%|
[proxz](#proxz)|493|493|7|1.4%|1.6%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|7|0.0%|1.6%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|4|0.0%|0.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.9%|
[et_tor](#et_tor)|6360|6360|4|0.0%|0.9%|
[et_block](#et_block)|997|18338381|4|0.0%|0.9%|
[dm_tor](#dm_tor)|6424|6424|4|0.0%|0.9%|
[bm_tor](#bm_tor)|6427|6427|4|0.0%|0.9%|
[ri_connect_proxies](#ri_connect_proxies)|2068|2068|3|0.1%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|2|1.2%|0.4%|
[proxyrss](#proxyrss)|1722|1722|1|0.0%|0.2%|
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
[stopforumspam_1d](#stopforumspam_1d)|7208|7208|35|0.4%|13.6%|
[blocklist_de](#blocklist_de)|23464|23464|25|0.1%|9.7%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|19|0.5%|7.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|5.8%|
[snort_ipfilter](#snort_ipfilter)|8058|8058|9|0.1%|3.5%|
[php_commenters](#php_commenters)|281|281|9|3.2%|3.5%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|8|0.0%|3.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|7|0.0%|2.7%|
[dm_tor](#dm_tor)|6424|6424|7|0.1%|2.7%|
[bm_tor](#bm_tor)|6427|6427|7|0.1%|2.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|6|1.6%|2.3%|
[et_tor](#et_tor)|6360|6360|6|0.0%|2.3%|
[blocklist_de_ftp](#blocklist_de_ftp)|327|327|4|1.2%|1.5%|
[xroxy](#xroxy)|2022|2022|2|0.0%|0.7%|
[proxyrss](#proxyrss)|1722|1722|2|0.1%|0.7%|
[openbl_60d](#openbl_60d)|7583|7583|2|0.0%|0.7%|
[nixspam](#nixspam)|21661|21661|2|0.0%|0.7%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|2|1.2%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|14766|14766|2|0.0%|0.7%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|1|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|1|0.0%|0.3%|
[ri_web_proxies](#ri_web_proxies)|5604|5604|1|0.0%|0.3%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.3%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|
[fullbogons](#fullbogons)|3639|670579672|1|0.0%|0.3%|
[et_block](#et_block)|997|18338381|1|0.0%|0.3%|
[bogons](#bogons)|13|592708608|1|0.0%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|14303|14303|1|0.0%|0.3%|

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
[nixspam](#nixspam)|21661|21661|62|0.2%|14.8%|
[snort_ipfilter](#snort_ipfilter)|8058|8058|51|0.6%|12.2%|
[blocklist_de](#blocklist_de)|23464|23464|44|0.1%|10.5%|
[php_commenters](#php_commenters)|281|281|32|11.3%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|31|0.0%|7.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|26|0.0%|6.2%|
[stopforumspam_1d](#stopforumspam_1d)|7208|7208|25|0.3%|5.9%|
[ri_web_proxies](#ri_web_proxies)|5604|5604|25|0.4%|5.9%|
[blocklist_de_mail](#blocklist_de_mail)|14766|14766|23|0.1%|5.5%|
[xroxy](#xroxy)|2022|2022|19|0.9%|4.5%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|14|0.4%|3.3%|
[proxz](#proxz)|493|493|7|1.4%|1.6%|
[et_tor](#et_tor)|6360|6360|6|0.0%|1.4%|
[dm_tor](#dm_tor)|6424|6424|6|0.0%|1.4%|
[bm_tor](#bm_tor)|6427|6427|6|0.0%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|1.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1883|1883|5|0.2%|1.1%|
[blocklist_de_apache](#blocklist_de_apache)|14303|14303|5|0.0%|1.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.9%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|4|2.4%|0.9%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|3|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|2|0.0%|0.4%|
[ri_connect_proxies](#ri_connect_proxies)|2068|2068|2|0.0%|0.4%|
[proxyrss](#proxyrss)|1722|1722|2|0.1%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[et_block](#et_block)|997|18338381|2|0.0%|0.4%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1826|1826|1|0.0%|0.2%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Tue Jun  2 00:11:27 UTC 2015.

The ipset `proxyrss` has **1722** entries, **1722** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|862|0.9%|50.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|727|2.3%|42.2%|
[ri_web_proxies](#ri_web_proxies)|5604|5604|629|11.2%|36.5%|
[xroxy](#xroxy)|2022|2022|460|22.7%|26.7%|
[stopforumspam_1d](#stopforumspam_1d)|7208|7208|456|6.3%|26.4%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|247|7.6%|14.3%|
[blocklist_de](#blocklist_de)|23464|23464|246|1.0%|14.2%|
[ri_connect_proxies](#ri_connect_proxies)|2068|2068|198|9.5%|11.4%|
[proxz](#proxz)|493|493|165|33.4%|9.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|58|0.0%|3.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|56|0.0%|3.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|36|0.0%|2.0%|
[nixspam](#nixspam)|21661|21661|19|0.0%|1.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|6|3.6%|0.3%|
[snort_ipfilter](#snort_ipfilter)|8058|8058|3|0.0%|0.1%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.1%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.1%|
[php_commenters](#php_commenters)|281|281|2|0.7%|0.1%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|2|0.0%|0.1%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Tue Jun  2 00:11:33 UTC 2015.

The ipset `proxz` has **493** entries, **493** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|292|0.3%|59.2%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|259|0.8%|52.5%|
[xroxy](#xroxy)|2022|2022|237|11.7%|48.0%|
[ri_web_proxies](#ri_web_proxies)|5604|5604|208|3.7%|42.1%|
[proxyrss](#proxyrss)|1722|1722|165|9.5%|33.4%|
[stopforumspam_1d](#stopforumspam_1d)|7208|7208|106|1.4%|21.5%|
[blocklist_de](#blocklist_de)|23464|23464|98|0.4%|19.8%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|85|2.6%|17.2%|
[ri_connect_proxies](#ri_connect_proxies)|2068|2068|76|3.6%|15.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|46|0.0%|9.3%|
[nixspam](#nixspam)|21661|21661|25|0.1%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|24|0.0%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|16|0.0%|3.2%|
[blocklist_de_mail](#blocklist_de_mail)|14766|14766|12|0.0%|2.4%|
[snort_ipfilter](#snort_ipfilter)|8058|8058|11|0.1%|2.2%|
[php_spammers](#php_spammers)|417|417|7|1.6%|1.4%|
[php_dictionary](#php_dictionary)|433|433|7|1.6%|1.4%|
[php_commenters](#php_commenters)|281|281|3|1.0%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|3|1.8%|0.6%|
[et_compromised](#et_compromised)|2191|2191|2|0.0%|0.4%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|2|0.0%|0.4%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|2|0.0%|0.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.2%|
[et_tor](#et_tor)|6360|6360|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|1826|1826|1|0.0%|0.2%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Tue Jun  2 01:26:13 UTC 2015.

The ipset `ri_connect_proxies` has **2068** entries, **2068** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|1217|1.3%|58.8%|
[ri_web_proxies](#ri_web_proxies)|5604|5604|844|15.0%|40.8%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|661|2.1%|31.9%|
[xroxy](#xroxy)|2022|2022|320|15.8%|15.4%|
[proxyrss](#proxyrss)|1722|1722|198|11.4%|9.5%|
[stopforumspam_1d](#stopforumspam_1d)|7208|7208|147|2.0%|7.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|82|0.0%|3.9%|
[proxz](#proxz)|493|493|76|15.4%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|69|0.0%|3.3%|
[blocklist_de](#blocklist_de)|23464|23464|63|0.2%|3.0%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|62|1.9%|2.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|47|0.0%|2.2%|
[nixspam](#nixspam)|21661|21661|12|0.0%|0.5%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.2%|
[snort_ipfilter](#snort_ipfilter)|8058|8058|3|0.0%|0.1%|
[php_dictionary](#php_dictionary)|433|433|3|0.6%|0.1%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[et_tor](#et_tor)|6360|6360|2|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[dm_tor](#dm_tor)|6424|6424|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6427|6427|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14766|14766|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Tue Jun  2 01:26:05 UTC 2015.

The ipset `ri_web_proxies` has **5604** entries, **5604** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|2760|2.9%|49.2%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|1704|5.4%|30.4%|
[ri_connect_proxies](#ri_connect_proxies)|2068|2068|844|40.8%|15.0%|
[xroxy](#xroxy)|2022|2022|827|40.9%|14.7%|
[proxyrss](#proxyrss)|1722|1722|629|36.5%|11.2%|
[stopforumspam_1d](#stopforumspam_1d)|7208|7208|563|7.8%|10.0%|
[blocklist_de](#blocklist_de)|23464|23464|367|1.5%|6.5%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|332|10.2%|5.9%|
[proxz](#proxz)|493|493|208|42.1%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|174|0.0%|3.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|160|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|120|0.0%|2.1%|
[nixspam](#nixspam)|21661|21661|86|0.3%|1.5%|
[snort_ipfilter](#snort_ipfilter)|8058|8058|47|0.5%|0.8%|
[php_dictionary](#php_dictionary)|433|433|33|7.6%|0.5%|
[blocklist_de_mail](#blocklist_de_mail)|14766|14766|33|0.2%|0.5%|
[php_spammers](#php_spammers)|417|417|25|5.9%|0.4%|
[php_commenters](#php_commenters)|281|281|11|3.9%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|10|1.4%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.0%|
[et_tor](#et_tor)|6360|6360|4|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|4|2.4%|0.0%|
[dm_tor](#dm_tor)|6424|6424|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6427|6427|3|0.0%|0.0%|
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
[bruteforceblocker](#bruteforceblocker)|2175|2175|522|24.0%|41.6%|
[blocklist_de](#blocklist_de)|23464|23464|405|1.7%|32.3%|
[openbl_7d](#openbl_7d)|913|913|393|43.0%|31.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|1826|1826|367|20.0%|29.2%|
[et_block](#et_block)|997|18338381|108|0.0%|8.6%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|102|0.0%|8.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|100|0.0%|7.9%|
[openbl_1d](#openbl_1d)|151|151|72|47.6%|5.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|69|0.0%|5.5%|
[dshield](#dshield)|20|5120|67|1.3%|5.3%|
[sslbl](#sslbl)|363|363|43|11.8%|3.4%|
[blocklist_de_apache](#blocklist_de_apache)|14303|14303|29|0.2%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|25|0.0%|1.9%|
[ciarmy](#ciarmy)|294|294|23|7.8%|1.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|18|10.9%|1.4%|
[voipbl](#voipbl)|10350|10759|11|0.1%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|14766|14766|6|0.0%|0.4%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|5|0.0%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|4|0.0%|0.3%|
[blocklist_de_imap](#blocklist_de_imap)|722|722|4|0.5%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|3|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|8058|8058|3|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1883|1883|3|0.1%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.1%|
[blocklist_de_ftp](#blocklist_de_ftp)|327|327|2|0.6%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7208|7208|1|0.0%|0.0%|
[nixspam](#nixspam)|21661|21661|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_tor](#et_tor)|6360|6360|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6424|6424|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6427|6427|1|0.0%|0.0%|

## snort_ipfilter

[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)

Source is downloaded from [this link](http://labs.snort.org/feeds/ip-filter.blf).

The last time downloaded was found to be dated: Tue Jun  2 01:30:00 UTC 2015.

The ipset `snort_ipfilter` has **8058** entries, **8058** unique IPs.

The following table shows the overlaps of `snort_ipfilter` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `snort_ipfilter`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `snort_ipfilter`.
- ` this % ` is the percentage **of this ipset (`snort_ipfilter`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[dm_tor](#dm_tor)|6424|6424|1088|16.9%|13.5%|
[bm_tor](#bm_tor)|6427|6427|1088|16.9%|13.5%|
[et_tor](#et_tor)|6360|6360|1078|16.9%|13.3%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|779|0.8%|9.6%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|607|1.9%|7.5%|
[stopforumspam_1d](#stopforumspam_1d)|7208|7208|342|4.7%|4.2%|
[et_block](#et_block)|997|18338381|297|0.0%|3.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|238|0.0%|2.9%|
[zeus](#zeus)|267|267|228|85.3%|2.8%|
[nixspam](#nixspam)|21661|21661|225|1.0%|2.7%|
[zeus_badips](#zeus_badips)|231|231|203|87.8%|2.5%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|178|47.8%|2.2%|
[blocklist_de](#blocklist_de)|23464|23464|127|0.5%|1.5%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|119|0.0%|1.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|108|0.0%|1.3%|
[blocklist_de_mail](#blocklist_de_mail)|14766|14766|89|0.6%|1.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|75|0.0%|0.9%|
[feodo](#feodo)|77|77|61|79.2%|0.7%|
[php_dictionary](#php_dictionary)|433|433|60|13.8%|0.7%|
[php_spammers](#php_spammers)|417|417|51|12.2%|0.6%|
[ri_web_proxies](#ri_web_proxies)|5604|5604|47|0.8%|0.5%|
[xroxy](#xroxy)|2022|2022|44|2.1%|0.5%|
[php_commenters](#php_commenters)|281|281|37|13.1%|0.4%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|29|0.8%|0.3%|
[sslbl](#sslbl)|363|363|27|7.4%|0.3%|
[openbl_60d](#openbl_60d)|7583|7583|26|0.3%|0.3%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|26|2.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|19|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|13|0.0%|0.1%|
[proxz](#proxz)|493|493|11|2.2%|0.1%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|722|722|9|1.2%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|14303|14303|8|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|6|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1883|1883|5|0.2%|0.0%|
[openbl_30d](#openbl_30d)|3180|3180|4|0.1%|0.0%|
[shunlist](#shunlist)|1253|1253|3|0.2%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2068|2068|3|0.1%|0.0%|
[proxyrss](#proxyrss)|1722|1722|3|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|426|426|3|0.7%|0.0%|
[openbl_7d](#openbl_7d)|913|913|2|0.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_compromised](#et_compromised)|2191|2191|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1826|1826|2|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|1|0.6%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|327|327|1|0.3%|0.0%|

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
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|981|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|512|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|340|1.0%|0.0%|
[nixspam](#nixspam)|21661|21661|319|1.4%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[openbl_60d](#openbl_60d)|7583|7583|240|3.1%|0.0%|
[openbl_30d](#openbl_30d)|3180|3180|199|6.2%|0.0%|
[blocklist_de](#blocklist_de)|23464|23464|168|0.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1826|1826|113|6.1%|0.0%|
[shunlist](#shunlist)|1253|1253|102|8.1%|0.0%|
[et_compromised](#et_compromised)|2191|2191|102|4.6%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|101|4.6%|0.0%|
[openbl_7d](#openbl_7d)|913|913|86|9.4%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7208|7208|78|1.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|29|2.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14766|14766|26|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|26|0.8%|0.0%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|722|722|20|2.7%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8058|8058|19|0.2%|0.0%|
[zeus_badips](#zeus_badips)|231|231|16|6.9%|0.0%|
[zeus](#zeus)|267|267|16|5.9%|0.0%|
[voipbl](#voipbl)|10350|10759|14|0.1%|0.0%|
[openbl_1d](#openbl_1d)|151|151|12|7.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|6|3.6%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[malc0de](#malc0de)|397|397|4|1.0%|0.0%|
[sslbl](#sslbl)|363|363|3|0.8%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6360|6360|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6424|6424|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6427|6427|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[et_botcc](#et_botcc)|505|505|1|0.1%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|426|426|1|0.2%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|107|107|1|0.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1883|1883|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14303|14303|1|0.0%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|173822|173822|271|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|101|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|27|0.0%|0.0%|
[blocklist_de](#blocklist_de)|23464|23464|8|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7208|7208|7|0.0%|0.0%|
[php_commenters](#php_commenters)|281|281|7|2.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|8058|8058|6|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7583|7583|6|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3180|3180|6|0.1%|0.0%|
[zeus_badips](#zeus_badips)|231|231|5|2.1%|0.0%|
[zeus](#zeus)|267|267|5|1.8%|0.0%|
[shunlist](#shunlist)|1253|1253|5|0.3%|0.0%|
[openbl_7d](#openbl_7d)|913|913|5|0.5%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|4|2.4%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|4|0.1%|0.0%|
[nixspam](#nixspam)|21661|21661|2|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14766|14766|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[malc0de](#malc0de)|397|397|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1826|1826|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14303|14303|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Tue Jun  2 02:15:07 UTC 2015.

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
[snort_ipfilter](#snort_ipfilter)|8058|8058|27|0.3%|7.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|23|0.0%|6.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|6|0.0%|1.6%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|3|0.0%|0.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Tue Jun  2 02:00:02 UTC 2015.

The ipset `stopforumspam_1d` has **7208** entries, **7208** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|7208|23.0%|100.0%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|7075|7.6%|98.1%|
[blocklist_de](#blocklist_de)|23464|23464|1470|6.2%|20.3%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|1416|43.7%|19.6%|
[ri_web_proxies](#ri_web_proxies)|5604|5604|563|10.0%|7.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|512|0.0%|7.1%|
[proxyrss](#proxyrss)|1722|1722|456|26.4%|6.3%|
[xroxy](#xroxy)|2022|2022|355|17.5%|4.9%|
[snort_ipfilter](#snort_ipfilter)|8058|8058|342|4.2%|4.7%|
[et_tor](#et_tor)|6360|6360|297|4.6%|4.1%|
[dm_tor](#dm_tor)|6424|6424|295|4.5%|4.0%|
[bm_tor](#bm_tor)|6427|6427|295|4.5%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|240|0.0%|3.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|157|42.2%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|157|0.0%|2.1%|
[ri_connect_proxies](#ri_connect_proxies)|2068|2068|147|7.1%|2.0%|
[php_commenters](#php_commenters)|281|281|108|38.4%|1.4%|
[proxz](#proxz)|493|493|106|21.5%|1.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|106|64.6%|1.4%|
[et_block](#et_block)|997|18338381|79|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|78|0.0%|1.0%|
[blocklist_de_apache](#blocklist_de_apache)|14303|14303|64|0.4%|0.8%|
[nixspam](#nixspam)|21661|21661|58|0.2%|0.8%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|56|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|14766|14766|39|0.2%|0.5%|
[php_harvesters](#php_harvesters)|257|257|35|13.6%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|26|0.0%|0.3%|
[php_spammers](#php_spammers)|417|417|25|5.9%|0.3%|
[php_dictionary](#php_dictionary)|433|433|23|5.3%|0.3%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1883|1883|22|1.1%|0.3%|
[openbl_60d](#openbl_60d)|7583|7583|21|0.2%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|10|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|7|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[et_compromised](#et_compromised)|2191|2191|4|0.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|4|0.1%|0.0%|
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

The last time downloaded was found to be dated: Tue Jun  2 00:00:38 UTC 2015.

The ipset `stopforumspam_30d` has **92372** entries, **92372** unique IPs.

The following table shows the overlaps of `stopforumspam_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_30d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|31205|99.5%|33.7%|
[stopforumspam_1d](#stopforumspam_1d)|7208|7208|7075|98.1%|7.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|5888|0.0%|6.3%|
[ri_web_proxies](#ri_web_proxies)|5604|5604|2760|49.2%|2.9%|
[blocklist_de](#blocklist_de)|23464|23464|2476|10.5%|2.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2466|0.0%|2.6%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|2207|68.1%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1537|0.0%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|2068|2068|1217|58.8%|1.3%|
[xroxy](#xroxy)|2022|2022|1190|58.8%|1.2%|
[et_block](#et_block)|997|18338381|986|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|981|0.0%|1.0%|
[proxyrss](#proxyrss)|1722|1722|862|50.0%|0.9%|
[snort_ipfilter](#snort_ipfilter)|8058|8058|779|9.6%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|731|0.0%|0.7%|
[dm_tor](#dm_tor)|6424|6424|637|9.9%|0.6%|
[bm_tor](#bm_tor)|6427|6427|637|9.9%|0.6%|
[et_tor](#et_tor)|6360|6360|636|10.0%|0.6%|
[proxz](#proxz)|493|493|292|59.2%|0.3%|
[nixspam](#nixspam)|21661|21661|241|1.1%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|234|62.9%|0.2%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|211|0.1%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|14303|14303|207|1.4%|0.2%|
[php_commenters](#php_commenters)|281|281|206|73.3%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|14766|14766|201|1.3%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|122|74.3%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|101|0.0%|0.1%|
[php_spammers](#php_spammers)|417|417|100|23.9%|0.1%|
[php_dictionary](#php_dictionary)|433|433|85|19.6%|0.0%|
[php_harvesters](#php_harvesters)|257|257|63|24.5%|0.0%|
[openbl_60d](#openbl_60d)|7583|7583|54|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|45|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1883|1883|44|2.3%|0.0%|
[voipbl](#voipbl)|10350|10759|39|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|22|3.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|16|0.0%|0.0%|
[et_compromised](#et_compromised)|2191|2191|9|0.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|8|0.3%|0.0%|
[dshield](#dshield)|20|5120|6|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1826|1826|6|0.3%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|327|327|6|1.8%|0.0%|
[shunlist](#shunlist)|1253|1253|4|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3180|3180|4|0.1%|0.0%|
[zeus_badips](#zeus_badips)|231|231|3|1.2%|0.0%|
[zeus](#zeus)|267|267|3|1.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|3|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|722|722|3|0.4%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3639|670579672|2|0.0%|0.0%|
[sslbl](#sslbl)|363|363|1|0.2%|0.0%|
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
[stopforumspam_1d](#stopforumspam_1d)|7208|7208|7208|100.0%|23.0%|
[blocklist_de](#blocklist_de)|23464|23464|2227|9.4%|7.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2085|0.0%|6.6%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|2056|63.4%|6.5%|
[ri_web_proxies](#ri_web_proxies)|5604|5604|1704|30.4%|5.4%|
[xroxy](#xroxy)|2022|2022|980|48.4%|3.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|934|0.0%|2.9%|
[proxyrss](#proxyrss)|1722|1722|727|42.2%|2.3%|
[ri_connect_proxies](#ri_connect_proxies)|2068|2068|661|31.9%|2.1%|
[snort_ipfilter](#snort_ipfilter)|8058|8058|607|7.5%|1.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|558|0.0%|1.7%|
[dm_tor](#dm_tor)|6424|6424|493|7.6%|1.5%|
[bm_tor](#bm_tor)|6427|6427|493|7.6%|1.5%|
[et_tor](#et_tor)|6360|6360|491|7.7%|1.5%|
[et_block](#et_block)|997|18338381|341|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|340|0.0%|1.0%|
[proxz](#proxz)|493|493|259|52.5%|0.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|200|53.7%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|178|0.0%|0.5%|
[php_commenters](#php_commenters)|281|281|163|58.0%|0.5%|
[nixspam](#nixspam)|21661|21661|151|0.6%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|14303|14303|132|0.9%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|14766|14766|122|0.8%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|113|68.9%|0.3%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|99|0.0%|0.3%|
[php_spammers](#php_spammers)|417|417|71|17.0%|0.2%|
[php_dictionary](#php_dictionary)|433|433|69|15.9%|0.2%|
[php_harvesters](#php_harvesters)|257|257|48|18.6%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1883|1883|36|1.9%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|27|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7583|7583|25|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.0%|
[voipbl](#voipbl)|10350|10759|12|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|7|0.0%|0.0%|
[et_compromised](#et_compromised)|2191|2191|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|5|0.2%|0.0%|
[shunlist](#shunlist)|1253|1253|3|0.2%|0.0%|
[dshield](#dshield)|20|5120|3|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|327|327|3|0.9%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1282|1282|2|0.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|722|722|2|0.2%|0.0%|
[zeus_badips](#zeus_badips)|231|231|1|0.4%|0.0%|
[zeus](#zeus)|267|267|1|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3180|3180|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1826|1826|1|0.0%|0.0%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Tue Jun  2 01:27:11 UTC 2015.

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
[blocklist_de](#blocklist_de)|23464|23464|41|0.1%|0.3%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|39|0.0%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|107|107|31|28.9%|0.2%|
[et_block](#et_block)|997|18338381|24|0.0%|0.2%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|14|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|12|0.0%|0.1%|
[shunlist](#shunlist)|1253|1253|11|0.8%|0.1%|
[openbl_60d](#openbl_60d)|7583|7583|9|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|14303|14303|5|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7208|7208|3|0.0%|0.0%|
[openbl_7d](#openbl_7d)|913|913|3|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3180|3180|3|0.0%|0.0%|
[ciarmy](#ciarmy)|294|294|3|1.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[et_tor](#et_tor)|6360|6360|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6424|6424|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6427|6427|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1826|1826|2|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|1883|1883|2|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2191|2191|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|14766|14766|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|722|722|1|0.1%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Tue Jun  2 01:33:02 UTC 2015.

The ipset `xroxy` has **2022** entries, **2022** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|1190|1.2%|58.8%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|980|3.1%|48.4%|
[ri_web_proxies](#ri_web_proxies)|5604|5604|827|14.7%|40.9%|
[proxyrss](#proxyrss)|1722|1722|460|26.7%|22.7%|
[stopforumspam_1d](#stopforumspam_1d)|7208|7208|355|4.9%|17.5%|
[ri_connect_proxies](#ri_connect_proxies)|2068|2068|320|15.4%|15.8%|
[proxz](#proxz)|493|493|237|48.0%|11.7%|
[blocklist_de](#blocklist_de)|23464|23464|236|1.0%|11.6%|
[blocklist_de_bots](#blocklist_de_bots)|3238|3238|205|6.3%|10.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|99|0.0%|4.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|84|0.0%|4.1%|
[nixspam](#nixspam)|21661|21661|74|0.3%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|57|0.0%|2.8%|
[snort_ipfilter](#snort_ipfilter)|8058|8058|44|0.5%|2.1%|
[blocklist_de_mail](#blocklist_de_mail)|14766|14766|29|0.1%|1.4%|
[php_dictionary](#php_dictionary)|433|433|24|5.5%|1.1%|
[php_spammers](#php_spammers)|417|417|19|4.5%|0.9%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|13|1.9%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|164|164|6|3.6%|0.2%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|5|0.0%|0.2%|
[php_commenters](#php_commenters)|281|281|3|1.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.1%|
[et_tor](#et_tor)|6360|6360|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[dm_tor](#dm_tor)|6424|6424|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6427|6427|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2191|2191|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|1826|1826|1|0.0%|0.0%|

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
[snort_ipfilter](#snort_ipfilter)|8058|8058|228|2.8%|85.3%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|66|0.0%|24.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|19|0.0%|7.1%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|16|0.0%|5.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|7|0.0%|2.6%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|5|0.0%|1.8%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|3|0.0%|1.1%|
[openbl_60d](#openbl_60d)|7583|7583|2|0.0%|0.7%|
[openbl_30d](#openbl_30d)|3180|3180|2|0.0%|0.7%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|1|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7208|7208|1|0.0%|0.3%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.3%|
[openbl_7d](#openbl_7d)|913|913|1|0.1%|0.3%|
[nixspam](#nixspam)|21661|21661|1|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|
[et_compromised](#et_compromised)|2191|2191|1|0.0%|0.3%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|1|0.0%|0.3%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Tue Jun  2 02:18:21 UTC 2015.

The ipset `zeus_badips` has **231** entries, **231** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|267|267|231|86.5%|100.0%|
[et_block](#et_block)|997|18338381|229|0.0%|99.1%|
[snort_ipfilter](#snort_ipfilter)|8058|8058|203|2.5%|87.8%|
[alienvault_reputation](#alienvault_reputation)|173822|173822|37|0.0%|16.0%|
[spamhaus_drop](#spamhaus_drop)|656|18600704|16|0.0%|6.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14|0.0%|6.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8|0.0%|3.4%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|5|0.0%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4|0.0%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|92372|92372|3|0.0%|1.2%|
[stopforumspam_7d](#stopforumspam_7d)|31339|31339|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|7208|7208|1|0.0%|0.4%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.4%|
[openbl_60d](#openbl_60d)|7583|7583|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|3180|3180|1|0.0%|0.4%|
[nixspam](#nixspam)|21661|21661|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.4%|
[et_compromised](#et_compromised)|2191|2191|1|0.0%|0.4%|
[bruteforceblocker](#bruteforceblocker)|2175|2175|1|0.0%|0.4%|
