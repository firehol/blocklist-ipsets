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

The following list was automatically generated on Wed Jun  3 15:46:26 UTC 2015.

The update frequency is the maximum allowed by internal configuration. A list will never be downloaded sooner than the update frequency stated. A list may also not be downloaded, after this frequency expired, if it has not been modified on the server (as reported by HTTP `IF_MODIFIED_SINCE` method).

name|info|type|entries|update|
:--:|:--:|:--:|:-----:|:----:|
[alienvault_reputation](#alienvault_reputation)|[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)|ipv4 hash:ip|179596 unique IPs|updated every 6 hours  from [this link](https://reputation.alienvault.com/reputation.generic)
[blocklist_de](#blocklist_de)|[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**|ipv4 hash:ip|36060 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/all.txt)
[blocklist_de_apache](#blocklist_de_apache)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.|ipv4 hash:ip|13972 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/apache.txt)
[blocklist_de_bots](#blocklist_de_bots)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).|ipv4 hash:ip|3042 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bots.txt)
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.|ipv4 hash:ip|2649 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt)
[blocklist_de_ftp](#blocklist_de_ftp)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.|ipv4 hash:ip|874 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ftp.txt)
[blocklist_de_imap](#blocklist_de_imap)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.|ipv4 hash:ip|2401 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/imap.txt)
[blocklist_de_mail](#blocklist_de_mail)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.|ipv4 hash:ip|16484 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/mail.txt)
[blocklist_de_sip](#blocklist_de_sip)|[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)|ipv4 hash:ip|110 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/sip.txt)
[blocklist_de_ssh](#blocklist_de_ssh)|[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.|ipv4 hash:ip|12692 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/ssh.txt)
[blocklist_de_strongips](#blocklist_de_strongips)|[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.|ipv4 hash:ip|175 unique IPs|updated every 30 mins  from [this link](http://lists.blocklist.de/lists/strongips.txt)
[bm_tor](#bm_tor)|[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers|ipv4 hash:ip|6514 unique IPs|updated every 30 mins  from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv)
[bogons](#bogons)|[Team-Cymru.org](http://www.team-cymru.org) private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598 and netblocks that have not been allocated to a regional internet registry - **excellent list - use it only your internet interface**|ipv4 hash:net|13 subnets, 592708608 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt)
[bruteforceblocker](#bruteforceblocker)|[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.|ipv4 hash:ip|2168 unique IPs|updated every 3 hours  from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php)
[ciarmy](#ciarmy)|[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community|ipv4 hash:ip|338 unique IPs|updated every 3 hours  from [this link](http://cinsscore.com/list/ci-badguys.txt)
[cleanmx_viruses](#cleanmx_viruses)|[Clean-MX.de](http://support.clean-mx.de/clean-mx/viruses.php) IPs with viruses|ipv4 hash:ip|46 unique IPs|updated every 12 hours  from [this link](http://support.clean-mx.de/clean-mx/xmlviruses.php?sort=id%20desc&response=alive)
[dm_tor](#dm_tor)|[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points|ipv4 hash:ip|6509 unique IPs|updated every 30 mins  from [this link](https://www.dan.me.uk/torlist/)
[dshield](#dshield)|[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**|ipv4 hash:net|20 subnets, 5120 unique IPs|updated every 4 hours  from [this link](http://feeds.dshield.org/block.txt)
[et_block](#et_block)|[EmergingThreats.net](http://www.emergingthreats.net/) default blacklist (at the time of writing includes spamhaus DROP, dshield and abuse.ch trackers, which are available separately too - prefer to use the direct ipsets instead of this, they seem to lag a bit in updates)|ipv4 hash:net|1007 subnets, 18338646 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
[et_botcc](#et_botcc)|[EmergingThreats.net Command and Control IPs](http://doc.emergingthreats.net/bin/view/Main/BotCC) These IPs are updates every 24 hours and should be considered VERY highly reliable indications that a host is communicating with a known and active Bot or Malware command and control server - (although they say this includes abuse.ch trackers, it does not - most probably it is the shadowserver.org C&C list)|ipv4 hash:ip|511 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules)
[et_compromised](#et_compromised)|[EmergingThreats.net compromised hosts](http://doc.emergingthreats.net/bin/view/Main/CompromisedHost) - (this seems to be based on bruteforceblocker)|ipv4 hash:ip|2174 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
[et_tor](#et_tor)|[EmergingThreats.net](http://www.emergingthreats.net/) [list](http://doc.emergingthreats.net/bin/view/Main/TorRules) of TOR network IPs|ipv4 hash:ip|6520 unique IPs|updated every 12 hours  from [this link](http://rules.emergingthreats.net/blockrules/emerging-tor.rules)
[feodo](#feodo)|[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**|ipv4 hash:ip|86 unique IPs|updated every 30 mins  from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist)
[fullbogons](#fullbogons)|[Team-Cymru.org](http://www.team-cymru.org) IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user - **excellent list - use it only your internet interface**|ipv4 hash:net|3702 subnets, 670445080 unique IPs|updated every 1 day  from [this link](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt)
[geolite2_country](https://github.com/ktsaou/blocklist-ipsets/tree/master/geolite2_country)|[MaxMind GeoLite2](http://dev.maxmind.com/geoip/geoip2/geolite2/) databases are free IP geolocation databases comparable to, but less accurate than, MaxMind’s GeoIP2 databases. They include IPs per country, IPs per continent, IPs used by anonymous services (VPNs, Proxies, etc) and Satellite Providers.|ipv4 hash:net|All the world|updated every 7 days  from [this link](http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country-CSV.zip)
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) IPs that have been reported for bad deeds in p2p|ipv4 hash:ip|48134 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=cwworuawihqvocglcoss&fileformat=p2p&archiveformat=gz)
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) hijacked IP-Blocks Hijacked IP space are IP blocks that are being used without permission|ipv4 hash:net|535 subnets, 9177856 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=usrcshglbiilevmyfhse&fileformat=p2p&archiveformat=gz)
[ib_bluetack_level1](#ib_bluetack_level1)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Level 1 (for use in p2p): Companies or organizations who are clearly involved with trying to stop filesharing (e.g. Baytsp, MediaDefender, Mediasentry a.o.). Companies which anti-p2p activity has been seen from. Companies that produce or have a strong financial interest in copyrighted material (e.g. music, movie, software industries a.o.). Government ranges or companies that have a strong financial interest in doing work for governments. Legal industry ranges. IPs or ranges of ISPs from which anti-p2p activity has been observed. Basically this list will block all kinds of internet connections that most people would rather not have during their internet travels.|ipv4 hash:net|218309 subnets, 764987411 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz)
[ib_bluetack_level2](#ib_bluetack_level2)|[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 2 (for use in p2p). General corporate ranges. Ranges used by labs or researchers. Proxies.|ipv4 hash:net|72774 subnets, 348707599 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw&fileformat=p2p&archiveformat=gz)
[ib_bluetack_level3](#ib_bluetack_level3)|[iBlocklist.com](https://www.iblocklist.com/) free version of BlueTack.co.uk Level 3 (for use in p2p). Many portal-type websites. ISP ranges that may be dodgy for some reason. Ranges that belong to an individual, but which have not been determined to be used by a particular company. Ranges for things that are unusual in some way. The L3 list is aka the paranoid list.|ipv4 hash:net|17802 subnets, 139104824 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh&fileformat=p2p&archiveformat=gz)
[ib_bluetack_proxies](#ib_bluetack_proxies)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Open Proxies IPs list (without TOR)|ipv4 hash:ip|673 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=xoebmbyexwuiogmbyprb&fileformat=p2p&archiveformat=gz)
[ib_bluetack_spyware](#ib_bluetack_spyware)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) known malicious SPYWARE and ADWARE IP Address ranges|ipv4 hash:net|3274 subnets, 339192 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=llvtlsjyoyiczbkjsxpf&fileformat=p2p&archiveformat=gz)
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) web server hack and exploit attempts|ipv4 hash:ip|1460 unique IPs|updated every 12 hours  from [this link](http://list.iblocklist.com/?list=ghlzqtqxnzctvvajwwag&fileformat=p2p&archiveformat=gz)
[malc0de](#malc0de)|[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days|ipv4 hash:ip|386 unique IPs|updated every 1 day  from [this link](http://malc0de.com/bl/IP_Blacklist.txt)
[malwaredomainlist](#malwaredomainlist)|[malwaredomainlist.com](http://www.malwaredomainlist.com) list of malware active ip addresses|ipv4 hash:ip|1284 unique IPs|updated every 12 hours  from [this link](http://www.malwaredomainlist.com/hostslist/ip.txt)
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.|ipv4 hash:ip|372 unique IPs|updated every 4 hours  from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list)
[nixspam](#nixspam)|[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.|ipv4 hash:ip|22860 unique IPs|updated every 15 mins  from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz)
[openbl_1d](#openbl_1d)|[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|306 unique IPs|updated every 1 hour  from [this link](http://www.openbl.org/lists/base_1days.txt)
[openbl_30d](#openbl_30d)|[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|3280 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_30days.txt)
[openbl_60d](#openbl_60d)|[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|7694 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_60days.txt)
[openbl_7d](#openbl_7d)|[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.|ipv4 hash:ip|1005 unique IPs|updated every 4 hours  from [this link](http://www.openbl.org/lists/base_7days.txt)
[palevo](#palevo)|[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**|ipv4 hash:ip|13 unique IPs|updated every 30 mins  from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist)
[php_commenters](#php_commenters)|[projecthoneypot.org](http://www.projecthoneypot.org/) comment spammers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|281 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=c&rss=1)
[php_dictionary](#php_dictionary)|[projecthoneypot.org](http://www.projecthoneypot.org/?rf=192670) directory attackers (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|433 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1)
[php_harvesters](#php_harvesters)|[projecthoneypot.org](http://www.projecthoneypot.org/) harvesters (IPs that surf the internet looking for email addresses) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|257 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=h&rss=1)
[php_spammers](#php_spammers)|[projecthoneypot.org](http://www.projecthoneypot.org/) spam servers (IPs used by spammers to send messages) (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|417 unique IPs|updated every 1 hour  from [this link](http://www.projecthoneypot.org/list_of_ips.php?t=s&rss=1)
[proxyrss](#proxyrss)|[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.|ipv4 hash:ip|1525 unique IPs|updated every 4 hours  from [this link](http://www.proxyrss.com/proxylists/all.gz)
[proxz](#proxz)|[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|631 unique IPs|updated every 1 hour  from [this link](http://www.proxz.com/proxylists.xml)
[ri_connect_proxies](#ri_connect_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2205 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/plab100.xml)
[ri_web_proxies](#ri_web_proxies)|[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|5930 unique IPs|updated every 1 hour  from [this link](http://tools.rosinstrument.com/proxy/l100.xml)
[shunlist](#shunlist)|[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin|ipv4 hash:ip|1296 unique IPs|updated every 4 hours  from [this link](http://www.autoshun.org/files/shunlist.csv)
[snort_ipfilter](#snort_ipfilter)|[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)|ipv4 hash:ip|9091 unique IPs|updated every 12 hours  from [this link](http://labs.snort.org/feeds/ip-filter.blf)
[spamhaus_drop](#spamhaus_drop)|[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**|ipv4 hash:net|655 subnets, 18535168 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/drop.txt)
[spamhaus_edrop](#spamhaus_edrop)|[Spamhaus.org](http://www.spamhaus.org) EDROP (extended matches that should be used with DROP) - **excellent list**|ipv4 hash:net|57 subnets, 487168 unique IPs|updated every 12 hours  from [this link](http://www.spamhaus.org/drop/edrop.txt)
[sslbl](#sslbl)|[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**|ipv4 hash:ip|357 unique IPs|updated every 30 mins  from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
[stopforumspam_1d](#stopforumspam_1d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**|ipv4 hash:ip|7344 unique IPs|updated every 1 hour  from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip)
[stopforumspam_30d](#stopforumspam_30d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 30 days)|ipv4 hash:ip|92665 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_30.zip)
[stopforumspam_7d](#stopforumspam_7d)|[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers (last 7 days)|ipv4 hash:ip|31033 unique IPs|updated every 1 day  from [this link](http://www.stopforumspam.com/downloads/listed_ip_7.zip)
[virbl](#virbl)|[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.|ipv4 hash:ip|42 unique IPs|updated every 1 hour  from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt)
[voipbl](#voipbl)|[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.|ipv4 hash:net|10398 subnets, 10808 unique IPs|updated every 4 hours  from [this link](http://www.voipbl.org/update/)
[xroxy](#xroxy)|[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)|ipv4 hash:ip|2051 unique IPs|updated every 1 hour  from [this link](http://www.xroxy.com/proxyrss.xml)
[zeus](#zeus)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**|ipv4 hash:ip|270 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist)
[zeus_badips](#zeus_badips)|[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**|ipv4 hash:ip|234 unique IPs|updated every 30 mins  from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips)

# Comparison of ipsets

Below we compare each ipset against all other.


## alienvault_reputation

[AlienVault.com](https://www.alienvault.com/) IP reputation database (this list seems to include port scanning hosts and to be updated regularly, but we found no information about its retention policy)

Source is downloaded from [this link](https://reputation.alienvault.com/reputation.generic).

The last time downloaded was found to be dated: Wed Jun  3 10:00:39 UTC 2015.

The ipset `alienvault_reputation` has **179596** entries, **179596** unique IPs.

The following table shows the overlaps of `alienvault_reputation` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `alienvault_reputation`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `alienvault_reputation`.
- ` this % ` is the percentage **of this ipset (`alienvault_reputation`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14652|0.0%|8.1%|
[openbl_60d](#openbl_60d)|7694|7694|7663|99.5%|4.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7610|0.0%|4.2%|
[et_block](#et_block)|1007|18338646|6557|0.0%|3.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4702|0.0%|2.6%|
[openbl_30d](#openbl_30d)|3280|3280|3255|99.2%|1.8%|
[dshield](#dshield)|20|5120|2821|55.0%|1.5%|
[blocklist_de](#blocklist_de)|36060|36060|2191|6.0%|1.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|12692|12692|1937|15.2%|1.0%|
[spamhaus_drop](#spamhaus_drop)|655|18535168|1884|0.0%|1.0%|
[et_compromised](#et_compromised)|2174|2174|1410|64.8%|0.7%|
[bruteforceblocker](#bruteforceblocker)|2168|2168|1393|64.2%|0.7%|
[shunlist](#shunlist)|1296|1296|1291|99.6%|0.7%|
[openbl_7d](#openbl_7d)|1005|1005|990|98.5%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|518|0.0%|0.2%|
[ciarmy](#ciarmy)|338|338|330|97.6%|0.1%|
[openbl_1d](#openbl_1d)|306|306|294|96.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|289|0.0%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|271|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|217|0.2%|0.1%|
[voipbl](#voipbl)|10398|10808|203|1.8%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13972|13972|129|0.9%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9091|9091|118|1.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|102|0.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16484|16484|85|0.5%|0.0%|
[zeus](#zeus)|270|270|66|24.4%|0.0%|
[sslbl](#sslbl)|357|357|63|17.6%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7344|7344|60|0.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2401|2401|51|2.1%|0.0%|
[et_tor](#et_tor)|6520|6520|46|0.7%|0.0%|
[dm_tor](#dm_tor)|6509|6509|44|0.6%|0.0%|
[bm_tor](#bm_tor)|6514|6514|44|0.6%|0.0%|
[nixspam](#nixspam)|22860|22860|40|0.1%|0.0%|
[zeus_badips](#zeus_badips)|234|234|37|15.8%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|36|20.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3042|3042|26|0.8%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|25|6.7%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|110|110|19|17.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2649|2649|15|0.5%|0.0%|
[php_commenters](#php_commenters)|281|281|14|4.9%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|14|0.0%|0.0%|
[malc0de](#malc0de)|386|386|12|3.1%|0.0%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|8|0.5%|0.0%|
[php_dictionary](#php_dictionary)|433|433|7|1.6%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|874|874|7|0.8%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1284|1284|6|0.4%|0.0%|
[xroxy](#xroxy)|2051|2051|5|0.2%|0.0%|
[et_botcc](#et_botcc)|511|511|4|0.7%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5930|5930|3|0.0%|0.0%|
[proxz](#proxz)|631|631|3|0.4%|0.0%|
[proxyrss](#proxyrss)|1525|1525|3|0.1%|0.0%|
[php_spammers](#php_spammers)|417|417|3|0.7%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|46|46|3|6.5%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2205|2205|2|0.0%|0.0%|
[feodo](#feodo)|86|86|2|2.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|

## blocklist_de

[Blocklist.de](https://www.blocklist.de/) IPs that have been detected by fail2ban in the last 48 hours - **excellent list**

Source is downloaded from [this link](http://lists.blocklist.de/lists/all.txt).

The last time downloaded was found to be dated: Wed Jun  3 15:14:04 UTC 2015.

The ipset `blocklist_de` has **36060** entries, **36060** unique IPs.

The following table shows the overlaps of `blocklist_de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de`.
- ` this % ` is the percentage **of this ipset (`blocklist_de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|16484|16484|16459|99.8%|45.6%|
[blocklist_de_apache](#blocklist_de_apache)|13972|13972|13972|100.0%|38.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|12692|12692|12659|99.7%|35.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|6321|0.0%|17.5%|
[blocklist_de_bots](#blocklist_de_bots)|3042|3042|3034|99.7%|8.4%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2649|2649|2649|100.0%|7.3%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|2459|2.6%|6.8%|
[blocklist_de_imap](#blocklist_de_imap)|2401|2401|2378|99.0%|6.5%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|2191|1.2%|6.0%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|2097|6.7%|5.8%|
[openbl_60d](#openbl_60d)|7694|7694|1827|23.7%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1559|0.0%|4.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1542|0.0%|4.2%|
[stopforumspam_1d](#stopforumspam_1d)|7344|7344|1477|20.1%|4.0%|
[openbl_30d](#openbl_30d)|3280|3280|915|27.8%|2.5%|
[blocklist_de_ftp](#blocklist_de_ftp)|874|874|868|99.3%|2.4%|
[nixspam](#nixspam)|22860|22860|757|3.3%|2.0%|
[bruteforceblocker](#bruteforceblocker)|2168|2168|718|33.1%|1.9%|
[et_compromised](#et_compromised)|2174|2174|676|31.0%|1.8%|
[openbl_7d](#openbl_7d)|1005|1005|607|60.3%|1.6%|
[shunlist](#shunlist)|1296|1296|417|32.1%|1.1%|
[ri_web_proxies](#ri_web_proxies)|5930|5930|363|6.1%|1.0%|
[xroxy](#xroxy)|2051|2051|242|11.7%|0.6%|
[openbl_1d](#openbl_1d)|306|306|239|78.1%|0.6%|
[proxyrss](#proxyrss)|1525|1525|206|13.5%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|175|100.0%|0.4%|
[et_block](#et_block)|1007|18338646|167|0.0%|0.4%|
[snort_ipfilter](#snort_ipfilter)|9091|9091|164|1.8%|0.4%|
[spamhaus_drop](#spamhaus_drop)|655|18535168|158|0.0%|0.4%|
[proxz](#proxz)|631|631|123|19.4%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|110|110|91|82.7%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2205|2205|75|3.4%|0.2%|
[php_commenters](#php_commenters)|281|281|62|22.0%|0.1%|
[dshield](#dshield)|20|5120|61|1.1%|0.1%|
[php_dictionary](#php_dictionary)|433|433|57|13.1%|0.1%|
[php_spammers](#php_spammers)|417|417|50|11.9%|0.1%|
[voipbl](#voipbl)|10398|10808|46|0.4%|0.1%|
[ciarmy](#ciarmy)|338|338|44|13.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|26|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|23|8.9%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|13|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|8|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|3|0.4%|0.0%|
[et_tor](#et_tor)|6520|6520|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6509|6509|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6514|6514|3|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1284|1284|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## blocklist_de_apache

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Apache, Apache-DDOS, RFI-Attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/apache.txt).

The last time downloaded was found to be dated: Wed Jun  3 15:28:05 UTC 2015.

The ipset `blocklist_de_apache` has **13972** entries, **13972** unique IPs.

The following table shows the overlaps of `blocklist_de_apache` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_apache`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_apache`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_apache`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|36060|36060|13972|38.7%|100.0%|
[blocklist_de_mail](#blocklist_de_mail)|16484|16484|11059|67.0%|79.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2649|2649|2649|100.0%|18.9%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2271|0.0%|16.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1319|0.0%|9.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1078|0.0%|7.7%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|202|0.2%|1.4%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|129|0.0%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|120|0.3%|0.8%|
[stopforumspam_1d](#stopforumspam_1d)|7344|7344|62|0.8%|0.4%|
[ciarmy](#ciarmy)|338|338|39|11.5%|0.2%|
[shunlist](#shunlist)|1296|1296|36|2.7%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|36|20.5%|0.2%|
[nixspam](#nixspam)|22860|22860|29|0.1%|0.2%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3042|3042|21|0.6%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9091|9091|8|0.0%|0.0%|
[voipbl](#voipbl)|10398|10808|5|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|4|0.9%|0.0%|
[openbl_60d](#openbl_60d)|7694|7694|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3280|3280|3|0.0%|0.0%|
[et_tor](#et_tor)|6520|6520|3|0.0%|0.0%|
[et_block](#et_block)|1007|18338646|3|0.0%|0.0%|
[dshield](#dshield)|20|5120|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6509|6509|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6514|6514|3|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|655|18535168|2|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[et_compromised](#et_compromised)|2174|2174|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2168|2168|2|0.0%|0.0%|
[proxyrss](#proxyrss)|1525|1525|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.0%|
[openbl_7d](#openbl_7d)|1005|1005|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|306|306|1|0.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|

## blocklist_de_bots

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (BadBots = he has posted a Spam-Comment on a open Forum or Wiki).

Source is downloaded from [this link](http://lists.blocklist.de/lists/bots.txt).

The last time downloaded was found to be dated: Wed Jun  3 15:28:07 UTC 2015.

The ipset `blocklist_de_bots` has **3042** entries, **3042** unique IPs.

The following table shows the overlaps of `blocklist_de_bots` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bots`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bots`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bots`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|36060|36060|3034|8.4%|99.7%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|2072|2.2%|68.1%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|1905|6.1%|62.6%|
[stopforumspam_1d](#stopforumspam_1d)|7344|7344|1422|19.3%|46.7%|
[ri_web_proxies](#ri_web_proxies)|5930|5930|317|5.3%|10.4%|
[xroxy](#xroxy)|2051|2051|205|9.9%|6.7%|
[proxyrss](#proxyrss)|1525|1525|201|13.1%|6.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|170|0.0%|5.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|131|74.8%|4.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|114|0.0%|3.7%|
[proxz](#proxz)|631|631|106|16.7%|3.4%|
[ri_connect_proxies](#ri_connect_proxies)|2205|2205|72|3.2%|2.3%|
[nixspam](#nixspam)|22860|22860|50|0.2%|1.6%|
[php_commenters](#php_commenters)|281|281|46|16.3%|1.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|32|0.0%|1.0%|
[snort_ipfilter](#snort_ipfilter)|9091|9091|26|0.2%|0.8%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|26|0.0%|0.8%|
[blocklist_de_mail](#blocklist_de_mail)|16484|16484|21|0.1%|0.6%|
[blocklist_de_apache](#blocklist_de_apache)|13972|13972|21|0.1%|0.6%|
[et_block](#et_block)|1007|18338646|20|0.0%|0.6%|
[spamhaus_drop](#spamhaus_drop)|655|18535168|19|0.0%|0.6%|
[php_harvesters](#php_harvesters)|257|257|18|7.0%|0.5%|
[php_dictionary](#php_dictionary)|433|433|16|3.6%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|13|0.0%|0.4%|
[php_spammers](#php_spammers)|417|417|10|2.3%|0.3%|
[dshield](#dshield)|20|5120|8|0.1%|0.2%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|5|0.0%|0.1%|
[voipbl](#voipbl)|10398|10808|2|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7694|7694|2|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2174|2174|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2168|2168|1|0.0%|0.0%|

## blocklist_de_bruteforce

[Blocklist.de](https://www.blocklist.de/) All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins.

Source is downloaded from [this link](http://lists.blocklist.de/lists/bruteforcelogin.txt).

The last time downloaded was found to be dated: Wed Jun  3 15:28:09 UTC 2015.

The ipset `blocklist_de_bruteforce` has **2649** entries, **2649** unique IPs.

The following table shows the overlaps of `blocklist_de_bruteforce` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_bruteforce`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_bruteforce`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_bruteforce`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_apache](#blocklist_de_apache)|13972|13972|2649|18.9%|100.0%|
[blocklist_de](#blocklist_de)|36060|36060|2649|7.3%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|176|0.0%|6.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|44|0.0%|1.6%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|41|0.0%|1.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|32|0.0%|1.2%|
[nixspam](#nixspam)|22860|22860|29|0.1%|1.0%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|28|0.0%|1.0%|
[stopforumspam_1d](#stopforumspam_1d)|7344|7344|18|0.2%|0.6%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|15|0.0%|0.5%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|9|5.1%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9091|9091|5|0.0%|0.1%|
[php_commenters](#php_commenters)|281|281|5|1.7%|0.1%|
[php_spammers](#php_spammers)|417|417|4|0.9%|0.1%|
[voipbl](#voipbl)|10398|10808|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|655|18535168|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[et_block](#et_block)|1007|18338646|2|0.0%|0.0%|
[shunlist](#shunlist)|1296|1296|1|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.0%|
[openbl_60d](#openbl_60d)|7694|7694|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16484|16484|1|0.0%|0.0%|

## blocklist_de_ftp

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service FTP.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ftp.txt).

The last time downloaded was found to be dated: Wed Jun  3 15:28:06 UTC 2015.

The ipset `blocklist_de_ftp` has **874** entries, **874** unique IPs.

The following table shows the overlaps of `blocklist_de_ftp` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ftp`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ftp`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ftp`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|36060|36060|868|2.4%|99.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|82|0.0%|9.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|17|0.0%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|12|0.0%|1.3%|
[nixspam](#nixspam)|22860|22860|10|0.0%|1.1%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|8|0.0%|0.9%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|7|0.0%|0.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|0.5%|
[stopforumspam_1d](#stopforumspam_1d)|7344|7344|4|0.0%|0.4%|
[php_harvesters](#php_harvesters)|257|257|3|1.1%|0.3%|
[openbl_60d](#openbl_60d)|7694|7694|2|0.0%|0.2%|
[shunlist](#shunlist)|1296|1296|1|0.0%|0.1%|
[openbl_7d](#openbl_7d)|1005|1005|1|0.0%|0.1%|
[openbl_30d](#openbl_30d)|3280|3280|1|0.0%|0.1%|
[et_compromised](#et_compromised)|2174|2174|1|0.0%|0.1%|
[dshield](#dshield)|20|5120|1|0.0%|0.1%|
[ciarmy](#ciarmy)|338|338|1|0.2%|0.1%|
[bruteforceblocker](#bruteforceblocker)|2168|2168|1|0.0%|0.1%|

## blocklist_de_imap

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours for attacks on the Service imap, sasl, pop3, etc.

Source is downloaded from [this link](http://lists.blocklist.de/lists/imap.txt).

The last time downloaded was found to be dated: Wed Jun  3 15:42:14 UTC 2015.

The ipset `blocklist_de_imap` has **2401** entries, **2401** unique IPs.

The following table shows the overlaps of `blocklist_de_imap` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_imap`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_imap`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_imap`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de_mail](#blocklist_de_mail)|16484|16484|2393|14.5%|99.6%|
[blocklist_de](#blocklist_de)|36060|36060|2378|6.5%|99.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|265|0.0%|11.0%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|51|0.0%|2.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|49|0.0%|2.0%|
[openbl_60d](#openbl_60d)|7694|7694|38|0.4%|1.5%|
[openbl_30d](#openbl_30d)|3280|3280|34|1.0%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|26|0.0%|1.0%|
[nixspam](#nixspam)|22860|22860|21|0.0%|0.8%|
[openbl_7d](#openbl_7d)|1005|1005|16|1.5%|0.6%|
[et_block](#et_block)|1007|18338646|14|0.0%|0.5%|
[spamhaus_drop](#spamhaus_drop)|655|18535168|13|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|9|0.0%|0.3%|
[openbl_1d](#openbl_1d)|306|306|5|1.6%|0.2%|
[shunlist](#shunlist)|1296|1296|4|0.3%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|4|0.0%|0.1%|
[et_compromised](#et_compromised)|2174|2174|4|0.1%|0.1%|
[bruteforceblocker](#bruteforceblocker)|2168|2168|4|0.1%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|3|0.0%|0.1%|
[snort_ipfilter](#snort_ipfilter)|9091|9091|2|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7344|7344|1|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[ciarmy](#ciarmy)|338|338|1|0.2%|0.0%|

## blocklist_de_mail

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service Mail, Postfix.

Source is downloaded from [this link](http://lists.blocklist.de/lists/mail.txt).

The last time downloaded was found to be dated: Wed Jun  3 15:28:04 UTC 2015.

The ipset `blocklist_de_mail` has **16484** entries, **16484** unique IPs.

The following table shows the overlaps of `blocklist_de_mail` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_mail`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_mail`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_mail`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|36060|36060|16459|45.6%|99.8%|
[blocklist_de_apache](#blocklist_de_apache)|13972|13972|11059|79.1%|67.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2482|0.0%|15.0%|
[blocklist_de_imap](#blocklist_de_imap)|2401|2401|2393|99.6%|14.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1344|0.0%|8.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1152|0.0%|6.9%|
[nixspam](#nixspam)|22860|22860|633|2.7%|3.8%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|224|0.2%|1.3%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|133|0.4%|0.8%|
[snort_ipfilter](#snort_ipfilter)|9091|9091|131|1.4%|0.7%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|85|0.0%|0.5%|
[openbl_60d](#openbl_60d)|7694|7694|49|0.6%|0.2%|
[ri_web_proxies](#ri_web_proxies)|5930|5930|46|0.7%|0.2%|
[openbl_30d](#openbl_30d)|3280|3280|43|1.3%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7344|7344|41|0.5%|0.2%|
[php_dictionary](#php_dictionary)|433|433|40|9.2%|0.2%|
[php_spammers](#php_spammers)|417|417|36|8.6%|0.2%|
[xroxy](#xroxy)|2051|2051|35|1.7%|0.2%|
[et_block](#et_block)|1007|18338646|27|0.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|655|18535168|24|0.0%|0.1%|
[php_commenters](#php_commenters)|281|281|22|7.8%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|21|12.0%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3042|3042|21|0.6%|0.1%|
[openbl_7d](#openbl_7d)|1005|1005|20|1.9%|0.1%|
[proxz](#proxz)|631|631|15|2.3%|0.0%|
[et_compromised](#et_compromised)|2174|2174|10|0.4%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2168|2168|9|0.4%|0.0%|
[shunlist](#shunlist)|1296|1296|7|0.5%|0.0%|
[openbl_1d](#openbl_1d)|306|306|6|1.9%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|4|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.0%|
[et_tor](#et_tor)|6520|6520|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6509|6509|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6514|6514|3|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2205|2205|2|0.0%|0.0%|
[proxyrss](#proxyrss)|1525|1525|2|0.1%|0.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[ciarmy](#ciarmy)|338|338|2|0.5%|0.0%|
[voipbl](#voipbl)|10398|10808|1|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2649|2649|1|0.0%|0.0%|

## blocklist_de_sip

[Blocklist.de](https://www.blocklist.de/) All IP addresses that tried to login in a SIP, VOIP or Asterisk Server and are included in the IPs list from [infiltrated.net](www.infiltrated.net)

Source is downloaded from [this link](http://lists.blocklist.de/lists/sip.txt).

The last time downloaded was found to be dated: Wed Jun  3 15:28:06 UTC 2015.

The ipset `blocklist_de_sip` has **110** entries, **110** unique IPs.

The following table shows the overlaps of `blocklist_de_sip` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_sip`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_sip`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_sip`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|36060|36060|91|0.2%|82.7%|
[voipbl](#voipbl)|10398|10808|34|0.3%|30.9%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|19|0.0%|17.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14|0.0%|12.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|8.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4|0.0%|3.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|1.8%|
[spamhaus_drop](#spamhaus_drop)|655|18535168|1|0.0%|0.9%|
[et_botcc](#et_botcc)|511|511|1|0.1%|0.9%|
[et_block](#et_block)|1007|18338646|1|0.0%|0.9%|
[ciarmy](#ciarmy)|338|338|1|0.2%|0.9%|

## blocklist_de_ssh

[Blocklist.de](https://www.blocklist.de/) All IP addresses which have been reported within the last 48 hours as having run attacks on the service SSH.

Source is downloaded from [this link](http://lists.blocklist.de/lists/ssh.txt).

The last time downloaded was found to be dated: Wed Jun  3 15:28:03 UTC 2015.

The ipset `blocklist_de_ssh` has **12692** entries, **12692** unique IPs.

The following table shows the overlaps of `blocklist_de_ssh` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_ssh`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_ssh`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_ssh`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|36060|36060|12659|35.1%|99.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|3384|0.0%|26.6%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|1937|1.0%|15.2%|
[openbl_60d](#openbl_60d)|7694|7694|1770|23.0%|13.9%|
[openbl_30d](#openbl_30d)|3280|3280|867|26.4%|6.8%|
[bruteforceblocker](#bruteforceblocker)|2168|2168|705|32.5%|5.5%|
[et_compromised](#et_compromised)|2174|2174|662|30.4%|5.2%|
[openbl_7d](#openbl_7d)|1005|1005|585|58.2%|4.6%|
[shunlist](#shunlist)|1296|1296|372|28.7%|2.9%|
[openbl_1d](#openbl_1d)|306|306|231|75.4%|1.8%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|220|0.0%|1.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|121|0.0%|0.9%|
[et_block](#et_block)|1007|18338646|116|0.0%|0.9%|
[spamhaus_drop](#spamhaus_drop)|655|18535168|112|0.0%|0.8%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|100|0.1%|0.7%|
[dshield](#dshield)|20|5120|47|0.9%|0.3%|
[nixspam](#nixspam)|22860|22860|43|0.1%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|27|15.4%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|15|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|6|0.0%|0.0%|
[voipbl](#voipbl)|10398|10808|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.0%|
[xroxy](#xroxy)|2051|2051|2|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|2|0.0%|0.0%|
[proxz](#proxz)|631|631|2|0.3%|0.0%|
[proxyrss](#proxyrss)|1525|1525|2|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7344|7344|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9091|9091|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2205|2205|1|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1284|1284|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ciarmy](#ciarmy)|338|338|1|0.2%|0.0%|

## blocklist_de_strongips

[Blocklist.de](https://www.blocklist.de/) All IPs which are older then 2 month and have more then 5.000 attacks.

Source is downloaded from [this link](http://lists.blocklist.de/lists/strongips.txt).

The last time downloaded was found to be dated: Wed Jun  3 15:14:12 UTC 2015.

The ipset `blocklist_de_strongips` has **175** entries, **175** unique IPs.

The following table shows the overlaps of `blocklist_de_strongips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `blocklist_de_strongips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `blocklist_de_strongips`.
- ` this % ` is the percentage **of this ipset (`blocklist_de_strongips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[blocklist_de](#blocklist_de)|36060|36060|175|0.4%|100.0%|
[blocklist_de_bots](#blocklist_de_bots)|3042|3042|131|4.3%|74.8%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|129|0.1%|73.7%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|118|0.3%|67.4%|
[stopforumspam_1d](#stopforumspam_1d)|7344|7344|105|1.4%|60.0%|
[blocklist_de_apache](#blocklist_de_apache)|13972|13972|36|0.2%|20.5%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|36|0.0%|20.5%|
[php_commenters](#php_commenters)|281|281|29|10.3%|16.5%|
[openbl_60d](#openbl_60d)|7694|7694|27|0.3%|15.4%|
[blocklist_de_ssh](#blocklist_de_ssh)|12692|12692|27|0.2%|15.4%|
[openbl_7d](#openbl_7d)|1005|1005|24|2.3%|13.7%|
[openbl_30d](#openbl_30d)|3280|3280|24|0.7%|13.7%|
[blocklist_de_mail](#blocklist_de_mail)|16484|16484|21|0.1%|12.0%|
[shunlist](#shunlist)|1296|1296|20|1.5%|11.4%|
[openbl_1d](#openbl_1d)|306|306|18|5.8%|10.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|16|0.0%|9.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2649|2649|9|0.3%|5.1%|
[xroxy](#xroxy)|2051|2051|7|0.3%|4.0%|
[spamhaus_drop](#spamhaus_drop)|655|18535168|7|0.0%|4.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7|0.0%|4.0%|
[et_block](#et_block)|1007|18338646|7|0.0%|4.0%|
[dshield](#dshield)|20|5120|7|0.1%|4.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|6|0.0%|3.4%|
[proxyrss](#proxyrss)|1525|1525|6|0.3%|3.4%|
[ri_web_proxies](#ri_web_proxies)|5930|5930|5|0.0%|2.8%|
[proxz](#proxz)|631|631|3|0.4%|1.7%|
[php_spammers](#php_spammers)|417|417|3|0.7%|1.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|1.7%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|1.1%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|1.1%|
[snort_ipfilter](#snort_ipfilter)|9091|9091|1|0.0%|0.5%|
[nixspam](#nixspam)|22860|22860|1|0.0%|0.5%|

## bm_tor

[torstatus.blutmagie.de](https://torstatus.blutmagie.de) list of all TOR network servers

Source is downloaded from [this link](https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv).

The last time downloaded was found to be dated: Wed Jun  3 15:27:09 UTC 2015.

The ipset `bm_tor` has **6514** entries, **6514** unique IPs.

The following table shows the overlaps of `bm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bm_tor`.
- ` this % ` is the percentage **of this ipset (`bm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[dm_tor](#dm_tor)|6509|6509|6509|100.0%|99.9%|
[et_tor](#et_tor)|6520|6520|5714|87.6%|87.7%|
[snort_ipfilter](#snort_ipfilter)|9091|9091|1073|11.8%|16.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|629|0.0%|9.6%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|623|0.6%|9.5%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|474|1.5%|7.2%|
[stopforumspam_1d](#stopforumspam_1d)|7344|7344|290|3.9%|4.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|187|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|170|45.6%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|167|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|44|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[openbl_60d](#openbl_60d)|7694|7694|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5930|5930|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16484|16484|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13972|13972|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|36060|36060|3|0.0%|0.0%|
[xroxy](#xroxy)|2051|2051|2|0.0%|0.0%|
[voipbl](#voipbl)|10398|10808|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|655|18535168|2|0.0%|0.0%|
[et_block](#et_block)|1007|18338646|2|0.0%|0.0%|
[shunlist](#shunlist)|1296|1296|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2205|2205|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1525|1525|1|0.0%|0.0%|
[nixspam](#nixspam)|22860|22860|1|0.0%|0.0%|
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
[fullbogons](#fullbogons)|3702|670445080|592708608|88.4%|100.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|4194304|3.0%|0.7%|
[voipbl](#voipbl)|10398|10808|319|2.9%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2168|2168|1|0.0%|0.0%|

## bruteforceblocker

[danger.rulez.sk](http://danger.rulez.sk/) IPs detected by [bruteforceblocker](http://danger.rulez.sk/index.php/bruteforceblocker/) (fail2ban alternative for SSH on OpenBSD). This is an automatically generated list from users reporting failed authentication attempts. An IP seems to be included if 3 or more users report it. Its retention pocily seems 30 days.

Source is downloaded from [this link](http://danger.rulez.sk/projects/bruteforceblocker/blist.php).

The last time downloaded was found to be dated: Wed Jun  3 14:36:26 UTC 2015.

The ipset `bruteforceblocker` has **2168** entries, **2168** unique IPs.

The following table shows the overlaps of `bruteforceblocker` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `bruteforceblocker`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `bruteforceblocker`.
- ` this % ` is the percentage **of this ipset (`bruteforceblocker`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_compromised](#et_compromised)|2174|2174|2103|96.7%|97.0%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|1393|0.7%|64.2%|
[openbl_60d](#openbl_60d)|7694|7694|1299|16.8%|59.9%|
[openbl_30d](#openbl_30d)|3280|3280|1222|37.2%|56.3%|
[blocklist_de](#blocklist_de)|36060|36060|718|1.9%|33.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|12692|12692|705|5.5%|32.5%|
[shunlist](#shunlist)|1296|1296|515|39.7%|23.7%|
[openbl_7d](#openbl_7d)|1005|1005|477|47.4%|22.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|218|0.0%|10.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|112|0.0%|5.1%|
[spamhaus_drop](#spamhaus_drop)|655|18535168|100|0.0%|4.6%|
[et_block](#et_block)|1007|18338646|100|0.0%|4.6%|
[openbl_1d](#openbl_1d)|306|306|92|30.0%|4.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|62|0.0%|2.8%|
[dshield](#dshield)|20|5120|57|1.1%|2.6%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|10|0.0%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|16484|16484|9|0.0%|0.4%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|6|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2401|2401|4|0.1%|0.1%|
[voipbl](#voipbl)|10398|10808|2|0.0%|0.0%|
[proxz](#proxz)|631|631|2|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13972|13972|2|0.0%|0.0%|
[xroxy](#xroxy)|2051|2051|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5930|5930|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1525|1525|1|0.0%|0.0%|
[fullbogons](#fullbogons)|3702|670445080|1|0.0%|0.0%|
[ciarmy](#ciarmy)|338|338|1|0.2%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|874|874|1|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3042|3042|1|0.0%|0.0%|

## ciarmy

[CIArmy.com](http://ciarmy.com/) IPs with poor Rogue Packet score that have not yet been identified as malicious by the community

Source is downloaded from [this link](http://cinsscore.com/list/ci-badguys.txt).

The last time downloaded was found to be dated: Wed Jun  3 13:15:15 UTC 2015.

The ipset `ciarmy` has **338** entries, **338** unique IPs.

The following table shows the overlaps of `ciarmy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ciarmy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ciarmy`.
- ` this % ` is the percentage **of this ipset (`ciarmy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|179596|179596|330|0.1%|97.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|57|0.0%|16.8%|
[blocklist_de](#blocklist_de)|36060|36060|44|0.1%|13.0%|
[blocklist_de_apache](#blocklist_de_apache)|13972|13972|39|0.2%|11.5%|
[shunlist](#shunlist)|1296|1296|26|2.0%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|12|0.0%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|10|0.0%|2.9%|
[voipbl](#voipbl)|10398|10808|6|0.0%|1.7%|
[blocklist_de_mail](#blocklist_de_mail)|16484|16484|2|0.0%|0.5%|
[openbl_7d](#openbl_7d)|1005|1005|1|0.0%|0.2%|
[openbl_60d](#openbl_60d)|7694|7694|1|0.0%|0.2%|
[openbl_30d](#openbl_30d)|3280|3280|1|0.0%|0.2%|
[et_block](#et_block)|1007|18338646|1|0.0%|0.2%|
[dshield](#dshield)|20|5120|1|0.0%|0.2%|
[bruteforceblocker](#bruteforceblocker)|2168|2168|1|0.0%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|12692|12692|1|0.0%|0.2%|
[blocklist_de_sip](#blocklist_de_sip)|110|110|1|0.9%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2401|2401|1|0.0%|0.2%|
[blocklist_de_ftp](#blocklist_de_ftp)|874|874|1|0.1%|0.2%|

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
[malc0de](#malc0de)|386|386|3|0.7%|6.5%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|3|0.0%|6.5%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|1|0.0%|2.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|1|0.0%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1|0.0%|2.1%|

## dm_tor

[dan.me.uk](https://www.dan.me.uk) dynamic list of TOR exit points

Source is downloaded from [this link](https://www.dan.me.uk/torlist/).

The last time downloaded was found to be dated: Wed Jun  3 15:27:07 UTC 2015.

The ipset `dm_tor` has **6509** entries, **6509** unique IPs.

The following table shows the overlaps of `dm_tor` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dm_tor`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dm_tor`.
- ` this % ` is the percentage **of this ipset (`dm_tor`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bm_tor](#bm_tor)|6514|6514|6509|99.9%|100.0%|
[et_tor](#et_tor)|6520|6520|5711|87.5%|87.7%|
[snort_ipfilter](#snort_ipfilter)|9091|9091|1073|11.8%|16.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|629|0.0%|9.6%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|623|0.6%|9.5%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|474|1.5%|7.2%|
[stopforumspam_1d](#stopforumspam_1d)|7344|7344|290|3.9%|4.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|187|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|170|45.6%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|167|0.0%|2.5%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|44|0.0%|0.6%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[openbl_60d](#openbl_60d)|7694|7694|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5930|5930|3|0.0%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16484|16484|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13972|13972|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|36060|36060|3|0.0%|0.0%|
[xroxy](#xroxy)|2051|2051|2|0.0%|0.0%|
[voipbl](#voipbl)|10398|10808|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|655|18535168|2|0.0%|0.0%|
[et_block](#et_block)|1007|18338646|2|0.0%|0.0%|
[shunlist](#shunlist)|1296|1296|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2205|2205|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1525|1525|1|0.0%|0.0%|
[nixspam](#nixspam)|22860|22860|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|

## dshield

[DShield.org](https://dshield.org/) top 20 attacking class C (/24) subnets over the last three days - **excellent list**

Source is downloaded from [this link](http://feeds.dshield.org/block.txt).

The last time downloaded was found to be dated: Wed Jun  3 15:16:34 UTC 2015.

The ipset `dshield` has **20** entries, **5120** unique IPs.

The following table shows the overlaps of `dshield` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `dshield`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `dshield`.
- ` this % ` is the percentage **of this ipset (`dshield`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|179596|179596|2821|1.5%|55.0%|
[et_block](#et_block)|1007|18338646|1024|0.0%|20.0%|
[spamhaus_drop](#spamhaus_drop)|655|18535168|256|0.0%|5.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|256|0.0%|5.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|256|0.0%|5.0%|
[openbl_60d](#openbl_60d)|7694|7694|102|1.3%|1.9%|
[openbl_30d](#openbl_30d)|3280|3280|88|2.6%|1.7%|
[blocklist_de](#blocklist_de)|36060|36060|61|0.1%|1.1%|
[shunlist](#shunlist)|1296|1296|59|4.5%|1.1%|
[openbl_7d](#openbl_7d)|1005|1005|58|5.7%|1.1%|
[et_compromised](#et_compromised)|2174|2174|57|2.6%|1.1%|
[bruteforceblocker](#bruteforceblocker)|2168|2168|57|2.6%|1.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|12692|12692|47|0.3%|0.9%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|19|0.0%|0.3%|
[voipbl](#voipbl)|10398|10808|12|0.1%|0.2%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|12|0.0%|0.2%|
[openbl_1d](#openbl_1d)|306|306|12|3.9%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7344|7344|10|0.1%|0.1%|
[blocklist_de_bots](#blocklist_de_bots)|3042|3042|8|0.2%|0.1%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|7|4.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13972|13972|3|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9091|9091|2|0.0%|0.0%|
[malc0de](#malc0de)|386|386|2|0.5%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16484|16484|2|0.0%|0.0%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.0%|
[et_tor](#et_tor)|6520|6520|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6509|6509|1|0.0%|0.0%|
[ciarmy](#ciarmy)|338|338|1|0.2%|0.0%|
[bm_tor](#bm_tor)|6514|6514|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|874|874|1|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2649|2649|1|0.0%|0.0%|

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
[spamhaus_drop](#spamhaus_drop)|655|18535168|18267904|98.5%|99.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8598568|2.4%|46.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7079936|77.1%|38.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|2272350|0.2%|12.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|196188|0.1%|1.0%|
[fullbogons](#fullbogons)|3702|670445080|20480|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|6557|3.6%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1041|0.3%|0.0%|
[dshield](#dshield)|20|5120|1024|20.0%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|1002|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|517|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|345|1.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9091|9091|305|3.3%|0.0%|
[zeus](#zeus)|270|270|264|97.7%|0.0%|
[openbl_60d](#openbl_60d)|7694|7694|244|3.1%|0.0%|
[zeus_badips](#zeus_badips)|234|234|230|98.2%|0.0%|
[blocklist_de](#blocklist_de)|36060|36060|167|0.4%|0.0%|
[openbl_30d](#openbl_30d)|3280|3280|165|5.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|12692|12692|116|0.9%|0.0%|
[shunlist](#shunlist)|1296|1296|106|8.1%|0.0%|
[et_compromised](#et_compromised)|2174|2174|102|4.6%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2168|2168|100|4.6%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7344|7344|96|1.3%|0.0%|
[feodo](#feodo)|86|86|77|89.5%|0.0%|
[openbl_7d](#openbl_7d)|1005|1005|76|7.5%|0.0%|
[nixspam](#nixspam)|22860|22860|73|0.3%|0.0%|
[sslbl](#sslbl)|357|357|33|9.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1284|1284|29|2.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16484|16484|27|0.1%|0.0%|
[php_commenters](#php_commenters)|281|281|24|8.5%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3042|3042|20|0.6%|0.0%|
[openbl_1d](#openbl_1d)|306|306|17|5.5%|0.0%|
[voipbl](#voipbl)|10398|10808|14|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2401|2401|14|0.5%|0.0%|
[palevo](#palevo)|13|13|13|100.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|11|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|7|4.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[malc0de](#malc0de)|386|386|4|1.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13972|13972|3|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6520|6520|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6509|6509|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6514|6514|2|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2649|2649|2|0.0%|0.0%|
[xroxy](#xroxy)|2051|2051|1|0.0%|0.0%|
[proxz](#proxz)|631|631|1|0.1%|0.0%|
[proxyrss](#proxyrss)|1525|1525|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[et_botcc](#et_botcc)|511|511|1|0.1%|0.0%|
[ciarmy](#ciarmy)|338|338|1|0.2%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|110|110|1|0.9%|0.0%|

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
[alienvault_reputation](#alienvault_reputation)|179596|179596|4|0.0%|0.7%|
[spamhaus_drop](#spamhaus_drop)|655|18535168|1|0.0%|0.1%|
[malwaredomainlist](#malwaredomainlist)|1284|1284|1|0.0%|0.1%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.1%|
[et_block](#et_block)|1007|18338646|1|0.0%|0.1%|
[blocklist_de_sip](#blocklist_de_sip)|110|110|1|0.9%|0.1%|

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
[bruteforceblocker](#bruteforceblocker)|2168|2168|2103|97.0%|96.7%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|1410|0.7%|64.8%|
[openbl_60d](#openbl_60d)|7694|7694|1316|17.1%|60.5%|
[openbl_30d](#openbl_30d)|3280|3280|1227|37.4%|56.4%|
[blocklist_de](#blocklist_de)|36060|36060|676|1.8%|31.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|12692|12692|662|5.2%|30.4%|
[shunlist](#shunlist)|1296|1296|514|39.6%|23.6%|
[openbl_7d](#openbl_7d)|1005|1005|474|47.1%|21.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|217|0.0%|9.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|112|0.0%|5.1%|
[et_block](#et_block)|1007|18338646|102|0.0%|4.6%|
[spamhaus_drop](#spamhaus_drop)|655|18535168|101|0.0%|4.6%|
[openbl_1d](#openbl_1d)|306|306|88|28.7%|4.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|61|0.0%|2.8%|
[dshield](#dshield)|20|5120|57|1.1%|2.6%|
[blocklist_de_mail](#blocklist_de_mail)|16484|16484|10|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|8|0.0%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|5|0.0%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|0.2%|
[blocklist_de_imap](#blocklist_de_imap)|2401|2401|4|0.1%|0.1%|
[proxz](#proxz)|631|631|2|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13972|13972|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|234|234|1|0.4%|0.0%|
[zeus](#zeus)|270|270|1|0.3%|0.0%|
[xroxy](#xroxy)|2051|2051|1|0.0%|0.0%|
[voipbl](#voipbl)|10398|10808|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9091|9091|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1525|1525|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|874|874|1|0.1%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3042|3042|1|0.0%|0.0%|

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
[bm_tor](#bm_tor)|6514|6514|5714|87.7%|87.6%|
[dm_tor](#dm_tor)|6509|6509|5711|87.7%|87.5%|
[snort_ipfilter](#snort_ipfilter)|9091|9091|1113|12.2%|17.0%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|643|0.6%|9.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|635|0.0%|9.7%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|492|1.5%|7.5%|
[stopforumspam_1d](#stopforumspam_1d)|7344|7344|292|3.9%|4.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|188|0.0%|2.8%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|170|45.6%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|170|0.0%|2.6%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|46|0.0%|0.7%|
[php_commenters](#php_commenters)|281|281|29|10.3%|0.4%|
[openbl_60d](#openbl_60d)|7694|7694|21|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|21|0.0%|0.3%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.1%|
[php_spammers](#php_spammers)|417|417|6|1.4%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5930|5930|4|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16484|16484|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13972|13972|3|0.0%|0.0%|
[blocklist_de](#blocklist_de)|36060|36060|3|0.0%|0.0%|
[xroxy](#xroxy)|2051|2051|2|0.0%|0.0%|
[voipbl](#voipbl)|10398|10808|2|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|655|18535168|2|0.0%|0.0%|
[et_block](#et_block)|1007|18338646|2|0.0%|0.0%|
[shunlist](#shunlist)|1296|1296|1|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2205|2205|1|0.0%|0.0%|
[proxyrss](#proxyrss)|1525|1525|1|0.0%|0.0%|
[nixspam](#nixspam)|22860|22860|1|0.0%|0.0%|
[dshield](#dshield)|20|5120|1|0.0%|0.0%|

## feodo

[Abuse.ch Feodo tracker](https://feodotracker.abuse.ch) trojan includes IPs which are being used by Feodo (also known as Cridex or Bugat) which commits ebanking fraud - **excellent list**

Source is downloaded from [this link](https://feodotracker.abuse.ch/blocklist/?download=ipblocklist).

The last time downloaded was found to be dated: Wed Jun  3 15:27:16 UTC 2015.

The ipset `feodo` has **86** entries, **86** unique IPs.

The following table shows the overlaps of `feodo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `feodo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `feodo`.
- ` this % ` is the percentage **of this ipset (`feodo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|1007|18338646|77|0.0%|89.5%|
[snort_ipfilter](#snort_ipfilter)|9091|9091|65|0.7%|75.5%|
[sslbl](#sslbl)|357|357|31|8.6%|36.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|8|0.0%|9.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|3|0.0%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|3.4%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|2|0.0%|2.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|1.1%|

## fullbogons

[Team-Cymru.org](http://www.team-cymru.org) IP space that has been allocated to an RIR, but not assigned by that RIR to an actual ISP or other end-user - **excellent list - use it only your internet interface**

Source is downloaded from [this link](http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt).

The last time downloaded was found to be dated: Wed Jun  3 09:35:07 UTC 2015.

The ipset `fullbogons` has **3702** entries, **670445080** unique IPs.

The following table shows the overlaps of `fullbogons` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `fullbogons`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `fullbogons`.
- ` this % ` is the percentage **of this ipset (`fullbogons`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[bogons](#bogons)|13|592708608|592708608|100.0%|88.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|4236335|3.0%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|565248|6.1%|0.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|248575|0.0%|0.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|235897|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|655|18535168|151552|0.8%|0.0%|
[et_block](#et_block)|1007|18338646|20480|0.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|890|0.2%|0.0%|
[voipbl](#voipbl)|10398|10808|319|2.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|33|2.2%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|15|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1284|1284|9|0.7%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2168|2168|1|0.0%|0.0%|

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
[fullbogons](#fullbogons)|3702|670445080|15|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|14|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.0%|
[et_block](#et_block)|1007|18338646|11|0.0%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|7|0.0%|0.0%|
[spamhaus_drop](#spamhaus_drop)|655|18535168|6|0.0%|0.0%|
[nixspam](#nixspam)|22860|22860|6|0.0%|0.0%|
[blocklist_de](#blocklist_de)|36060|36060|6|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[xroxy](#xroxy)|2051|2051|3|0.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16484|16484|3|0.0%|0.0%|
[voipbl](#voipbl)|10398|10808|2|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7344|7344|2|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9091|9091|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2649|2649|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13972|13972|2|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5930|5930|1|0.0%|0.0%|
[proxz](#proxz)|631|631|1|0.1%|0.0%|
[proxyrss](#proxyrss)|1525|1525|1|0.0%|0.0%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2401|2401|1|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3042|3042|1|0.0%|0.0%|

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
[spamhaus_drop](#spamhaus_drop)|655|18535168|7079936|38.1%|77.1%|
[et_block](#et_block)|1007|18338646|7079936|38.6%|77.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2526625|0.7%|27.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|904796|0.1%|9.8%|
[fullbogons](#fullbogons)|3702|670445080|565248|0.0%|6.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|145472|0.1%|1.5%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1036|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|737|0.7%|0.0%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|518|0.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|174|0.5%|0.0%|
[nixspam](#nixspam)|22860|22860|72|0.3%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7344|7344|46|0.6%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1284|1284|27|2.1%|0.0%|
[blocklist_de](#blocklist_de)|36060|36060|26|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7694|7694|18|0.2%|0.0%|
[openbl_30d](#openbl_30d)|3280|3280|13|0.3%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3042|3042|13|0.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9091|9091|11|0.1%|0.0%|
[zeus_badips](#zeus_badips)|234|234|10|4.2%|0.0%|
[zeus](#zeus)|270|270|10|3.7%|0.0%|
[openbl_7d](#openbl_7d)|1005|1005|9|0.8%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|7|0.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|12692|12692|6|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16484|16484|6|0.0%|0.0%|
[openbl_1d](#openbl_1d)|306|306|5|1.6%|0.0%|
[et_compromised](#et_compromised)|2174|2174|5|0.2%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2168|2168|5|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2401|2401|4|0.1%|0.0%|
[shunlist](#shunlist)|1296|1296|3|0.2%|0.0%|
[et_tor](#et_tor)|6520|6520|3|0.0%|0.0%|
[dm_tor](#dm_tor)|6509|6509|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6514|6514|3|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|3|1.7%|0.0%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[voipbl](#voipbl)|10398|10808|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.0%|
[et_botcc](#et_botcc)|511|511|1|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2649|2649|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13972|13972|1|0.0%|0.0%|

## ib_bluetack_level1

[iBlocklist.com](https://www.iblocklist.com/) free version of [BlueTack.co.uk](http://www.bluetack.co.uk/) Level 1 (for use in p2p): Companies or organizations who are clearly involved with trying to stop filesharing (e.g. Baytsp, MediaDefender, Mediasentry a.o.). Companies which anti-p2p activity has been seen from. Companies that produce or have a strong financial interest in copyrighted material (e.g. music, movie, software industries a.o.). Government ranges or companies that have a strong financial interest in doing work for governments. Legal industry ranges. IPs or ranges of ISPs from which anti-p2p activity has been observed. Basically this list will block all kinds of internet connections that most people would rather not have during their internet travels.

Source is downloaded from [this link](http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz).

The last time downloaded was found to be dated: Wed Jun  3 09:35:00 UTC 2015.

The ipset `ib_bluetack_level1` has **218309** entries, **764987411** unique IPs.

The following table shows the overlaps of `ib_bluetack_level1` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ib_bluetack_level1`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ib_bluetack_level1`.
- ` this % ` is the percentage **of this ipset (`ib_bluetack_level1`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|16300309|4.6%|2.1%|
[et_block](#et_block)|1007|18338646|2272350|12.3%|0.2%|
[spamhaus_drop](#spamhaus_drop)|655|18535168|2272266|12.2%|0.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1354348|0.9%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|904796|9.8%|0.1%|
[fullbogons](#fullbogons)|3702|670445080|235897|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|33155|6.8%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|13248|3.9%|0.0%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|4702|2.6%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|1545|1.6%|0.0%|
[blocklist_de](#blocklist_de)|36060|36060|1542|4.2%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16484|16484|1344|8.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13972|13972|1319|9.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|581|1.8%|0.0%|
[nixspam](#nixspam)|22860|22860|437|1.9%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|406|0.8%|0.0%|
[voipbl](#voipbl)|10398|10808|298|2.7%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7344|7344|178|2.4%|0.0%|
[openbl_60d](#openbl_60d)|7694|7694|172|2.2%|0.0%|
[et_tor](#et_tor)|6520|6520|170|2.6%|0.0%|
[dm_tor](#dm_tor)|6509|6509|167|2.5%|0.0%|
[bm_tor](#bm_tor)|6514|6514|167|2.5%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5930|5930|125|2.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|12692|12692|121|0.9%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9091|9091|101|1.1%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|97|6.6%|0.0%|
[openbl_30d](#openbl_30d)|3280|3280|74|2.2%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2205|2205|72|3.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1284|1284|66|5.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2168|2168|62|2.8%|0.0%|
[et_compromised](#et_compromised)|2174|2174|61|2.8%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|58|8.6%|0.0%|
[xroxy](#xroxy)|2051|2051|57|2.7%|0.0%|
[et_botcc](#et_botcc)|511|511|42|8.2%|0.0%|
[proxyrss](#proxyrss)|1525|1525|41|2.6%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2649|2649|32|1.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3042|3042|32|1.0%|0.0%|
[shunlist](#shunlist)|1296|1296|26|2.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2401|2401|26|1.0%|0.0%|
[proxz](#proxz)|631|631|25|3.9%|0.0%|
[openbl_7d](#openbl_7d)|1005|1005|21|2.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|17|4.5%|0.0%|
[malc0de](#malc0de)|386|386|12|3.1%|0.0%|
[ciarmy](#ciarmy)|338|338|10|2.9%|0.0%|
[php_dictionary](#php_dictionary)|433|433|9|2.0%|0.0%|
[openbl_1d](#openbl_1d)|306|306|8|2.6%|0.0%|
[zeus](#zeus)|270|270|7|2.5%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[php_spammers](#php_spammers)|417|417|5|1.1%|0.0%|
[php_commenters](#php_commenters)|281|281|5|1.7%|0.0%|
[bogons](#bogons)|13|592708608|5|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|874|874|5|0.5%|0.0%|
[zeus_badips](#zeus_badips)|234|234|4|1.7%|0.0%|
[virbl](#virbl)|42|42|4|9.5%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|110|110|4|3.6%|0.0%|
[sslbl](#sslbl)|357|357|3|0.8%|0.0%|
[feodo](#feodo)|86|86|3|3.4%|0.0%|
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
[spamhaus_drop](#spamhaus_drop)|655|18535168|8598042|46.3%|2.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2830140|2.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2526625|27.5%|0.7%|
[fullbogons](#fullbogons)|3702|670445080|248575|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|98904|20.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|7733|2.2%|0.0%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|7610|4.2%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|2510|2.7%|0.0%|
[blocklist_de](#blocklist_de)|36060|36060|1559|4.3%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16484|16484|1152|6.9%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13972|13972|1078|7.7%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|940|3.0%|0.0%|
[nixspam](#nixspam)|22860|22860|657|2.8%|0.0%|
[voipbl](#voipbl)|10398|10808|432|3.9%|0.0%|
[openbl_60d](#openbl_60d)|7694|7694|340|4.4%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7344|7344|248|3.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|230|0.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|12692|12692|220|1.7%|0.0%|
[et_tor](#et_tor)|6520|6520|188|2.8%|0.0%|
[dm_tor](#dm_tor)|6509|6509|187|2.8%|0.0%|
[bm_tor](#bm_tor)|6514|6514|187|2.8%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5930|5930|179|3.0%|0.0%|
[openbl_30d](#openbl_30d)|3280|3280|179|5.4%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3042|3042|114|3.7%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9091|9091|112|1.2%|0.0%|
[et_compromised](#et_compromised)|2174|2174|112|5.1%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2168|2168|112|5.1%|0.0%|
[xroxy](#xroxy)|2051|2051|99|4.8%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2205|2205|88|3.9%|0.0%|
[shunlist](#shunlist)|1296|1296|72|5.5%|0.0%|
[proxyrss](#proxyrss)|1525|1525|59|3.8%|0.0%|
[openbl_7d](#openbl_7d)|1005|1005|49|4.8%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2401|2401|49|2.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|45|3.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2649|2649|44|1.6%|0.0%|
[php_spammers](#php_spammers)|417|417|31|7.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|28|4.1%|0.0%|
[proxz](#proxz)|631|631|27|4.2%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1284|1284|26|2.0%|0.0%|
[malc0de](#malc0de)|386|386|24|6.2%|0.0%|
[et_botcc](#et_botcc)|511|511|22|4.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|21|5.6%|0.0%|
[openbl_1d](#openbl_1d)|306|306|17|5.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|874|874|17|1.9%|0.0%|
[ciarmy](#ciarmy)|338|338|12|3.5%|0.0%|
[php_dictionary](#php_dictionary)|433|433|10|2.3%|0.0%|
[zeus](#zeus)|270|270|9|3.3%|0.0%|
[php_commenters](#php_commenters)|281|281|9|3.2%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|110|110|9|8.1%|0.0%|
[zeus_badips](#zeus_badips)|234|234|8|3.4%|0.0%|
[php_harvesters](#php_harvesters)|257|257|7|2.7%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|7|4.0%|0.0%|
[sslbl](#sslbl)|357|357|6|1.6%|0.0%|
[palevo](#palevo)|13|13|3|23.0%|0.0%|
[feodo](#feodo)|86|86|3|3.4%|0.0%|
[virbl](#virbl)|42|42|2|4.7%|0.0%|
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
[fullbogons](#fullbogons)|3702|670445080|4236335|0.6%|3.0%|
[bogons](#bogons)|13|592708608|4194304|0.7%|3.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2830140|0.8%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1354348|0.1%|0.9%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|270785|55.5%|0.1%|
[et_block](#et_block)|1007|18338646|196188|1.0%|0.1%|
[spamhaus_drop](#spamhaus_drop)|655|18535168|195904|1.0%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|145472|1.5%|0.1%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|14652|8.1%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|9231|2.7%|0.0%|
[blocklist_de](#blocklist_de)|36060|36060|6321|17.5%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|5884|6.3%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|12692|12692|3384|26.6%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16484|16484|2482|15.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13972|13972|2271|16.2%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|2017|6.4%|0.0%|
[nixspam](#nixspam)|22860|22860|1601|7.0%|0.0%|
[voipbl](#voipbl)|10398|10808|1594|14.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1172|2.4%|0.0%|
[openbl_60d](#openbl_60d)|7694|7694|747|9.7%|0.0%|
[et_tor](#et_tor)|6520|6520|635|9.7%|0.0%|
[dm_tor](#dm_tor)|6509|6509|629|9.6%|0.0%|
[bm_tor](#bm_tor)|6514|6514|629|9.6%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7344|7344|465|6.3%|0.0%|
[openbl_30d](#openbl_30d)|3280|3280|319|9.7%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2401|2401|265|11.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9091|9091|234|2.5%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2168|2168|218|10.0%|0.0%|
[et_compromised](#et_compromised)|2174|2174|217|9.9%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2649|2649|176|6.6%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3042|3042|170|5.5%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5930|5930|167|2.8%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1284|1284|146|11.3%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|125|33.6%|0.0%|
[openbl_7d](#openbl_7d)|1005|1005|114|11.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|110|7.5%|0.0%|
[shunlist](#shunlist)|1296|1296|105|8.1%|0.0%|
[xroxy](#xroxy)|2051|2051|89|4.3%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|874|874|82|9.3%|0.0%|
[et_botcc](#et_botcc)|511|511|77|15.0%|0.0%|
[malc0de](#malc0de)|386|386|67|17.3%|0.0%|
[ciarmy](#ciarmy)|338|338|57|16.8%|0.0%|
[proxz](#proxz)|631|631|56|8.8%|0.0%|
[proxyrss](#proxyrss)|1525|1525|52|3.4%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|51|7.5%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2205|2205|48|2.1%|0.0%|
[openbl_1d](#openbl_1d)|306|306|45|14.7%|0.0%|
[php_spammers](#php_spammers)|417|417|26|6.2%|0.0%|
[php_dictionary](#php_dictionary)|433|433|24|5.5%|0.0%|
[sslbl](#sslbl)|357|357|23|6.4%|0.0%|
[zeus](#zeus)|270|270|19|7.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|16|9.1%|0.0%|
[php_harvesters](#php_harvesters)|257|257|15|5.8%|0.0%|
[php_commenters](#php_commenters)|281|281|15|5.3%|0.0%|
[zeus_badips](#zeus_badips)|234|234|14|5.9%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|110|110|14|12.7%|0.0%|
[feodo](#feodo)|86|86|8|9.3%|0.0%|
[virbl](#virbl)|42|42|7|16.6%|0.0%|
[cleanmx_viruses](#cleanmx_viruses)|46|46|5|10.8%|0.0%|
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
[xroxy](#xroxy)|2051|2051|13|0.6%|1.9%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|12|0.0%|1.7%|
[ri_web_proxies](#ri_web_proxies)|5930|5930|11|0.1%|1.6%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|11|0.0%|1.6%|
[proxyrss](#proxyrss)|1525|1525|10|0.6%|1.4%|
[ri_connect_proxies](#ri_connect_proxies)|2205|2205|6|0.2%|0.8%|
[stopforumspam_1d](#stopforumspam_1d)|7344|7344|4|0.0%|0.5%|
[proxz](#proxz)|631|631|3|0.4%|0.4%|
[blocklist_de](#blocklist_de)|36060|36060|3|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|655|18535168|2|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.2%|
[et_block](#et_block)|1007|18338646|2|0.0%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3042|3042|2|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9091|9091|1|0.0%|0.1%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.1%|
[nixspam](#nixspam)|22860|22860|1|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|16484|16484|1|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|1|0.0%|0.1%|

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
[spamhaus_drop](#spamhaus_drop)|655|18535168|1037|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1036|0.0%|0.3%|
[fullbogons](#fullbogons)|3702|670445080|890|0.0%|0.2%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|289|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|48|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1284|1284|27|2.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|26|0.0%|0.0%|
[et_tor](#et_tor)|6520|6520|21|0.3%|0.0%|
[dm_tor](#dm_tor)|6509|6509|21|0.3%|0.0%|
[bm_tor](#bm_tor)|6514|6514|21|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|19|1.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9091|9091|14|0.1%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7344|7344|12|0.1%|0.0%|
[nixspam](#nixspam)|22860|22860|9|0.0%|0.0%|
[blocklist_de](#blocklist_de)|36060|36060|8|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5930|5930|5|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7694|7694|5|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|5|1.3%|0.0%|
[voipbl](#voipbl)|10398|10808|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3280|3280|4|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|4|0.0%|0.0%|
[proxyrss](#proxyrss)|1525|1525|3|0.1%|0.0%|
[malc0de](#malc0de)|386|386|3|0.7%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|12692|12692|3|0.0%|0.0%|
[palevo](#palevo)|13|13|2|15.3%|0.0%|
[et_compromised](#et_compromised)|2174|2174|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2168|2168|2|0.0%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|110|110|2|1.8%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16484|16484|2|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3042|3042|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13972|13972|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|234|234|1|0.4%|0.0%|
[zeus](#zeus)|270|270|1|0.3%|0.0%|
[xroxy](#xroxy)|2051|2051|1|0.0%|0.0%|
[sslbl](#sslbl)|357|357|1|0.2%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|1|0.0%|0.0%|
[shunlist](#shunlist)|1296|1296|1|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.0%|
[openbl_7d](#openbl_7d)|1005|1005|1|0.0%|0.0%|
[feodo](#feodo)|86|86|1|1.1%|0.0%|
[bogons](#bogons)|13|592708608|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2401|2401|1|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2649|2649|1|0.0%|0.0%|

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
[fullbogons](#fullbogons)|3702|670445080|33|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|19|0.0%|1.3%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|8|0.0%|0.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7|0.0%|0.4%|
[spamhaus_drop](#spamhaus_drop)|655|18535168|6|0.0%|0.4%|
[et_block](#et_block)|1007|18338646|6|0.0%|0.4%|
[malwaredomainlist](#malwaredomainlist)|1284|1284|3|0.2%|0.2%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|2|0.0%|0.1%|
[openbl_60d](#openbl_60d)|7694|7694|2|0.0%|0.1%|
[openbl_30d](#openbl_30d)|3280|3280|2|0.0%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7344|7344|1|0.0%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9091|9091|1|0.0%|0.0%|
[ri_web_proxies](#ri_web_proxies)|5930|5930|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|1005|1005|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_botcc](#et_botcc)|511|511|1|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|12692|12692|1|0.0%|0.0%|
[blocklist_de](#blocklist_de)|36060|36060|1|0.0%|0.0%|

## malc0de

[Malc0de.com](http://malc0de.com) malicious IPs of the last 30 days

Source is downloaded from [this link](http://malc0de.com/bl/IP_Blacklist.txt).

The last time downloaded was found to be dated: Wed Jun  3 13:17:02 UTC 2015.

The ipset `malc0de` has **386** entries, **386** unique IPs.

The following table shows the overlaps of `malc0de` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `malc0de`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `malc0de`.
- ` this % ` is the percentage **of this ipset (`malc0de`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|67|0.0%|17.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|24|0.0%|6.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|12|0.0%|3.1%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|12|0.0%|3.1%|
[spamhaus_drop](#spamhaus_drop)|655|18535168|4|0.0%|1.0%|
[malwaredomainlist](#malwaredomainlist)|1284|1284|4|0.3%|1.0%|
[et_block](#et_block)|1007|18338646|4|0.0%|1.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.7%|
[cleanmx_viruses](#cleanmx_viruses)|46|46|3|6.5%|0.7%|
[dshield](#dshield)|20|5120|2|0.0%|0.5%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|1|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9091|9091|1|0.0%|0.2%|

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
[spamhaus_drop](#spamhaus_drop)|655|18535168|29|0.0%|2.2%|
[et_block](#et_block)|1007|18338646|29|0.0%|2.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|27|0.0%|2.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|27|0.0%|2.1%|
[snort_ipfilter](#snort_ipfilter)|9091|9091|26|0.2%|2.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|26|0.0%|2.0%|
[fullbogons](#fullbogons)|3702|670445080|9|0.0%|0.7%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|6|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|4|0.0%|0.3%|
[malc0de](#malc0de)|386|386|4|1.0%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|3|0.0%|0.2%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|3|0.2%|0.2%|
[nixspam](#nixspam)|22860|22860|2|0.0%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7344|7344|1|0.0%|0.0%|
[et_botcc](#et_botcc)|511|511|1|0.1%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|12692|12692|1|0.0%|0.0%|
[blocklist_de](#blocklist_de)|36060|36060|1|0.0%|0.0%|

## maxmind_proxy_fraud

[MaxMind.com](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list) list of anonymous proxy fraudelent IP addresses.

Source is downloaded from [this link](https://www.maxmind.com/en/anonymous-proxy-fraudulent-ip-address-list).

The last time downloaded was found to be dated: Wed Jun  3 12:18:22 UTC 2015.

The ipset `maxmind_proxy_fraud` has **372** entries, **372** unique IPs.

The following table shows the overlaps of `maxmind_proxy_fraud` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `maxmind_proxy_fraud`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `maxmind_proxy_fraud`.
- ` this % ` is the percentage **of this ipset (`maxmind_proxy_fraud`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|232|0.2%|62.3%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|196|0.6%|52.6%|
[snort_ipfilter](#snort_ipfilter)|9091|9091|176|1.9%|47.3%|
[et_tor](#et_tor)|6520|6520|170|2.6%|45.6%|
[dm_tor](#dm_tor)|6509|6509|170|2.6%|45.6%|
[bm_tor](#bm_tor)|6514|6514|170|2.6%|45.6%|
[stopforumspam_1d](#stopforumspam_1d)|7344|7344|153|2.0%|41.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|125|0.0%|33.6%|
[php_commenters](#php_commenters)|281|281|28|9.9%|7.5%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|25|0.0%|6.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|21|0.0%|5.6%|
[openbl_60d](#openbl_60d)|7694|7694|18|0.2%|4.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|17|0.0%|4.5%|
[php_harvesters](#php_harvesters)|257|257|6|2.3%|1.6%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|1.3%|
[ri_web_proxies](#ri_web_proxies)|5930|5930|4|0.0%|1.0%|
[php_spammers](#php_spammers)|417|417|4|0.9%|1.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|1.0%|
[shunlist](#shunlist)|1296|1296|2|0.1%|0.5%|
[xroxy](#xroxy)|2051|2051|1|0.0%|0.2%|
[voipbl](#voipbl)|10398|10808|1|0.0%|0.2%|
[ri_connect_proxies](#ri_connect_proxies)|2205|2205|1|0.0%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|16484|16484|1|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|13972|13972|1|0.0%|0.2%|
[blocklist_de](#blocklist_de)|36060|36060|1|0.0%|0.2%|

## nixspam

[NiX Spam](http://www.heise.de/ix/NiX-Spam-DNSBL-and-blacklist-for-download-499637.html) IP addresses that sent spam in the last hour - automatically generated entries without distinguishing open proxies from relays, dialup gateways, and so on. All IPs are removed after 12 hours if there is no spam from there.

Source is downloaded from [this link](http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz).

The last time downloaded was found to be dated: Wed Jun  3 15:30:02 UTC 2015.

The ipset `nixspam` has **22860** entries, **22860** unique IPs.

The following table shows the overlaps of `nixspam` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `nixspam`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `nixspam`.
- ` this % ` is the percentage **of this ipset (`nixspam`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1601|0.0%|7.0%|
[blocklist_de](#blocklist_de)|36060|36060|757|2.0%|3.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|657|0.0%|2.8%|
[blocklist_de_mail](#blocklist_de_mail)|16484|16484|633|3.8%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|437|0.0%|1.9%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|254|0.2%|1.1%|
[snort_ipfilter](#snort_ipfilter)|9091|9091|206|2.2%|0.9%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|157|0.5%|0.6%|
[ri_web_proxies](#ri_web_proxies)|5930|5930|95|1.6%|0.4%|
[spamhaus_drop](#spamhaus_drop)|655|18535168|73|0.0%|0.3%|
[php_dictionary](#php_dictionary)|433|433|73|16.8%|0.3%|
[et_block](#et_block)|1007|18338646|73|0.0%|0.3%|
[xroxy](#xroxy)|2051|2051|72|3.5%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|72|0.0%|0.3%|
[stopforumspam_1d](#stopforumspam_1d)|7344|7344|67|0.9%|0.2%|
[php_spammers](#php_spammers)|417|417|54|12.9%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3042|3042|50|1.6%|0.2%|
[blocklist_de_ssh](#blocklist_de_ssh)|12692|12692|43|0.3%|0.1%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|40|0.0%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2649|2649|29|1.0%|0.1%|
[blocklist_de_apache](#blocklist_de_apache)|13972|13972|29|0.2%|0.1%|
[proxz](#proxz)|631|631|27|4.2%|0.1%|
[ri_connect_proxies](#ri_connect_proxies)|2205|2205|23|1.0%|0.1%|
[blocklist_de_imap](#blocklist_de_imap)|2401|2401|21|0.8%|0.0%|
[proxyrss](#proxyrss)|1525|1525|20|1.3%|0.0%|
[openbl_60d](#openbl_60d)|7694|7694|17|0.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|874|874|10|1.1%|0.0%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|9|0.0%|0.0%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1284|1284|2|0.1%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|1|0.0%|0.0%|
[shunlist](#shunlist)|1296|1296|1|0.0%|0.0%|
[openbl_7d](#openbl_7d)|1005|1005|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3280|3280|1|0.0%|0.0%|
[openbl_1d](#openbl_1d)|306|306|1|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[et_tor](#et_tor)|6520|6520|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6509|6509|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6514|6514|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|1|0.5%|0.0%|

## openbl_1d

[OpenBL.org](http://www.openbl.org/) last 24 hours IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_1days.txt).

The last time downloaded was found to be dated: Wed Jun  3 15:32:00 UTC 2015.

The ipset `openbl_1d` has **306** entries, **306** unique IPs.

The following table shows the overlaps of `openbl_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_1d`.
- ` this % ` is the percentage **of this ipset (`openbl_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_7d](#openbl_7d)|1005|1005|306|30.4%|100.0%|
[openbl_60d](#openbl_60d)|7694|7694|306|3.9%|100.0%|
[openbl_30d](#openbl_30d)|3280|3280|306|9.3%|100.0%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|294|0.1%|96.0%|
[blocklist_de](#blocklist_de)|36060|36060|239|0.6%|78.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|12692|12692|231|1.8%|75.4%|
[bruteforceblocker](#bruteforceblocker)|2168|2168|92|4.2%|30.0%|
[et_compromised](#et_compromised)|2174|2174|88|4.0%|28.7%|
[shunlist](#shunlist)|1296|1296|83|6.4%|27.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|45|0.0%|14.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|18|10.2%|5.8%|
[spamhaus_drop](#spamhaus_drop)|655|18535168|17|0.0%|5.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|17|0.0%|5.5%|
[et_block](#et_block)|1007|18338646|17|0.0%|5.5%|
[dshield](#dshield)|20|5120|12|0.2%|3.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|8|0.0%|2.6%|
[blocklist_de_mail](#blocklist_de_mail)|16484|16484|6|0.0%|1.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|5|0.0%|1.6%|
[blocklist_de_imap](#blocklist_de_imap)|2401|2401|5|0.2%|1.6%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|3|0.0%|0.9%|
[nixspam](#nixspam)|22860|22860|1|0.0%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|13972|13972|1|0.0%|0.3%|

## openbl_30d

[OpenBL.org](http://www.openbl.org/) last 30 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_30days.txt).

The last time downloaded was found to be dated: Wed Jun  3 15:42:00 UTC 2015.

The ipset `openbl_30d` has **3280** entries, **3280** unique IPs.

The following table shows the overlaps of `openbl_30d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_30d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_30d`.
- ` this % ` is the percentage **of this ipset (`openbl_30d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7694|7694|3280|42.6%|100.0%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|3255|1.8%|99.2%|
[et_compromised](#et_compromised)|2174|2174|1227|56.4%|37.4%|
[bruteforceblocker](#bruteforceblocker)|2168|2168|1222|56.3%|37.2%|
[openbl_7d](#openbl_7d)|1005|1005|1005|100.0%|30.6%|
[blocklist_de](#blocklist_de)|36060|36060|915|2.5%|27.8%|
[blocklist_de_ssh](#blocklist_de_ssh)|12692|12692|867|6.8%|26.4%|
[shunlist](#shunlist)|1296|1296|600|46.2%|18.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|319|0.0%|9.7%|
[openbl_1d](#openbl_1d)|306|306|306|100.0%|9.3%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|179|0.0%|5.4%|
[et_block](#et_block)|1007|18338646|165|0.0%|5.0%|
[spamhaus_drop](#spamhaus_drop)|655|18535168|160|0.0%|4.8%|
[dshield](#dshield)|20|5120|88|1.7%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|74|0.0%|2.2%|
[blocklist_de_mail](#blocklist_de_mail)|16484|16484|43|0.2%|1.3%|
[blocklist_de_imap](#blocklist_de_imap)|2401|2401|34|1.4%|1.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|24|13.7%|0.7%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|13|0.0%|0.3%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|6|0.0%|0.1%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|4|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.1%|
[voipbl](#voipbl)|10398|10808|3|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13972|13972|3|0.0%|0.0%|
[zeus](#zeus)|270|270|2|0.7%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9091|9091|2|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[zeus_badips](#zeus_badips)|234|234|1|0.4%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|1|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7344|7344|1|0.0%|0.0%|
[nixspam](#nixspam)|22860|22860|1|0.0%|0.0%|
[ciarmy](#ciarmy)|338|338|1|0.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|874|874|1|0.1%|0.0%|

## openbl_60d

[OpenBL.org](http://www.openbl.org/) last 60 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_60days.txt).

The last time downloaded was found to be dated: Wed Jun  3 15:42:00 UTC 2015.

The ipset `openbl_60d` has **7694** entries, **7694** unique IPs.

The following table shows the overlaps of `openbl_60d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_60d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_60d`.
- ` this % ` is the percentage **of this ipset (`openbl_60d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|179596|179596|7663|4.2%|99.5%|
[openbl_30d](#openbl_30d)|3280|3280|3280|100.0%|42.6%|
[blocklist_de](#blocklist_de)|36060|36060|1827|5.0%|23.7%|
[blocklist_de_ssh](#blocklist_de_ssh)|12692|12692|1770|13.9%|23.0%|
[et_compromised](#et_compromised)|2174|2174|1316|60.5%|17.1%|
[bruteforceblocker](#bruteforceblocker)|2168|2168|1299|59.9%|16.8%|
[openbl_7d](#openbl_7d)|1005|1005|1005|100.0%|13.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|747|0.0%|9.7%|
[shunlist](#shunlist)|1296|1296|616|47.5%|8.0%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|340|0.0%|4.4%|
[openbl_1d](#openbl_1d)|306|306|306|100.0%|3.9%|
[et_block](#et_block)|1007|18338646|244|0.0%|3.1%|
[spamhaus_drop](#spamhaus_drop)|655|18535168|239|0.0%|3.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|172|0.0%|2.2%|
[dshield](#dshield)|20|5120|102|1.9%|1.3%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|56|0.0%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|16484|16484|49|0.2%|0.6%|
[blocklist_de_imap](#blocklist_de_imap)|2401|2401|38|1.5%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|27|15.4%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|26|0.0%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9091|9091|24|0.2%|0.3%|
[et_tor](#et_tor)|6520|6520|21|0.3%|0.2%|
[dm_tor](#dm_tor)|6509|6509|21|0.3%|0.2%|
[bm_tor](#bm_tor)|6514|6514|21|0.3%|0.2%|
[stopforumspam_1d](#stopforumspam_1d)|7344|7344|20|0.2%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|18|4.8%|0.2%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|18|0.0%|0.2%|
[nixspam](#nixspam)|22860|22860|17|0.0%|0.2%|
[voipbl](#voipbl)|10398|10808|8|0.0%|0.1%|
[php_commenters](#php_commenters)|281|281|8|2.8%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|6|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13972|13972|4|0.0%|0.0%|
[zeus](#zeus)|270|270|2|0.7%|0.0%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|874|874|2|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3042|3042|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|234|234|1|0.4%|0.0%|
[ciarmy](#ciarmy)|338|338|1|0.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2649|2649|1|0.0%|0.0%|

## openbl_7d

[OpenBL.org](http://www.openbl.org/) last 7 days IPs.  OpenBL.org is detecting, logging and reporting various types of internet abuse. Currently they monitor ports 21 (FTP), 22 (SSH), 23 (TELNET), 25 (SMTP), 110 (POP3), 143 (IMAP), 587 (Submission), 993 (IMAPS) and 995 (POP3S) for bruteforce login attacks as well as scans on ports 80 (HTTP) and 443 (HTTPS) for vulnerable installations of phpMyAdmin and other web applications.

Source is downloaded from [this link](http://www.openbl.org/lists/base_7days.txt).

The last time downloaded was found to be dated: Wed Jun  3 15:42:00 UTC 2015.

The ipset `openbl_7d` has **1005** entries, **1005** unique IPs.

The following table shows the overlaps of `openbl_7d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `openbl_7d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `openbl_7d`.
- ` this % ` is the percentage **of this ipset (`openbl_7d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[openbl_60d](#openbl_60d)|7694|7694|1005|13.0%|100.0%|
[openbl_30d](#openbl_30d)|3280|3280|1005|30.6%|100.0%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|990|0.5%|98.5%|
[blocklist_de](#blocklist_de)|36060|36060|607|1.6%|60.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|12692|12692|585|4.6%|58.2%|
[bruteforceblocker](#bruteforceblocker)|2168|2168|477|22.0%|47.4%|
[et_compromised](#et_compromised)|2174|2174|474|21.8%|47.1%|
[shunlist](#shunlist)|1296|1296|383|29.5%|38.1%|
[openbl_1d](#openbl_1d)|306|306|306|100.0%|30.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|114|0.0%|11.3%|
[et_block](#et_block)|1007|18338646|76|0.0%|7.5%|
[spamhaus_drop](#spamhaus_drop)|655|18535168|74|0.0%|7.3%|
[dshield](#dshield)|20|5120|58|1.1%|5.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|49|0.0%|4.8%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|24|13.7%|2.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|21|0.0%|2.0%|
[blocklist_de_mail](#blocklist_de_mail)|16484|16484|20|0.1%|1.9%|
[blocklist_de_imap](#blocklist_de_imap)|2401|2401|16|0.6%|1.5%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|9|0.0%|0.8%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|5|0.0%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|3|0.0%|0.2%|
[voipbl](#voipbl)|10398|10808|2|0.0%|0.1%|
[zeus](#zeus)|270|270|1|0.3%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9091|9091|1|0.0%|0.0%|
[nixspam](#nixspam)|22860|22860|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[ciarmy](#ciarmy)|338|338|1|0.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|874|874|1|0.1%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13972|13972|1|0.0%|0.0%|

## palevo

[Abuse.ch Palevo tracker](https://palevotracker.abuse.ch) worm includes IPs which are being used as botnet C&C for the Palevo crimeware - **excellent list**

Source is downloaded from [this link](https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist).

The last time downloaded was found to be dated: Wed Jun  3 15:27:14 UTC 2015.

The ipset `palevo` has **13** entries, **13** unique IPs.

The following table shows the overlaps of `palevo` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `palevo`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `palevo`.
- ` this % ` is the percentage **of this ipset (`palevo`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|1007|18338646|13|0.0%|100.0%|
[snort_ipfilter](#snort_ipfilter)|9091|9091|11|0.1%|84.6%|
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
[stopforumspam_1d](#stopforumspam_1d)|7344|7344|107|1.4%|38.0%|
[blocklist_de](#blocklist_de)|36060|36060|62|0.1%|22.0%|
[blocklist_de_bots](#blocklist_de_bots)|3042|3042|46|1.5%|16.3%|
[snort_ipfilter](#snort_ipfilter)|9091|9091|37|0.4%|13.1%|
[php_spammers](#php_spammers)|417|417|32|7.6%|11.3%|
[et_tor](#et_tor)|6520|6520|29|0.4%|10.3%|
[dm_tor](#dm_tor)|6509|6509|29|0.4%|10.3%|
[bm_tor](#bm_tor)|6514|6514|29|0.4%|10.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|29|16.5%|10.3%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|28|7.5%|9.9%|
[spamhaus_drop](#spamhaus_drop)|655|18535168|25|0.0%|8.8%|
[et_block](#et_block)|1007|18338646|24|0.0%|8.5%|
[blocklist_de_apache](#blocklist_de_apache)|13972|13972|24|0.1%|8.5%|
[php_dictionary](#php_dictionary)|433|433|22|5.0%|7.8%|
[blocklist_de_mail](#blocklist_de_mail)|16484|16484|22|0.1%|7.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|5.3%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|14|0.0%|4.9%|
[ri_web_proxies](#ri_web_proxies)|5930|5930|11|0.1%|3.9%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|3.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.2%|
[openbl_60d](#openbl_60d)|7694|7694|8|0.1%|2.8%|
[nixspam](#nixspam)|22860|22860|8|0.0%|2.8%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|7|0.0%|2.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|1.7%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2649|2649|5|0.1%|1.7%|
[xroxy](#xroxy)|2051|2051|3|0.1%|1.0%|
[proxz](#proxz)|631|631|3|0.4%|1.0%|
[zeus_badips](#zeus_badips)|234|234|1|0.4%|0.3%|
[zeus](#zeus)|270|270|1|0.3%|0.3%|
[proxyrss](#proxyrss)|1525|1525|1|0.0%|0.3%|
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
[nixspam](#nixspam)|22860|22860|73|0.3%|16.8%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|65|0.2%|15.0%|
[snort_ipfilter](#snort_ipfilter)|9091|9091|57|0.6%|13.1%|
[blocklist_de](#blocklist_de)|36060|36060|57|0.1%|13.1%|
[blocklist_de_mail](#blocklist_de_mail)|16484|16484|40|0.2%|9.2%|
[ri_web_proxies](#ri_web_proxies)|5930|5930|33|0.5%|7.6%|
[xroxy](#xroxy)|2051|2051|24|1.1%|5.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|24|0.0%|5.5%|
[php_commenters](#php_commenters)|281|281|22|7.8%|5.0%|
[stopforumspam_1d](#stopforumspam_1d)|7344|7344|17|0.2%|3.9%|
[blocklist_de_bots](#blocklist_de_bots)|3042|3042|16|0.5%|3.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|10|0.0%|2.3%|
[proxz](#proxz)|631|631|9|1.4%|2.0%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|9|0.0%|2.0%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|7|0.0%|1.6%|
[spamhaus_drop](#spamhaus_drop)|655|18535168|4|0.0%|0.9%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.9%|
[et_tor](#et_tor)|6520|6520|4|0.0%|0.9%|
[et_block](#et_block)|1007|18338646|4|0.0%|0.9%|
[dm_tor](#dm_tor)|6509|6509|4|0.0%|0.9%|
[bm_tor](#bm_tor)|6514|6514|4|0.0%|0.9%|
[ri_connect_proxies](#ri_connect_proxies)|2205|2205|3|0.1%|0.6%|
[proxyrss](#proxyrss)|1525|1525|2|0.1%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|2|1.1%|0.4%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.2%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2649|2649|1|0.0%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|13972|13972|1|0.0%|0.2%|

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
[stopforumspam_1d](#stopforumspam_1d)|7344|7344|34|0.4%|13.2%|
[blocklist_de](#blocklist_de)|36060|36060|23|0.0%|8.9%|
[blocklist_de_bots](#blocklist_de_bots)|3042|3042|18|0.5%|7.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|15|0.0%|5.8%|
[snort_ipfilter](#snort_ipfilter)|9091|9091|9|0.0%|3.5%|
[php_commenters](#php_commenters)|281|281|9|3.2%|3.5%|
[nixspam](#nixspam)|22860|22860|9|0.0%|3.5%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|9|0.0%|3.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|7|0.0%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|7|0.0%|2.7%|
[et_tor](#et_tor)|6520|6520|7|0.1%|2.7%|
[dm_tor](#dm_tor)|6509|6509|7|0.1%|2.7%|
[bm_tor](#bm_tor)|6514|6514|7|0.1%|2.7%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|6|1.6%|2.3%|
[blocklist_de_ftp](#blocklist_de_ftp)|874|874|3|0.3%|1.1%|
[xroxy](#xroxy)|2051|2051|2|0.0%|0.7%|
[openbl_60d](#openbl_60d)|7694|7694|2|0.0%|0.7%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|2|1.1%|0.7%|
[blocklist_de_mail](#blocklist_de_mail)|16484|16484|2|0.0%|0.7%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|1|0.0%|0.3%|
[spamhaus_drop](#spamhaus_drop)|655|18535168|1|0.0%|0.3%|
[ri_web_proxies](#ri_web_proxies)|5930|5930|1|0.0%|0.3%|
[proxyrss](#proxyrss)|1525|1525|1|0.0%|0.3%|
[php_spammers](#php_spammers)|417|417|1|0.2%|0.3%|
[php_dictionary](#php_dictionary)|433|433|1|0.2%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.3%|
[fullbogons](#fullbogons)|3702|670445080|1|0.0%|0.3%|
[et_block](#et_block)|1007|18338646|1|0.0%|0.3%|
[bogons](#bogons)|13|592708608|1|0.0%|0.3%|
[blocklist_de_apache](#blocklist_de_apache)|13972|13972|1|0.0%|0.3%|

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
[nixspam](#nixspam)|22860|22860|54|0.2%|12.9%|
[snort_ipfilter](#snort_ipfilter)|9091|9091|53|0.5%|12.7%|
[blocklist_de](#blocklist_de)|36060|36060|50|0.1%|11.9%|
[blocklist_de_mail](#blocklist_de_mail)|16484|16484|36|0.2%|8.6%|
[php_commenters](#php_commenters)|281|281|32|11.3%|7.6%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|31|0.0%|7.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|26|0.0%|6.2%|
[ri_web_proxies](#ri_web_proxies)|5930|5930|25|0.4%|5.9%|
[xroxy](#xroxy)|2051|2051|20|0.9%|4.7%|
[stopforumspam_1d](#stopforumspam_1d)|7344|7344|18|0.2%|4.3%|
[blocklist_de_bots](#blocklist_de_bots)|3042|3042|10|0.3%|2.3%|
[proxz](#proxz)|631|631|9|1.4%|2.1%|
[et_tor](#et_tor)|6520|6520|6|0.0%|1.4%|
[dm_tor](#dm_tor)|6509|6509|6|0.0%|1.4%|
[bm_tor](#bm_tor)|6514|6514|6|0.0%|1.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|5|0.0%|1.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.9%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2649|2649|4|0.1%|0.9%|
[blocklist_de_apache](#blocklist_de_apache)|13972|13972|4|0.0%|0.9%|
[spamhaus_drop](#spamhaus_drop)|655|18535168|3|0.0%|0.7%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|3|1.7%|0.7%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|3|0.0%|0.7%|
[ri_connect_proxies](#ri_connect_proxies)|2205|2205|2|0.0%|0.4%|
[proxyrss](#proxyrss)|1525|1525|2|0.1%|0.4%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|2|0.0%|0.4%|
[et_block](#et_block)|1007|18338646|2|0.0%|0.4%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.2%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.2%|

## proxyrss

[proxyrss.com](http://www.proxyrss.com) open proxies syndicated from multiple sources.

Source is downloaded from [this link](http://www.proxyrss.com/proxylists/all.gz).

The last time downloaded was found to be dated: Wed Jun  3 13:01:35 UTC 2015.

The ipset `proxyrss` has **1525** entries, **1525** unique IPs.

The following table shows the overlaps of `proxyrss` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxyrss`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxyrss`.
- ` this % ` is the percentage **of this ipset (`proxyrss`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|831|0.8%|54.4%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|688|2.2%|45.1%|
[ri_web_proxies](#ri_web_proxies)|5930|5930|674|11.3%|44.1%|
[xroxy](#xroxy)|2051|2051|460|22.4%|30.1%|
[stopforumspam_1d](#stopforumspam_1d)|7344|7344|438|5.9%|28.7%|
[ri_connect_proxies](#ri_connect_proxies)|2205|2205|259|11.7%|16.9%|
[blocklist_de](#blocklist_de)|36060|36060|206|0.5%|13.5%|
[blocklist_de_bots](#blocklist_de_bots)|3042|3042|201|6.6%|13.1%|
[proxz](#proxz)|631|631|194|30.7%|12.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|59|0.0%|3.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|52|0.0%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|41|0.0%|2.6%|
[nixspam](#nixspam)|22860|22860|20|0.0%|1.3%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|10|1.4%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|6|3.4%|0.3%|
[snort_ipfilter](#snort_ipfilter)|9091|9091|3|0.0%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|3|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|3|0.0%|0.1%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.1%|
[php_dictionary](#php_dictionary)|433|433|2|0.4%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|12692|12692|2|0.0%|0.1%|
[blocklist_de_mail](#blocklist_de_mail)|16484|16484|2|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[et_tor](#et_tor)|6520|6520|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2174|2174|1|0.0%|0.0%|
[et_block](#et_block)|1007|18338646|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6509|6509|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2168|2168|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6514|6514|1|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13972|13972|1|0.0%|0.0%|

## proxz

[proxz.com](http://www.proxz.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.proxz.com/proxylists.xml).

The last time downloaded was found to be dated: Wed Jun  3 15:11:45 UTC 2015.

The ipset `proxz` has **631** entries, **631** unique IPs.

The following table shows the overlaps of `proxz` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `proxz`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `proxz`.
- ` this % ` is the percentage **of this ipset (`proxz`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|387|0.4%|61.3%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|329|1.0%|52.1%|
[xroxy](#xroxy)|2051|2051|277|13.5%|43.8%|
[ri_web_proxies](#ri_web_proxies)|5930|5930|270|4.5%|42.7%|
[proxyrss](#proxyrss)|1525|1525|194|12.7%|30.7%|
[stopforumspam_1d](#stopforumspam_1d)|7344|7344|141|1.9%|22.3%|
[blocklist_de](#blocklist_de)|36060|36060|123|0.3%|19.4%|
[blocklist_de_bots](#blocklist_de_bots)|3042|3042|106|3.4%|16.7%|
[ri_connect_proxies](#ri_connect_proxies)|2205|2205|99|4.4%|15.6%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|56|0.0%|8.8%|
[nixspam](#nixspam)|22860|22860|27|0.1%|4.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|27|0.0%|4.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|25|0.0%|3.9%|
[snort_ipfilter](#snort_ipfilter)|9091|9091|15|0.1%|2.3%|
[blocklist_de_mail](#blocklist_de_mail)|16484|16484|15|0.0%|2.3%|
[php_spammers](#php_spammers)|417|417|9|2.1%|1.4%|
[php_dictionary](#php_dictionary)|433|433|9|2.0%|1.4%|
[php_commenters](#php_commenters)|281|281|3|1.0%|0.4%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|3|0.4%|0.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|3|1.7%|0.4%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|3|0.0%|0.4%|
[et_compromised](#et_compromised)|2174|2174|2|0.0%|0.3%|
[bruteforceblocker](#bruteforceblocker)|2168|2168|2|0.0%|0.3%|
[blocklist_de_ssh](#blocklist_de_ssh)|12692|12692|2|0.0%|0.3%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.1%|
[et_block](#et_block)|1007|18338646|1|0.0%|0.1%|

## ri_connect_proxies

[rosinstrument.com](http://www.rosinstrument.com) open CONNECT proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/plab100.xml).

The last time downloaded was found to be dated: Wed Jun  3 11:29:54 UTC 2015.

The ipset `ri_connect_proxies` has **2205** entries, **2205** unique IPs.

The following table shows the overlaps of `ri_connect_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_connect_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_connect_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_connect_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|1295|1.3%|58.7%|
[ri_web_proxies](#ri_web_proxies)|5930|5930|907|15.2%|41.1%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|697|2.2%|31.6%|
[xroxy](#xroxy)|2051|2051|339|16.5%|15.3%|
[proxyrss](#proxyrss)|1525|1525|259|16.9%|11.7%|
[stopforumspam_1d](#stopforumspam_1d)|7344|7344|195|2.6%|8.8%|
[proxz](#proxz)|631|631|99|15.6%|4.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|88|0.0%|3.9%|
[blocklist_de](#blocklist_de)|36060|36060|75|0.2%|3.4%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|72|0.0%|3.2%|
[blocklist_de_bots](#blocklist_de_bots)|3042|3042|72|2.3%|3.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|48|0.0%|2.1%|
[nixspam](#nixspam)|22860|22860|23|0.1%|1.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|6|0.8%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9091|9091|5|0.0%|0.2%|
[php_dictionary](#php_dictionary)|433|433|3|0.6%|0.1%|
[php_spammers](#php_spammers)|417|417|2|0.4%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16484|16484|2|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[et_tor](#et_tor)|6520|6520|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6509|6509|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6514|6514|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|12692|12692|1|0.0%|0.0%|

## ri_web_proxies

[rosinstrument.com](http://www.rosinstrument.com) open HTTP proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://tools.rosinstrument.com/proxy/l100.xml).

The last time downloaded was found to be dated: Wed Jun  3 13:41:42 UTC 2015.

The ipset `ri_web_proxies` has **5930** entries, **5930** unique IPs.

The following table shows the overlaps of `ri_web_proxies` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `ri_web_proxies`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `ri_web_proxies`.
- ` this % ` is the percentage **of this ipset (`ri_web_proxies`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|2908|3.1%|49.0%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|1734|5.5%|29.2%|
[ri_connect_proxies](#ri_connect_proxies)|2205|2205|907|41.1%|15.2%|
[xroxy](#xroxy)|2051|2051|858|41.8%|14.4%|
[proxyrss](#proxyrss)|1525|1525|674|44.1%|11.3%|
[stopforumspam_1d](#stopforumspam_1d)|7344|7344|558|7.5%|9.4%|
[blocklist_de](#blocklist_de)|36060|36060|363|1.0%|6.1%|
[blocklist_de_bots](#blocklist_de_bots)|3042|3042|317|10.4%|5.3%|
[proxz](#proxz)|631|631|270|42.7%|4.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|179|0.0%|3.0%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|167|0.0%|2.8%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|125|0.0%|2.1%|
[nixspam](#nixspam)|22860|22860|95|0.4%|1.6%|
[snort_ipfilter](#snort_ipfilter)|9091|9091|55|0.6%|0.9%|
[blocklist_de_mail](#blocklist_de_mail)|16484|16484|46|0.2%|0.7%|
[php_dictionary](#php_dictionary)|433|433|33|7.6%|0.5%|
[php_spammers](#php_spammers)|417|417|25|5.9%|0.4%|
[php_commenters](#php_commenters)|281|281|11|3.9%|0.1%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|11|1.6%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|5|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|5|2.8%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|4|1.0%|0.0%|
[et_tor](#et_tor)|6520|6520|4|0.0%|0.0%|
[dm_tor](#dm_tor)|6509|6509|3|0.0%|0.0%|
[bm_tor](#bm_tor)|6514|6514|3|0.0%|0.0%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|3|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2168|2168|1|0.0%|0.0%|

## shunlist

[AutoShun.org](http://autoshun.org/) IPs identified as hostile by correlating logs from distributed snort installations running the autoshun plugin

Source is downloaded from [this link](http://www.autoshun.org/files/shunlist.csv).

The last time downloaded was found to be dated: Wed Jun  3 14:30:06 UTC 2015.

The ipset `shunlist` has **1296** entries, **1296** unique IPs.

The following table shows the overlaps of `shunlist` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `shunlist`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `shunlist`.
- ` this % ` is the percentage **of this ipset (`shunlist`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|179596|179596|1291|0.7%|99.6%|
[openbl_60d](#openbl_60d)|7694|7694|616|8.0%|47.5%|
[openbl_30d](#openbl_30d)|3280|3280|600|18.2%|46.2%|
[bruteforceblocker](#bruteforceblocker)|2168|2168|515|23.7%|39.7%|
[et_compromised](#et_compromised)|2174|2174|514|23.6%|39.6%|
[blocklist_de](#blocklist_de)|36060|36060|417|1.1%|32.1%|
[openbl_7d](#openbl_7d)|1005|1005|383|38.1%|29.5%|
[blocklist_de_ssh](#blocklist_de_ssh)|12692|12692|372|2.9%|28.7%|
[et_block](#et_block)|1007|18338646|106|0.0%|8.1%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|105|0.0%|8.1%|
[spamhaus_drop](#spamhaus_drop)|655|18535168|99|0.0%|7.6%|
[openbl_1d](#openbl_1d)|306|306|83|27.1%|6.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|72|0.0%|5.5%|
[dshield](#dshield)|20|5120|59|1.1%|4.5%|
[sslbl](#sslbl)|357|357|55|15.4%|4.2%|
[blocklist_de_apache](#blocklist_de_apache)|13972|13972|36|0.2%|2.7%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|26|0.0%|2.0%|
[ciarmy](#ciarmy)|338|338|26|7.6%|2.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|20|11.4%|1.5%|
[voipbl](#voipbl)|10398|10808|13|0.1%|1.0%|
[blocklist_de_mail](#blocklist_de_mail)|16484|16484|7|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|5|0.0%|0.3%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|5|0.0%|0.3%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|4|0.0%|0.3%|
[blocklist_de_imap](#blocklist_de_imap)|2401|2401|4|0.1%|0.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|3|0.0%|0.2%|
[snort_ipfilter](#snort_ipfilter)|9091|9091|2|0.0%|0.1%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|2|0.5%|0.1%|
[stopforumspam_1d](#stopforumspam_1d)|7344|7344|1|0.0%|0.0%|
[nixspam](#nixspam)|22860|22860|1|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_tor](#et_tor)|6520|6520|1|0.0%|0.0%|
[dm_tor](#dm_tor)|6509|6509|1|0.0%|0.0%|
[bm_tor](#bm_tor)|6514|6514|1|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|874|874|1|0.1%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2649|2649|1|0.0%|0.0%|

## snort_ipfilter

[labs.snort.org](https://labs.snort.org/) supplied IP blacklist (this list seems to be updated frequently, but we found no information about it)

Source is downloaded from [this link](http://labs.snort.org/feeds/ip-filter.blf).

The last time downloaded was found to be dated: Wed Jun  3 13:30:00 UTC 2015.

The ipset `snort_ipfilter` has **9091** entries, **9091** unique IPs.

The following table shows the overlaps of `snort_ipfilter` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `snort_ipfilter`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `snort_ipfilter`.
- ` this % ` is the percentage **of this ipset (`snort_ipfilter`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_tor](#et_tor)|6520|6520|1113|17.0%|12.2%|
[dm_tor](#dm_tor)|6509|6509|1073|16.4%|11.8%|
[bm_tor](#bm_tor)|6514|6514|1073|16.4%|11.8%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|808|0.8%|8.8%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|611|1.9%|6.7%|
[stopforumspam_1d](#stopforumspam_1d)|7344|7344|324|4.4%|3.5%|
[et_block](#et_block)|1007|18338646|305|0.0%|3.3%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|234|0.0%|2.5%|
[zeus](#zeus)|270|270|230|85.1%|2.5%|
[nixspam](#nixspam)|22860|22860|206|0.9%|2.2%|
[zeus_badips](#zeus_badips)|234|234|205|87.6%|2.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|176|47.3%|1.9%|
[blocklist_de](#blocklist_de)|36060|36060|164|0.4%|1.8%|
[blocklist_de_mail](#blocklist_de_mail)|16484|16484|131|0.7%|1.4%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|118|0.0%|1.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|112|0.0%|1.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|101|0.0%|1.1%|
[feodo](#feodo)|86|86|65|75.5%|0.7%|
[php_dictionary](#php_dictionary)|433|433|57|13.1%|0.6%|
[ri_web_proxies](#ri_web_proxies)|5930|5930|55|0.9%|0.6%|
[php_spammers](#php_spammers)|417|417|53|12.7%|0.5%|
[xroxy](#xroxy)|2051|2051|48|2.3%|0.5%|
[php_commenters](#php_commenters)|281|281|37|13.1%|0.4%|
[sslbl](#sslbl)|357|357|27|7.5%|0.2%|
[malwaredomainlist](#malwaredomainlist)|1284|1284|26|2.0%|0.2%|
[blocklist_de_bots](#blocklist_de_bots)|3042|3042|26|0.8%|0.2%|
[openbl_60d](#openbl_60d)|7694|7694|24|0.3%|0.2%|
[spamhaus_drop](#spamhaus_drop)|655|18535168|20|0.0%|0.2%|
[proxz](#proxz)|631|631|15|2.3%|0.1%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|14|0.0%|0.1%|
[palevo](#palevo)|13|13|11|84.6%|0.1%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|11|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|9|3.5%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13972|13972|8|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|6|0.0%|0.0%|
[ri_connect_proxies](#ri_connect_proxies)|2205|2205|5|0.2%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2649|2649|5|0.1%|0.0%|
[proxyrss](#proxyrss)|1525|1525|3|0.1%|0.0%|
[shunlist](#shunlist)|1296|1296|2|0.1%|0.0%|
[openbl_30d](#openbl_30d)|3280|3280|2|0.0%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[dshield](#dshield)|20|5120|2|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2401|2401|2|0.0%|0.0%|
[openbl_7d](#openbl_7d)|1005|1005|1|0.0%|0.0%|
[malc0de](#malc0de)|386|386|1|0.2%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|1|0.1%|0.0%|
[et_compromised](#et_compromised)|2174|2174|1|0.0%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|1|0.5%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|12692|12692|1|0.0%|0.0%|

## spamhaus_drop

[Spamhaus.org](http://www.spamhaus.org) DROP list (according to their site this list should be dropped at tier-1 ISPs globaly) - **excellent list**

Source is downloaded from [this link](http://www.spamhaus.org/drop/drop.txt).

The last time downloaded was found to be dated: Wed Jun  3 09:51:26 UTC 2015.

The ipset `spamhaus_drop` has **655** entries, **18535168** unique IPs.

The following table shows the overlaps of `spamhaus_drop` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `spamhaus_drop`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `spamhaus_drop`.
- ` this % ` is the percentage **of this ipset (`spamhaus_drop`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|1007|18338646|18267904|99.6%|98.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8598042|2.4%|46.3%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|7079936|77.1%|38.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|2272266|0.2%|12.2%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|195904|0.1%|1.0%|
[fullbogons](#fullbogons)|3702|670445080|151552|0.0%|0.8%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|1884|1.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1037|0.3%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|1001|1.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|512|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|345|1.1%|0.0%|
[dshield](#dshield)|20|5120|256|5.0%|0.0%|
[openbl_60d](#openbl_60d)|7694|7694|239|3.1%|0.0%|
[openbl_30d](#openbl_30d)|3280|3280|160|4.8%|0.0%|
[blocklist_de](#blocklist_de)|36060|36060|158|0.4%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|12692|12692|112|0.8%|0.0%|
[et_compromised](#et_compromised)|2174|2174|101|4.6%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2168|2168|100|4.6%|0.0%|
[shunlist](#shunlist)|1296|1296|99|7.6%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7344|7344|94|1.2%|0.0%|
[openbl_7d](#openbl_7d)|1005|1005|74|7.3%|0.0%|
[nixspam](#nixspam)|22860|22860|73|0.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1284|1284|29|2.2%|0.0%|
[php_commenters](#php_commenters)|281|281|25|8.8%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16484|16484|24|0.1%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9091|9091|20|0.2%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3042|3042|19|0.6%|0.0%|
[openbl_1d](#openbl_1d)|306|306|17|5.5%|0.0%|
[zeus_badips](#zeus_badips)|234|234|16|6.8%|0.0%|
[zeus](#zeus)|270|270|16|5.9%|0.0%|
[voipbl](#voipbl)|10398|10808|14|0.1%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2401|2401|13|0.5%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|7|4.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|6|0.4%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|6|0.0%|0.0%|
[php_dictionary](#php_dictionary)|433|433|4|0.9%|0.0%|
[malc0de](#malc0de)|386|386|4|1.0%|0.0%|
[php_spammers](#php_spammers)|417|417|3|0.7%|0.0%|
[sslbl](#sslbl)|357|357|2|0.5%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|2|0.2%|0.0%|
[et_tor](#et_tor)|6520|6520|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6509|6509|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6514|6514|2|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2649|2649|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13972|13972|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[et_botcc](#et_botcc)|511|511|1|0.1%|0.0%|
[blocklist_de_sip](#blocklist_de_sip)|110|110|1|0.9%|0.0%|

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
[spamhaus_drop](#spamhaus_drop)|655|18535168|512|0.0%|0.1%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|271|0.1%|0.0%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|98|0.1%|0.0%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|23|0.0%|0.0%|
[blocklist_de](#blocklist_de)|36060|36060|13|0.0%|0.0%|
[php_commenters](#php_commenters)|281|281|7|2.4%|0.0%|
[snort_ipfilter](#snort_ipfilter)|9091|9091|6|0.0%|0.0%|
[openbl_60d](#openbl_60d)|7694|7694|6|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3280|3280|6|0.1%|0.0%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|6|3.4%|0.0%|
[zeus_badips](#zeus_badips)|234|234|5|2.1%|0.0%|
[zeus](#zeus)|270|270|5|1.8%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7344|7344|5|0.0%|0.0%|
[shunlist](#shunlist)|1296|1296|5|0.3%|0.0%|
[openbl_7d](#openbl_7d)|1005|1005|5|0.4%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3042|3042|5|0.1%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16484|16484|4|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|12692|12692|2|0.0%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13972|13972|2|0.0%|0.0%|
[php_harvesters](#php_harvesters)|257|257|1|0.3%|0.0%|
[nixspam](#nixspam)|22860|22860|1|0.0%|0.0%|
[malc0de](#malc0de)|386|386|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2401|2401|1|0.0%|0.0%|

## sslbl

[Abuse.ch SSL Blacklist](https://sslbl.abuse.ch/) bad SSL traffic related to malware or botnet activities - **excellent list**

Source is downloaded from [this link](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv).

The last time downloaded was found to be dated: Wed Jun  3 15:15:06 UTC 2015.

The ipset `sslbl` has **357** entries, **357** unique IPs.

The following table shows the overlaps of `sslbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `sslbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `sslbl`.
- ` this % ` is the percentage **of this ipset (`sslbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[alienvault_reputation](#alienvault_reputation)|179596|179596|63|0.0%|17.6%|
[shunlist](#shunlist)|1296|1296|55|4.2%|15.4%|
[et_block](#et_block)|1007|18338646|33|0.0%|9.2%|
[feodo](#feodo)|86|86|31|36.0%|8.6%|
[snort_ipfilter](#snort_ipfilter)|9091|9091|27|0.2%|7.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|23|0.0%|6.4%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|6|0.0%|1.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|3|0.0%|0.8%|
[spamhaus_drop](#spamhaus_drop)|655|18535168|2|0.0%|0.5%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|1|0.0%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.2%|

## stopforumspam_1d

[StopForumSpam.com](http://www.stopforumspam.com) IPs used by forum spammers in the last 24 hours - **excellent list**

Source is downloaded from [this link](http://www.stopforumspam.com/downloads/listed_ip_1.zip).

The last time downloaded was found to be dated: Wed Jun  3 15:00:02 UTC 2015.

The ipset `stopforumspam_1d` has **7344** entries, **7344** unique IPs.

The following table shows the overlaps of `stopforumspam_1d` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `stopforumspam_1d`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `stopforumspam_1d`.
- ` this % ` is the percentage **of this ipset (`stopforumspam_1d`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|5559|5.9%|75.6%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|5427|17.4%|73.8%|
[blocklist_de](#blocklist_de)|36060|36060|1477|4.0%|20.1%|
[blocklist_de_bots](#blocklist_de_bots)|3042|3042|1422|46.7%|19.3%|
[ri_web_proxies](#ri_web_proxies)|5930|5930|558|9.4%|7.5%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|465|0.0%|6.3%|
[proxyrss](#proxyrss)|1525|1525|438|28.7%|5.9%|
[xroxy](#xroxy)|2051|2051|325|15.8%|4.4%|
[snort_ipfilter](#snort_ipfilter)|9091|9091|324|3.5%|4.4%|
[et_tor](#et_tor)|6520|6520|292|4.4%|3.9%|
[dm_tor](#dm_tor)|6509|6509|290|4.4%|3.9%|
[bm_tor](#bm_tor)|6514|6514|290|4.4%|3.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|248|0.0%|3.3%|
[ri_connect_proxies](#ri_connect_proxies)|2205|2205|195|8.8%|2.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|178|0.0%|2.4%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|153|41.1%|2.0%|
[proxz](#proxz)|631|631|141|22.3%|1.9%|
[php_commenters](#php_commenters)|281|281|107|38.0%|1.4%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|105|60.0%|1.4%|
[et_block](#et_block)|1007|18338646|96|0.0%|1.3%|
[spamhaus_drop](#spamhaus_drop)|655|18535168|94|0.0%|1.2%|
[nixspam](#nixspam)|22860|22860|67|0.2%|0.9%|
[blocklist_de_apache](#blocklist_de_apache)|13972|13972|62|0.4%|0.8%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|60|0.0%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|46|0.0%|0.6%|
[blocklist_de_mail](#blocklist_de_mail)|16484|16484|41|0.2%|0.5%|
[php_harvesters](#php_harvesters)|257|257|34|13.2%|0.4%|
[openbl_60d](#openbl_60d)|7694|7694|20|0.2%|0.2%|
[php_spammers](#php_spammers)|417|417|18|4.3%|0.2%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2649|2649|18|0.6%|0.2%|
[php_dictionary](#php_dictionary)|433|433|17|3.9%|0.2%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|12|0.0%|0.1%|
[dshield](#dshield)|20|5120|10|0.1%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|5|0.0%|0.0%|
[voipbl](#voipbl)|10398|10808|4|0.0%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|4|0.5%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|874|874|4|0.4%|0.0%|
[zeus](#zeus)|270|270|2|0.7%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[zeus_badips](#zeus_badips)|234|234|1|0.4%|0.0%|
[shunlist](#shunlist)|1296|1296|1|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3280|3280|1|0.0%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1284|1284|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|12692|12692|1|0.0%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2401|2401|1|0.0%|0.0%|

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
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|5884|0.0%|6.3%|
[stopforumspam_1d](#stopforumspam_1d)|7344|7344|5559|75.6%|5.9%|
[ri_web_proxies](#ri_web_proxies)|5930|5930|2908|49.0%|3.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2510|0.0%|2.7%|
[blocklist_de](#blocklist_de)|36060|36060|2459|6.8%|2.6%|
[blocklist_de_bots](#blocklist_de_bots)|3042|3042|2072|68.1%|2.2%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|1545|0.0%|1.6%|
[ri_connect_proxies](#ri_connect_proxies)|2205|2205|1295|58.7%|1.3%|
[xroxy](#xroxy)|2051|2051|1205|58.7%|1.3%|
[et_block](#et_block)|1007|18338646|1002|0.0%|1.0%|
[spamhaus_drop](#spamhaus_drop)|655|18535168|1001|0.0%|1.0%|
[proxyrss](#proxyrss)|1525|1525|831|54.4%|0.8%|
[snort_ipfilter](#snort_ipfilter)|9091|9091|808|8.8%|0.8%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|737|0.0%|0.7%|
[et_tor](#et_tor)|6520|6520|643|9.8%|0.6%|
[dm_tor](#dm_tor)|6509|6509|623|9.5%|0.6%|
[bm_tor](#bm_tor)|6514|6514|623|9.5%|0.6%|
[proxz](#proxz)|631|631|387|61.3%|0.4%|
[nixspam](#nixspam)|22860|22860|254|1.1%|0.2%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|232|62.3%|0.2%|
[blocklist_de_mail](#blocklist_de_mail)|16484|16484|224|1.3%|0.2%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|217|0.1%|0.2%|
[php_commenters](#php_commenters)|281|281|206|73.3%|0.2%|
[blocklist_de_apache](#blocklist_de_apache)|13972|13972|202|1.4%|0.2%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|129|73.7%|0.1%|
[php_spammers](#php_spammers)|417|417|100|23.9%|0.1%|
[blocklist_de_ssh](#blocklist_de_ssh)|12692|12692|100|0.7%|0.1%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|98|0.0%|0.1%|
[php_dictionary](#php_dictionary)|433|433|85|19.6%|0.0%|
[php_harvesters](#php_harvesters)|257|257|62|24.1%|0.0%|
[openbl_60d](#openbl_60d)|7694|7694|56|0.7%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|48|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2649|2649|41|1.5%|0.0%|
[voipbl](#voipbl)|10398|10808|39|0.3%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|22|3.2%|0.0%|
[dshield](#dshield)|20|5120|19|0.3%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|15|0.0%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|874|874|12|1.3%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2168|2168|10|0.4%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2401|2401|9|0.3%|0.0%|
[et_compromised](#et_compromised)|2174|2174|8|0.3%|0.0%|
[shunlist](#shunlist)|1296|1296|5|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3280|3280|4|0.1%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1284|1284|4|0.3%|0.0%|
[zeus_badips](#zeus_badips)|234|234|3|1.2%|0.0%|
[zeus](#zeus)|270|270|3|1.1%|0.0%|
[openbl_7d](#openbl_7d)|1005|1005|3|0.2%|0.0%|
[openbl_1d](#openbl_1d)|306|306|3|0.9%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|2|0.1%|0.0%|
[fullbogons](#fullbogons)|3702|670445080|2|0.0%|0.0%|
[sslbl](#sslbl)|357|357|1|0.2%|0.0%|
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
[stopforumspam_1d](#stopforumspam_1d)|7344|7344|5427|73.8%|17.4%|
[blocklist_de](#blocklist_de)|36060|36060|2097|5.8%|6.7%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|2017|0.0%|6.4%|
[blocklist_de_bots](#blocklist_de_bots)|3042|3042|1905|62.6%|6.1%|
[ri_web_proxies](#ri_web_proxies)|5930|5930|1734|29.2%|5.5%|
[xroxy](#xroxy)|2051|2051|968|47.1%|3.1%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|940|0.0%|3.0%|
[ri_connect_proxies](#ri_connect_proxies)|2205|2205|697|31.6%|2.2%|
[proxyrss](#proxyrss)|1525|1525|688|45.1%|2.2%|
[snort_ipfilter](#snort_ipfilter)|9091|9091|611|6.7%|1.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|581|0.0%|1.8%|
[et_tor](#et_tor)|6520|6520|492|7.5%|1.5%|
[dm_tor](#dm_tor)|6509|6509|474|7.2%|1.5%|
[bm_tor](#bm_tor)|6514|6514|474|7.2%|1.5%|
[spamhaus_drop](#spamhaus_drop)|655|18535168|345|0.0%|1.1%|
[et_block](#et_block)|1007|18338646|345|0.0%|1.1%|
[proxz](#proxz)|631|631|329|52.1%|1.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|196|52.6%|0.6%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|174|0.0%|0.5%|
[nixspam](#nixspam)|22860|22860|157|0.6%|0.5%|
[php_commenters](#php_commenters)|281|281|151|53.7%|0.4%|
[blocklist_de_mail](#blocklist_de_mail)|16484|16484|133|0.8%|0.4%|
[blocklist_de_apache](#blocklist_de_apache)|13972|13972|120|0.8%|0.3%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|118|67.4%|0.3%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|102|0.0%|0.3%|
[php_dictionary](#php_dictionary)|433|433|65|15.0%|0.2%|
[php_spammers](#php_spammers)|417|417|61|14.6%|0.1%|
[php_harvesters](#php_harvesters)|257|257|48|18.6%|0.1%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2649|2649|28|1.0%|0.0%|
[openbl_60d](#openbl_60d)|7694|7694|26|0.3%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|26|0.0%|0.0%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|23|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|12692|12692|15|0.1%|0.0%|
[voipbl](#voipbl)|10398|10808|13|0.1%|0.0%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|12|1.7%|0.0%|
[dshield](#dshield)|20|5120|12|0.2%|0.0%|
[blocklist_de_ftp](#blocklist_de_ftp)|874|874|8|0.9%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|7|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2168|2168|6|0.2%|0.0%|
[et_compromised](#et_compromised)|2174|2174|5|0.2%|0.0%|
[shunlist](#shunlist)|1296|1296|4|0.3%|0.0%|
[malwaredomainlist](#malwaredomainlist)|1284|1284|3|0.2%|0.0%|
[blocklist_de_imap](#blocklist_de_imap)|2401|2401|3|0.1%|0.0%|
[zeus_badips](#zeus_badips)|234|234|1|0.4%|0.0%|
[zeus](#zeus)|270|270|1|0.3%|0.0%|
[openbl_30d](#openbl_30d)|3280|3280|1|0.0%|0.0%|
[ib_bluetack_webexploit](#ib_bluetack_webexploit)|1460|1460|1|0.0%|0.0%|

## virbl

[VirBL](http://virbl.bit.nl/) is a project of which the idea was born during the RIPE-48 meeting. The plan was to get reports of virusscanning mailservers, and put the IP-addresses that were reported to send viruses on a blacklist.

Source is downloaded from [this link](http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt).

The last time downloaded was found to be dated: Wed Jun  3 15:42:03 UTC 2015.

The ipset `virbl` has **42** entries, **42** unique IPs.

The following table shows the overlaps of `virbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `virbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `virbl`.
- ` this % ` is the percentage **of this ipset (`virbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|7|0.0%|16.6%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4|0.0%|9.5%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|2|0.0%|4.7%|

## voipbl

[VoIPBL.org](http://www.voipbl.org/) a distributed VoIP blacklist that is aimed to protects against VoIP Fraud and minimizing abuse for network that have publicly accessible PBX's. Several algorithms, external sources and manual confirmation are used before they categorize something as an attack and determine the threat level.

Source is downloaded from [this link](http://www.voipbl.org/update/).

The last time downloaded was found to be dated: Wed Jun  3 14:45:09 UTC 2015.

The ipset `voipbl` has **10398** entries, **10808** unique IPs.

The following table shows the overlaps of `voipbl` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `voipbl`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `voipbl`.
- ` this % ` is the percentage **of this ipset (`voipbl`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|1594|0.0%|14.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|432|0.0%|3.9%|
[fullbogons](#fullbogons)|3702|670445080|319|0.0%|2.9%|
[bogons](#bogons)|13|592708608|319|0.0%|2.9%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|298|0.0%|2.7%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|203|0.1%|1.8%|
[blocklist_de](#blocklist_de)|36060|36060|46|0.1%|0.4%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|39|0.0%|0.3%|
[blocklist_de_sip](#blocklist_de_sip)|110|110|34|30.9%|0.3%|
[spamhaus_drop](#spamhaus_drop)|655|18535168|14|0.0%|0.1%|
[et_block](#et_block)|1007|18338646|14|0.0%|0.1%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|13|0.0%|0.1%|
[shunlist](#shunlist)|1296|1296|13|1.0%|0.1%|
[dshield](#dshield)|20|5120|12|0.2%|0.1%|
[openbl_60d](#openbl_60d)|7694|7694|8|0.1%|0.0%|
[ciarmy](#ciarmy)|338|338|6|1.7%|0.0%|
[blocklist_de_apache](#blocklist_de_apache)|13972|13972|5|0.0%|0.0%|
[stopforumspam_1d](#stopforumspam_1d)|7344|7344|4|0.0%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|4|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|12692|12692|4|0.0%|0.0%|
[openbl_30d](#openbl_30d)|3280|3280|3|0.0%|0.0%|
[openbl_7d](#openbl_7d)|1005|1005|2|0.1%|0.0%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|2|0.0%|0.0%|
[et_tor](#et_tor)|6520|6520|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6509|6509|2|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2168|2168|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6514|6514|2|0.0%|0.0%|
[blocklist_de_bruteforce](#blocklist_de_bruteforce)|2649|2649|2|0.0%|0.0%|
[blocklist_de_bots](#blocklist_de_bots)|3042|3042|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2174|2174|1|0.0%|0.0%|
[blocklist_de_mail](#blocklist_de_mail)|16484|16484|1|0.0%|0.0%|

## xroxy

[xroxy.com](http://www.xroxy.com) open proxies (this list is composed using an RSS feed and aggregated for the last 30 days)

Source is downloaded from [this link](http://www.xroxy.com/proxyrss.xml).

The last time downloaded was found to be dated: Wed Jun  3 15:33:01 UTC 2015.

The ipset `xroxy` has **2051** entries, **2051** unique IPs.

The following table shows the overlaps of `xroxy` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `xroxy`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `xroxy`.
- ` this % ` is the percentage **of this ipset (`xroxy`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|1205|1.3%|58.7%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|968|3.1%|47.1%|
[ri_web_proxies](#ri_web_proxies)|5930|5930|858|14.4%|41.8%|
[proxyrss](#proxyrss)|1525|1525|460|30.1%|22.4%|
[ri_connect_proxies](#ri_connect_proxies)|2205|2205|339|15.3%|16.5%|
[stopforumspam_1d](#stopforumspam_1d)|7344|7344|325|4.4%|15.8%|
[proxz](#proxz)|631|631|277|43.8%|13.5%|
[blocklist_de](#blocklist_de)|36060|36060|242|0.6%|11.7%|
[blocklist_de_bots](#blocklist_de_bots)|3042|3042|205|6.7%|9.9%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|99|0.0%|4.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|89|0.0%|4.3%|
[nixspam](#nixspam)|22860|22860|72|0.3%|3.5%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|57|0.0%|2.7%|
[snort_ipfilter](#snort_ipfilter)|9091|9091|48|0.5%|2.3%|
[blocklist_de_mail](#blocklist_de_mail)|16484|16484|35|0.2%|1.7%|
[php_dictionary](#php_dictionary)|433|433|24|5.5%|1.1%|
[php_spammers](#php_spammers)|417|417|20|4.7%|0.9%|
[ib_bluetack_proxies](#ib_bluetack_proxies)|673|673|13|1.9%|0.6%|
[blocklist_de_strongips](#blocklist_de_strongips)|175|175|7|4.0%|0.3%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|5|0.0%|0.2%|
[php_commenters](#php_commenters)|281|281|3|1.0%|0.1%|
[ib_bluetack_badpeers](#ib_bluetack_badpeers)|48134|48134|3|0.0%|0.1%|
[php_harvesters](#php_harvesters)|257|257|2|0.7%|0.0%|
[et_tor](#et_tor)|6520|6520|2|0.0%|0.0%|
[dm_tor](#dm_tor)|6509|6509|2|0.0%|0.0%|
[bm_tor](#bm_tor)|6514|6514|2|0.0%|0.0%|
[blocklist_de_ssh](#blocklist_de_ssh)|12692|12692|2|0.0%|0.0%|
[maxmind_proxy_fraud](#maxmind_proxy_fraud)|372|372|1|0.2%|0.0%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.0%|
[et_compromised](#et_compromised)|2174|2174|1|0.0%|0.0%|
[et_block](#et_block)|1007|18338646|1|0.0%|0.0%|
[bruteforceblocker](#bruteforceblocker)|2168|2168|1|0.0%|0.0%|

## zeus

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) standard, contains the same data as the ZeuS IP blocklist (zeus_badips) but with the slight difference that it doesn't exclude hijacked websites (level 2) and free web hosting providers (level 3). This means that this blocklist contains all IPv4 addresses associated with ZeuS C&Cs which are currently being tracked by ZeuS Tracker. Hence this blocklist will likely cause some false positives. - **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist).

The last time downloaded was found to be dated: Wed Jun  3 13:00:13 UTC 2015.

The ipset `zeus` has **270** entries, **270** unique IPs.

The following table shows the overlaps of `zeus` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus`.
- ` this % ` is the percentage **of this ipset (`zeus`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[et_block](#et_block)|1007|18338646|264|0.0%|97.7%|
[zeus_badips](#zeus_badips)|234|234|234|100.0%|86.6%|
[snort_ipfilter](#snort_ipfilter)|9091|9091|230|2.5%|85.1%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|66|0.0%|24.4%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|19|0.0%|7.0%|
[spamhaus_drop](#spamhaus_drop)|655|18535168|16|0.0%|5.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|3.7%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|9|0.0%|3.3%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|7|0.0%|2.5%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|5|0.0%|1.8%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|3|0.0%|1.1%|
[stopforumspam_1d](#stopforumspam_1d)|7344|7344|2|0.0%|0.7%|
[openbl_60d](#openbl_60d)|7694|7694|2|0.0%|0.7%|
[openbl_30d](#openbl_30d)|3280|3280|2|0.0%|0.7%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|1|0.0%|0.3%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.3%|
[openbl_7d](#openbl_7d)|1005|1005|1|0.0%|0.3%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.3%|
[et_compromised](#et_compromised)|2174|2174|1|0.0%|0.3%|

## zeus_badips

[Abuse.ch Zeus tracker](https://zeustracker.abuse.ch) badips includes IPv4 addresses that are used by the ZeuS trojan. It is the recommened blocklist if you want to block only ZeuS IPs. It excludes IP addresses that ZeuS Tracker believes to be hijacked (level 2) or belong to a free web hosting provider (level 3). Hence the false postive rate should be much lower compared to the standard ZeuS IP blocklist. **excellent list**

Source is downloaded from [this link](https://zeustracker.abuse.ch/blocklist.php?download=badips).

The last time downloaded was found to be dated: Wed Jun  3 15:27:12 UTC 2015.

The ipset `zeus_badips` has **234** entries, **234** unique IPs.

The following table shows the overlaps of `zeus_badips` with all the other ipsets supported. Only the ipsets that have at least 1 IP overlap are shown. if an ipset is not shown here, it does not have any overlap with `zeus_badips`.

- ` them % ` is the percentage of IPs of each row ipset (them), found in `zeus_badips`.
- ` this % ` is the percentage **of this ipset (`zeus_badips`)**, found in the IPs of each other ipset.

ipset|entries|unique IPs|IPs on both| them % | this % |
:---:|:-----:|:--------:|:---------:|:------:|:------:|
[zeus](#zeus)|270|270|234|86.6%|100.0%|
[et_block](#et_block)|1007|18338646|230|0.0%|98.2%|
[snort_ipfilter](#snort_ipfilter)|9091|9091|205|2.2%|87.6%|
[alienvault_reputation](#alienvault_reputation)|179596|179596|37|0.0%|15.8%|
[spamhaus_drop](#spamhaus_drop)|655|18535168|16|0.0%|6.8%|
[ib_bluetack_level3](#ib_bluetack_level3)|17802|139104824|14|0.0%|5.9%|
[ib_bluetack_hijacked](#ib_bluetack_hijacked)|535|9177856|10|0.0%|4.2%|
[ib_bluetack_level2](#ib_bluetack_level2)|72774|348707599|8|0.0%|3.4%|
[spamhaus_edrop](#spamhaus_edrop)|57|487168|5|0.0%|2.1%|
[ib_bluetack_level1](#ib_bluetack_level1)|218309|764987411|4|0.0%|1.7%|
[stopforumspam_30d](#stopforumspam_30d)|92665|92665|3|0.0%|1.2%|
[stopforumspam_7d](#stopforumspam_7d)|31033|31033|1|0.0%|0.4%|
[stopforumspam_1d](#stopforumspam_1d)|7344|7344|1|0.0%|0.4%|
[php_commenters](#php_commenters)|281|281|1|0.3%|0.4%|
[openbl_60d](#openbl_60d)|7694|7694|1|0.0%|0.4%|
[openbl_30d](#openbl_30d)|3280|3280|1|0.0%|0.4%|
[ib_bluetack_spyware](#ib_bluetack_spyware)|3274|339192|1|0.0%|0.4%|
[et_compromised](#et_compromised)|2174|2174|1|0.0%|0.4%|
